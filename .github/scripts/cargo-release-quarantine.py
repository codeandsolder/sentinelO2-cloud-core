#!/usr/bin/env python3
"""Enforce a minimum crates.io release age on Cargo update proposals."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
import tomllib
import urllib.parse
import urllib.request

DEP_TABLES = {"dependencies", "dev-dependencies", "build-dependencies"}
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
_cache: dict[str, dict] = {}


def git_show(path: str) -> bytes:
    return subprocess.check_output(["git", "show", f"HEAD:{path}"])


def load_lock(raw: bytes) -> list[dict]:
    return tomllib.loads(raw.decode()).get("package", [])


def package_key(pkg: dict) -> tuple[str, str, str | None]:
    return pkg["name"], pkg["version"], pkg.get("source")


def crate_versions(name: str) -> dict:
    if name in _cache:
        return _cache[name]
    url = "https://crates.io/api/v1/crates/" + urllib.parse.quote(name, safe="")
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "codeandsolder-maintenance-detector/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.load(response)
    versions = {v["num"]: v for v in payload.get("versions", [])}
    _cache[name] = versions
    return versions


def created_at(pkg: dict) -> dt.datetime | None:
    if pkg.get("source") != CRATES_IO_SOURCE:
        return None
    info = crate_versions(pkg["name"]).get(pkg["version"])
    if not info:
        return None
    value = info.get("created_at")
    if not value:
        return None
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def ineligible(pkg: dict, cutoff: dt.datetime) -> str | None:
    when = created_at(pkg)
    if when is None:
        return (
            f"{pkg['name']} {pkg['version']}: no authoritative crates.io "
            f"publication timestamp for source {pkg.get('source')!r}"
        )
    if when > cutoff:
        return (
            f"{pkg['name']} {pkg['version']}: published {when.isoformat()} "
            f"(cutoff {cutoff.isoformat()})"
        )
    return None


def declaration_name(alias: str, spec) -> str:
    if isinstance(spec, dict):
        return spec.get("package", alias)
    return alias


def collect_dependencies(obj, prefix=()) -> dict[tuple[str, str], object]:
    out = {}
    if not isinstance(obj, dict):
        return out
    for key, value in obj.items():
        if key in DEP_TABLES and isinstance(value, dict):
            table = ".".join((*prefix, key))
            for alias, spec in value.items():
                out[(table, alias)] = spec
        if isinstance(value, dict):
            out.update(collect_dependencies(value, (*prefix, key)))
    return out


def changed_direct_crates() -> tuple[set[str], set[str]]:
    files = subprocess.check_output(
        ["git", "ls-files", "*Cargo.toml"], text=True
    ).splitlines()
    names: set[str] = set()
    unknown_source: set[str] = set()
    for path in files:
        with open(path, "rb") as f:
            after = collect_dependencies(tomllib.load(f))
        before = collect_dependencies(tomllib.loads(git_show(path).decode()))
        for key in set(before) | set(after):
            old = before.get(key)
            new = after.get(key)
            if old == new:
                continue
            alias = key[1]
            spec = new if new is not None else old
            name = declaration_name(alias, spec)
            names.add(name)
            if isinstance(spec, dict) and any(k in spec for k in ("git", "path")):
                unknown_source.add(name)
    return names, unknown_source


def changed_lock_packages() -> list[dict]:
    before = {package_key(p) for p in load_lock(git_show("Cargo.lock"))}
    with open("Cargo.lock", "rb") as f:
        after = load_lock(f.read())
    return [p for p in after if package_key(p) not in before and p.get("source")]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("manifest", "lockfile"))
    parser.add_argument("--hours", type=int, default=72)
    args = parser.parse_args()

    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=args.hours)
    changed = changed_lock_packages()

    if args.mode == "lockfile":
        bad = []
        for pkg in changed:
            reason = ineligible(pkg, cutoff)
            if reason:
                bad.append(reason)
        for reason in bad:
            print(f"quarantined: {reason}", file=sys.stderr)
        return 1 if bad else 0

    direct, unknown_source = changed_direct_crates()
    blocked = set(unknown_source)
    reasons = []
    for pkg in changed:
        if pkg["name"] not in direct:
            continue
        reason = ineligible(pkg, cutoff)
        if reason:
            blocked.add(pkg["name"])
            reasons.append(reason)

    for name in sorted(unknown_source):
        reasons.append(f"{name}: changed git/path dependency has no release timestamp")
    for reason in reasons:
        print(f"quarantined: {reason}", file=sys.stderr)
    for name in sorted(blocked):
        print(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
