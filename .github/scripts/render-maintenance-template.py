#!/usr/bin/env python3
"""Render maintenance issue Markdown without evaluating it as shell code."""

import os
import re
import sys

PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def substitute(match: re.Match[str]) -> str:
    name = match.group(1)
    try:
        return os.environ[name]
    except KeyError as exc:
        raise SystemExit(f"missing template variable: {name}") from exc


sys.stdout.write(PLACEHOLDER.sub(substitute, sys.stdin.read()))
