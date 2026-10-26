"""Small standard-library execution helpers staged beside SentinelO2 Python scripts."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

_AGENT_EXECUTABLE = __SENTINELX_AGENT_EXECUTABLE__


@dataclass(frozen=True)
class RunResult:
    args: str | list[str]
    returncode: int
    stdout: str
    stderr: str
    output_truncated: bool = False
    stdout_bytes: int = 0
    stderr_bytes: int = 0

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def check(self) -> "RunResult":
        if self.returncode != 0:
            raise subprocess.CalledProcessError(
                self.returncode, self.args, output=self.stdout, stderr=self.stderr
            )
        return self


def _env_payload(env: Mapping[str, str] | None) -> dict[str, str]:
    if env is None:
        return {}
    out: dict[str, str] = {}
    for key, value in env.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("env must map strings to strings")
        out[key] = value
    return out


class SshExecutionTarget:
    def __init__(self, destination: str) -> None:
        if not destination or destination.startswith("-"):
            raise ValueError("destination must be a non-empty SSH destination, not an option")
        self.destination = destination
        self._next_id = 1
        self._process: subprocess.Popen[str] | None = subprocess.Popen(
            [_AGENT_EXECUTABLE, "--ssh-execution-target", destination],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        try:
            ready = self._read_line("SSH helper did not report readiness")
            if not ready.get("ready"):
                raise RuntimeError(f"SSH helper rejected connection: {ready!r}")
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> "SshExecutionTarget":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        del exc_type, exc, traceback
        self.close()

    def _live_process(self) -> subprocess.Popen[str]:
        process = self._process
        if process is None:
            raise RuntimeError("SSH execution target is closed")
        return process

    def _read_line(self, missing: str) -> dict[str, Any]:
        process = self._live_process()
        stdout = process.stdout
        if stdout is None:
            raise RuntimeError("SSH helper stdout is unavailable")
        line = stdout.readline()
        if not line:
            stderr = process.stderr
            detail = stderr.read().strip() if stderr is not None else ""
            raise RuntimeError(f"{missing}: {detail or 'helper exited without details'}")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError(f"SSH helper returned non-object JSON: {value!r}")
        return value

    def _request(self, kind: str, *, check: bool, shown_args: str | list[str], **payload: Any) -> RunResult:
        stdin = self._live_process().stdin
        if stdin is None:
            raise RuntimeError("SSH helper stdin is unavailable")
        request_id = self._next_id
        self._next_id += 1
        request = {"id": request_id, "kind": kind, **payload}
        stdin.write(json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n")
        stdin.flush()
        response = self._read_line("SSH helper exited before answering")
        if response.get("id") != request_id:
            raise RuntimeError(f"SSH helper response id mismatch: wanted {request_id}, got {response.get('id')!r}")
        error = response.get("error")
        if error:
            raise RuntimeError(str(error))
        result = RunResult(
            args=shown_args, returncode=int(response["returncode"]),
            stdout=str(response.get("stdout", "")), stderr=str(response.get("stderr", "")),
            output_truncated=bool(response.get("output_truncated", False)),
            stdout_bytes=int(response.get("stdout_bytes", 0)),
            stderr_bytes=int(response.get("stderr_bytes", 0)),
        )
        return result.check() if check else result

    def run(
        self,
        command: str | Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        sudo: bool = False,
        timeout: int = 60,
        check: bool = False,
    ) -> RunResult:
        common = {"cwd": cwd, "env": _env_payload(env), "sudo": sudo, "timeout_seconds": timeout}
        if isinstance(command, str):
            return self._request("shell", check=check, shown_args=command, command=command, **common)
        argv = [str(arg) for arg in command]
        if not argv:
            raise ValueError("command argv must not be empty")
        return self._request("argv", check=check, shown_args=argv, argv=argv, **common)

    def bash(
        self,
        source: str,
        *args: str,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        sudo: bool = False,
        timeout: int = 60,
        check: bool = False,
    ) -> RunResult:
        return self._request(
            "bash", check=check, shown_args=["bash", "-s", "--", *args],
            source=source, args=list(args), cwd=cwd, env=_env_payload(env), sudo=sudo, timeout_seconds=timeout,
        )

    def python(
        self,
        source: str,
        *args: str,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        sudo: bool = False,
        timeout: int = 60,
        check: bool = False,
    ) -> RunResult:
        return self._request(
            "python", check=check, shown_args=["python", "-", *args],
            source=source, args=list(args), cwd=cwd, env=_env_payload(env), sudo=sudo, timeout_seconds=timeout,
        )

    def close(self) -> None:
        process = self._process
        if process is None:
            return
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        finally:
            self._process = None


def exec_ssh(destination: str) -> SshExecutionTarget:
    return SshExecutionTarget(destination)
