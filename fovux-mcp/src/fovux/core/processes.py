"""Process identity capture and safe training-worker termination."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from fovux.core.json_io import read_json_file


@dataclass(frozen=True)
class ProcessIdentity:
    """Stable identity fields recorded when a worker process is spawned."""

    pid: int
    command_fingerprint: str
    cwd: str | None
    start_marker: str | None
    process_group_id: int | None
    platform: str


@dataclass(frozen=True)
class TerminationResult:
    """Result of a guarded process-tree termination attempt."""

    status: str
    signal_sent: bool
    message: str


def command_fingerprint(command: Sequence[str]) -> str:
    """Return a stable fingerprint for a normalized command vector."""
    normalized = json.dumps([str(part) for part in command], separators=(",", ":"), sort_keys=False)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def capture_process_identity(
    *,
    pid: int,
    command: Sequence[str],
    cwd: Path,
) -> ProcessIdentity:
    """Capture the process metadata needed to reject stale PID reuse."""
    try:
        snapshot = _snapshot_process(pid)
    except Exception:
        snapshot = {}
    start_marker = snapshot.get("start_marker")
    return ProcessIdentity(
        pid=pid,
        command_fingerprint=command_fingerprint(command),
        cwd=str(cwd.expanduser().resolve(strict=False)),
        start_marker=str(start_marker) if start_marker is not None else None,
        process_group_id=_as_int(snapshot.get("process_group_id")),
        platform=sys.platform,
    )


def process_identity_payload(identity: ProcessIdentity) -> dict[str, object]:
    """Serialize a process identity into a JSON-compatible payload."""
    return asdict(identity)


def load_process_identity(run_dir: Path, fallback_pid: int | None) -> ProcessIdentity | None:
    """Load a recorded process identity from a run directory."""
    payload = read_json_file(run_dir / "pid.txt")
    if not isinstance(payload, dict):
        return None
    raw_identity = payload.get("process")
    if not isinstance(raw_identity, dict):
        return None
    pid = _as_int(raw_identity.get("pid"))
    if pid is None or (fallback_pid is not None and pid != fallback_pid):
        return None
    command_hash = raw_identity.get("command_fingerprint")
    if not isinstance(command_hash, str) or not command_hash:
        return None
    cwd = raw_identity.get("cwd")
    start_marker = raw_identity.get("start_marker")
    platform = raw_identity.get("platform")
    return ProcessIdentity(
        pid=pid,
        command_fingerprint=command_hash,
        cwd=str(cwd) if cwd is not None else None,
        start_marker=str(start_marker) if start_marker is not None else None,
        process_group_id=_as_int(raw_identity.get("process_group_id")),
        platform=str(platform) if platform is not None else "unknown",
    )


def terminate_process_tree(
    identity: ProcessIdentity,
    *,
    force: bool,
    timeout_seconds: float = 5.0,
) -> TerminationResult:
    """Verify process identity before terminating a worker process tree."""
    snapshot = _snapshot_process(identity.pid)
    if not snapshot:
        return TerminationResult(
            status="missing",
            signal_sent=False,
            message=f"PID {identity.pid} no longer exists; no signal was sent.",
        )
    mismatch = _identity_mismatch(identity, snapshot)
    if mismatch is not None:
        return TerminationResult(
            status="mismatch",
            signal_sent=False,
            message=(
                f"PID {identity.pid} no longer matches the recorded worker identity: {mismatch}."
            ),
        )

    try:
        if sys.platform == "win32":
            return _terminate_windows_process_tree(identity, force=force)
        else:
            kill_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
            sig = kill_signal if force else signal.SIGTERM
            if identity.process_group_id is not None:
                os.killpg(identity.process_group_id, sig)
            else:
                os.kill(identity.pid, sig)
            _wait_for_exit(identity.pid, timeout_seconds)
            latest_snapshot = _snapshot_process(identity.pid)
            if force is False and latest_snapshot:
                latest_mismatch = _identity_mismatch(identity, latest_snapshot)
                if latest_mismatch is not None:
                    return TerminationResult(
                        status="mismatch",
                        signal_sent=True,
                        message=(
                            "Worker identity changed after graceful termination signal; "
                            f"final kill was not sent: {latest_mismatch}."
                        ),
                    )
                if identity.process_group_id is not None:
                    os.killpg(identity.process_group_id, kill_signal)
                else:
                    os.kill(identity.pid, kill_signal)
        return TerminationResult(
            status="terminated",
            signal_sent=True,
            message=f"Signal sent to verified worker PID {identity.pid}.",
        )
    except (ProcessLookupError, OSError):
        return TerminationResult(
            status="missing",
            signal_sent=False,
            message=f"PID {identity.pid} no longer exists; no signal was sent.",
        )


def _identity_mismatch(identity: ProcessIdentity, snapshot: dict[str, object]) -> str | None:
    if identity.start_marker is None:
        return "recorded start marker is missing"
    if snapshot.get("start_marker") != identity.start_marker:
        return "process start marker changed"
    if identity.process_group_id is not None:
        actual_process_group_id = _as_int(snapshot.get("process_group_id"))
        if actual_process_group_id != identity.process_group_id:
            return "process group id changed"
    snapshot_command = snapshot.get("command")
    if isinstance(snapshot_command, list) and snapshot_command:
        actual_hash = command_fingerprint([str(part) for part in snapshot_command])
        if actual_hash != identity.command_fingerprint:
            return "command fingerprint changed"
    if identity.cwd is not None and snapshot.get("cwd") is not None:
        expected_cwd = str(Path(identity.cwd).expanduser().resolve(strict=False))
        actual_cwd = str(Path(str(snapshot["cwd"])).expanduser().resolve(strict=False))
        if actual_cwd != expected_cwd:
            return "working directory changed"
    return None


def _terminate_windows_process_tree(identity: ProcessIdentity, *, force: bool) -> TerminationResult:
    args = ["taskkill", "/PID", str(identity.pid), "/T"]
    if force:
        args.append("/F")
    result = subprocess.run(  # noqa: S603
        args,
        capture_output=True,
        check=False,
        encoding="utf-8",
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        suffix = f": {detail}" if detail else f" (exit {result.returncode})"
        return TerminationResult(
            status="failed",
            signal_sent=False,
            message=f"taskkill failed for verified worker PID {identity.pid}{suffix}.",
        )
    return TerminationResult(
        status="terminated",
        signal_sent=True,
        message=f"Signal sent to verified worker PID {identity.pid}.",
    )


def _snapshot_process(pid: int) -> dict[str, object]:
    if sys.platform == "win32":
        return _snapshot_process_windows(pid)
    if sys.platform == "darwin":
        return _snapshot_process_darwin(pid)
    return _snapshot_process_procfs(pid)


def _snapshot_process_procfs(pid: int) -> dict[str, object]:
    proc_dir = Path("/proc") / str(pid)
    stat_path = proc_dir / "stat"
    if not stat_path.exists():
        return {}
    try:
        stat = stat_path.read_text(encoding="utf-8")
        after_comm = stat[stat.rfind(")") + 2 :].split()
        start_marker = after_comm[19] if len(after_comm) > 19 else None
        raw_cmd = (proc_dir / "cmdline").read_bytes()
        command_parts = raw_cmd.split(b"\0")
        if command_parts and command_parts[-1] == b"":
            command_parts = command_parts[:-1]
        command = [part.decode("utf-8", errors="replace") for part in command_parts]
        cwd = os.readlink(proc_dir / "cwd")
        getpgid = getattr(os, "getpgid", None)
        process_group_id = getpgid(pid) if callable(getpgid) else None
    except (IndexError, OSError, ValueError):
        return {}
    return {
        "start_marker": start_marker,
        "command": command,
        "cwd": cwd,
        "process_group_id": process_group_id,
    }


def _snapshot_process_darwin(pid: int) -> dict[str, object]:
    try:
        result = subprocess.run(  # noqa: S603
            ["/bin/ps", "-p", str(pid), "-o", "lstart=", "-o", "command="],
            capture_output=True,
            check=False,
            encoding="utf-8",
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    line = result.stdout.strip()
    if result.returncode != 0 or not line:
        return {}
    first_line = line.splitlines()[0]
    start_marker = first_line[:24].strip()
    command_line = first_line[24:].strip()
    if not start_marker or not command_line:
        return {}
    try:
        command = shlex.split(command_line)
    except ValueError:
        command = [command_line]
    try:
        getpgid = getattr(os, "getpgid", None)
        process_group_id = getpgid(pid) if callable(getpgid) else None
    except OSError:
        process_group_id = None
    return {
        "start_marker": start_marker,
        "command": command,
        "cwd": _snapshot_process_darwin_cwd(pid),
        "process_group_id": process_group_id,
    }


def _snapshot_process_darwin_cwd(pid: int) -> str | None:
    try:
        result = subprocess.run(  # noqa: S603
            ["/usr/sbin/lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
            capture_output=True,
            check=False,
            encoding="utf-8",
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.startswith("n"):
            return line[1:]
    return None


def _snapshot_process_windows(pid: int) -> dict[str, object]:
    command = (
        "$ErrorActionPreference='Stop';"
        f'$p=Get-CimInstance Win32_Process -Filter "ProcessId={pid}";'
        "if ($null -eq $p) { exit 3 };"
        "$p | Select-Object ProcessId,CreationDate,CommandLine | ConvertTo-Json -Compress"
    )
    powershell = (
        Path(os.environ.get("SystemRoot", r"C:\Windows"))
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    if not powershell.exists():
        return {}
    try:
        result = subprocess.run(  # noqa: S603
            [str(powershell), "-NoProfile", "-Command", command],
            capture_output=True,
            check=False,
            encoding="utf-8",
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if result.returncode != 0 or not result.stdout.strip():
        return {}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    command_line = str(payload.get("CommandLine") or "")
    return {
        "start_marker": str(payload.get("CreationDate") or ""),
        "command": _windows_command_parts(command_line),
        "cwd": None,
        "process_group_id": None,
    }


def _windows_command_parts(command_line: str) -> list[str]:
    if not command_line:
        return []
    try:
        argc = ctypes.c_int()
        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return [part for part in command_line.split(" ") if part]
        command_line_to_argv = windll.shell32.CommandLineToArgvW
        command_line_to_argv.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
        command_line_to_argv.restype = ctypes.POINTER(ctypes.c_wchar_p)
        local_free = windll.kernel32.LocalFree
        argv = command_line_to_argv(command_line, ctypes.byref(argc))
        if not argv:
            return []
        try:
            return [argv[index] for index in range(argc.value)]
        finally:
            local_free(argv)
    except (AttributeError, OSError, ValueError):
        return [part for part in command_line.split(" ") if part]


def _wait_for_exit(pid: int, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _snapshot_process(pid):
            return
        time.sleep(0.05)


def _as_int(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    try:
        return int(value)
    except ValueError:
        return None
