"""Tests for guarded process identity and termination helpers."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fovux.core.json_io import write_json_atomically
from fovux.core.processes import (
    ProcessIdentity,
    _as_int,
    _snapshot_process,
    _snapshot_process_darwin,
    _snapshot_process_darwin_cwd,
    _snapshot_process_procfs,
    _snapshot_process_windows,
    _wait_for_exit,
    _windows_command_parts,
    capture_process_identity,
    command_fingerprint,
    load_process_identity,
    process_identity_payload,
    terminate_process_tree,
)


def _identity() -> ProcessIdentity:
    command = ["python", "-m", "fovux.core.train_worker", "run"]
    return ProcessIdentity(
        pid=123,
        command_fingerprint=command_fingerprint(command),
        cwd=str(Path.cwd()),
        start_marker="start-1",
        process_group_id=456,
        platform="linux",
    )


def _snapshot() -> dict[str, object]:
    return {
        "start_marker": "start-1",
        "command": ["python", "-m", "fovux.core.train_worker", "run"],
        "cwd": str(Path.cwd()),
        "process_group_id": 456,
    }


def test_command_fingerprint_is_stable_and_sensitive_to_command() -> None:
    """Command fingerprints should be deterministic and command-specific."""
    command = ["python", "-m", "worker"]

    assert command_fingerprint(command) == command_fingerprint(command)
    assert command_fingerprint(command) != command_fingerprint(["python", "-m", "other"])


def test_capture_process_identity_uses_snapshot_metadata() -> None:
    """Captured process identity should store start marker and process group."""
    with patch("fovux.core.processes._snapshot_process", return_value=_snapshot()):
        identity = capture_process_identity(
            pid=123,
            command=["python", "-m", "fovux.core.train_worker", "run"],
            cwd=Path.cwd(),
        )

    assert identity.pid == 123
    assert identity.start_marker == "start-1"
    assert identity.process_group_id == 456


def test_capture_process_identity_tolerates_snapshot_failure() -> None:
    """Snapshot failures should produce PID metadata that still refuses stale kills."""
    with patch("fovux.core.processes._snapshot_process", side_effect=ValueError("boom")):
        identity = capture_process_identity(pid=123, command=["python"], cwd=Path.cwd())

    assert identity.pid == 123
    assert identity.start_marker is None


def test_process_identity_payload_and_load_roundtrip(tmp_path: Path) -> None:
    """pid.txt should roundtrip the structured process identity payload."""
    identity = _identity()
    write_json_atomically(
        tmp_path / "pid.txt",
        {"pid": identity.pid, "process": process_identity_payload(identity)},
    )

    loaded = load_process_identity(tmp_path, identity.pid)

    assert loaded == identity


def test_load_process_identity_rejects_legacy_or_mismatched_payload(tmp_path: Path) -> None:
    """Legacy PID-only files and PID mismatches must not be trusted."""
    write_json_atomically(tmp_path / "pid.txt", {"pid": 123})
    assert load_process_identity(tmp_path, 123) is None

    write_json_atomically(
        tmp_path / "pid.txt",
        {"pid": 123, "process": {**process_identity_payload(_identity()), "pid": 999}},
    )
    assert load_process_identity(tmp_path, 123) is None


def test_load_process_identity_rejects_missing_file_or_hash(tmp_path: Path) -> None:
    """Missing identity files and incomplete identity payloads are not trusted."""
    assert load_process_identity(tmp_path, 123) is None

    write_json_atomically(
        tmp_path / "pid.txt",
        {
            "pid": 123,
            "process": {
                **process_identity_payload(_identity()),
                "command_fingerprint": "",
            },
        },
    )
    assert load_process_identity(tmp_path, 123) is None


def test_terminate_process_tree_returns_missing_when_pid_is_absent() -> None:
    """A missing PID should not be signalled."""
    with patch("fovux.core.processes._snapshot_process", return_value={}):
        result = terminate_process_tree(_identity(), force=False)

    assert result.status == "missing"
    assert result.signal_sent is False


def test_terminate_process_tree_rejects_missing_start_marker() -> None:
    """A recorded identity without start metadata should not be used."""
    identity = ProcessIdentity(
        pid=123,
        command_fingerprint=command_fingerprint(["python"]),
        cwd=None,
        start_marker=None,
        process_group_id=None,
        platform="linux",
    )
    with patch("fovux.core.processes._snapshot_process", return_value=_snapshot()):
        result = terminate_process_tree(identity, force=False)

    assert result.status == "mismatch"
    assert "start marker" in result.message


def test_terminate_process_tree_rejects_start_marker_mismatch() -> None:
    """PID reuse should be rejected when the process start marker changed."""
    snapshot = {**_snapshot(), "start_marker": "different"}
    with patch("fovux.core.processes._snapshot_process", return_value=snapshot):
        result = terminate_process_tree(_identity(), force=False)

    assert result.status == "mismatch"
    assert result.signal_sent is False


def test_terminate_process_tree_rejects_command_mismatch() -> None:
    """A matching PID with a different command should not be terminated."""
    snapshot = {**_snapshot(), "command": ["python", "-m", "other"]}
    with patch("fovux.core.processes._snapshot_process", return_value=snapshot):
        result = terminate_process_tree(_identity(), force=False)

    assert result.status == "mismatch"
    assert "command" in result.message


def test_terminate_process_tree_rejects_cwd_mismatch() -> None:
    """A matching PID with a different working directory should not be terminated."""
    snapshot = {**_snapshot(), "cwd": str(Path.cwd().parent)}
    with patch("fovux.core.processes._snapshot_process", return_value=snapshot):
        result = terminate_process_tree(_identity(), force=False)

    assert result.status == "mismatch"
    assert "working directory" in result.message


def test_terminate_process_tree_rejects_process_group_mismatch() -> None:
    """A matching PID in a different process group should not be terminated."""
    snapshot = {**_snapshot(), "process_group_id": 999}
    with patch("fovux.core.processes._snapshot_process", return_value=snapshot):
        result = terminate_process_tree(_identity(), force=False)

    assert result.status == "mismatch"
    assert "process group" in result.message


def test_terminate_process_tree_sends_posix_process_group_signal() -> None:
    """Verified POSIX workers should be terminated by process group."""
    with (
        patch("fovux.core.processes.sys.platform", "linux"),
        patch("fovux.core.processes._snapshot_process", side_effect=[_snapshot(), {}]),
        patch("fovux.core.processes._wait_for_exit"),
        patch("fovux.core.processes.os.killpg", create=True) as killpg,
    ):
        result = terminate_process_tree(_identity(), force=False)

    killpg.assert_called_once()
    assert result.status == "terminated"
    assert result.signal_sent is True


def test_terminate_process_tree_sends_posix_pid_signal_without_group() -> None:
    """Verified POSIX workers without a recorded process group fall back to PID signals."""
    identity = ProcessIdentity(
        pid=123,
        command_fingerprint=command_fingerprint(["python", "-m", "fovux.core.train_worker", "run"]),
        cwd=str(Path.cwd()),
        start_marker="start-1",
        process_group_id=None,
        platform="linux",
    )
    with (
        patch("fovux.core.processes.sys.platform", "linux"),
        patch("fovux.core.processes._snapshot_process", side_effect=[_snapshot(), _snapshot()]),
        patch("fovux.core.processes._wait_for_exit"),
        patch("fovux.core.processes.os.kill") as kill,
    ):
        result = terminate_process_tree(identity, force=False)

    assert kill.call_count == 2
    assert result.status == "terminated"


def test_terminate_process_tree_reverifies_before_final_kill() -> None:
    """A changed identity after SIGTERM should prevent the SIGKILL fallback."""
    stale_snapshot = {**_snapshot(), "start_marker": "reused"}
    with (
        patch("fovux.core.processes.sys.platform", "linux"),
        patch("fovux.core.processes._snapshot_process", side_effect=[_snapshot(), stale_snapshot]),
        patch("fovux.core.processes._wait_for_exit"),
        patch("fovux.core.processes.os.killpg", create=True) as killpg,
    ):
        result = terminate_process_tree(_identity(), force=False)

    assert killpg.call_count == 1
    assert result.status == "mismatch"
    assert result.signal_sent is True


def test_terminate_process_tree_sends_windows_tree_signal() -> None:
    """Verified Windows workers should be terminated through taskkill /T."""
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    with (
        patch("fovux.core.processes.sys.platform", "win32"),
        patch("fovux.core.processes._snapshot_process", return_value=_snapshot()),
        patch("fovux.core.processes.subprocess.run", return_value=completed) as run,
    ):
        result = terminate_process_tree(_identity(), force=True)

    assert run.call_args.args[0] == ["taskkill", "/PID", "123", "/T", "/F"]
    assert result.status == "terminated"


def test_terminate_process_tree_reports_windows_taskkill_failure() -> None:
    """taskkill failures should not be reported as clean termination."""
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=5,
        stdout="",
        stderr="Access is denied.",
    )
    with (
        patch("fovux.core.processes.sys.platform", "win32"),
        patch("fovux.core.processes._snapshot_process", return_value=_snapshot()),
        patch("fovux.core.processes.subprocess.run", return_value=completed),
    ):
        result = terminate_process_tree(_identity(), force=True)

    assert result.status == "failed"
    assert result.signal_sent is False
    assert "Access is denied" in result.message


def test_terminate_process_tree_handles_signal_race() -> None:
    """A process disappearing between verification and signalling is treated as gone."""
    with (
        patch("fovux.core.processes.sys.platform", "linux"),
        patch("fovux.core.processes._snapshot_process", return_value=_snapshot()),
        patch("fovux.core.processes.os.killpg", side_effect=ProcessLookupError, create=True),
    ):
        result = terminate_process_tree(_identity(), force=True)

    assert result.status == "missing"
    assert result.signal_sent is False


def test_snapshot_process_dispatches_by_platform() -> None:
    """The platform dispatcher should choose the correct snapshot strategy."""
    with (
        patch("fovux.core.processes.sys.platform", "win32"),
        patch("fovux.core.processes._snapshot_process_windows", return_value={"os": "win"}),
    ):
        assert _snapshot_process(1) == {"os": "win"}

    with (
        patch("fovux.core.processes.sys.platform", "darwin"),
        patch("fovux.core.processes._snapshot_process_darwin", return_value={"os": "mac"}),
    ):
        assert _snapshot_process(1) == {"os": "mac"}

    with (
        patch("fovux.core.processes.sys.platform", "linux"),
        patch("fovux.core.processes._snapshot_process_procfs", return_value={"os": "posix"}),
    ):
        assert _snapshot_process(1) == {"os": "posix"}


def test_procfs_snapshot_parses_stat_cmdline_and_group() -> None:
    """Procfs snapshots should extract start marker, command, cwd, and process group."""
    stat_tail = " ".join(["S", *["0"] * 18, "start-token", "0"])
    with (
        patch("fovux.core.processes.Path.exists", return_value=True),
        patch("fovux.core.processes.Path.read_text", return_value=f"123 (python) {stat_tail}"),
        patch("fovux.core.processes.Path.read_bytes", return_value=b"python\0-m\0worker\0"),
        patch("fovux.core.processes.os.readlink", return_value=str(Path.cwd())),
        patch("fovux.core.processes.os.getpgid", return_value=456, create=True),
    ):
        snapshot = _snapshot_process_procfs(123)

    assert snapshot["start_marker"] == "start-token"
    assert snapshot["command"] == ["python", "-m", "worker"]
    assert snapshot["process_group_id"] == 456


def test_procfs_snapshot_preserves_intentional_empty_command_arguments() -> None:
    """Procfs command parsing should drop only the trailing NUL terminator."""
    stat_tail = " ".join(["S", *["0"] * 18, "start-token", "0"])
    with (
        patch("fovux.core.processes.Path.exists", return_value=True),
        patch("fovux.core.processes.Path.read_text", return_value=f"123 (python) {stat_tail}"),
        patch("fovux.core.processes.Path.read_bytes", return_value=b"python\0\0worker\0\0"),
        patch("fovux.core.processes.os.readlink", return_value=str(Path.cwd())),
        patch("fovux.core.processes.os.getpgid", return_value=456, create=True),
    ):
        snapshot = _snapshot_process_procfs(123)

    assert snapshot["command"] == ["python", "", "worker", ""]


def test_procfs_snapshot_handles_parse_errors() -> None:
    """Procfs read failures should be treated as missing process metadata."""
    with (
        patch("fovux.core.processes.Path.exists", return_value=True),
        patch("fovux.core.processes.Path.read_text", side_effect=OSError("gone")),
    ):
        assert _snapshot_process_procfs(123) == {}


def test_snapshot_process_windows_parses_cim_payload() -> None:
    """Windows process snapshots should parse CIM JSON output."""
    completed = SimpleNamespace(
        returncode=0,
        stdout=json.dumps({"CreationDate": "2026050901", "CommandLine": "python -m worker"}),
    )
    with (
        patch("fovux.core.processes.Path.exists", return_value=True),
        patch("fovux.core.processes.subprocess.run", return_value=completed),
    ):
        snapshot = _snapshot_process_windows(123)

    assert snapshot["start_marker"] == "2026050901"
    assert snapshot["command"] == ["python", "-m", "worker"]


def test_snapshot_process_windows_handles_failures() -> None:
    """Windows process snapshot failures should return an empty payload."""
    with patch("fovux.core.processes.Path.exists", return_value=False):
        assert _snapshot_process_windows(123) == {}

    completed_error = SimpleNamespace(returncode=1, stdout="")
    with (
        patch("fovux.core.processes.Path.exists", return_value=True),
        patch("fovux.core.processes.subprocess.run", return_value=completed_error),
    ):
        assert _snapshot_process_windows(123) == {}

    completed_invalid_json = SimpleNamespace(returncode=0, stdout="not-json")
    with (
        patch("fovux.core.processes.Path.exists", return_value=True),
        patch("fovux.core.processes.subprocess.run", return_value=completed_invalid_json),
    ):
        assert _snapshot_process_windows(123) == {}

    completed_non_object = SimpleNamespace(returncode=0, stdout="[]")
    with (
        patch("fovux.core.processes.Path.exists", return_value=True),
        patch("fovux.core.processes.subprocess.run", return_value=completed_non_object),
    ):
        assert _snapshot_process_windows(123) == {}

    with (
        patch("fovux.core.processes.Path.exists", return_value=True),
        patch("fovux.core.processes.subprocess.run", side_effect=subprocess.TimeoutExpired("p", 1)),
    ):
        assert _snapshot_process_windows(123) == {}


def test_procfs_snapshot_missing_pid_returns_empty() -> None:
    """Missing procfs entries should return an empty snapshot."""
    assert _snapshot_process_procfs(20_000_000) == {}


def test_darwin_snapshot_uses_ps_and_lsof_metadata() -> None:
    """macOS snapshots should not rely on Linux procfs."""
    ps_output = "Sat May  9 09:50:00 2026 python -m fovux.core.train_worker run\n"
    ps_result = subprocess.CompletedProcess(args=[], returncode=0, stdout=ps_output, stderr="")
    lsof_result = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=f"p123{os.linesep}n{Path.cwd()}{os.linesep}",
        stderr="",
    )
    with (
        patch("fovux.core.processes.subprocess.run", side_effect=[ps_result, lsof_result]),
        patch("fovux.core.processes.os.getpgid", return_value=456, create=True),
    ):
        snapshot = _snapshot_process_darwin(123)

    assert snapshot["start_marker"] == "Sat May  9 09:50:00 2026"
    assert snapshot["command"] == ["python", "-m", "fovux.core.train_worker", "run"]
    assert snapshot["cwd"] == str(Path.cwd())
    assert snapshot["process_group_id"] == 456


def test_darwin_snapshot_handles_missing_process() -> None:
    """macOS snapshot failures should be treated as missing process metadata."""
    ps_result = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
    with patch("fovux.core.processes.subprocess.run", return_value=ps_result):
        assert _snapshot_process_darwin(123) == {}

    with patch("fovux.core.processes.subprocess.run", side_effect=OSError("missing ps")):
        assert _snapshot_process_darwin(123) == {}


def test_darwin_snapshot_handles_parse_edges() -> None:
    """macOS snapshots should reject incomplete ps output and tolerate odd command text."""
    incomplete = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="Sat May  9 09:50:00 2026\n",
        stderr="",
    )
    with patch("fovux.core.processes.subprocess.run", return_value=incomplete):
        assert _snapshot_process_darwin(123) == {}

    quoted = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout='Sat May  9 09:50:00 2026 "unterminated\n',
        stderr="",
    )
    with (
        patch("fovux.core.processes.subprocess.run", return_value=quoted),
        patch("fovux.core.processes.os.getpgid", side_effect=OSError("gone"), create=True),
        patch("fovux.core.processes._snapshot_process_darwin_cwd", return_value=None),
    ):
        snapshot = _snapshot_process_darwin(123)

    assert snapshot["command"] == ['"unterminated']
    assert snapshot["process_group_id"] is None


def test_darwin_cwd_snapshot_handles_lsof_failures() -> None:
    """macOS cwd lookup is optional and should fail closed to None."""
    with patch("fovux.core.processes.subprocess.run", side_effect=OSError("missing lsof")):
        assert _snapshot_process_darwin_cwd(123) is None

    failed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
    with patch("fovux.core.processes.subprocess.run", return_value=failed):
        assert _snapshot_process_darwin_cwd(123) is None

    no_name = subprocess.CompletedProcess(args=[], returncode=0, stdout="p123\n", stderr="")
    with patch("fovux.core.processes.subprocess.run", return_value=no_name):
        assert _snapshot_process_darwin_cwd(123) is None


def test_wait_for_exit_returns_on_missing_process_and_sleeps_until_deadline() -> None:
    """The wait loop should exit on disappearance or deadline."""
    with patch("fovux.core.processes._snapshot_process", side_effect=[{"pid": 1}, {}]):
        _wait_for_exit(1, 1.0)

    with (
        patch("fovux.core.processes.time.monotonic", side_effect=[0.0, 0.0, 0.2]),
        patch("fovux.core.processes._snapshot_process", return_value={"pid": 1}),
        patch("fovux.core.processes.time.sleep") as sleep,
    ):
        _wait_for_exit(1, 0.1)

    sleep.assert_called_once_with(0.05)


def test_windows_command_parts_and_int_coercion() -> None:
    """Small parsing helpers should keep predictable coercion semantics."""
    assert _windows_command_parts("") == []
    assert _windows_command_parts("python  -m worker") == ["python", "-m", "worker"]
    assert _as_int(12) == 12
    assert _as_int("12") == 12
    assert _as_int("not-int") is None
    assert _as_int(None) is None
