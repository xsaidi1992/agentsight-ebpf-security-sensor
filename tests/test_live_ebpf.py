from __future__ import annotations

import io
import subprocess
from pathlib import Path

import pytest

import src.collector.live_ebpf as live_module
from src.collector.live_ebpf import LiveEBPFError, LiveExecCollector


class StreamProcess:
    def __init__(self, stdout: str = "", stderr: str = "", running: bool = True):
        self.stdout = io.StringIO(stdout)
        self.stderr = io.StringIO(stderr)
        self.running = running
        self.terminated = False
        self.killed = False

    def poll(self):
        return None if self.running else 0

    def terminate(self):
        self.terminated = True
        self.running = False

    def kill(self):
        self.killed = True
        self.running = False

    def wait(self, timeout=None):
        self.running = False
        return 0


def test_live_queue_requires_a_positive_bound(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="queue_size"):
        LiveExecCollector(build_dir=tmp_path, queue_size=0)


def test_stdout_reader_accounts_for_stats_errors_unknown_records_and_queue_drops(
    tmp_path: Path,
) -> None:
    collector = LiveExecCollector(build_dir=tmp_path, queue_size=1)
    collector.process = StreamProcess(
        stdout=(
            '{"record_type":"stats","kernel_ringbuf_drops":3,"emitted_events":7}\n'
            '{"record_type":"stats","kernel_ringbuf_drops":"not-an-int"}\n'
            'not-json\n'
            '{"record_type":"future_event"}\n'
            '{"record_type":"exec","pid":1}\n'
            '{"record_type":"exit","pid":1}\n'
        )
    )

    collector._read_stdout()
    metrics = collector.metrics()

    assert metrics["kernel_ringbuf_drops"] == 3
    assert metrics["emitted_events"] == 7
    assert metrics["invalid_stats_records"] == 1
    assert metrics["json_decode_errors"] == 1
    assert metrics["unknown_record_types"] == 1
    assert metrics["userspace_queue_drops"] == 1
    assert metrics["queued_events"] == 1
    assert metrics["collector_running"] == 1
    assert collector.poll(timeout=0, max_events=1)[0]["record_type"] == "exec"


def test_stderr_reader_detects_ready_and_bounds_history(tmp_path: Path) -> None:
    collector = LiveExecCollector(build_dir=tmp_path)
    lines = "".join(f"line-{index}\n" for index in range(450)) + "READY attached\n"
    collector.process = StreamProcess(stderr=lines)

    collector._read_stderr()

    assert collector.ready.is_set()
    assert len(collector.stderr_lines) <= 400
    assert collector.stderr_lines[-1] == "READY attached"


def test_poll_and_start_arguments_are_validated_before_kernel_preflight(tmp_path: Path) -> None:
    collector = LiveExecCollector(build_dir=tmp_path)
    with pytest.raises(ValueError, match="timeout"):
        collector.poll(timeout=-1)
    with pytest.raises(ValueError, match="max_events"):
        collector.poll(max_events=0)
    with pytest.raises(ValueError, match="startup_timeout"):
        collector.start(startup_timeout=0)
    with pytest.raises(ValueError, match="root_pid"):
        collector.start(root_pid=0)
    with pytest.raises(ValueError, match="tracked_pids"):
        collector.start(tracked_pids=[1, -2])


def test_preflight_aggregates_capability_and_tracepoint_failures(monkeypatch) -> None:
    monkeypatch.setattr(
        LiveExecCollector,
        "build_preflight",
        staticmethod(lambda: {"ok": True, "reason": "ok", "missing": []}),
    )
    monkeypatch.setattr(live_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(live_module, "_has_bpf_capabilities", lambda: False)
    monkeypatch.setattr(live_module, "_tracepoint_exists", lambda group, name: False)

    status = LiveExecCollector.preflight()

    assert status["ok"] is False
    assert "CAP_SYS_ADMIN" in status["reason"]
    assert all(
        f"tracepoint {group}:{name}" in status["missing"]
        for group, name in LiveExecCollector.REQUIRED_TRACEPOINTS
    )


def test_run_surfaces_stderr_and_command(monkeypatch) -> None:
    monkeypatch.setattr(
        live_module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 2, stdout="", stderr="compiler failed"
        ),
    )
    with pytest.raises(LiveEBPFError, match=r"(?s)compiler failed.*command: clang -c probe.c"):
        LiveExecCollector._run(["clang", "-c", "probe.c"])


def test_stop_terminates_running_native_process(tmp_path: Path) -> None:
    collector = LiveExecCollector(build_dir=tmp_path)
    process = StreamProcess(running=True)
    collector.process = process
    collector.ready.set()

    collector.stop()

    assert process.terminated is True
    assert collector.process is None
    assert not collector.ready.is_set()


def test_poll_surfaces_unexpected_native_exit(tmp_path: Path) -> None:
    collector = LiveExecCollector(build_dir=tmp_path)
    collector.process = StreamProcess(stderr="verifier rejected program\n", running=False)
    collector._read_stderr()

    with pytest.raises(LiveEBPFError, match=r"(?s)exited unexpectedly.*verifier rejected"):
        collector.poll(timeout=0)
    assert collector.metrics()["native_exit_code"] == 0


def test_start_rejects_an_already_running_native_process(tmp_path: Path) -> None:
    collector = LiveExecCollector(build_dir=tmp_path)
    collector.process = StreamProcess(running=True)

    with pytest.raises(LiveEBPFError, match="already running"):
        collector.start()
