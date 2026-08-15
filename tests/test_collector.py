from __future__ import annotations

from src.collector import BPFEventCollector
from src.models import (
    FileAccessEvent,
    FileDeleteEvent,
    FileWriteEvent,
    NetworkConnectionEvent,
    ProcessExecutionEvent,
    ProcessExitEvent,
    ProcessForkEvent,
)


class FakeLive:
    def __init__(self):
        self.started = False
        self.start_kwargs = {}
        self.records = []

    def start(self, **kwargs):
        self.started = True
        self.start_kwargs = kwargs

    def stop(self):
        self.started = False

    def poll(self, timeout=0.25, max_events=512):
        batch, self.records = self.records[:max_events], self.records[max_events:]
        return batch

    def metrics(self):
        return {
            "kernel_ringbuf_drops": 2,
            "userspace_queue_drops": 1,
            "collector_running": int(self.started),
        }


def common(record_type: str, event_type: int, sequence: int = 1, pid: int = 123, ppid: int = 100):
    return {
        "record_type": record_type,
        "version": 2,
        "event_type": event_type,
        "pid": pid,
        "ppid": ppid,
        "uid": 1000,
        "gid": 1000,
        "timestamp_ns": 1_000_000_000 + sequence,
        "sequence": sequence,
        "process_start_ns": pid * 1_000_000,
        "parent_start_ns": ppid * 1_000_000,
        "comm": "agent",
    }


def test_decode_all_kernel_record_types() -> None:
    collector = BPFEventCollector(live=FakeLive())
    records = [
        {
            **common("exec", 1, 1),
            "filename": "/usr/bin/curl",
            "argv": ["/usr/bin/curl", "https://example.test"],
            "argv_truncated": False,
            "syscall_kind": 2,
        },
        {**common("fork", 2, 2, 124, 123), "child_comm": "bash"},
        {**common("exit", 3, 3), "exit_code": 0, "signal": 0, "duration_ns": 50},
        {
            **common("file_open", 4, 4),
            "path": "/tmp/result.txt",
            "fd": 3,
            "dirfd": -100,
            "open_flags": 577,
            "result": 3,
        },
        {
            **common("file_write", 5, 5),
            "path": "/tmp/result.txt",
            "fd": 3,
            "dirfd": -100,
            "bytes": 128,
            "result": 128,
        },
        {
            **common("file_delete", 6, 6),
            "path": "/tmp/result.txt",
            "dirfd": -100,
            "result": 0,
        },
        {
            **common("network_connect", 7, 7),
            "remote_addr": "127.0.0.1",
            "remote_port": 443,
            "family": 2,
            "result": 0,
        },
    ]
    events = [collector.decode_record(record) for record in records]
    assert [type(event) for event in events] == [
        ProcessExecutionEvent,
        ProcessForkEvent,
        ProcessExitEvent,
        FileAccessEvent,
        FileWriteEvent,
        FileDeleteEvent,
        NetworkConnectionEvent,
    ]
    assert events[0].command == "/usr/bin/curl https://example.test"
    assert events[0].syscall == "execveat"
    assert events[3].write_intent is True
    assert events[4].bytes_written == 128
    assert events[4].dirfd == -100
    assert events[6].remote_port == 443
    assert collector.metrics()["by_type"]["network_connect"] == 1


def test_sequence_gap_out_of_order_and_native_loss_are_observable() -> None:
    collector = BPFEventCollector(live=FakeLive())
    for sequence in (10, 13, 12):
        collector.decode_record(
            {
                **common("exec", 1, sequence),
                "filename": "/bin/true",
                "argv": ["/bin/true"],
            }
        )
    metrics = collector.metrics()
    assert metrics["sequence_gap_events"] == 1
    assert metrics["estimated_sequence_drops"] == 2
    assert metrics["out_of_order_records"] == 1
    assert metrics["kernel_ringbuf_drops"] == 2
    assert metrics["userspace_queue_drops"] == 1


def test_invalid_or_unknown_records_are_handled_without_crashing() -> None:
    collector = BPFEventCollector(live=FakeLive())
    mismatched = {**common("exec", 1), "version": 99, "filename": "/bin/true", "argv": []}
    assert collector.decode_record(mismatched) is None
    assert collector.decode_record({"record_type": "unknown"}) is None
    assert collector.decode_record({**common("network_connect", 7), "remote_port": 99999}) is None
    assert collector.metrics()["invalid_records"] == 2


def test_poll_starts_with_root_filter_and_decodes_live_queue() -> None:
    live = FakeLive()
    live.records = [
        {
            **common("exec", 1),
            "filename": "/usr/bin/curl",
            "argv": ["/usr/bin/curl"],
        }
    ]
    collector = BPFEventCollector(live=live)
    collector.start(root_pid=123, tracked_pids=[124, 125])
    try:
        events = collector.poll()
        assert len(events) == 1
        assert events[0].command_name == "curl"
        assert live.start_kwargs == {"root_pid": 123, "tracked_pids": [124, 125]}
    finally:
        collector.stop()
    assert live.started is False


def test_exec_uses_proc_executable_when_available_and_preserves_kernel_filename(monkeypatch) -> None:
    collector = BPFEventCollector(live=FakeLive())
    monkeypatch.setattr(collector, "_read_executable", lambda pid: "/usr/bin/python3.13")
    event = collector.decode_record(
        {
            **common("exec", 1, pid=501, ppid=500),
            "filename": "python3",
            "argv": ["python3", "agent file.py", "--mode=test"],
        }
    )
    assert isinstance(event, ProcessExecutionEvent)
    assert event.executable == "/usr/bin/python3.13"
    assert event.metadata["kernel_filename"] == "python3"
    assert event.command == "python3 'agent file.py' --mode=test"


def test_relative_write_uses_the_openat_directory_descriptor(monkeypatch) -> None:
    collector = BPFEventCollector(live=FakeLive())

    def fake_readlink(path):
        text = str(path)
        if text.endswith("/fd/9"):
            return "/var/lib/agent-output"
        if text.endswith("/cwd"):
            return "/wrong/current-directory"
        raise OSError(text)

    monkeypatch.setattr("src.collector.collector.os.readlink", fake_readlink)
    event = collector.decode_record(
        {
            **common("file_write", 5, pid=501, ppid=500),
            "path": "reports/result.txt",
            "fd": 12,
            "dirfd": 9,
            "bytes": 64,
            "result": 64,
        }
    )

    assert isinstance(event, FileWriteEvent)
    assert event.dirfd == 9
    assert event.cwd == "/var/lib/agent-output"
    assert event.path == "/var/lib/agent-output/reports/result.txt"


def test_inherited_fd_write_is_emitted_and_resolved_from_procfs(monkeypatch) -> None:
    collector = BPFEventCollector(live=FakeLive())
    monkeypatch.setattr(collector, "_read_fd_path", lambda pid, fd: "/tmp/inherited.txt")

    event = collector.decode_record(
        {
            **common("file_write", 5, pid=501, ppid=500),
            "path": "",
            "fd": 12,
            "dirfd": -100,
            "bytes": 64,
            "result": 64,
        }
    )

    assert isinstance(event, FileWriteEvent)
    assert event.path == "/tmp/inherited.txt"
    assert event.metadata["path_resolution"] == "procfs-fd"


def test_unresolved_inherited_fd_write_remains_observable(monkeypatch) -> None:
    collector = BPFEventCollector(live=FakeLive())
    monkeypatch.setattr(collector, "_read_fd_path", lambda pid, fd: "")

    event = collector.decode_record(
        {
            **common("file_write", 5, pid=501, ppid=500),
            "path": "",
            "fd": 12,
            "dirfd": -100,
            "bytes": 64,
            "result": 64,
        }
    )

    assert isinstance(event, FileWriteEvent)
    assert event.path == "fd:12"
    assert event.metadata["path_resolution"] == "unresolved"
