from __future__ import annotations

import os
import sys
import time

import pytest

from src.collector import AgentSightRuntime
from src.service import LiveSensorService, discover_process_tree, process_event_from_proc


class FakeCollector:
    def __init__(self):
        self.running = False
        self.start_kwargs = None
        self.stop_calls = 0

    def start(self, **kwargs):
        self.running = True
        self.start_kwargs = kwargs

    def stop(self):
        self.running = False
        self.stop_calls += 1

    def poll(self, timeout=0.25, max_events=512):
        time.sleep(min(timeout, 0.01))
        return []

    def metrics(self):
        return {"collector_running": int(self.running)}


def test_proc_registration_has_stable_identity_and_command() -> None:
    event = process_event_from_proc(os.getpid())
    assert event.pid == os.getpid()
    assert event.ppid == os.getppid()
    assert event.process_start_ns > 0
    assert event.event_id == f"procfs:{event.pid}:{event.process_start_ns}"
    assert event.argv
    assert event.source == "procfs-registration"


def test_process_tree_discovery_contains_root() -> None:
    tree = discover_process_tree(os.getpid())
    assert tree[0] == os.getpid()
    assert len(tree) == len(set(tree))


def test_controlled_launch_attaches_before_agent_exec(event_factory) -> None:
    collector = FakeCollector()
    runtime = AgentSightRuntime()
    service = LiveSensorService(collector=collector, runtime=runtime)
    process = service.start_command(
        [sys.executable, "-c", "print('controlled-launch-ok')"],
        "s1",
        "gated-agent",
        llm_events=[event_factory["llm"]("different-session", -1)],
        stdout=None,
        stderr=None,
    )
    try:
        assert collector.start_kwargs == {"root_pid": process.pid}
        session = runtime.sessions.get_session("s1")
        assert session is not None
        assert session.main_pid == process.pid
        assert session.llm_interactions[0].session_id == "s1"
        assert process.wait(timeout=5) == 0
    finally:
        service.stop()
    assert collector.running is False


def test_start_existing_seeds_current_process_without_modification() -> None:
    collector = FakeCollector()
    runtime = AgentSightRuntime()
    service = LiveSensorService(collector=collector, runtime=runtime)
    service.start_existing(os.getpid(), "s1", "current-test-process")
    try:
        assert collector.start_kwargs["root_pid"] == os.getpid()
        assert runtime.sessions.get_session("s1") is not None
        assert service.metrics()["service_running"] == 1
    finally:
        service.stop(terminate_owned_process=False)


def test_service_rejects_double_start() -> None:
    collector = FakeCollector()
    service = LiveSensorService(collector=collector, runtime=AgentSightRuntime())
    service.start_existing(os.getpid(), "s1", "current-test-process")
    try:
        with pytest.raises(RuntimeError, match="already running"):
            service.start_existing(os.getpid(), "s2", "second-process")
    finally:
        service.stop(terminate_owned_process=False)


class FailingCollector(FakeCollector):
    def poll(self, timeout=0.25, max_events=512):
        raise RuntimeError("native reader failed")


def test_collection_failure_is_exposed_without_crashing_the_api_process() -> None:
    collector = FailingCollector()
    service = LiveSensorService(collector=collector, runtime=AgentSightRuntime())
    service.start_existing(os.getpid(), "s1", "current-test-process")
    try:
        deadline = time.monotonic() + 2
        while service.metrics()["service_error"] is None and time.monotonic() < deadline:
            time.sleep(0.01)
        metrics = service.metrics()
        assert "native reader failed" in str(metrics["service_error"])
        assert metrics["service_running"] == 0
    finally:
        service.stop(terminate_owned_process=False)


def test_boot_epoch_fallback_uses_monotonic_clock(monkeypatch) -> None:
    import src.service as service_module

    def fail_read(*args, **kwargs):
        raise OSError("no proc stat")

    monkeypatch.setattr(service_module.Path, "read_text", fail_read)
    monkeypatch.setattr(service_module.time, "time", lambda: 10_000.0)
    monkeypatch.setattr(service_module.time, "monotonic", lambda: 1_234.5)
    assert service_module._boot_epoch_seconds() == 8_765.5
