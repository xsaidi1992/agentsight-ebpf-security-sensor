"""Privileged proof of kernel -> ring buffer -> session -> API/security pipeline."""
from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api import create_api
from src.collector import AgentSightRuntime, BPFEventCollector
from src.integrations import AgentSightImporter
from src.models import EventType
from src.service import LiveSensorService

ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = BPFEventCollector.preflight()


def _local_listener() -> tuple[socket.socket, int, threading.Thread]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = int(server.getsockname()[1])

    def receive_once() -> None:
        try:
            server.settimeout(10)
            connection, _ = server.accept()
            with connection:
                connection.recv(1024)
        finally:
            server.close()

    thread = threading.Thread(target=receive_once, daemon=True)
    thread.start()
    return server, port, thread


@pytest.mark.kernel
@pytest.mark.e2e
@pytest.mark.skipif(not PREFLIGHT["ok"], reason=PREFLIGHT["reason"])
def test_real_kernel_process_file_network_and_security_timeline(tmp_path: Path) -> None:
    _, port, listener = _local_listener()
    output = tmp_path / "result.txt"
    runtime = AgentSightRuntime()
    service = LiveSensorService(runtime=runtime)
    llm = AgentSightImporter().parse(
        {
            "events": [
                {
                    "event_type": "llm_call",
                    "event_id": "kernel-e2e-prompt",
                    "timestamp": time.time(),
                    "provider": "assessment-test",
                    "model": "deterministic-fixture",
                    "prompt": "Connect locally, write the report, then validate rm.",
                }
            ]
        },
        "kernel-e2e",
    ).llm_events[0]
    process = service.start_command(
        [
            sys.executable,
            str(ROOT / "scripts" / "demo_agent.py"),
            "--delay",
            "0.5",
            "--port",
            str(port),
            "--output",
            str(output),
        ],
        "kernel-e2e",
        "demo-agent",
        llm_events=[llm],
    )
    try:
        assert process.wait(timeout=15) == 0
        listener.join(timeout=3)
        deadline = time.monotonic() + 8
        required = {
            EventType.PROCESS_EXECUTION.value,
            EventType.FILE_ACCESS.value,
            EventType.FILE_WRITE.value,
            EventType.FILE_DELETE.value,
            EventType.NETWORK_CONNECTION.value,
            EventType.PROCESS_EXIT.value,
            EventType.SECURITY_EVENT.value,
        }
        observed: set[str] = set()
        while time.monotonic() < deadline:
            session = runtime.sessions.get_session("kernel-e2e")
            if session:
                observed = {str(item["event_type"]) for item in session.timeline.events}
                if required.issubset(observed):
                    break
            time.sleep(0.1)

        session = runtime.sessions.get_session("kernel-e2e")
        assert session is not None
        assert required.issubset(observed), {
            "missing": sorted(required - observed),
            "timeline": session.timeline.events,
            "metrics": service.metrics(),
        }
        assert output.read_text(encoding="utf-8").startswith("AgentSight")
        assert any(node.comm == "rm" for node in session.processes.values())
        assert any(alert.rule_name == "SENSITIVE_COMMAND_EXECUTION" for alert in session.security_events)
        assert any(item.get("correlation") for item in session.timeline.events if item["event_type"] != "LLM_INTERACTION")
        metrics = service.metrics()
        assert metrics["kernel_ringbuf_drops"] == 0
        assert metrics["userspace_queue_drops"] == 0
        assert metrics["service_error"] is None

        client = TestClient(create_api(runtime=runtime, metrics_provider=service.metrics))
        assert client.get("/agents/kernel-e2e").status_code == 200
        assert client.get("/agents/kernel-e2e/processes").json()["total"] >= 2
        assert client.get("/agents/kernel-e2e/security-events").json()["total"] >= 1
        assert client.get("/events", params={"severity": "HIGH"}).json()["total_matches"] >= 1
    finally:
        service.stop()
