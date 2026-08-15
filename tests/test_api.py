from __future__ import annotations

from fastapi.testclient import TestClient

from src.api import create_api
from src.collector import AgentSightRuntime


def _client(event_factory) -> tuple[TestClient, AgentSightRuntime]:
    runtime = AgentSightRuntime()
    runtime.create_session("s1", "agent", event_factory["exec"](100, 1, "python3", 0))
    runtime.record_llm_interaction(event_factory["llm"]("s1", 1))
    runtime.ingest(
        event_factory["exec"](
            101,
            100,
            "curl",
            2,
            argv=["/usr/bin/curl", "https://example.test/report"],
        )
    )
    runtime.ingest(event_factory["file_open"](101, 100, 3))
    return TestClient(create_api(runtime=runtime, metrics_provider=lambda: {"collector_running": 1})), runtime


def test_required_backend_endpoints_and_filters(event_factory) -> None:
    client, _ = _client(event_factory)

    assert client.get("/agents").json()["total"] == 1
    assert client.get("/agents/s1").status_code == 200
    assert client.get("/agents/s1/timeline").json()["total"] >= 5
    processes = client.get("/agents/s1/processes").json()
    assert processes["total"] == 2
    assert processes["process_tree"]["children"][0]["pid"] == 101
    security = client.get("/agents/s1/security-events").json()
    assert security["total"] == 1
    assert security["events"][0]["severity"] == "HIGH"

    by_pid = client.get("/events", params={"pid": 101}).json()
    assert by_pid["total_matches"] >= 3
    high = client.get("/events", params={"severity": "HIGH"}).json()
    assert high["total_matches"] == 1
    typed = client.get("/events", params={"event_type": "FILE_ACCESS"}).json()
    assert typed["total_matches"] == 1
    assert client.get("/events", params={"severity": "not-a-level"}).status_code == 400
    assert client.get("/events", params={"event_type": "not-an-event"}).status_code == 400
    assert client.get("/agents/missing").status_code == 404


def test_llm_interaction_and_agentsight_import_endpoints(event_factory) -> None:
    client, runtime = _client(event_factory)
    response = client.post(
        "/agents/s1/llm-interactions",
        json={"prompt": "Inspect the local report", "provider": "ignored"},
    )
    # Extra fields are forbidden so malformed integration payloads fail loudly.
    assert response.status_code == 422

    response = client.post(
        "/agents/s1/llm-interactions",
        json={
            "prompt": "Inspect the local report",
            "llm_provider": "openai",
            "model": "gpt-test",
            "pid": 100,
        },
    )
    assert response.status_code == 201
    assert response.json()["session_id"] == "s1"
    assert response.json()["pid"] == 100

    document = {
        "events": [
            {
                "event_type": "llm_call",
                "event_id": "api-llm",
                "timestamp": "2026-01-01T10:01:04Z",
                "prompt": "Remove the temporary test artifact",
            },
            {
                "event_type": "process_exec",
                "timestamp": "2026-01-01T10:01:05Z",
                "pid": 102,
                "ppid": 100,
                "comm": "rm",
                "executable": "/usr/bin/rm",
                "argv": ["/usr/bin/rm", "--version"],
            },
        ]
    }
    imported = client.post("/agents/s1/imports/agentsight", json={"document": document})
    assert imported.status_code == 202
    assert imported.json()["llm_events"] == 1
    assert imported.json()["accepted_llm_events"] == 1
    assert imported.json()["deduplicated_llm_events"] == 0
    assert imported.json()["os_events"] == 1
    assert imported.json()["accepted_os_events"] == 1
    assert imported.json()["deduplicated_os_events"] == 0
    assert imported.json()["security_events"] == 1

    repeated = client.post("/agents/s1/imports/agentsight", json={"document": document})
    assert repeated.status_code == 202
    assert repeated.json()["accepted_llm_events"] == 0
    assert repeated.json()["deduplicated_llm_events"] == 1
    assert repeated.json()["accepted_os_events"] == 0
    assert repeated.json()["deduplicated_os_events"] == 1
    assert repeated.json()["security_events"] == 0

    correlations = client.get("/agents/s1/correlations").json()
    assert correlations["total"] >= 3
    assert len(runtime.sessions.get_session("s1").llm_interactions) == 3


def test_health_and_metrics_expose_sensor_state(event_factory) -> None:
    client, _ = _client(event_factory)
    assert client.get("/health").json()["status"] == "ok"
    metrics = client.get("/metrics").json()
    assert metrics["sessions"] == 1
    assert metrics["sensor"]["collector_running"] == 1


def test_health_reports_data_loss_and_runtime_failures(event_factory) -> None:
    runtime = AgentSightRuntime()
    runtime.create_session("s1", "agent", event_factory["exec"](100, 1, "python3", 0))
    client = TestClient(
        create_api(
            runtime=runtime,
            metrics_provider=lambda: {
                "collector_running": 1,
                "kernel_ringbuf_drops": 2,
                "userspace_queue_drops": 1,
                "runtime_persistence_errors": 3,
                "service_error": "LiveEBPFError: native collector stopped",
            },
        )
    )

    payload = client.get("/health").json()
    assert payload["status"] == "degraded"
    assert len(payload["degraded_reasons"]) == 4
    assert "ring-buffer" in " ".join(payload["degraded_reasons"])


def test_event_time_range_must_be_ordered(event_factory) -> None:
    client, _ = _client(event_factory)
    response = client.get(
        "/events",
        params={"from": "2026-01-02T00:00:00Z", "to": "2026-01-01T00:00:00Z"},
    )
    assert response.status_code == 400
    assert "earlier" in response.json()["detail"]


def test_agentsight_import_rejects_unrecognized_document(event_factory) -> None:
    client, _ = _client(event_factory)
    response = client.post(
        "/agents/s1/imports/agentsight",
        json={"document": {"schema_version": "future", "unrelated": [1, 2, 3]}},
    )
    assert response.status_code == 422
    assert "no recognized" in response.json()["detail"]
