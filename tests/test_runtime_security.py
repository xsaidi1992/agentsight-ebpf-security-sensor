from __future__ import annotations

from pathlib import Path

from src.collector import AgentSightRuntime, SecurityEngine
from src.models import EventSeverity, FileDeleteEvent, NetworkConnectionEvent
from src.storage import JsonlEventStore


def test_runtime_correlates_sensitive_command_and_persists_audit_log(tmp_path: Path, event_factory) -> None:
    store = JsonlEventStore(tmp_path / "events.jsonl")
    runtime = AgentSightRuntime(store=store)
    runtime.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    runtime.record_llm_interaction(event_factory["llm"]("s1", 1))

    session, alert = runtime.ingest(
        event_factory["exec"](
            101,
            100,
            "rm",
            2,
            argv=["/usr/bin/rm", "--version"],
        )
    )

    assert session is not None
    assert alert is not None
    assert alert.severity == EventSeverity.HIGH
    assert alert.rule_name == "SENSITIVE_COMMAND_EXECUTION"
    assert alert.correlation is not None
    assert alert.metadata["source_event_id"]
    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4  # root, LLM, child exec, security finding
    assert '"record_type":"security_event"' in lines[-1].replace(" ", "")


def test_sensitive_file_delete_and_metadata_endpoint_rules(event_factory) -> None:
    engine = SecurityEngine()
    delete = FileDeleteEvent(
        timestamp=event_factory["at"](1),
        pid=101,
        ppid=100,
        uid=1000,
        gid=1000,
        comm="rm",
        path="/home/user/.ssh/id_rsa",
        raw_path="/home/user/.ssh/id_rsa",
        result=0,
    )
    delete_alert = engine.analyze_event(delete, "s1")
    assert delete_alert is not None
    assert delete_alert.severity == EventSeverity.CRITICAL
    assert delete_alert.rule_name == "SENSITIVE_FILE_DELETE"

    network = NetworkConnectionEvent(
        timestamp=event_factory["at"](2),
        pid=101,
        ppid=100,
        uid=1000,
        gid=1000,
        comm="curl",
        remote_addr="169.254.169.254",
        remote_port=80,
        family=2,
        result=0,
    )
    network_alert = engine.analyze_event(network, "s1")
    assert network_alert is not None
    assert network_alert.severity == EventSeverity.CRITICAL
    assert network_alert.rule_name == "CLOUD_METADATA_CONNECTION"


def test_unrelated_pid_is_not_assigned_to_session(event_factory) -> None:
    runtime = AgentSightRuntime()
    runtime.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    session, alert = runtime.ingest(event_factory["exec"](900, 899, "curl", 2))
    assert session is None
    assert alert is None


def test_exit_removes_pid_mapping(event_factory) -> None:
    runtime = AgentSightRuntime()
    runtime.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    runtime.ingest(event_factory["fork"](101, 100, 1))
    assert runtime.sessions.pid_to_session[101] == "s1"
    runtime.ingest(event_factory["exit"](101, 100, 2))
    assert 101 not in runtime.sessions.pid_to_session


class FailingStore:
    def append_many(self, records):
        raise OSError("disk full")


def test_persistence_failure_is_observable_without_stopping_detection(event_factory) -> None:
    runtime = AgentSightRuntime(store=FailingStore())
    runtime.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    session, alert = runtime.ingest(
        event_factory["exec"](101, 100, "rm", 1, argv=["/usr/bin/rm", "--version"])
    )

    assert session is not None
    assert alert is not None
    assert len(session.security_events) == 1
    metrics = runtime.metrics()
    assert metrics["runtime_persistence_errors"] == 2
    assert "disk full" in str(metrics["runtime_last_persistence_error"])


def test_relative_dotenv_path_is_sensitive(event_factory) -> None:
    engine = SecurityEngine()
    event = event_factory["file_open"](path=".env", write_intent=False)
    alert = engine.analyze_event(event, "s1")
    assert alert is not None
    assert alert.rule_name == "SENSITIVE_FILE_ACCESS"


def test_root_process_is_evaluated_by_security_engine(tmp_path: Path, event_factory) -> None:
    store = JsonlEventStore(tmp_path / "events.jsonl")
    runtime = AgentSightRuntime(store=store)
    root = event_factory["exec"](
        100,
        1,
        "rm",
        argv=["/usr/bin/rm", "--version"],
    )

    session = runtime.create_session("s1", "sensitive-root", root)

    assert len(session.security_events) == 1
    assert session.security_events[0].rule_name == "SENSITIVE_COMMAND_EXECUTION"
    records = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(records) == 2
    assert '"record_type":"security_event"' in records[-1].replace(" ", "")
