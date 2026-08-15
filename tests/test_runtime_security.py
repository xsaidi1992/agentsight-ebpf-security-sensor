from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN D] Partie D - détection et explication des actions sensibles.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# [BESOIN T] Section 11 - démonstration reproductible, tests et livrables.
# Rôle du module : valider les règles sensibles, l’isolation des sessions et les erreurs de persistance.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


from pathlib import Path

from src.collector import AgentSightRuntime, SecurityEngine
from src.models import EventSeverity, FileDeleteEvent, NetworkConnectionEvent
from src.storage import JsonlEventStore


# [TESTS / BESOIN C/D/E/P/T] Fonction `test_runtime_correlates_sensitive_command_and_persists_audit_log`
# : prouve automatiquement le scénario
# `test_runtime_correlates_sensitive_command_and_persists_audit_log` et
# protège le comportement contre les régressions.
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

    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert session is not None
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert alert is not None
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert alert.severity == EventSeverity.HIGH
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert alert.rule_name == "SENSITIVE_COMMAND_EXECUTION"
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert alert.correlation is not None
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert alert.metadata["source_event_id"]
    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(lines) == 4  # root, LLM, child exec, security finding
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert '"record_type":"security_event"' in lines[-1].replace(" ", "")


# [TESTS / BESOIN C/D/E/P/T] Fonction `test_sensitive_file_delete_and_metadata_endpoint_rules` : prouve
# automatiquement le scénario
# `test_sensitive_file_delete_and_metadata_endpoint_rules` et protège le
# comportement contre les régressions.
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
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert delete_alert is not None
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert delete_alert.severity == EventSeverity.CRITICAL
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
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
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert network_alert is not None
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert network_alert.severity == EventSeverity.CRITICAL
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert network_alert.rule_name == "CLOUD_METADATA_CONNECTION"


# [TESTS / BESOIN C/D/E/P/T] Fonction `test_unrelated_pid_is_not_assigned_to_session` : prouve
# automatiquement le scénario `test_unrelated_pid_is_not_assigned_to_session`
# et protège le comportement contre les régressions.
def test_unrelated_pid_is_not_assigned_to_session(event_factory) -> None:
    runtime = AgentSightRuntime()
    runtime.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    session, alert = runtime.ingest(event_factory["exec"](900, 899, "curl", 2))
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert session is None
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert alert is None


# [TESTS / BESOIN C/D/E/P/T] Fonction `test_exit_removes_pid_mapping` : prouve automatiquement le
# scénario `test_exit_removes_pid_mapping` et protège le comportement contre
# les régressions.
def test_exit_removes_pid_mapping(event_factory) -> None:
    runtime = AgentSightRuntime()
    runtime.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    runtime.ingest(event_factory["fork"](101, 100, 1))
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert runtime.sessions.pid_to_session[101] == "s1"
    runtime.ingest(event_factory["exit"](101, 100, 2))
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert 101 not in runtime.sessions.pid_to_session


# [TESTS / BESOIN C/D/E/P/T] Classe `FailingStore` : classe dédiée à l’opération `FailingStore` dans le
# flux qui consiste à valider les règles sensibles, l’isolation des sessions
# et les erreurs de persistance.
class FailingStore:
    # [TESTS / BESOIN C/D/E/P/T] Fonction `append_many` : sérialise puis écrit atomiquement un lot
    # d’enregistrements JSONL.
    def append_many(self, records):
        # [TESTS / BESOIN C/D/E/P/T] Échec explicite : refuse une donnée ou un état ambigu au lieu de
        # produire une fausse preuve.
        raise OSError("disk full")


# [TESTS / BESOIN C/D/E/P/T] Fonction
# `test_persistence_failure_is_observable_without_stopping_detection` :
# prouve automatiquement le scénario
# `test_persistence_failure_is_observable_without_stopping_detection` et
# protège le comportement contre les régressions.
def test_persistence_failure_is_observable_without_stopping_detection(event_factory) -> None:
    runtime = AgentSightRuntime(store=FailingStore())
    runtime.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    session, alert = runtime.ingest(
        event_factory["exec"](101, 100, "rm", 1, argv=["/usr/bin/rm", "--version"])
    )

    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert session is not None
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert alert is not None
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(session.security_events) == 1
    metrics = runtime.metrics()
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert metrics["runtime_persistence_errors"] == 2
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert "disk full" in str(metrics["runtime_last_persistence_error"])


# [TESTS / BESOIN C/D/E/P/T] Fonction `test_relative_dotenv_path_is_sensitive` : prouve automatiquement
# le scénario `test_relative_dotenv_path_is_sensitive` et protège le
# comportement contre les régressions.
def test_relative_dotenv_path_is_sensitive(event_factory) -> None:
    engine = SecurityEngine()
    event = event_factory["file_open"](path=".env", write_intent=False)
    alert = engine.analyze_event(event, "s1")
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert alert is not None
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert alert.rule_name == "SENSITIVE_FILE_ACCESS"


# [TESTS / BESOIN C/D/E/P/T] Fonction `test_root_process_is_evaluated_by_security_engine` : prouve
# automatiquement le scénario
# `test_root_process_is_evaluated_by_security_engine` et protège le
# comportement contre les régressions.
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

    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(session.security_events) == 1
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert session.security_events[0].rule_name == "SENSITIVE_COMMAND_EXECUTION"
    records = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(records) == 2
    # [TESTS / BESOIN C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert '"record_type":"security_event"' in records[-1].replace(" ", "")
