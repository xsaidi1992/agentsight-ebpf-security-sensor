from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN A] Partie A - architecture AgentSight et chaîne Linux kernel vers collecteur userspace.
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# [BESOIN T] Section 11 - démonstration reproductible, tests et livrables.
# Rôle du module : valider l’import, la normalisation et l’idempotence des données AgentSight.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


import json
from pathlib import Path

import pytest

from src.collector import AgentSightRuntime
from src.integrations import AgentSightImporter, AgentSightIntegrationError
from src.models import (
    FileAccessEvent,
    FileWriteEvent,
    LLMInteractionEvent,
    NetworkConnectionEvent,
    ProcessExecutionEvent,
)


# [TESTS / BESOIN A/C/E/P/T] Fonction `agentsight_document` : fonction dédiée à l’opération
# `agentsight_document` dans le flux qui consiste à valider l’import, la
# normalisation et l’idempotence des données AgentSight.
def agentsight_document() -> dict:
    return {
        "schema_version": "upstream-compatible-semantic-fixture",
        "sessions": [
            {
                "session_id": "upstream-session",
                "events": [
                    {
                        "event_type": "llm_call",
                        "event_id": "llm-upstream-1",
                        "timestamp": "2026-01-01T10:01:02Z",
                        "provider": "openai",
                        "model": "gpt-test",
                        "messages": [{"role": "user", "content": "Download the report"}],
                        "response": "Downloading it now",
                    },
                    {
                        "event_type": "process_exec",
                        "timestamp": "2026-01-01T10:01:05Z",
                        "pid": 101,
                        "ppid": 100,
                        "uid": 1000,
                        "gid": 1000,
                        "comm": "curl",
                        "executable": "/usr/bin/curl",
                        "argv": ["/usr/bin/curl", "https://example.test/report"],
                    },
                    {
                        "event_type": "network_connect",
                        "timestamp": "2026-01-01T10:01:06Z",
                        "pid": 101,
                        "ppid": 100,
                        "remote_addr": "203.0.113.10",
                        "remote_port": 443,
                    },
                    {
                        "event_type": "file_open",
                        "timestamp": "2026-01-01T10:01:07Z",
                        "pid": 101,
                        "ppid": 100,
                        "path": "/tmp/result.txt",
                        "fd": 3,
                        "write_intent": True,
                    },
                    {
                        "event_type": "file_write",
                        "timestamp": "2026-01-01T10:01:07.100Z",
                        "pid": 101,
                        "ppid": 100,
                        "path": "/tmp/result.txt",
                        "fd": 3,
                        "bytes_written": 128,
                    },
                ],
            }
        ],
    }


# [TESTS / BESOIN A/C/E/P/T] Fonction `test_importer_normalizes_llm_process_file_and_network_records` :
# prouve automatiquement le scénario
# `test_importer_normalizes_llm_process_file_and_network_records` et protège
# le comportement contre les régressions.
def test_importer_normalizes_llm_process_file_and_network_records() -> None:
    result = AgentSightImporter().parse(agentsight_document(), "s1")
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(result.llm_events) == 1
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(result.os_events) == 4
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert isinstance(result.llm_events[0], LLMInteractionEvent)
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert [type(item) for item in result.os_events] == [
        ProcessExecutionEvent,
        NetworkConnectionEvent,
        FileAccessEvent,
        FileWriteEvent,
    ]
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.llm_events[0].prompt == "user: Download the report"
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.os_events[0].command_name == "curl"
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.os_events[0].metadata["agentsight_record"]["event_type"] == "process_exec"
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.os_events[-1].bytes_written == 128


# [TESTS / BESOIN A/C/E/P/T] Fonction `test_json_and_jsonl_file_loading` : prouve automatiquement le
# scénario `test_json_and_jsonl_file_loading` et protège le comportement
# contre les régressions.
def test_json_and_jsonl_file_loading(tmp_path: Path) -> None:
    importer = AgentSightImporter()
    json_path = tmp_path / "snapshot.json"
    json_path.write_text(json.dumps(agentsight_document()), encoding="utf-8")
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert importer.parse_file(json_path, "s1").total_events == 5

    jsonl_path = tmp_path / "prompts.jsonl"
    jsonl_path.write_text(
        json.dumps({
            "event_type": "llm_call",
            "timestamp": "2026-01-01T10:00:00Z",
            "prompt": "one",
            "session_id": "x",
        })
        + "\n"
        + json.dumps({
            "event_type": "llm_call",
            "timestamp": "2026-01-01T10:00:01Z",
            "prompt": "two",
            "session_id": "x",
        })
        + "\n",
        encoding="utf-8",
    )
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(importer.parse_file(jsonl_path, "s1").llm_events) == 2


# [TESTS / BESOIN A/C/E/P/T] Fonction `test_invalid_jsonl_has_actionable_error` : prouve automatiquement
# le scénario `test_invalid_jsonl_has_actionable_error` et protège le
# comportement contre les régressions.
def test_invalid_jsonl_has_actionable_error(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text('{"valid": true}\nnot-json\n', encoding="utf-8")
    # [TESTS / BESOIN A/C/E/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(AgentSightIntegrationError, match=r"bad\.jsonl:2"):
        AgentSightImporter.load(path)


# [TESTS / BESOIN A/C/E/P/T] Fonction `test_import_into_runtime_links_upstream_records_to_local_session`
# : prouve automatiquement le scénario
# `test_import_into_runtime_links_upstream_records_to_local_session` et
# protège le comportement contre les régressions.
def test_import_into_runtime_links_upstream_records_to_local_session(tmp_path: Path, event_factory) -> None:
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(agentsight_document()), encoding="utf-8")
    runtime = AgentSightRuntime()
    runtime.create_session("s1", "agent", event_factory["exec"](100, 1, "python3", 0))

    result = AgentSightImporter().import_into_runtime(path, runtime, "s1")
    session = runtime.sessions.get_session("s1")
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert session is not None
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.total_events == 5
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(session.llm_interactions) == 1
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert "/tmp/result.txt" in session.files_accessed
    process = session.processes[session.latest_process_by_pid[101]]
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert process.comm == "curl"
    imported_process = next(
        item for item in session.timeline.events if item["event_type"] == "PROCESS_EXECUTION" and item["pid"] == 101
    )
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert imported_process["correlation"]["llm_event_id"] == "agentsight:llm:llm-upstream-1"


# [TESTS / BESOIN A/C/E/P/T] Fonction `test_reimport_is_idempotent_for_timeline_and_security` : prouve
# automatiquement le scénario
# `test_reimport_is_idempotent_for_timeline_and_security` et protège le
# comportement contre les régressions.
def test_reimport_is_idempotent_for_timeline_and_security(tmp_path: Path, event_factory) -> None:
    document = agentsight_document()
    # Make the process record security-sensitive so duplicate alerts are observable.
    process = document["sessions"][0]["events"][1]
    process.update({"comm": "rm", "executable": "/usr/bin/rm", "argv": ["/usr/bin/rm", "--version"]})
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    runtime = AgentSightRuntime()
    runtime.create_session("s1", "agent", event_factory["exec"](100, 1, "python3", 0))
    importer = AgentSightImporter()

    importer.import_into_runtime(path, runtime, "s1")
    session = runtime.sessions.get_session("s1")
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert session is not None
    timeline_count = len(session.timeline.events)
    alert_count = len(session.security_events)
    importer.import_into_runtime(path, runtime, "s1")

    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(session.timeline.events) == timeline_count
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(session.security_events) == alert_count == 1


# [TESTS / BESOIN A/C/E/P/T] Fonction
# `test_agentsight_cli_falls_back_between_supported_report_syntaxes_and_decodes_jsonl`
# : prouve automatiquement le scénario
# `test_agentsight_cli_falls_back_between_supported_report_syntaxes_and_decodes_jsonl`
# et protège le comportement contre les régressions.
def test_agentsight_cli_falls_back_between_supported_report_syntaxes_and_decodes_jsonl(
    monkeypatch, tmp_path: Path
) -> None:
    import subprocess

    import src.integrations.agentsight as adapter
    from src.integrations import AgentSightCLI

    calls: list[list[str]] = []
    responses = iter(
        [
            subprocess.CompletedProcess([], 2, stdout="", stderr="unsupported ordering"),
            subprocess.CompletedProcess(
                [],
                0,
                stdout=(
                    '{"event_type":"llm_call","prompt":"one"}\n'
                    '{"event_type":"llm_call","prompt":"two"}\n'
                ),
                stderr="",
            ),
        ]
    )

    monkeypatch.setattr(adapter.shutil, "which", lambda executable: "/opt/bin/agentsight")

    # [TESTS / BESOIN A/C/E/P/T] Fonction `fake_run` : fonction dédiée à l’opération `fake_run` dans le
    # flux qui consiste à valider l’import, la normalisation et l’idempotence
    # des données AgentSight.
    def fake_run(command, **kwargs):
        calls.append(list(command))
        return next(responses)

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    result = AgentSightCLI().prompts_json(tmp_path / "run.db")

    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(result) == 2
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert calls[0][1:] == ["report", "--db", str(tmp_path / "run.db"), "prompts", "--json"]
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert calls[1][1:] == ["report", "prompts", "--db", str(tmp_path / "run.db"), "--json"]


# [TESTS / BESOIN A/C/E/P/T] Fonction `test_agentsight_cli_reports_actionable_errors` : prouve
# automatiquement le scénario `test_agentsight_cli_reports_actionable_errors`
# et protège le comportement contre les régressions.
def test_agentsight_cli_reports_actionable_errors(monkeypatch, tmp_path: Path) -> None:
    import subprocess

    import src.integrations.agentsight as adapter
    from src.integrations import AgentSightCLI

    monkeypatch.setattr(adapter.shutil, "which", lambda executable: "/opt/bin/agentsight")
    monkeypatch.setattr(
        adapter.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 1, stdout="", stderr="database could not be opened"
        ),
    )
    # [TESTS / BESOIN A/C/E/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(AgentSightIntegrationError, match="database could not be opened"):
        AgentSightCLI().audit_json(tmp_path / "missing.db")


# [TESTS / BESOIN A/C/E/P/T] Fonction `test_prompt_poller_imports_only_new_llm_events` : prouve
# automatiquement le scénario
# `test_prompt_poller_imports_only_new_llm_events` et protège le comportement
# contre les régressions.
def test_prompt_poller_imports_only_new_llm_events(event_factory, tmp_path: Path) -> None:
    from src.integrations import AgentSightPromptPoller

    runtime = AgentSightRuntime()
    runtime.create_session("s1", "agent", event_factory["exec"](100, 1, "python3", 0))

    # [TESTS / BESOIN A/C/E/P/T] Classe `FakeCLI` : classe dédiée à l’opération `FakeCLI` dans le flux
    # qui consiste à valider l’import, la normalisation et l’idempotence des
    # données AgentSight.
    class FakeCLI:
        # [TESTS / BESOIN A/C/E/P/T] Fonction `__init__` : initialise l’état interne et les dépendances
        # nécessaires au composant.
        def __init__(self):
            self.calls = 0

        # [TESTS / BESOIN A/C/E/P/T] Fonction `prompts_json` : fonction dédiée à l’opération
        # `prompts_json` dans le flux qui consiste à valider l’import, la
        # normalisation et l’idempotence des données AgentSight.
        def prompts_json(self, database):
            self.calls += 1
            events = [
                {
                    "event_type": "llm_call",
                    "event_id": "poll-1",
                    "timestamp": "2026-01-01T10:00:00Z",
                    "prompt": "first",
                }
            ]
            # [TESTS / BESOIN A/C/E/P/T] Condition de garde : valide le cas courant avant de poursuivre
            # le flux fonctionnel.
            if self.calls >= 2:
                events.append(
                    {
                        "event_type": "llm_call",
                        "event_id": "poll-2",
                        "timestamp": "2026-01-01T10:00:01Z",
                        "prompt": "second",
                    }
                )
            return {"events": events}

    poller = AgentSightPromptPoller(
        tmp_path / "run.db",
        runtime,
        "s1",
        interval_seconds=0.01,
        cli=FakeCLI(),
    )
    poller.refresh()
    poller.refresh()
    poller.refresh()

    session = runtime.sessions.get_session("s1")
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert session is not None
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert [item.prompt for item in session.llm_interactions] == ["first", "second"]
    metrics = poller.metrics()
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert metrics["poll_count"] == 3
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert metrics["imported_events"] == 2
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert metrics["last_error"] is None


# [TESTS / BESOIN A/C/E/P/T] Fonction `test_payload_envelope_without_source_id_is_not_imported_twice` :
# prouve automatiquement le scénario
# `test_payload_envelope_without_source_id_is_not_imported_twice` et protège
# le comportement contre les régressions.
def test_payload_envelope_without_source_id_is_not_imported_twice() -> None:
    document = {
        "payload": {
            "event_type": "llm_call",
            "timestamp": "2026-01-01T10:00:00Z",
            "prompt": "one semantic event",
        }
    }
    result = AgentSightImporter().parse(document, "s1")
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(result.llm_events) == 1


# [TESTS / BESOIN A/C/E/P/T] Fonction `test_importer_supports_fork_exit_and_api_network_records` :
# prouve automatiquement le scénario
# `test_importer_supports_fork_exit_and_api_network_records` et protège le
# comportement contre les régressions.
def test_importer_supports_fork_exit_and_api_network_records() -> None:
    document = {
        "events": [
            {
                "event_type": "process_fork",
                "event_id": "fork-1",
                "timestamp": "2026-01-01T10:00:01Z",
                "child_pid": 101,
                "parent_pid": 100,
                "child_comm": "bash",
                "child_start_ns": 101000000,
                "parent_start_ns": 100000000,
            },
            {
                "event_type": "process_exit",
                "event_id": "exit-1",
                "timestamp": "2026-01-01T10:00:02Z",
                "pid": 101,
                "ppid": 100,
                "exit_code": 7,
                "signal": 0,
            },
            {
                "event_type": "api_call",
                "event_id": "api-1",
                "timestamp": "2026-01-01T10:00:03Z",
                "pid": 100,
                "host": "203.0.113.9",
                "port": 443,
            },
        ]
    }
    result = AgentSightImporter().parse(document, "s1")
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert [item.event_type.value for item in result.os_events] == [
        "PROCESS_FORK",
        "PROCESS_EXIT",
        "NETWORK_CONNECTION",
    ]
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.os_events[0].pid == 101
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.os_events[0].ppid == 100
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.os_events[1].exit_code == 7
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.os_events[2].remote_addr == "203.0.113.9"


# [TESTS / BESOIN A/C/E/P/T] Fonction `test_missing_or_malformed_timestamps_are_not_replaced_with_now` :
# prouve automatiquement le scénario
# `test_missing_or_malformed_timestamps_are_not_replaced_with_now` et protège
# le comportement contre les régressions.
def test_missing_or_malformed_timestamps_are_not_replaced_with_now() -> None:
    result = AgentSightImporter().parse(
        {
            "events": [
                {"event_type": "llm_call", "prompt": "missing time"},
                {"event_type": "process_exec", "timestamp": "not-a-time", "pid": 12},
            ]
        },
        "s1",
    )
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.total_events == 0
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.ignored_records == 2
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert all("timestamp" in warning for warning in result.warnings)


# [TESTS / BESOIN A/C/E/P/T] Fonction `test_epoch_timestamp_units_and_llm_pid_are_normalized` : prouve
# automatiquement le scénario
# `test_epoch_timestamp_units_and_llm_pid_are_normalized` et protège le
# comportement contre les régressions.
def test_epoch_timestamp_units_and_llm_pid_are_normalized() -> None:
    seconds = 1_767_225_600  # 2026-01-01T00:00:00Z
    document = {
        "events": [
            {
                "event_type": "llm_call",
                "event_id": f"unit-{index}",
                "timestamp": value,
                "prompt": f"unit {index}",
                "pid": 100,
            }
            for index, value in enumerate(
                (seconds, seconds * 1_000, seconds * 1_000_000, seconds * 1_000_000_000)
            )
        ]
    }
    result = AgentSightImporter().parse(document, "s1")
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(result.llm_events) == 4
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert {item.timestamp.isoformat() for item in result.llm_events} == {
        "2026-01-01T00:00:00+00:00"
    }
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert {item.pid for item in result.llm_events} == {100}


# [TESTS / BESOIN A/C/E/P/T] Fonction `test_monotonic_timestamp_ns_is_rejected_without_boot_mapping` :
# prouve automatiquement le scénario
# `test_monotonic_timestamp_ns_is_rejected_without_boot_mapping` et protège
# le comportement contre les régressions.
def test_monotonic_timestamp_ns_is_rejected_without_boot_mapping() -> None:
    result = AgentSightImporter().parse(
        {
            "event_type": "process_exec",
            "timestamp_ns": 123_456_789_000,
            "pid": 100,
            "command": "/bin/true",
        },
        "s1",
    )
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.total_events == 0
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.ignored_records == 1
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert "boot mapping" in result.warnings[0]


# [TESTS / BESOIN A/C/E/P/T] Fonction
# `test_one_upstream_record_can_emit_llm_and_os_semantics_with_distinct_ids`
# : prouve automatiquement le scénario
# `test_one_upstream_record_can_emit_llm_and_os_semantics_with_distinct_ids`
# et protège le comportement contre les régressions.
def test_one_upstream_record_can_emit_llm_and_os_semantics_with_distinct_ids() -> None:
    result = AgentSightImporter().parse(
        {
            "event_type": "llm_process_exec",
            "event_id": "shared-upstream-id",
            "timestamp": "2026-01-01T10:00:00Z",
            "prompt": "Run curl",
            "model": "example-model",
            "pid": 101,
            "ppid": 100,
            "comm": "curl",
            "executable": "/usr/bin/curl",
            "argv": ["/usr/bin/curl", "https://example.test"],
        },
        "s1",
    )
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(result.llm_events) == 1
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(result.os_events) == 1
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.llm_events[0].event_id == "agentsight:llm:shared-upstream-id"
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert result.os_events[0].event_id == "agentsight:os:llm_process_exec:shared-upstream-id"


# [TESTS / BESOIN A/C/E/P/T] Fonction
# `test_non_llm_audit_record_with_prompt_metadata_is_not_false_positive` :
# prouve automatiquement le scénario
# `test_non_llm_audit_record_with_prompt_metadata_is_not_false_positive` et
# protège le comportement contre les régressions.
def test_non_llm_audit_record_with_prompt_metadata_is_not_false_positive() -> None:
    result = AgentSightImporter().parse(
        {
            "event_type": "process_exec",
            "event_id": "process-1",
            "timestamp": "2026-01-01T10:00:00Z",
            "pid": 101,
            "ppid": 100,
            "comm": "python",
            "command": "python agent.py",
            "prompt": "copied diagnostic metadata",
        },
        "s1",
    )
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(result.llm_events) == 0
    # [TESTS / BESOIN A/C/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(result.os_events) == 1
