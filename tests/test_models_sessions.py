from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# [BESOIN T] Section 11 - démonstration reproductible, tests et livrables.
# Rôle du module : valider l’arbre de processus, la réutilisation des PID et la corrélation temporelle.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


from src.collector import SessionManager
from src.models import EventType


# [TESTS / BESOIN C/E/T] Fonction `test_complete_session_timeline_and_process_tree` : prouve
# automatiquement le scénario `test_complete_session_timeline_and_process_tree`
# et protège le comportement contre les régressions.
def test_complete_session_timeline_and_process_tree(event_factory) -> None:
    manager = SessionManager()
    root = event_factory["exec"](100, 1, "python3", 0)
    session = manager.create_session("s1", "demo-agent", root)
    session.add_llm_interaction(event_factory["llm"]("s1", -1))

    manager.correlate_and_add(event_factory["fork"](101, 100, 1))
    _, child_exec = manager.correlate_and_add(
        event_factory["exec"](
            101,
            100,
            "curl",
            1.1,
            argv=["/usr/bin/curl", "https://example.test/report"],
        )
    )
    manager.correlate_and_add(event_factory["network"](101, 100, 2, "127.0.0.1", 443))
    manager.correlate_and_add(event_factory["file_open"](101, 100, 3))
    manager.correlate_and_add(event_factory["file_write"](101, 100, 4))

    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert child_exec.correlation is not None
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert child_exec.correlation.llm_event_id.startswith("llm-s1")
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert child_exec.correlation.rationale

    tree = session.get_process_tree()
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert tree["pid"] == 100
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert tree["children"][0]["pid"] == 101
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert tree["children"][0]["comm"] == "curl"
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.files_accessed == {"/tmp/result.txt"}
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert len(session.network_events) == 1
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert [item["event_type"] for item in session.timeline.events] == [
        EventType.LLM_INTERACTION.value,
        EventType.PROCESS_EXECUTION.value,
        EventType.PROCESS_FORK.value,
        EventType.PROCESS_EXECUTION.value,
        EventType.NETWORK_CONNECTION.value,
        EventType.FILE_ACCESS.value,
        EventType.FILE_WRITE.value,
    ]


# [TESTS / BESOIN C/E/T] Fonction `test_exec_updates_fork_placeholder_without_losing_children` : prouve
# automatiquement le scénario
# `test_exec_updates_fork_placeholder_without_losing_children` et protège le
# comportement contre les régressions.
def test_exec_updates_fork_placeholder_without_losing_children(event_factory) -> None:
    manager = SessionManager()
    session = manager.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    manager.correlate_and_add(event_factory["fork"](101, 100, 1))
    manager.correlate_and_add(event_factory["fork"](102, 101, 2))
    manager.correlate_and_add(event_factory["exec"](101, 100, "bash", 3))

    tree = session.get_process_tree()
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert tree["children"][0]["comm"] == "bash"
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert tree["children"][0]["children"][0]["pid"] == 102
    node = session.processes[session.latest_process_by_pid[101]]
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert node.observed_via == "fork+exec"
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert node.exec_count == 1


# [TESTS / BESOIN C/E/T] Fonction `test_pid_reuse_creates_a_new_generation_and_preserves_history` :
# prouve automatiquement le scénario
# `test_pid_reuse_creates_a_new_generation_and_preserves_history` et protège le
# comportement contre les régressions.
def test_pid_reuse_creates_a_new_generation_and_preserves_history(event_factory) -> None:
    manager = SessionManager()
    session = manager.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    manager.correlate_and_add(event_factory["fork"](101, 100, 1, start_ns=101_000_000))
    manager.correlate_and_add(event_factory["exec"](101, 100, "bash", 1.1, start_ns=101_000_000))
    manager.correlate_and_add(event_factory["exit"](101, 100, 2, start_ns=101_000_000))

    # A future process reuses PID 101 with a different kernel start time.
    manager.pid_to_session[100] = "s1"
    manager.correlate_and_add(event_factory["exec"](101, 100, "curl", 3, start_ns=999_000_000))

    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.pid_generations[101] == 2
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.processes["101:1"].status == "EXITED"
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.processes["101:2"].comm == "curl"
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.latest_process_by_pid[101] == "101:2"


# [TESTS / BESOIN C/E/T] Fonction `test_session_ends_only_after_root_and_all_descendants_exit` : prouve
# automatiquement le scénario
# `test_session_ends_only_after_root_and_all_descendants_exit` et protège le
# comportement contre les régressions.
def test_session_ends_only_after_root_and_all_descendants_exit(event_factory) -> None:
    manager = SessionManager()
    session = manager.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    manager.correlate_and_add(event_factory["fork"](101, 100, 1))
    manager.correlate_and_add(event_factory["exit"](100, 1, 2))
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.is_active()
    manager.correlate_and_add(event_factory["exit"](101, 100, 3))
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.is_active() is False
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.end_time == event_factory["at"](3)


# [TESTS / BESOIN C/E/T] Fonction `test_events_outside_correlation_window_are_not_linked` : prouve
# automatiquement le scénario
# `test_events_outside_correlation_window_are_not_linked` et protège le
# comportement contre les régressions.
def test_events_outside_correlation_window_are_not_linked(event_factory) -> None:
    manager = SessionManager()
    session = manager.create_session("s1", "agent", event_factory["exec"](100, 1, "python", 0))
    session.add_llm_interaction(event_factory["llm"]("s1", 1))
    _, event = manager.correlate_and_add(event_factory["exec"](101, 100, "curl", 400))
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert event.correlation is None


# [TESTS / BESOIN C/E/T] Fonction `test_fork_event_is_kept_when_child_was_already_registered` : prouve
# automatiquement le scénario
# `test_fork_event_is_kept_when_child_was_already_registered` et protège le
# comportement contre les régressions.
def test_fork_event_is_kept_when_child_was_already_registered(event_factory) -> None:
    manager = SessionManager()
    session = manager.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    child = event_factory["exec"](101, 100, "bash", 1)
    manager.correlate_and_add(child)
    fork = event_factory["fork"](101, 100, 0.5)
    manager.correlate_and_add(fork)

    event_ids = [item["event_id"] for item in session.timeline.events]
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert child.event_id in event_ids
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert fork.event_id in event_ids
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.pid_generations[101] == 1


# [TESTS / BESOIN C/E/T] Fonction `test_live_pid_identity_conflict_retires_stale_generation` : prouve
# automatiquement le scénario
# `test_live_pid_identity_conflict_retires_stale_generation` et protège le
# comportement contre les régressions.
def test_live_pid_identity_conflict_retires_stale_generation(event_factory) -> None:
    manager = SessionManager()
    session = manager.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    manager.correlate_and_add(
        event_factory["exec"](101, 100, "bash", 1, start_ns=101_000_000)
    )

    manager.correlate_and_add(
        event_factory["exec"](101, 100, "curl", 2, start_ns=999_000_000)
    )

    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.processes["101:1"].status == "REPLACED"
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.processes["101:1"].end_time == event_factory["at"](2)
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.processes["101:2"].status == "RUNNING"
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.active_process_count() == 2  # root plus the current PID 101 generation


# [TESTS / BESOIN C/E/T] Fonction `test_parent_start_time_prevents_linking_to_reused_parent` : prouve
# automatiquement le scénario
# `test_parent_start_time_prevents_linking_to_reused_parent` et protège le
# comportement contre les régressions.
def test_parent_start_time_prevents_linking_to_reused_parent(event_factory) -> None:
    manager = SessionManager()
    session = manager.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    child = event_factory["fork"](101, 100, 1)
    child = child.model_copy(update={"parent_start_ns": 999_000_000})

    resolved, _ = manager.correlate_and_add(child)
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert resolved is None
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert 101 not in session.latest_process_by_pid

    # Even when an external importer assigns the record explicitly, the tree
    # does not link it to a different generation of the same numeric PID.
    session.add_fork(child)
    child_node = session.processes[session.latest_process_by_pid[101]]
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert child_node.parent_identity is None
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.get_process_tree()["children"] == []


# [TESTS / BESOIN C/E/T] Fonction `test_child_seen_before_parent_is_adopted_when_parent_arrives` :
# prouve automatiquement le scénario
# `test_child_seen_before_parent_is_adopted_when_parent_arrives` et protège le
# comportement contre les régressions.
def test_child_seen_before_parent_is_adopted_when_parent_arrives(event_factory) -> None:
    manager = SessionManager()
    session = manager.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))

    # An imported/out-of-order grandchild can arrive before its direct parent.
    grandchild = event_factory["exec"](102, 101, "curl", 2)
    grandchild = grandchild.model_copy(update={"parent_start_ns": 101_000_000})
    session.add_process(grandchild)
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.processes[session.latest_process_by_pid[102]].parent_identity is None

    parent = event_factory["exec"](101, 100, "bash", 1, start_ns=101_000_000)
    session.add_process(parent)

    tree = session.get_process_tree()
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert tree["children"][0]["pid"] == 101
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert tree["children"][0]["children"][0]["pid"] == 102


# [TESTS / BESOIN C/E/T] Fonction `test_timeline_index_is_internal_and_survives_model_copy` : prouve
# automatiquement le scénario
# `test_timeline_index_is_internal_and_survives_model_copy` et protège le
# comportement contre les régressions.
def test_timeline_index_is_internal_and_survives_model_copy(event_factory) -> None:
    manager = SessionManager()
    session = manager.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    child = event_factory["exec"](101, 100, "bash", 2)
    manager.correlate_and_add(child)

    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert session.timeline.contains(child.event_id)
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "event_ids" not in session.timeline.model_dump(mode="json")
    copied = session.model_copy(deep=True)
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert copied.timeline.contains(child.event_id)
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert copied.timeline.add(child) is False


# [TESTS / BESOIN C/E/T] Fonction `test_stale_exit_cannot_terminate_a_reused_pid_generation` : prouve
# automatiquement le scénario
# `test_stale_exit_cannot_terminate_a_reused_pid_generation` et protège le
# comportement contre les régressions.
def test_stale_exit_cannot_terminate_a_reused_pid_generation(event_factory) -> None:
    manager = SessionManager()
    session = manager.create_session("s1", "agent", event_factory["exec"](100, 1, "python"))
    manager.correlate_and_add(
        event_factory["exec"](101, 100, "bash", 1, start_ns=101_000_000)
    )

    stale_exit = event_factory["exit"](
        101, 100, 2, start_ns=999_000_000
    )
    resolved, _ = manager.correlate_and_add(stale_exit)

    # The parent identity still proves that the exit belongs to this session,
    # but its different start time must not terminate the older PID generation.
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert resolved is session
    node = session.processes[session.latest_process_by_pid[101]]
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert node.status == "RUNNING"
    # [TESTS / BESOIN C/E/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert stale_exit.event_id in {
        item["event_id"] for item in session.timeline.events
    }
