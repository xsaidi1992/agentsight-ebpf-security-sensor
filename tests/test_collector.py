from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN A] Partie A - architecture AgentSight et chaîne Linux kernel vers collecteur userspace.
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# [BESOIN T] Section 11 - démonstration reproductible, tests et livrables.
# Rôle du module : valider le décodage de chaque type d’événement et l’observabilité des pertes.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


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


# [TESTS / BESOIN A/B/C/P/T] Classe `FakeLive` : classe dédiée à l’opération `FakeLive` dans le flux qui
# consiste à valider le décodage de chaque type d’événement et
# l’observabilité des pertes.
class FakeLive:
    # [TESTS / BESOIN A/B/C/P/T] Fonction `__init__` : initialise l’état interne et les dépendances
    # nécessaires au composant.
    def __init__(self):
        self.started = False
        self.start_kwargs = {}
        self.records = []

    # [TESTS / BESOIN A/B/C/P/T] Fonction `start` : démarre le composant de façon contrôlée et refuse
    # les états ambigus.
    def start(self, **kwargs):
        self.started = True
        self.start_kwargs = kwargs

    # [TESTS / BESOIN A/B/C/P/T] Fonction `stop` : arrête proprement le composant et libère les
    # ressources associées.
    def stop(self):
        self.started = False

    # [TESTS / BESOIN A/B/C/P/T] Fonction `poll` : récupère un lot borné d’événements sans bloquer
    # indéfiniment le runtime.
    def poll(self, timeout=0.25, max_events=512):
        batch, self.records = self.records[:max_events], self.records[max_events:]
        return batch

    # [TESTS / BESOIN A/B/C/P/T] Fonction `metrics` : expose les compteurs de fonctionnement, d’erreur
    # et de perte nécessaires à l’observabilité.
    def metrics(self):
        return {
            "kernel_ringbuf_drops": 2,
            "userspace_queue_drops": 1,
            "collector_running": int(self.started),
        }


# [TESTS / BESOIN A/B/C/P/T] Fonction `common` : fonction dédiée à l’opération `common` dans le flux qui
# consiste à valider le décodage de chaque type d’événement et
# l’observabilité des pertes.
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


# [TESTS / BESOIN A/B/C/P/T] Fonction `test_decode_all_kernel_record_types` : prouve automatiquement le
# scénario `test_decode_all_kernel_record_types` et protège le comportement
# contre les régressions.
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
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert [type(event) for event in events] == [
        ProcessExecutionEvent,
        ProcessForkEvent,
        ProcessExitEvent,
        FileAccessEvent,
        FileWriteEvent,
        FileDeleteEvent,
        NetworkConnectionEvent,
    ]
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert events[0].command == "/usr/bin/curl https://example.test"
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert events[0].syscall == "execveat"
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert events[3].write_intent is True
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert events[4].bytes_written == 128
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert events[4].dirfd == -100
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert events[6].remote_port == 443
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert collector.metrics()["by_type"]["network_connect"] == 1


# [TESTS / BESOIN A/B/C/P/T] Fonction `test_sequence_gap_out_of_order_and_native_loss_are_observable` :
# prouve automatiquement le scénario
# `test_sequence_gap_out_of_order_and_native_loss_are_observable` et protège
# le comportement contre les régressions.
def test_sequence_gap_out_of_order_and_native_loss_are_observable() -> None:
    collector = BPFEventCollector(live=FakeLive())
    # [TESTS / BESOIN A/B/C/P/T] Boucle de traitement : parcourt chaque élément de manière déterministe
    # et traçable.
    for sequence in (10, 13, 12):
        collector.decode_record(
            {
                **common("exec", 1, sequence),
                "filename": "/bin/true",
                "argv": ["/bin/true"],
            }
        )
    metrics = collector.metrics()
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert metrics["sequence_gap_events"] == 1
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert metrics["estimated_sequence_drops"] == 2
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert metrics["out_of_order_records"] == 1
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert metrics["kernel_ringbuf_drops"] == 2
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert metrics["userspace_queue_drops"] == 1


# [TESTS / BESOIN A/B/C/P/T] Fonction `test_invalid_or_unknown_records_are_handled_without_crashing` :
# prouve automatiquement le scénario
# `test_invalid_or_unknown_records_are_handled_without_crashing` et protège
# le comportement contre les régressions.
def test_invalid_or_unknown_records_are_handled_without_crashing() -> None:
    collector = BPFEventCollector(live=FakeLive())
    mismatched = {**common("exec", 1), "version": 99, "filename": "/bin/true", "argv": []}
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert collector.decode_record(mismatched) is None
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert collector.decode_record({"record_type": "unknown"}) is None
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert collector.decode_record({**common("network_connect", 7), "remote_port": 99999}) is None
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert collector.metrics()["invalid_records"] == 2


# [TESTS / BESOIN A/B/C/P/T] Fonction `test_poll_starts_with_root_filter_and_decodes_live_queue` :
# prouve automatiquement le scénario
# `test_poll_starts_with_root_filter_and_decodes_live_queue` et protège le
# comportement contre les régressions.
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
    # [TESTS / BESOIN A/B/C/P/T] Gestion d’erreur : isole les dépendances externes et conserve un
    # diagnostic explicite.
    try:
        events = collector.poll()
        # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert len(events) == 1
        # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert events[0].command_name == "curl"
        # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert live.start_kwargs == {"root_pid": 123, "tracked_pids": [124, 125]}
    finally:
        collector.stop()
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert live.started is False


# [TESTS / BESOIN A/B/C/P/T] Fonction
# `test_exec_uses_proc_executable_when_available_and_preserves_kernel_filename`
# : prouve automatiquement le scénario
# `test_exec_uses_proc_executable_when_available_and_preserves_kernel_filename`
# et protège le comportement contre les régressions.
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
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert isinstance(event, ProcessExecutionEvent)
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.executable == "/usr/bin/python3.13"
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.metadata["kernel_filename"] == "python3"
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.command == "python3 'agent file.py' --mode=test"


# [TESTS / BESOIN A/B/C/P/T] Fonction `test_relative_write_uses_the_openat_directory_descriptor` :
# prouve automatiquement le scénario
# `test_relative_write_uses_the_openat_directory_descriptor` et protège le
# comportement contre les régressions.
def test_relative_write_uses_the_openat_directory_descriptor(monkeypatch) -> None:
    collector = BPFEventCollector(live=FakeLive())

    # [TESTS / BESOIN A/B/C/P/T] Fonction `fake_readlink` : fonction dédiée à l’opération
    # `fake_readlink` dans le flux qui consiste à valider le décodage de
    # chaque type d’événement et l’observabilité des pertes.
    def fake_readlink(path):
        text = str(path)
        # [TESTS / BESOIN A/B/C/P/T] Condition de garde : valide le cas courant avant de poursuivre le
        # flux fonctionnel.
        if text.endswith("/fd/9"):
            return "/var/lib/agent-output"
        # [TESTS / BESOIN A/B/C/P/T] Condition de garde : valide le cas courant avant de poursuivre le
        # flux fonctionnel.
        if text.endswith("/cwd"):
            return "/wrong/current-directory"
        # [TESTS / BESOIN A/B/C/P/T] Échec explicite : refuse une donnée ou un état ambigu au lieu de
        # produire une fausse preuve.
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

    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert isinstance(event, FileWriteEvent)
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.dirfd == 9
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.cwd == "/var/lib/agent-output"
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.path == "/var/lib/agent-output/reports/result.txt"


# [TESTS / BESOIN A/B/C/P/T] Fonction `test_inherited_fd_write_is_emitted_and_resolved_from_procfs` :
# prouve automatiquement le scénario
# `test_inherited_fd_write_is_emitted_and_resolved_from_procfs` et protège le
# comportement contre les régressions.
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

    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert isinstance(event, FileWriteEvent)
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.path == "/tmp/inherited.txt"
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.metadata["path_resolution"] == "procfs-fd"


# [TESTS / BESOIN A/B/C/P/T] Fonction `test_unresolved_inherited_fd_write_remains_observable` : prouve
# automatiquement le scénario
# `test_unresolved_inherited_fd_write_remains_observable` et protège le
# comportement contre les régressions.
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

    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert isinstance(event, FileWriteEvent)
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.path == "fd:12"
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.metadata["path_resolution"] == "unresolved"
