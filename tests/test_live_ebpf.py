from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN A] Partie A - architecture AgentSight et chaîne Linux kernel vers collecteur userspace.
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# [BESOIN T] Section 11 - démonstration reproductible, tests et livrables.
# Rôle du module : valider le cycle de vie du processus natif, le préflight et les files bornées.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


import io
import subprocess
from pathlib import Path

import pytest

import src.collector.live_ebpf as live_module
from src.collector.live_ebpf import LiveEBPFError, LiveExecCollector


# [TESTS / BESOIN A/B/P/T] Classe `StreamProcess` : classe dédiée à l’opération `StreamProcess` dans le
# flux qui consiste à valider le cycle de vie du processus natif, le préflight
# et les files bornées.
class StreamProcess:
    # [TESTS / BESOIN A/B/P/T] Fonction `__init__` : initialise l’état interne et les dépendances
    # nécessaires au composant.
    def __init__(self, stdout: str = "", stderr: str = "", running: bool = True):
        self.stdout = io.StringIO(stdout)
        self.stderr = io.StringIO(stderr)
        self.running = running
        self.terminated = False
        self.killed = False

    # [TESTS / BESOIN A/B/P/T] Fonction `poll` : récupère un lot borné d’événements sans bloquer
    # indéfiniment le runtime.
    def poll(self):
        return None if self.running else 0

    # [TESTS / BESOIN A/B/P/T] Fonction `terminate` : fonction dédiée à l’opération `terminate` dans le
    # flux qui consiste à valider le cycle de vie du processus natif, le
    # préflight et les files bornées.
    def terminate(self):
        self.terminated = True
        self.running = False

    # [TESTS / BESOIN A/B/P/T] Fonction `kill` : fonction dédiée à l’opération `kill` dans le flux qui
    # consiste à valider le cycle de vie du processus natif, le préflight et
    # les files bornées.
    def kill(self):
        self.killed = True
        self.running = False

    # [TESTS / BESOIN A/B/P/T] Fonction `wait` : fonction dédiée à l’opération `wait` dans le flux qui
    # consiste à valider le cycle de vie du processus natif, le préflight et
    # les files bornées.
    def wait(self, timeout=None):
        self.running = False
        return 0


# [TESTS / BESOIN A/B/P/T] Fonction `test_live_queue_requires_a_positive_bound` : prouve automatiquement
# le scénario `test_live_queue_requires_a_positive_bound` et protège le
# comportement contre les régressions.
def test_live_queue_requires_a_positive_bound(tmp_path: Path) -> None:
    # [TESTS / BESOIN A/B/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(ValueError, match="queue_size"):
        LiveExecCollector(build_dir=tmp_path, queue_size=0)


# [TESTS / BESOIN A/B/P/T] Fonction
# `test_stdout_reader_accounts_for_stats_errors_unknown_records_and_queue_drops`
# : prouve automatiquement le scénario
# `test_stdout_reader_accounts_for_stats_errors_unknown_records_and_queue_drops`
# et protège le comportement contre les régressions.
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

    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert metrics["kernel_ringbuf_drops"] == 3
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert metrics["emitted_events"] == 7
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert metrics["invalid_stats_records"] == 1
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert metrics["json_decode_errors"] == 1
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert metrics["unknown_record_types"] == 1
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert metrics["userspace_queue_drops"] == 1
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert metrics["queued_events"] == 1
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert metrics["collector_running"] == 1
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert collector.poll(timeout=0, max_events=1)[0]["record_type"] == "exec"


# [TESTS / BESOIN A/B/P/T] Fonction `test_stderr_reader_detects_ready_and_bounds_history` : prouve
# automatiquement le scénario
# `test_stderr_reader_detects_ready_and_bounds_history` et protège le
# comportement contre les régressions.
def test_stderr_reader_detects_ready_and_bounds_history(tmp_path: Path) -> None:
    collector = LiveExecCollector(build_dir=tmp_path)
    lines = "".join(f"line-{index}\n" for index in range(450)) + "READY attached\n"
    collector.process = StreamProcess(stderr=lines)

    collector._read_stderr()

    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert collector.ready.is_set()
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert len(collector.stderr_lines) <= 400
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert collector.stderr_lines[-1] == "READY attached"


# [TESTS / BESOIN A/B/P/T] Fonction
# `test_poll_and_start_arguments_are_validated_before_kernel_preflight` :
# prouve automatiquement le scénario
# `test_poll_and_start_arguments_are_validated_before_kernel_preflight` et
# protège le comportement contre les régressions.
def test_poll_and_start_arguments_are_validated_before_kernel_preflight(tmp_path: Path) -> None:
    collector = LiveExecCollector(build_dir=tmp_path)
    # [TESTS / BESOIN A/B/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(ValueError, match="timeout"):
        collector.poll(timeout=-1)
    # [TESTS / BESOIN A/B/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(ValueError, match="max_events"):
        collector.poll(max_events=0)
    # [TESTS / BESOIN A/B/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(ValueError, match="startup_timeout"):
        collector.start(startup_timeout=0)
    # [TESTS / BESOIN A/B/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(ValueError, match="root_pid"):
        collector.start(root_pid=0)
    # [TESTS / BESOIN A/B/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(ValueError, match="tracked_pids"):
        collector.start(tracked_pids=[1, -2])


# [TESTS / BESOIN A/B/P/T] Fonction `test_preflight_aggregates_capability_and_tracepoint_failures` :
# prouve automatiquement le scénario
# `test_preflight_aggregates_capability_and_tracepoint_failures` et protège le
# comportement contre les régressions.
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

    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert status["ok"] is False
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "CAP_SYS_ADMIN" in status["reason"]
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert all(
        f"tracepoint {group}:{name}" in status["missing"]
        for group, name in LiveExecCollector.REQUIRED_TRACEPOINTS
    )


# [TESTS / BESOIN A/B/P/T] Fonction `test_run_surfaces_stderr_and_command` : prouve automatiquement le
# scénario `test_run_surfaces_stderr_and_command` et protège le comportement
# contre les régressions.
def test_run_surfaces_stderr_and_command(monkeypatch) -> None:
    monkeypatch.setattr(
        live_module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 2, stdout="", stderr="compiler failed"
        ),
    )
    # [TESTS / BESOIN A/B/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(LiveEBPFError, match=r"(?s)compiler failed.*command: clang -c probe.c"):
        LiveExecCollector._run(["clang", "-c", "probe.c"])


# [TESTS / BESOIN A/B/P/T] Fonction `test_stop_terminates_running_native_process` : prouve
# automatiquement le scénario `test_stop_terminates_running_native_process` et
# protège le comportement contre les régressions.
def test_stop_terminates_running_native_process(tmp_path: Path) -> None:
    collector = LiveExecCollector(build_dir=tmp_path)
    process = StreamProcess(running=True)
    collector.process = process
    collector.ready.set()

    collector.stop()

    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert process.terminated is True
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert collector.process is None
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert not collector.ready.is_set()


# [TESTS / BESOIN A/B/P/T] Fonction `test_poll_surfaces_unexpected_native_exit` : prouve automatiquement
# le scénario `test_poll_surfaces_unexpected_native_exit` et protège le
# comportement contre les régressions.
def test_poll_surfaces_unexpected_native_exit(tmp_path: Path) -> None:
    collector = LiveExecCollector(build_dir=tmp_path)
    collector.process = StreamProcess(stderr="verifier rejected program\n", running=False)
    collector._read_stderr()

    # [TESTS / BESOIN A/B/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(LiveEBPFError, match=r"(?s)exited unexpectedly.*verifier rejected"):
        collector.poll(timeout=0)
    # [TESTS / BESOIN A/B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert collector.metrics()["native_exit_code"] == 0


# [TESTS / BESOIN A/B/P/T] Fonction `test_start_rejects_an_already_running_native_process` : prouve
# automatiquement le scénario
# `test_start_rejects_an_already_running_native_process` et protège le
# comportement contre les régressions.
def test_start_rejects_an_already_running_native_process(tmp_path: Path) -> None:
    collector = LiveExecCollector(build_dir=tmp_path)
    collector.process = StreamProcess(running=True)

    # [TESTS / BESOIN A/B/P/T] Gestion de ressource : garantit une ouverture et une fermeture
    # déterministes.
    with pytest.raises(LiveEBPFError, match="already running"):
        collector.start()
