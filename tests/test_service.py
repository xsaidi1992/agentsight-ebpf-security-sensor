from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN A] Partie A - architecture AgentSight et chaîne Linux kernel vers collecteur userspace.
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# [BESOIN T] Section 11 - démonstration reproductible, tests et livrables.
# Rôle du module : valider l’attachement avant exec, la découverte /proc et la résilience du service.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


import os
import sys
import time

import pytest

from src.collector import AgentSightRuntime
from src.service import LiveSensorService, discover_process_tree, process_event_from_proc


# [TESTS / BESOIN A/B/C/P/T] Classe `FakeCollector` : classe dédiée à l’opération `FakeCollector` dans
# le flux qui consiste à valider l’attachement avant exec, la découverte
# /proc et la résilience du service.
class FakeCollector:
    # [TESTS / BESOIN A/B/C/P/T] Fonction `__init__` : initialise l’état interne et les dépendances
    # nécessaires au composant.
    def __init__(self):
        self.running = False
        self.start_kwargs = None
        self.stop_calls = 0

    # [TESTS / BESOIN A/B/C/P/T] Fonction `start` : démarre le composant de façon contrôlée et refuse
    # les états ambigus.
    def start(self, **kwargs):
        self.running = True
        self.start_kwargs = kwargs

    # [TESTS / BESOIN A/B/C/P/T] Fonction `stop` : arrête proprement le composant et libère les
    # ressources associées.
    def stop(self):
        self.running = False
        self.stop_calls += 1

    # [TESTS / BESOIN A/B/C/P/T] Fonction `poll` : récupère un lot borné d’événements sans bloquer
    # indéfiniment le runtime.
    def poll(self, timeout=0.25, max_events=512):
        time.sleep(min(timeout, 0.01))
        return []

    # [TESTS / BESOIN A/B/C/P/T] Fonction `metrics` : expose les compteurs de fonctionnement, d’erreur
    # et de perte nécessaires à l’observabilité.
    def metrics(self):
        return {"collector_running": int(self.running)}


# [TESTS / BESOIN A/B/C/P/T] Fonction `test_proc_registration_has_stable_identity_and_command` : prouve
# automatiquement le scénario
# `test_proc_registration_has_stable_identity_and_command` et protège le
# comportement contre les régressions.
def test_proc_registration_has_stable_identity_and_command() -> None:
    event = process_event_from_proc(os.getpid())
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.pid == os.getpid()
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.ppid == os.getppid()
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.process_start_ns > 0
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.event_id == f"procfs:{event.pid}:{event.process_start_ns}"
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.argv
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert event.source == "procfs-registration"


# [TESTS / BESOIN A/B/C/P/T] Fonction `test_process_tree_discovery_contains_root` : prouve
# automatiquement le scénario `test_process_tree_discovery_contains_root` et
# protège le comportement contre les régressions.
def test_process_tree_discovery_contains_root() -> None:
    tree = discover_process_tree(os.getpid())
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert tree[0] == os.getpid()
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert len(tree) == len(set(tree))


# [TESTS / BESOIN A/B/C/P/T] Fonction `test_controlled_launch_attaches_before_agent_exec` : prouve
# automatiquement le scénario
# `test_controlled_launch_attaches_before_agent_exec` et protège le
# comportement contre les régressions.
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
    # [TESTS / BESOIN A/B/C/P/T] Gestion d’erreur : isole les dépendances externes et conserve un
    # diagnostic explicite.
    try:
        # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert collector.start_kwargs == {"root_pid": process.pid}
        session = runtime.sessions.get_session("s1")
        # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert session is not None
        # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert session.main_pid == process.pid
        # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert session.llm_interactions[0].session_id == "s1"
        # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert process.wait(timeout=5) == 0
    finally:
        service.stop()
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert collector.running is False


# [TESTS / BESOIN A/B/C/P/T] Fonction `test_start_existing_seeds_current_process_without_modification` :
# prouve automatiquement le scénario
# `test_start_existing_seeds_current_process_without_modification` et protège
# le comportement contre les régressions.
def test_start_existing_seeds_current_process_without_modification() -> None:
    collector = FakeCollector()
    runtime = AgentSightRuntime()
    service = LiveSensorService(collector=collector, runtime=runtime)
    service.start_existing(os.getpid(), "s1", "current-test-process")
    # [TESTS / BESOIN A/B/C/P/T] Gestion d’erreur : isole les dépendances externes et conserve un
    # diagnostic explicite.
    try:
        # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert collector.start_kwargs["root_pid"] == os.getpid()
        # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert runtime.sessions.get_session("s1") is not None
        # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert service.metrics()["service_running"] == 1
    finally:
        service.stop(terminate_owned_process=False)


# [TESTS / BESOIN A/B/C/P/T] Fonction `test_service_rejects_double_start` : prouve automatiquement le
# scénario `test_service_rejects_double_start` et protège le comportement
# contre les régressions.
def test_service_rejects_double_start() -> None:
    collector = FakeCollector()
    service = LiveSensorService(collector=collector, runtime=AgentSightRuntime())
    service.start_existing(os.getpid(), "s1", "current-test-process")
    # [TESTS / BESOIN A/B/C/P/T] Gestion d’erreur : isole les dépendances externes et conserve un
    # diagnostic explicite.
    try:
        # [TESTS / BESOIN A/B/C/P/T] Gestion de ressource : garantit une ouverture et une fermeture
        # déterministes.
        with pytest.raises(RuntimeError, match="already running"):
            service.start_existing(os.getpid(), "s2", "second-process")
    finally:
        service.stop(terminate_owned_process=False)


# [TESTS / BESOIN A/B/C/P/T] Classe `FailingCollector` : classe dédiée à l’opération `FailingCollector`
# dans le flux qui consiste à valider l’attachement avant exec, la découverte
# /proc et la résilience du service.
class FailingCollector(FakeCollector):
    # [TESTS / BESOIN A/B/C/P/T] Fonction `poll` : récupère un lot borné d’événements sans bloquer
    # indéfiniment le runtime.
    def poll(self, timeout=0.25, max_events=512):
        # [TESTS / BESOIN A/B/C/P/T] Échec explicite : refuse une donnée ou un état ambigu au lieu de
        # produire une fausse preuve.
        raise RuntimeError("native reader failed")


# [TESTS / BESOIN A/B/C/P/T] Fonction
# `test_collection_failure_is_exposed_without_crashing_the_api_process` :
# prouve automatiquement le scénario
# `test_collection_failure_is_exposed_without_crashing_the_api_process` et
# protège le comportement contre les régressions.
def test_collection_failure_is_exposed_without_crashing_the_api_process() -> None:
    collector = FailingCollector()
    service = LiveSensorService(collector=collector, runtime=AgentSightRuntime())
    service.start_existing(os.getpid(), "s1", "current-test-process")
    # [TESTS / BESOIN A/B/C/P/T] Gestion d’erreur : isole les dépendances externes et conserve un
    # diagnostic explicite.
    try:
        deadline = time.monotonic() + 2
        # [TESTS / BESOIN A/B/C/P/T] Boucle contrôlée : maintient la collecte ou l’attente jusqu’à la
        # condition d’arrêt.
        while service.metrics()["service_error"] is None and time.monotonic() < deadline:
            time.sleep(0.01)
        metrics = service.metrics()
        # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert "native reader failed" in str(metrics["service_error"])
        # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert metrics["service_running"] == 0
    finally:
        service.stop(terminate_owned_process=False)


# [TESTS / BESOIN A/B/C/P/T] Fonction `test_boot_epoch_fallback_uses_monotonic_clock` : prouve
# automatiquement le scénario `test_boot_epoch_fallback_uses_monotonic_clock`
# et protège le comportement contre les régressions.
def test_boot_epoch_fallback_uses_monotonic_clock(monkeypatch) -> None:
    import src.service as service_module

    # [TESTS / BESOIN A/B/C/P/T] Fonction `fail_read` : fonction dédiée à l’opération `fail_read` dans
    # le flux qui consiste à valider l’attachement avant exec, la découverte
    # /proc et la résilience du service.
    def fail_read(*args, **kwargs):
        # [TESTS / BESOIN A/B/C/P/T] Échec explicite : refuse une donnée ou un état ambigu au lieu de
        # produire une fausse preuve.
        raise OSError("no proc stat")

    monkeypatch.setattr(service_module.Path, "read_text", fail_read)
    monkeypatch.setattr(service_module.time, "time", lambda: 10_000.0)
    monkeypatch.setattr(service_module.time, "monotonic", lambda: 1_234.5)
    # [TESTS / BESOIN A/B/C/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
    # le besoin.
    assert service_module._boot_epoch_seconds() == 8_765.5
