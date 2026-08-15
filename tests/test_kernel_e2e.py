"""Privileged proof of kernel -> ring buffer -> session -> API/security pipeline."""
from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN D] Partie D - détection et explication des actions sensibles.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# [BESOIN T] Section 11 - démonstration reproductible, tests et livrables.
# Rôle du module : prouver sur un vrai kernel la chaîne agent vers eBPF, session, alerte et métriques.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


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

# [TESTS / BESOIN B/C/D/E/P/T] Constante `ROOT` : fixe un paramètre stable et auditable utilisé par ce
# module.
ROOT = Path(__file__).resolve().parents[1]
# [TESTS / BESOIN B/C/D/E/P/T] Constante `PREFLIGHT` : fixe un paramètre stable et auditable utilisé par
# ce module.
PREFLIGHT = BPFEventCollector.preflight()


# [TESTS / BESOIN B/C/D/E/P/T] Fonction `_local_listener` : fonction dédiée à l’opération
# `_local_listener` dans le flux qui consiste à prouver sur un vrai kernel
# la chaîne agent vers eBPF, session, alerte et métriques.
def _local_listener() -> tuple[socket.socket, int, threading.Thread]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = int(server.getsockname()[1])

    # [TESTS / BESOIN B/C/D/E/P/T] Fonction `receive_once` : fonction dédiée à l’opération
    # `receive_once` dans le flux qui consiste à prouver sur un vrai kernel
    # la chaîne agent vers eBPF, session, alerte et métriques.
    def receive_once() -> None:
        # [TESTS / BESOIN B/C/D/E/P/T] Gestion d’erreur : isole les dépendances externes et conserve un
        # diagnostic explicite.
        try:
            server.settimeout(10)
            connection, _ = server.accept()
            # [TESTS / BESOIN B/C/D/E/P/T] Gestion de ressource : garantit une ouverture et une
            # fermeture déterministes.
            with connection:
                connection.recv(1024)
        finally:
            server.close()

    thread = threading.Thread(target=receive_once, daemon=True)
    thread.start()
    return server, port, thread


# [TESTS / BESOIN B/C/D/E/P/T] Fonction `test_real_kernel_process_file_network_and_security_timeline` :
# prouve automatiquement le scénario
# `test_real_kernel_process_file_network_and_security_timeline` et protège
# le comportement contre les régressions.
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
    # [TESTS / BESOIN B/C/D/E/P/T] Gestion d’erreur : isole les dépendances externes et conserve un
    # diagnostic explicite.
    try:
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
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
        # [TESTS / BESOIN B/C/D/E/P/T] Boucle contrôlée : maintient la collecte ou l’attente jusqu’à la
        # condition d’arrêt.
        while time.monotonic() < deadline:
            session = runtime.sessions.get_session("kernel-e2e")
            # [TESTS / BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de
            # poursuivre le flux fonctionnel.
            if session:
                observed = {str(item["event_type"]) for item in session.timeline.events}
                # [TESTS / BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de
                # poursuivre le flux fonctionnel.
                if required.issubset(observed):
                    break
            time.sleep(0.1)

        session = runtime.sessions.get_session("kernel-e2e")
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert session is not None
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert required.issubset(observed), {
            "missing": sorted(required - observed),
            "timeline": session.timeline.events,
            "metrics": service.metrics(),
        }
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert output.read_text(encoding="utf-8").startswith("AgentSight")
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert any(node.comm == "rm" for node in session.processes.values())
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert any(alert.rule_name == "SENSITIVE_COMMAND_EXECUTION" for alert in session.security_events)
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert any(item.get("correlation") for item in session.timeline.events if item["event_type"] != "LLM_INTERACTION")
        metrics = service.metrics()
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert metrics["kernel_ringbuf_drops"] == 0
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert metrics["userspace_queue_drops"] == 0
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert metrics["service_error"] is None

        client = TestClient(create_api(runtime=runtime, metrics_provider=service.metrics))
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert client.get("/agents/kernel-e2e").status_code == 200
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert client.get("/agents/kernel-e2e/processes").json()["total"] >= 2
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert client.get("/agents/kernel-e2e/security-events").json()["total"] >= 1
        # [TESTS / BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu
        # par le besoin.
        assert client.get("/events", params={"severity": "HIGH"}).json()["total_matches"] >= 1
    finally:
        service.stop()
