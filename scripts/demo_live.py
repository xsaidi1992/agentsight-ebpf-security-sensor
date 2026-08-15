#!/usr/bin/env python3
"""Kernel E2E: AgentSight LLM record -> exec/file/network -> security alert."""
from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN D] Partie D - détection et explication des actions sensibles.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# [BESOIN T] Section 11 - démonstration reproductible, tests et livrables.
# Rôle du module : orchestrer la démonstration privilégiée de bout en bout et vérifier chaque événement attendu.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


import argparse
import json
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# [BESOIN B/C/D/E/P/T] Constante `ROOT` : fixe un paramètre stable et auditable utilisé par ce module.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.collector import AgentSightRuntime, BPFEventCollector
from src.integrations import AgentSightCLI, AgentSightImporter
from src.service import LiveSensorService
from src.storage import JsonlEventStore


# [BESOIN B/C/D/E/P/T] Fonction `_listener` : fonction dédiée à l’opération `_listener` dans le flux qui
# consiste à orchestrer la démonstration privilégiée de bout en bout et vérifier
# chaque événement attendu.
def _listener() -> tuple[socket.socket, int, threading.Thread]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = int(server.getsockname()[1])

    # [BESOIN B/C/D/E/P/T] Fonction `accept_one` : fonction dédiée à l’opération `accept_one` dans le
    # flux qui consiste à orchestrer la démonstration privilégiée de bout en bout
    # et vérifier chaque événement attendu.
    def accept_one() -> None:
        # [BESOIN B/C/D/E/P/T] Gestion d’erreur : isole les dépendances externes et conserve un
        # diagnostic explicite.
        try:
            connection, _ = server.accept()
            # [BESOIN B/C/D/E/P/T] Gestion de ressource : garantit une ouverture et une fermeture
            # déterministes.
            with connection:
                connection.recv(4096)
        finally:
            server.close()

    thread = threading.Thread(target=accept_one, name="agentsight-demo-server", daemon=True)
    thread.start()
    return server, port, thread


# [BESOIN B/C/D/E/P/T] Fonction `_llm_events` : fonction dédiée à l’opération `_llm_events` dans le flux
# qui consiste à orchestrer la démonstration privilégiée de bout en bout et
# vérifier chaque événement attendu.
def _llm_events(
    import_path: Path | None,
    database: Path | None,
    executable: str,
):
    importer = AgentSightImporter()
    # [BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if import_path:
        result = importer.parse_file(import_path, "demo-session")
        # [BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not result.llm_events:
            # [BESOIN B/C/D/E/P/T] Échec explicite : refuse une donnée ou un état ambigu au lieu de
            # produire une fausse preuve.
            raise RuntimeError("the supplied AgentSight document has no LLM interaction")
        return result.llm_events
    # [BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if database:
        document = AgentSightCLI(executable).prompts_json(database)
        result = importer.parse(document, "demo-session")
        # [BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not result.llm_events:
            # [BESOIN B/C/D/E/P/T] Échec explicite : refuse une donnée ou un état ambigu au lieu de
            # produire une fausse preuve.
            raise RuntimeError("AgentSight prompts report has no LLM interaction")
        return result.llm_events
    document = {
        "session_id": "demo-session",
        "events": [
            {
                "type": "llm_call",
                "id": "agentsight-demo-llm-1",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "provider": "assessment-demo",
                "model": "deterministic-demo",
                "prompt": "Connect locally, write the report, and run rm --version.",
                "response": "Executing the requested validation workflow.",
                "duration_ms": 12,
            }
        ],
    }
    return importer.parse(document, "demo-session").llm_events


# [BESOIN B/C/D/E/P/T] Fonction `main` : orchestre le scénario exécutable, valide les préconditions et
# retourne un code de sortie explicite.
def main() -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--agentsight-json", type=Path, help="AgentSight JSON/JSONL export")
    source.add_argument("--agentsight-db", type=Path, help="AgentSight SQLite recording database")
    parser.add_argument("--agentsight-bin", default="agentsight", help="AgentSight executable")
    args = parser.parse_args()

    preflight = BPFEventCollector.preflight()
    # [BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if not preflight["ok"]:
        print(f"Live eBPF demo unavailable: {preflight['reason']}", file=sys.stderr)
        return 2

    artifacts = ROOT / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    report_path = artifacts / "demo-events.jsonl"
    output_path = artifacts / "demo-result.txt"
    report_path.unlink(missing_ok=True)
    output_path.unlink(missing_ok=True)

    _, port, server_thread = _listener()
    runtime = AgentSightRuntime(store=JsonlEventStore(report_path))
    service = LiveSensorService(runtime=runtime)
    process = None
    # [BESOIN B/C/D/E/P/T] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
    # explicite.
    try:
        process = service.start_command(
            [
                sys.executable,
                str(ROOT / "scripts" / "demo_agent.py"),
                "--port",
                str(port),
                "--output",
                str(output_path),
            ],
            session_id="demo-session",
            agent_name="demo-agent",
            llm_events=_llm_events(args.agentsight_json, args.agentsight_db, args.agentsight_bin),
            stdout=None,
            stderr=None,
        )
        return_code = process.wait(timeout=12)
        # [BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if return_code != 0:
            print(f"Demo agent exited with code {return_code}.", file=sys.stderr)
            return 6
        deadline = time.monotonic() + 5.0
        required_types = {
            "PROCESS_EXECUTION",
            "FILE_ACCESS",
            "FILE_WRITE",
            "FILE_DELETE",
            "NETWORK_CONNECTION",
            "PROCESS_EXIT",
            "AI_AGENT_SECURITY_EVENT",
        }
        session = runtime.sessions.snapshot_session("demo-session")
        # [BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
        # besoin.
        assert session is not None
        # [BESOIN B/C/D/E/P/T] Boucle contrôlée : maintient la collecte ou l’attente jusqu’à la
        # condition d’arrêt.
        while time.monotonic() < deadline:
            session = runtime.sessions.snapshot_session("demo-session")
            # [BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
            # le besoin.
            assert session is not None
            observed = {str(item.get("event_type")) for item in session.timeline.events}
            # [BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de poursuivre le
            # flux fonctionnel.
            if required_types.issubset(observed):
                break
            time.sleep(0.1)

        session = runtime.sessions.snapshot_session("demo-session")
        # [BESOIN B/C/D/E/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
        # besoin.
        assert session is not None
        observed = {str(item.get("event_type")) for item in session.timeline.events}
        missing = sorted(required_types - observed)
        # [BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if missing:
            print(f"Missing expected event types: {', '.join(missing)}", file=sys.stderr)
            return 3
        # [BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not any(alert.rule_name == "SENSITIVE_COMMAND_EXECUTION" for alert in session.security_events):
            print("The real rm execution did not generate the expected alert.", file=sys.stderr)
            return 4
        # [BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not output_path.exists() or not output_path.read_text(encoding="utf-8").startswith("AgentSight"):
            print("The demo file was not created correctly.", file=sys.stderr)
            return 5
        metrics = service.metrics()
        # [BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if metrics.get("service_error"):
            print(f"Sensor service error: {metrics['service_error']}", file=sys.stderr)
            return 7
        # [BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if int(metrics.get("kernel_ringbuf_drops", 0)) or int(
            metrics.get("userspace_queue_drops", 0)
        ):
            print("The demonstration observed event loss; inspect METRICS.", file=sys.stderr)
            return 8

        print("SESSION_SUMMARY", session.summary().model_dump_json())
        print("PROCESS_TREE", json.dumps(session.get_process_tree(), indent=2))
        print("TIMELINE", json.dumps(session.timeline.events, indent=2))
        print("METRICS", json.dumps(metrics, indent=2, sort_keys=True))
        print(f"JSONL_REPORT {report_path}")
        return 0
    finally:
        service.stop()
        server_thread.join(timeout=2)


# [BESOIN B/C/D/E/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
# fonctionnel.
if __name__ == "__main__":
    # [BESOIN B/C/D/E/P/T] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire une
    # fausse preuve.
    raise SystemExit(main())
