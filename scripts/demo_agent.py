#!/usr/bin/env python3
"""Harmless deterministic agent used by the privileged end-to-end demo."""
from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN D] Partie D - détection et explication des actions sensibles.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# [BESOIN T] Section 11 - démonstration reproductible, tests et livrables.
# Rôle du module : générer, sans danger, les actions OS réellement observées pendant la démonstration.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


import argparse
import shutil
import socket
import subprocess
import time
from pathlib import Path


# [BESOIN B/C/D/E/T] Fonction `main` : orchestre le scénario exécutable, valide les préconditions et
# retourne un code de sortie explicite.
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--delay", type=float, default=0.25)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    time.sleep(max(0.0, args.delay))

    # Harmless read of a path explicitly listed by the assessment.  The
    # content is not emitted by the sensor; only the OS-level access is.
    # [BESOIN B/C/D/E/T] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
    with Path("/etc/passwd").open("r", encoding="utf-8", errors="replace") as handle:
        handle.readline()

    # [BESOIN B/C/D/E/T] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
    with socket.create_connection((args.host, args.port), timeout=3) as connection:
        connection.sendall(b"agentsight-demo\n")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    # [BESOIN B/C/D/E/T] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
    with args.output.open("w", encoding="utf-8") as handle:
        handle.write("AgentSight eBPF assessment demo\n")
        handle.flush()

    # Exercise unlink detection without deleting user data.
    disposable = args.output.with_name(args.output.name + ".delete-me")
    disposable.write_text("temporary AgentSight demo file\n", encoding="utf-8")
    disposable.unlink()

    rm = shutil.which("rm")
    # [BESOIN B/C/D/E/T] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if not rm:
        # [BESOIN B/C/D/E/T] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
        # une fausse preuve.
        raise SystemExit("rm is unavailable")
    return subprocess.run(
        [rm, "--version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode


# [BESOIN B/C/D/E/T] Condition de garde : valide le cas courant avant de poursuivre le flux fonctionnel.
if __name__ == "__main__":
    # [BESOIN B/C/D/E/T] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire une
    # fausse preuve.
    raise SystemExit(main())
