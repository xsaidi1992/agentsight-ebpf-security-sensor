"""Thread-safe append-only JSONL persistence for sensor output."""
from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN A] Partie A - architecture AgentSight et chaîne Linux kernel vers collecteur userspace.
# [BESOIN F] Partie F - exposition des données par l’API backend.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# Rôle du module : persister de façon thread-safe les événements, corrélations et alertes au format JSONL.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable

from pydantic import BaseModel


# [BESOIN A/F/P] Classe `JsonlEventStore` : implémente le comportement documenté par sa docstring : «
# Small append-only store used by the assessment runtime ».
class JsonlEventStore:
    """Small append-only store used by the assessment runtime.

    The lock protects readers from observing a partially written batch inside
    this process. ``durable=True`` additionally calls ``fsync`` after every
    batch for crash-sensitive demonstrations; the default favors throughput.
    """

    # [BESOIN A/F/P] Constante `SCHEMA_VERSION` : fixe un paramètre stable et auditable utilisé par ce
    # module.
    SCHEMA_VERSION = 1

    # [BESOIN A/F/P] Fonction `__init__` : initialise l’état interne et les dépendances nécessaires au
    # composant.
    def __init__(self, path: Path | str, *, durable: bool = False):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.durable = durable
        self._lock = threading.RLock()

    # [BESOIN A/F/P] Fonction `_body` : fonction dédiée à l’opération `_body` dans le flux qui consiste
    # à persister de façon thread-safe les événements, corrélations et alertes au format
    # JSONL.
    @staticmethod
    def _body(payload: BaseModel | Dict[str, Any]) -> Dict[str, Any]:
        # [BESOIN A/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if isinstance(payload, BaseModel):
            return payload.model_dump(mode="json")
        return dict(payload)

    # [BESOIN A/F/P] Fonction `_validate_label` : fonction dédiée à l’opération `_validate_label` dans
    # le flux qui consiste à persister de façon thread-safe les événements, corrélations
    # et alertes au format JSONL.
    @staticmethod
    def _validate_label(name: str, value: str) -> str:
        normalized = str(value).strip()
        # [BESOIN A/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not normalized:
            # [BESOIN A/F/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError(f"{name} must not be empty")
        return normalized

    # [BESOIN A/F/P] Fonction `append` : persiste un seul enregistrement en réutilisant le chemin batch.
    def append(
        self,
        record_type: str,
        session_id: str,
        payload: BaseModel | Dict[str, Any],
    ) -> None:
        self.append_many([(record_type, session_id, payload)])

    # [BESOIN A/F/P] Fonction `append_many` : sérialise puis écrit atomiquement un lot d’enregistrements
    # JSONL.
    def append_many(
        self,
        records: Iterable[tuple[str, str, BaseModel | Dict[str, Any]]],
    ) -> int:
        encoded: list[str] = []
        persisted_at = datetime.now(timezone.utc).isoformat()
        # [BESOIN A/F/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for record_type, session_id, payload in records:
            record = {
                "schema_version": self.SCHEMA_VERSION,
                "persisted_at": persisted_at,
                "record_type": self._validate_label("record_type", record_type),
                "session_id": self._validate_label("session_id", session_id),
                "payload": self._body(payload),
            }
            encoded.append(
                json.dumps(
                    record,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        # [BESOIN A/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not encoded:
            return 0

        # [BESOIN A/F/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(encoded))
            handle.write("\n")
            handle.flush()
            # [BESOIN A/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if self.durable:
                os.fsync(handle.fileno())
        return len(encoded)

    # [BESOIN A/F/P] Fonction `read_all` : relit et valide chaque enregistrement JSONL persistant.
    def read_all(self) -> list[Dict[str, Any]]:
        # [BESOIN A/F/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock:
            # [BESOIN A/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if not self.path.exists():
                return []
            records: list[Dict[str, Any]] = []
            # [BESOIN A/F/P] Gestion de ressource : garantit une ouverture et une fermeture
            # déterministes.
            with self.path.open("r", encoding="utf-8") as handle:
                # [BESOIN A/F/P] Boucle de traitement : parcourt chaque élément de manière déterministe
                # et traçable.
                for line_number, line in enumerate(handle, start=1):
                    # [BESOIN A/F/P] Condition de garde : valide le cas courant avant de poursuivre le
                    # flux fonctionnel.
                    if not line.strip():
                        continue
                    # [BESOIN A/F/P] Gestion d’erreur : isole les dépendances externes et conserve un
                    # diagnostic explicite.
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError as exc:
                        # [BESOIN A/F/P] Échec explicite : refuse une donnée ou un état ambigu au lieu
                        # de produire une fausse preuve.
                        raise ValueError(
                            f"invalid JSONL record at {self.path}:{line_number}: {exc.msg}"
                        ) from exc
                    # [BESOIN A/F/P] Condition de garde : valide le cas courant avant de poursuivre le
                    # flux fonctionnel.
                    if not isinstance(value, dict):
                        # [BESOIN A/F/P] Échec explicite : refuse une donnée ou un état ambigu au lieu
                        # de produire une fausse preuve.
                        raise ValueError(
                            f"invalid JSONL record at {self.path}:{line_number}: expected object"
                        )
                    records.append(value)
            return records
