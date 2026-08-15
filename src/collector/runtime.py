"""Thread-safe session correlation and end-to-end event processing."""
from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN D] Partie D - détection et explication des actions sensibles.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# Rôle du module : gérer les sessions, corréler les événements, déclencher la sécurité et persister l’audit.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from src.models import (
    AgentSession,
    BaseOSEvent,
    LLMInteractionEvent,
    ProcessExecutionEvent,
    ProcessExitEvent,
    SecurityEvent,
)
from src.storage import JsonlEventStore

from .security import SecurityEngine


# [BESOIN C/D/E/P] Classe `SessionManager` : classe dédiée à l’opération `SessionManager` dans le flux
# qui consiste à gérer les sessions, corréler les événements, déclencher la sécurité et
# persister l’audit.
class SessionManager:
    # [BESOIN C/D/E/P] Fonction `__init__` : initialise l’état interne et les dépendances nécessaires au
    # composant.
    def __init__(self):
        self.sessions: Dict[str, AgentSession] = {}
        self.pid_to_session: Dict[int, str] = {}
        self._lock = threading.RLock()

    # [BESOIN C/D/E/P] Fonction `create_session` : crée une Agent Session et enregistre l’identité
    # stable de son processus racine.
    def create_session(
        self,
        session_id: str,
        agent_name: str,
        initial_event: ProcessExecutionEvent,
    ) -> AgentSession:
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock:
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if session_id in self.sessions:
                # [BESOIN C/D/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
                # produire une fausse preuve.
                raise ValueError(f"session already exists: {session_id}")
            session = AgentSession(
                session_id=session_id,
                agent_name=agent_name,
                start_time=initial_event.timestamp,
                main_pid=initial_event.pid,
                main_ppid=initial_event.ppid,
                main_executable=initial_event.executable,
                main_command=initial_event.command,
            )
            session.add_os_event(initial_event)
            self.sessions[session_id] = session
            self.pid_to_session[initial_event.pid] = session_id
            return session

    # [BESOIN C/D/E/P] Fonction `get_session` : retrouve une session par son identifiant.
    def get_session(self, session_id: str) -> Optional[AgentSession]:
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock:
            return self.sessions.get(session_id)

    # [BESOIN C/D/E/P] Fonction `list_sessions` : liste les sessions connues du runtime.
    def list_sessions(self) -> List[AgentSession]:
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock:
            return list(self.sessions.values())

    # [BESOIN C/D/E/P] Fonction `snapshot_session` : retourne une copie cohérente d’une session pour
    # éviter les lectures concurrentes.
    def snapshot_session(self, session_id: str) -> Optional[AgentSession]:
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock:
            session = self.sessions.get(session_id)
            return session.model_copy(deep=True) if session else None

    # [BESOIN C/D/E/P] Fonction `snapshot_sessions` : retourne des copies cohérentes de toutes les
    # sessions.
    def snapshot_sessions(self) -> List[AgentSession]:
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock:
            return [session.model_copy(deep=True) for session in self.sessions.values()]

    # [BESOIN C/D/E/P] Fonction `get_active_sessions` : sélectionne les sessions encore actives.
    def get_active_sessions(self) -> List[AgentSession]:
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock:
            return [session for session in self.sessions.values() if session.is_active()]

    # [BESOIN C/D/E/P] Fonction `_identity_matches` : fonction dédiée à l’opération `_identity_matches`
    # dans le flux qui consiste à gérer les sessions, corréler les événements,
    # déclencher la sécurité et persister l’audit.
    @staticmethod
    def _identity_matches(session: AgentSession, event: BaseOSEvent) -> bool:
        identity = session.latest_process_by_pid.get(event.pid)
        node = session.processes.get(identity) if identity else None
        # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if node is None:
            return False
        # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not event.process_start_ns or not node.process_start_ns:
            return True
        return event.process_start_ns == node.process_start_ns

    # [BESOIN C/D/E/P] Fonction `resolve_for_event` : détermine à quelle session appartient un événement
    # à partir de l’identité et de la filiation du processus.
    def resolve_for_event(self, event: BaseOSEvent) -> Optional[AgentSession]:
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock:
            direct = self.pid_to_session.get(event.pid)
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if direct:
                session = self.sessions.get(direct)
                # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
                if session and self._identity_matches(session, event):
                    return session
            parent_session_id = self.pid_to_session.get(event.ppid)
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if not parent_session_id:
                return None
            parent_session = self.sessions.get(parent_session_id)
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if parent_session is None:
                return None
            parent_identity = parent_session.latest_process_by_pid.get(event.ppid)
            parent_node = (
                parent_session.processes.get(parent_identity) if parent_identity else None
            )
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if parent_node is None:
                return None
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if (
                event.parent_start_ns
                and parent_node.process_start_ns
                and event.parent_start_ns != parent_node.process_start_ns
            ):
                return None
            return parent_session

    # [BESOIN C/D/E/P] Fonction `add_event` : ajoute un événement OS à la session en évitant les
    # doublons.
    def add_event(self, session_id: str, event: BaseOSEvent) -> AgentSession:
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock:
            session = self.sessions.get(session_id)
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if session is None:
                # [BESOIN C/D/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
                # produire une fausse preuve.
                raise KeyError(session_id)
            added = session.add_os_event(event)
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if added and event.event_type.value in {"PROCESS_FORK", "PROCESS_EXECUTION"}:
                self.pid_to_session[event.pid] = session_id
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if added and isinstance(event, ProcessExitEvent):
                mapped = self.pid_to_session.get(event.pid)
                # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
                if mapped == session_id:
                    self.pid_to_session.pop(event.pid, None)
            return session

    # [BESOIN C/D/E/P] Fonction `add_llm_interaction` : ajoute l’interaction LLM et déclenche le
    # recalcul des corrélations pertinentes.
    def add_llm_interaction(
        self, event: LLMInteractionEvent
    ) -> tuple[AgentSession, bool]:
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock:
            session = self.sessions.get(event.session_id)
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if session is None:
                # [BESOIN C/D/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
                # produire une fausse preuve.
                raise KeyError(event.session_id)
            return session, session.add_llm_interaction(event)

    # [BESOIN C/D/E/P] Fonction `add_security_event` : attache une alerte explicable à la session et à
    # sa timeline.
    def add_security_event(
        self, session_id: str, event: SecurityEvent
    ) -> tuple[AgentSession, bool]:
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock:
            session = self.sessions.get(session_id)
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if session is None:
                # [BESOIN C/D/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
                # produire une fausse preuve.
                raise KeyError(session_id)
            return session, session.add_security_event(event)

    # [BESOIN C/D/E/P] Fonction `correlate_and_add_unique` : corrèle puis ajoute un événement seulement
    # s’il n’a pas déjà été observé.
    def correlate_and_add_unique(
        self, event: BaseOSEvent
    ) -> tuple[Optional[AgentSession], BaseOSEvent, bool]:
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock:
            session = self.resolve_for_event(event)
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if session is None:
                return None, event, False
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if session.timeline.contains(event.event_id):
                return session, event, False
            correlated = session.correlate_os_event(event)
            self.add_event(session.session_id, correlated)
            return session, correlated, True

    # [BESOIN C/D/E/P] Fonction `correlate_and_add` : corrèle un événement OS avec l’interaction LLM la
    # plus pertinente.
    def correlate_and_add(self, event: BaseOSEvent) -> tuple[Optional[AgentSession], BaseOSEvent]:
        session, correlated, _ = self.correlate_and_add_unique(event)
        return session, correlated

    # [BESOIN C/D/E/P] Fonction `end_session` : marque explicitement la fin de la session.
    def end_session(self, session_id: str, when: Optional[datetime] = None) -> AgentSession:
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._lock:
            session = self.sessions[session_id]
            session.mark_ended(when or datetime.now(timezone.utc))
            # [BESOIN C/D/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
            # traçable.
            for pid, mapped_session in list(self.pid_to_session.items()):
                # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
                if mapped_session == session_id:
                    del self.pid_to_session[pid]
            return session


# [BESOIN C/D/E/P] Classe `AgentSightRuntime` : classe dédiée à l’opération `AgentSightRuntime` dans le
# flux qui consiste à gérer les sessions, corréler les événements, déclencher la
# sécurité et persister l’audit.
class AgentSightRuntime:
    # [BESOIN C/D/E/P] Fonction `__init__` : initialise l’état interne et les dépendances nécessaires au
    # composant.
    def __init__(
        self,
        sessions: Optional[SessionManager] = None,
        security: Optional[SecurityEngine] = None,
        store: Optional[JsonlEventStore] = None,
    ):
        self.sessions = sessions or SessionManager()
        self.security = security or SecurityEngine()
        self.store = store
        self._metrics_lock = threading.RLock()
        self._persisted_records = 0
        self._persistence_errors = 0
        self._last_persistence_error: Optional[str] = None

    # [BESOIN C/D/E/P] Fonction `_persist_many` : fonction dédiée à l’opération `_persist_many` dans le
    # flux qui consiste à gérer les sessions, corréler les événements, déclencher la
    # sécurité et persister l’audit.
    def _persist_many(
        self,
        records: Iterable[tuple[str, str, Any]],
    ) -> None:
        # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if self.store is None:
            return
        pending = list(records)
        # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not pending:
            return
        # [BESOIN C/D/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            written = self.store.append_many(pending)
        except (OSError, TypeError, ValueError) as exc:
            # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture
            # déterministes.
            with self._metrics_lock:
                self._persistence_errors += 1
                self._last_persistence_error = f"{type(exc).__name__}: {exc}"
            return
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._metrics_lock:
            self._persisted_records += written
            self._last_persistence_error = None

    # [BESOIN C/D/E/P] Fonction `metrics` : expose les compteurs de fonctionnement, d’erreur et de perte
    # nécessaires à l’observabilité.
    def metrics(self) -> Dict[str, object]:
        # [BESOIN C/D/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._metrics_lock:
            return {
                "runtime_persisted_records": self._persisted_records,
                "runtime_persistence_errors": self._persistence_errors,
                "runtime_last_persistence_error": self._last_persistence_error,
            }

    # [BESOIN C/D/E/P] Fonction `create_session` : crée une Agent Session et enregistre l’identité
    # stable de son processus racine.
    def create_session(
        self,
        session_id: str,
        agent_name: str,
        root_event: ProcessExecutionEvent,
    ) -> AgentSession:
        session = self.sessions.create_session(session_id, agent_name, root_event)
        records: list[tuple[str, str, Any]] = [("os_event", session_id, root_event)]
        # The root process is an OS event too.  Analyze it immediately so an
        # assessment launched directly as `curl`, `sudo`, `rm`, etc. cannot
        # bypass the policy engine merely because it created the session.
        alert = self.security.analyze_event(root_event, session_id)
        # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if alert is not None:
            _, added = self.sessions.add_security_event(session_id, alert)
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if added:
                records.append(("security_event", session_id, alert))
        self._persist_many(records)
        return session

    # [BESOIN C/D/E/P] Fonction `record_llm_interaction_with_status` : implémente le comportement
    # documenté par sa docstring : « Record an LLM interaction and report whether it
    # was newly added ».
    def record_llm_interaction_with_status(
        self, event: LLMInteractionEvent
    ) -> tuple[AgentSession, bool]:
        """Record an LLM interaction and report whether it was newly added.

        AgentSight exports are commonly polled or re-imported. Returning the
        idempotency result lets API and integration callers distinguish source
        records seen from records actually accepted into the session timeline.
        """
        session, added = self.sessions.add_llm_interaction(event)
        # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if added:
            self._persist_many([("llm_interaction", event.session_id, event)])
        return session, added

    # [BESOIN C/D/E/P] Fonction `record_llm_interaction` : fonction dédiée à l’opération
    # `record_llm_interaction` dans le flux qui consiste à gérer les sessions, corréler
    # les événements, déclencher la sécurité et persister l’audit.
    def record_llm_interaction(self, event: LLMInteractionEvent) -> AgentSession:
        session, _ = self.record_llm_interaction_with_status(event)
        return session

    # [BESOIN C/D/E/P] Fonction `ingest_with_status` : ingère un événement, résout sa session, applique
    # les règles et renvoie le statut détaillé.
    def ingest_with_status(
        self, event: BaseOSEvent
    ) -> tuple[Optional[AgentSession], Optional[SecurityEvent], bool]:
        """Ingest one OS event and expose matching/idempotency status."""
        session, correlated_event, added = self.sessions.correlate_and_add_unique(event)
        # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if session is None:
            return None, None, False
        # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not added:
            return session, None, False
        alert = self.security.analyze_event(correlated_event, session.session_id)
        records: list[tuple[str, str, Any]] = [
            ("os_event", session.session_id, correlated_event)
        ]
        # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if alert is not None:
            _, alert_added = self.sessions.add_security_event(session.session_id, alert)
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if alert_added:
                records.append(("security_event", session.session_id, alert))
            else:
                alert = None
        self._persist_many(records)
        return session, alert, True

    # [BESOIN C/D/E/P] Fonction `ingest` : ingère un événement dans le pipeline runtime.
    def ingest(self, event: BaseOSEvent) -> tuple[Optional[AgentSession], Optional[SecurityEvent]]:
        session, alert, _ = self.ingest_with_status(event)
        return session, alert

    # [BESOIN C/D/E/P] Fonction `ingest_many` : traite un lot d’événements pour réduire le coût de
    # persistance et de verrouillage.
    def ingest_many(self, events: Iterable[BaseOSEvent]) -> list[SecurityEvent]:
        alerts: list[SecurityEvent] = []
        # [BESOIN C/D/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for event in events:
            _, alert = self.ingest(event)
            # [BESOIN C/D/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if alert:
                alerts.append(alert)
        return alerts
