"""Thread-safe session correlation and end-to-end event processing."""
from __future__ import annotations

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


class SessionManager:
    def __init__(self):
        self.sessions: Dict[str, AgentSession] = {}
        self.pid_to_session: Dict[int, str] = {}
        self._lock = threading.RLock()

    def create_session(
        self,
        session_id: str,
        agent_name: str,
        initial_event: ProcessExecutionEvent,
    ) -> AgentSession:
        with self._lock:
            if session_id in self.sessions:
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

    def get_session(self, session_id: str) -> Optional[AgentSession]:
        with self._lock:
            return self.sessions.get(session_id)

    def list_sessions(self) -> List[AgentSession]:
        with self._lock:
            return list(self.sessions.values())

    def snapshot_session(self, session_id: str) -> Optional[AgentSession]:
        with self._lock:
            session = self.sessions.get(session_id)
            return session.model_copy(deep=True) if session else None

    def snapshot_sessions(self) -> List[AgentSession]:
        with self._lock:
            return [session.model_copy(deep=True) for session in self.sessions.values()]

    def get_active_sessions(self) -> List[AgentSession]:
        with self._lock:
            return [session for session in self.sessions.values() if session.is_active()]

    @staticmethod
    def _identity_matches(session: AgentSession, event: BaseOSEvent) -> bool:
        identity = session.latest_process_by_pid.get(event.pid)
        node = session.processes.get(identity) if identity else None
        if node is None:
            return False
        if not event.process_start_ns or not node.process_start_ns:
            return True
        return event.process_start_ns == node.process_start_ns

    def resolve_for_event(self, event: BaseOSEvent) -> Optional[AgentSession]:
        with self._lock:
            direct = self.pid_to_session.get(event.pid)
            if direct:
                session = self.sessions.get(direct)
                if session and self._identity_matches(session, event):
                    return session
            parent_session_id = self.pid_to_session.get(event.ppid)
            if not parent_session_id:
                return None
            parent_session = self.sessions.get(parent_session_id)
            if parent_session is None:
                return None
            parent_identity = parent_session.latest_process_by_pid.get(event.ppid)
            parent_node = (
                parent_session.processes.get(parent_identity) if parent_identity else None
            )
            if parent_node is None:
                return None
            if (
                event.parent_start_ns
                and parent_node.process_start_ns
                and event.parent_start_ns != parent_node.process_start_ns
            ):
                return None
            return parent_session

    def add_event(self, session_id: str, event: BaseOSEvent) -> AgentSession:
        with self._lock:
            session = self.sessions.get(session_id)
            if session is None:
                raise KeyError(session_id)
            added = session.add_os_event(event)
            if added and event.event_type.value in {"PROCESS_FORK", "PROCESS_EXECUTION"}:
                self.pid_to_session[event.pid] = session_id
            if added and isinstance(event, ProcessExitEvent):
                mapped = self.pid_to_session.get(event.pid)
                if mapped == session_id:
                    self.pid_to_session.pop(event.pid, None)
            return session

    def add_llm_interaction(
        self, event: LLMInteractionEvent
    ) -> tuple[AgentSession, bool]:
        with self._lock:
            session = self.sessions.get(event.session_id)
            if session is None:
                raise KeyError(event.session_id)
            return session, session.add_llm_interaction(event)

    def add_security_event(
        self, session_id: str, event: SecurityEvent
    ) -> tuple[AgentSession, bool]:
        with self._lock:
            session = self.sessions.get(session_id)
            if session is None:
                raise KeyError(session_id)
            return session, session.add_security_event(event)

    def correlate_and_add_unique(
        self, event: BaseOSEvent
    ) -> tuple[Optional[AgentSession], BaseOSEvent, bool]:
        with self._lock:
            session = self.resolve_for_event(event)
            if session is None:
                return None, event, False
            if session.timeline.contains(event.event_id):
                return session, event, False
            correlated = session.correlate_os_event(event)
            self.add_event(session.session_id, correlated)
            return session, correlated, True

    def correlate_and_add(self, event: BaseOSEvent) -> tuple[Optional[AgentSession], BaseOSEvent]:
        session, correlated, _ = self.correlate_and_add_unique(event)
        return session, correlated

    def end_session(self, session_id: str, when: Optional[datetime] = None) -> AgentSession:
        with self._lock:
            session = self.sessions[session_id]
            session.mark_ended(when or datetime.now(timezone.utc))
            for pid, mapped_session in list(self.pid_to_session.items()):
                if mapped_session == session_id:
                    del self.pid_to_session[pid]
            return session


class AgentSightRuntime:
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

    def _persist_many(
        self,
        records: Iterable[tuple[str, str, Any]],
    ) -> None:
        if self.store is None:
            return
        pending = list(records)
        if not pending:
            return
        try:
            written = self.store.append_many(pending)
        except (OSError, TypeError, ValueError) as exc:
            with self._metrics_lock:
                self._persistence_errors += 1
                self._last_persistence_error = f"{type(exc).__name__}: {exc}"
            return
        with self._metrics_lock:
            self._persisted_records += written
            self._last_persistence_error = None

    def metrics(self) -> Dict[str, object]:
        with self._metrics_lock:
            return {
                "runtime_persisted_records": self._persisted_records,
                "runtime_persistence_errors": self._persistence_errors,
                "runtime_last_persistence_error": self._last_persistence_error,
            }

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
        if alert is not None:
            _, added = self.sessions.add_security_event(session_id, alert)
            if added:
                records.append(("security_event", session_id, alert))
        self._persist_many(records)
        return session

    def record_llm_interaction_with_status(
        self, event: LLMInteractionEvent
    ) -> tuple[AgentSession, bool]:
        """Record an LLM interaction and report whether it was newly added.

        AgentSight exports are commonly polled or re-imported. Returning the
        idempotency result lets API and integration callers distinguish source
        records seen from records actually accepted into the session timeline.
        """
        session, added = self.sessions.add_llm_interaction(event)
        if added:
            self._persist_many([("llm_interaction", event.session_id, event)])
        return session, added

    def record_llm_interaction(self, event: LLMInteractionEvent) -> AgentSession:
        session, _ = self.record_llm_interaction_with_status(event)
        return session

    def ingest_with_status(
        self, event: BaseOSEvent
    ) -> tuple[Optional[AgentSession], Optional[SecurityEvent], bool]:
        """Ingest one OS event and expose matching/idempotency status."""
        session, correlated_event, added = self.sessions.correlate_and_add_unique(event)
        if session is None:
            return None, None, False
        if not added:
            return session, None, False
        alert = self.security.analyze_event(correlated_event, session.session_id)
        records: list[tuple[str, str, Any]] = [
            ("os_event", session.session_id, correlated_event)
        ]
        if alert is not None:
            _, alert_added = self.sessions.add_security_event(session.session_id, alert)
            if alert_added:
                records.append(("security_event", session.session_id, alert))
            else:
                alert = None
        self._persist_many(records)
        return session, alert, True

    def ingest(self, event: BaseOSEvent) -> tuple[Optional[AgentSession], Optional[SecurityEvent]]:
        session, alert, _ = self.ingest_with_status(event)
        return session, alert

    def ingest_many(self, events: Iterable[BaseOSEvent]) -> list[SecurityEvent]:
        alerts: list[SecurityEvent] = []
        for event in events:
            _, alert = self.ingest(event)
            if alert:
                alerts.append(alert)
        return alerts
