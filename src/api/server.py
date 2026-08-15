"""FastAPI backend required by the technical assessment."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.collector.runtime import AgentSightRuntime, SessionManager
from src.integrations import AgentSightImporter, AgentSightIntegrationError
from src.models import EventSeverity, EventType, LLMInteractionEvent


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _payload_time(payload: Dict[str, Any]) -> datetime:
    raw = payload.get("timestamp")
    if isinstance(raw, datetime):
        return _aware(raw) or datetime.min.replace(tzinfo=timezone.utc)
    if isinstance(raw, str):
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except (TypeError, ValueError, OverflowError):
            return datetime.min.replace(tzinfo=timezone.utc)
        return _aware(parsed) or datetime.min.replace(tzinfo=timezone.utc)
    return datetime.min.replace(tzinfo=timezone.utc)


class LLMInteractionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: Optional[datetime] = None
    request_id: Optional[str] = None
    pid: Optional[int] = Field(default=None, ge=0)
    llm_provider: str = "unknown"
    model: str = "unknown"
    prompt: str = Field(min_length=1)
    response: Optional[str] = None
    duration_ms: Optional[int] = Field(default=None, ge=0)
    source: str = "agentsight-api"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentSightDocumentRequest(BaseModel):
    document: Any


class AgentSightAPI:
    def __init__(
        self,
        runtime: AgentSightRuntime,
        metrics_provider: Optional[Callable[[], Dict[str, Any]]] = None,
    ):
        self.runtime = runtime
        self.sessions = runtime.sessions
        self.metrics_provider = metrics_provider
        self.importer = AgentSightImporter()
        self.app = FastAPI(title="AgentSight OS-Level Sensor", version="2.1.0")
        self._routes()

    def _session_or_404(self, session_id: str):
        session = self.sessions.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="Session not found")
        return session

    def _session_snapshot_or_404(self, session_id: str):
        session = self.sessions.snapshot_session(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="Session not found")
        return session

    def _routes(self) -> None:
        @self.app.get("/health")
        async def health() -> Dict[str, Any]:
            sensor = self.metrics_provider() if self.metrics_provider else {}
            reasons: list[str] = []
            if sensor.get("service_error"):
                reasons.append(str(sensor["service_error"]))
            if int(sensor.get("kernel_ringbuf_drops", 0) or 0) > 0:
                reasons.append("kernel ring-buffer drops observed")
            if int(sensor.get("userspace_queue_drops", 0) or 0) > 0:
                reasons.append("userspace queue drops observed")
            if int(sensor.get("runtime_persistence_errors", 0) or 0) > 0:
                reasons.append("persistence errors observed")
            return {
                "status": "degraded" if reasons else "ok",
                "active_sessions": len(self.sessions.get_active_sessions()),
                "sensor_running": bool(sensor.get("collector_running", 0)),
                "error": sensor.get("service_error"),
                "degraded_reasons": reasons,
            }

        @self.app.get("/agents")
        async def agents() -> Dict[str, Any]:
            items = [
                session.summary().model_dump(mode="json")
                for session in self.sessions.snapshot_sessions()
            ]
            items.sort(key=lambda item: item["session_id"])
            return {"total": len(items), "agents": items}

        @self.app.get("/agents/{session_id}")
        async def agent(session_id: str) -> Dict[str, Any]:
            return self._session_snapshot_or_404(session_id).model_dump(mode="json")

        @self.app.get("/agents/{session_id}/timeline")
        async def timeline(
            session_id: str,
            limit: int = Query(100, ge=1, le=5000),
            offset: int = Query(0, ge=0),
        ) -> Dict[str, Any]:
            session = self._session_snapshot_or_404(session_id)
            events = list(session.timeline.events)
            return {
                "session_id": session_id,
                "total": len(events),
                "offset": offset,
                "limit": limit,
                "events": events[offset : offset + limit],
            }

        @self.app.get("/agents/{session_id}/processes")
        async def processes(session_id: str) -> Dict[str, Any]:
            session = self._session_snapshot_or_404(session_id)
            flat_processes = [
                process.model_dump(mode="json")
                for process in sorted(
                    session.processes.values(),
                    key=lambda item: (item.first_seen, item.pid, item.generation),
                )
            ]
            return {
                "session_id": session_id,
                "total": len(flat_processes),
                "processes": flat_processes,
                "process_tree": session.get_process_tree(),
            }

        @self.app.get("/agents/{session_id}/security-events")
        async def security_events(
            session_id: str,
            severity: Optional[str] = Query(None),
        ) -> Dict[str, Any]:
            session = self._session_snapshot_or_404(session_id)
            selected = list(session.security_events)
            if severity:
                try:
                    expected = EventSeverity(severity.upper())
                except ValueError as exc:
                    raise HTTPException(status_code=400, detail="Invalid severity") from exc
                selected = [event for event in selected if event.severity == expected]
            return {
                "session_id": session_id,
                "total": len(selected),
                "events": [event.model_dump(mode="json") for event in selected],
            }

        @self.app.get("/agents/{session_id}/correlations")
        async def correlations(session_id: str) -> Dict[str, Any]:
            session = self._session_snapshot_or_404(session_id)
            events = [
                payload
                for payload in session.timeline.events
                if payload.get("correlation") is not None
            ]
            return {"session_id": session_id, "total": len(events), "events": events}

        @self.app.post("/agents/{session_id}/llm-interactions", status_code=201)
        async def add_llm_interaction(
            session_id: str,
            request: LLMInteractionRequest,
        ) -> Dict[str, Any]:
            self._session_or_404(session_id)
            values = request.model_dump(exclude={"timestamp"})
            event = LLMInteractionEvent(
                timestamp=request.timestamp or datetime.now(timezone.utc),
                session_id=session_id,
                **values,
            )
            self.runtime.record_llm_interaction(event)
            return event.model_dump(mode="json")

        @self.app.post("/agents/{session_id}/imports/agentsight", status_code=202)
        async def import_agentsight(
            session_id: str,
            request: AgentSightDocumentRequest,
        ) -> Dict[str, Any]:
            self._session_or_404(session_id)
            try:
                result = self.importer.parse(request.document, session_id)
            except (AgentSightIntegrationError, TypeError, ValueError) as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if result.total_events == 0:
                raise HTTPException(
                    status_code=422,
                    detail="AgentSight document contained no recognized LLM or OS events",
                )
            accepted_llm_events = 0
            deduplicated_llm_events = 0
            for event in result.llm_events:
                _, added = self.runtime.record_llm_interaction_with_status(
                    event.model_copy(update={"session_id": session_id})
                )
                if added:
                    accepted_llm_events += 1
                else:
                    deduplicated_llm_events += 1
            accepted_os_events = 0
            deduplicated_os_events = 0
            unmatched_os_events = 0
            alerts = []
            for event in result.os_events:
                matched_session, alert, added = self.runtime.ingest_with_status(event)
                if matched_session is None:
                    unmatched_os_events += 1
                    continue
                if added:
                    accepted_os_events += 1
                else:
                    deduplicated_os_events += 1
                if alert is not None:
                    alerts.append(alert)
            return {
                "session_id": session_id,
                "llm_events": len(result.llm_events),
                "accepted_llm_events": accepted_llm_events,
                "deduplicated_llm_events": deduplicated_llm_events,
                "os_events": len(result.os_events),
                "accepted_os_events": accepted_os_events,
                "deduplicated_os_events": deduplicated_os_events,
                "unmatched_os_events": unmatched_os_events,
                "security_events": len(alerts),
                "ignored_records": result.ignored_records,
                "warnings": result.warnings,
            }

        @self.app.get("/events")
        async def events(
            pid: Optional[int] = Query(None, ge=0),
            severity: Optional[str] = Query(None),
            event_type: Optional[str] = Query(None),
            from_time: Optional[datetime] = Query(None, alias="from"),
            to_time: Optional[datetime] = Query(None, alias="to"),
            query: Optional[str] = Query(None),
            limit: int = Query(100, ge=1, le=5000),
            offset: int = Query(0, ge=0),
        ) -> Dict[str, Any]:
            expected_severity: Optional[EventSeverity] = None
            if severity:
                try:
                    expected_severity = EventSeverity(severity.upper())
                except ValueError as exc:
                    raise HTTPException(status_code=400, detail="Invalid severity") from exc

            start = _aware(from_time)
            end = _aware(to_time)
            if start and end and start > end:
                raise HTTPException(
                    status_code=400,
                    detail="'from' must be earlier than or equal to 'to'",
                )
            text = query.casefold().strip() if query else ""
            expected_type: Optional[str] = None
            if event_type:
                try:
                    expected_type = EventType(event_type.upper()).value
                except ValueError as exc:
                    raise HTTPException(status_code=400, detail="Invalid event_type") from exc
            matches = []

            for session in self.sessions.snapshot_sessions():
                for payload in list(session.timeline.events):
                    payload_pid = payload.get("pid")
                    if pid is not None and (payload_pid is None or int(payload_pid) != pid):
                        continue
                    payload_severity = payload.get("severity")
                    if expected_severity and payload_severity != expected_severity.value:
                        continue
                    payload_type = str(payload.get("event_type", "")).upper()
                    if expected_type and payload_type != expected_type:
                        continue
                    timestamp = _payload_time(payload)
                    if start and timestamp < start:
                        continue
                    if end and timestamp > end:
                        continue
                    if text and text not in str(payload).casefold():
                        continue
                    matches.append({"session_id": session.session_id, **payload})

            matches.sort(key=_payload_time, reverse=True)
            return {
                "total_matches": len(matches),
                "offset": offset,
                "limit": limit,
                "events": matches[offset : offset + limit],
            }

        @self.app.get("/metrics")
        async def metrics() -> Dict[str, Any]:
            sensor = self.metrics_provider() if self.metrics_provider else {}
            return {
                "sessions": len(self.sessions.list_sessions()),
                "active_sessions": len(self.sessions.get_active_sessions()),
                "sensor": sensor,
            }


def create_api(
    sessions: Optional[SessionManager] = None,
    metrics_provider: Optional[Callable[[], Dict[str, Any]]] = None,
    runtime: Optional[AgentSightRuntime] = None,
) -> FastAPI:
    if runtime is None:
        runtime = AgentSightRuntime(sessions=sessions or SessionManager())
    return AgentSightAPI(runtime, metrics_provider).app
