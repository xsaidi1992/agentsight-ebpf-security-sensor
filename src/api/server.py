"""FastAPI backend required by the technical assessment."""
from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN D] Partie D - détection et explication des actions sensibles.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# [BESOIN F] Partie F - exposition des données par l’API backend.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# Rôle du module : implémenter les endpoints permettant d’inspecter sessions, timelines, alertes, événements et métriques.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.collector.runtime import AgentSightRuntime, SessionManager
from src.integrations import AgentSightImporter, AgentSightIntegrationError
from src.models import EventSeverity, EventType, LLMInteractionEvent


# [BESOIN C/D/E/F/P] Fonction `_aware` : fonction dédiée à l’opération `_aware` dans le flux qui
# consiste à implémenter les endpoints permettant d’inspecter sessions, timelines,
# alertes, événements et métriques.
def _aware(value: Optional[datetime]) -> Optional[datetime]:
    # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if value is None:
        return None
    # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# [BESOIN C/D/E/F/P] Fonction `_payload_time` : fonction dédiée à l’opération `_payload_time` dans le
# flux qui consiste à implémenter les endpoints permettant d’inspecter sessions,
# timelines, alertes, événements et métriques.
def _payload_time(payload: Dict[str, Any]) -> datetime:
    raw = payload.get("timestamp")
    # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if isinstance(raw, datetime):
        return _aware(raw) or datetime.min.replace(tzinfo=timezone.utc)
    # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if isinstance(raw, str):
        # [BESOIN C/D/E/F/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except (TypeError, ValueError, OverflowError):
            return datetime.min.replace(tzinfo=timezone.utc)
        return _aware(parsed) or datetime.min.replace(tzinfo=timezone.utc)
    return datetime.min.replace(tzinfo=timezone.utc)


# [BESOIN C/D/E/F/P] Classe `LLMInteractionRequest` : classe dédiée à l’opération
# `LLMInteractionRequest` dans le flux qui consiste à implémenter les endpoints
# permettant d’inspecter sessions, timelines, alertes, événements et métriques.
class LLMInteractionRequest(BaseModel):
    # [BESOIN C/D/E/F/P] Attribut `model_config` : porte une donnée nécessaire au rôle du composant.
    model_config = ConfigDict(extra="forbid")

    # [BESOIN C/D/E/F/P] Champ `timestamp` : horodatage UTC normalisé de l’événement.
    timestamp: Optional[datetime] = None
    # [BESOIN C/D/E/F/P] Attribut `request_id` : porte une donnée nécessaire au rôle du composant.
    request_id: Optional[str] = None
    # [BESOIN C/D/E/F/P] Champ `pid` : PID du processus réellement observé, utilisé pour les filtres et
    # le rattachement de session.
    pid: Optional[int] = Field(default=None, ge=0)
    # [BESOIN C/D/E/F/P] Attribut `llm_provider` : porte une donnée nécessaire au rôle du composant.
    llm_provider: str = "unknown"
    # [BESOIN C/D/E/F/P] Attribut `model` : porte une donnée nécessaire au rôle du composant.
    model: str = "unknown"
    # [BESOIN C/D/E/F/P] Attribut `prompt` : porte une donnée nécessaire au rôle du composant.
    prompt: str = Field(min_length=1)
    # [BESOIN C/D/E/F/P] Attribut `response` : porte une donnée nécessaire au rôle du composant.
    response: Optional[str] = None
    # [BESOIN C/D/E/F/P] Attribut `duration_ms` : porte une donnée nécessaire au rôle du composant.
    duration_ms: Optional[int] = Field(default=None, ge=0)
    # [BESOIN C/D/E/F/P] Attribut `source` : porte une donnée nécessaire au rôle du composant.
    source: str = "agentsight-api"
    # [BESOIN C/D/E/F/P] Champ `metadata` : métadonnées source conservées sans modifier le contrat
    # principal.
    metadata: Dict[str, Any] = Field(default_factory=dict)


# [BESOIN C/D/E/F/P] Classe `AgentSightDocumentRequest` : classe dédiée à l’opération
# `AgentSightDocumentRequest` dans le flux qui consiste à implémenter les endpoints
# permettant d’inspecter sessions, timelines, alertes, événements et métriques.
class AgentSightDocumentRequest(BaseModel):
    # [BESOIN C/D/E/F/P] Attribut `document` : porte une donnée nécessaire au rôle du composant.
    document: Any


# [BESOIN C/D/E/F/P] Classe `AgentSightAPI` : classe dédiée à l’opération `AgentSightAPI` dans le flux
# qui consiste à implémenter les endpoints permettant d’inspecter sessions,
# timelines, alertes, événements et métriques.
class AgentSightAPI:
    # [BESOIN C/D/E/F/P] Fonction `__init__` : initialise l’état interne et les dépendances nécessaires
    # au composant.
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

    # [BESOIN C/D/E/F/P] Fonction `_session_or_404` : fonction dédiée à l’opération `_session_or_404`
    # dans le flux qui consiste à implémenter les endpoints permettant d’inspecter
    # sessions, timelines, alertes, événements et métriques.
    def _session_or_404(self, session_id: str):
        session = self.sessions.get_session(session_id)
        # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if session is None:
            # [BESOIN C/D/E/F/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
            # produire une fausse preuve.
            raise HTTPException(status_code=404, detail="Session not found")
        return session

    # [BESOIN C/D/E/F/P] Fonction `_session_snapshot_or_404` : fonction dédiée à l’opération
    # `_session_snapshot_or_404` dans le flux qui consiste à implémenter les
    # endpoints permettant d’inspecter sessions, timelines, alertes, événements et
    # métriques.
    def _session_snapshot_or_404(self, session_id: str):
        session = self.sessions.snapshot_session(session_id)
        # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if session is None:
            # [BESOIN C/D/E/F/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
            # produire une fausse preuve.
            raise HTTPException(status_code=404, detail="Session not found")
        return session

    # [BESOIN C/D/E/F/P] Fonction `_routes` : fonction dédiée à l’opération `_routes` dans le flux qui
    # consiste à implémenter les endpoints permettant d’inspecter sessions,
    # timelines, alertes, événements et métriques.
    def _routes(self) -> None:
        # [BESOIN C/D/E/F/P] Route/fonction asynchrone `health` : fonction dédiée à l’opération `health`
        # dans le flux qui consiste à implémenter les endpoints permettant
        # d’inspecter sessions, timelines, alertes, événements et métriques.
        @self.app.get("/health")
        async def health() -> Dict[str, Any]:
            sensor = self.metrics_provider() if self.metrics_provider else {}
            reasons: list[str] = []
            # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if sensor.get("service_error"):
                reasons.append(str(sensor["service_error"]))
            # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if int(sensor.get("kernel_ringbuf_drops", 0) or 0) > 0:
                reasons.append("kernel ring-buffer drops observed")
            # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if int(sensor.get("userspace_queue_drops", 0) or 0) > 0:
                reasons.append("userspace queue drops observed")
            # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if int(sensor.get("runtime_persistence_errors", 0) or 0) > 0:
                reasons.append("persistence errors observed")
            return {
                "status": "degraded" if reasons else "ok",
                "active_sessions": len(self.sessions.get_active_sessions()),
                "sensor_running": bool(sensor.get("collector_running", 0)),
                "error": sensor.get("service_error"),
                "degraded_reasons": reasons,
            }

        # [BESOIN C/D/E/F/P] Route/fonction asynchrone `agents` : fonction dédiée à l’opération `agents`
        # dans le flux qui consiste à implémenter les endpoints permettant
        # d’inspecter sessions, timelines, alertes, événements et métriques.
        @self.app.get("/agents")
        async def agents() -> Dict[str, Any]:
            items = [
                session.summary().model_dump(mode="json")
                for session in self.sessions.snapshot_sessions()
            ]
            items.sort(key=lambda item: item["session_id"])
            return {"total": len(items), "agents": items}

        # [BESOIN C/D/E/F/P] Route/fonction asynchrone `agent` : fonction dédiée à l’opération `agent`
        # dans le flux qui consiste à implémenter les endpoints permettant
        # d’inspecter sessions, timelines, alertes, événements et métriques.
        @self.app.get("/agents/{session_id}")
        async def agent(session_id: str) -> Dict[str, Any]:
            return self._session_snapshot_or_404(session_id).model_dump(mode="json")

        # [BESOIN C/D/E/F/P] Route/fonction asynchrone `timeline` : fonction dédiée à l’opération
        # `timeline` dans le flux qui consiste à implémenter les endpoints permettant
        # d’inspecter sessions, timelines, alertes, événements et métriques.
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

        # [BESOIN C/D/E/F/P] Route/fonction asynchrone `processes` : fonction dédiée à l’opération
        # `processes` dans le flux qui consiste à implémenter les endpoints
        # permettant d’inspecter sessions, timelines, alertes, événements et
        # métriques.
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

        # [BESOIN C/D/E/F/P] Route/fonction asynchrone `security_events` : fonction dédiée à l’opération
        # `security_events` dans le flux qui consiste à implémenter les endpoints
        # permettant d’inspecter sessions, timelines, alertes, événements et
        # métriques.
        @self.app.get("/agents/{session_id}/security-events")
        async def security_events(
            session_id: str,
            severity: Optional[str] = Query(None),
        ) -> Dict[str, Any]:
            session = self._session_snapshot_or_404(session_id)
            selected = list(session.security_events)
            # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if severity:
                # [BESOIN C/D/E/F/P] Gestion d’erreur : isole les dépendances externes et conserve un
                # diagnostic explicite.
                try:
                    expected = EventSeverity(severity.upper())
                except ValueError as exc:
                    # [BESOIN C/D/E/F/P] Échec explicite : refuse une donnée ou un état ambigu au lieu
                    # de produire une fausse preuve.
                    raise HTTPException(status_code=400, detail="Invalid severity") from exc
                selected = [event for event in selected if event.severity == expected]
            return {
                "session_id": session_id,
                "total": len(selected),
                "events": [event.model_dump(mode="json") for event in selected],
            }

        # [BESOIN C/D/E/F/P] Route/fonction asynchrone `correlations` : fonction dédiée à l’opération
        # `correlations` dans le flux qui consiste à implémenter les endpoints
        # permettant d’inspecter sessions, timelines, alertes, événements et
        # métriques.
        @self.app.get("/agents/{session_id}/correlations")
        async def correlations(session_id: str) -> Dict[str, Any]:
            session = self._session_snapshot_or_404(session_id)
            events = [
                payload
                for payload in session.timeline.events
                if payload.get("correlation") is not None
            ]
            return {"session_id": session_id, "total": len(events), "events": events}

        # [BESOIN C/D/E/F/P] Route/fonction asynchrone `add_llm_interaction` : ajoute l’interaction LLM
        # et déclenche le recalcul des corrélations pertinentes.
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

        # [BESOIN C/D/E/F/P] Route/fonction asynchrone `import_agentsight` : fonction dédiée à
        # l’opération `import_agentsight` dans le flux qui consiste à implémenter les
        # endpoints permettant d’inspecter sessions, timelines, alertes, événements
        # et métriques.
        @self.app.post("/agents/{session_id}/imports/agentsight", status_code=202)
        async def import_agentsight(
            session_id: str,
            request: AgentSightDocumentRequest,
        ) -> Dict[str, Any]:
            self._session_or_404(session_id)
            # [BESOIN C/D/E/F/P] Gestion d’erreur : isole les dépendances externes et conserve un
            # diagnostic explicite.
            try:
                result = self.importer.parse(request.document, session_id)
            except (AgentSightIntegrationError, TypeError, ValueError) as exc:
                # [BESOIN C/D/E/F/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
                # produire une fausse preuve.
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if result.total_events == 0:
                # [BESOIN C/D/E/F/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
                # produire une fausse preuve.
                raise HTTPException(
                    status_code=422,
                    detail="AgentSight document contained no recognized LLM or OS events",
                )
            accepted_llm_events = 0
            deduplicated_llm_events = 0
            # [BESOIN C/D/E/F/P] Boucle de traitement : parcourt chaque élément de manière déterministe
            # et traçable.
            for event in result.llm_events:
                _, added = self.runtime.record_llm_interaction_with_status(
                    event.model_copy(update={"session_id": session_id})
                )
                # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
                if added:
                    accepted_llm_events += 1
                else:
                    deduplicated_llm_events += 1
            accepted_os_events = 0
            deduplicated_os_events = 0
            unmatched_os_events = 0
            alerts = []
            # [BESOIN C/D/E/F/P] Boucle de traitement : parcourt chaque élément de manière déterministe
            # et traçable.
            for event in result.os_events:
                matched_session, alert, added = self.runtime.ingest_with_status(event)
                # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
                if matched_session is None:
                    unmatched_os_events += 1
                    continue
                # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
                if added:
                    accepted_os_events += 1
                else:
                    deduplicated_os_events += 1
                # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
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

        # [BESOIN C/D/E/F/P] Route/fonction asynchrone `events` : fonction dédiée à l’opération `events`
        # dans le flux qui consiste à implémenter les endpoints permettant
        # d’inspecter sessions, timelines, alertes, événements et métriques.
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
            # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if severity:
                # [BESOIN C/D/E/F/P] Gestion d’erreur : isole les dépendances externes et conserve un
                # diagnostic explicite.
                try:
                    expected_severity = EventSeverity(severity.upper())
                except ValueError as exc:
                    # [BESOIN C/D/E/F/P] Échec explicite : refuse une donnée ou un état ambigu au lieu
                    # de produire une fausse preuve.
                    raise HTTPException(status_code=400, detail="Invalid severity") from exc

            start = _aware(from_time)
            end = _aware(to_time)
            # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if start and end and start > end:
                # [BESOIN C/D/E/F/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
                # produire une fausse preuve.
                raise HTTPException(
                    status_code=400,
                    detail="'from' must be earlier than or equal to 'to'",
                )
            text = query.casefold().strip() if query else ""
            expected_type: Optional[str] = None
            # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if event_type:
                # [BESOIN C/D/E/F/P] Gestion d’erreur : isole les dépendances externes et conserve un
                # diagnostic explicite.
                try:
                    expected_type = EventType(event_type.upper()).value
                except ValueError as exc:
                    # [BESOIN C/D/E/F/P] Échec explicite : refuse une donnée ou un état ambigu au lieu
                    # de produire une fausse preuve.
                    raise HTTPException(status_code=400, detail="Invalid event_type") from exc
            matches = []

            # [BESOIN C/D/E/F/P] Boucle de traitement : parcourt chaque élément de manière déterministe
            # et traçable.
            for session in self.sessions.snapshot_sessions():
                # [BESOIN C/D/E/F/P] Boucle de traitement : parcourt chaque élément de manière
                # déterministe et traçable.
                for payload in list(session.timeline.events):
                    payload_pid = payload.get("pid")
                    # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre
                    # le flux fonctionnel.
                    if pid is not None and (payload_pid is None or int(payload_pid) != pid):
                        continue
                    payload_severity = payload.get("severity")
                    # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre
                    # le flux fonctionnel.
                    if expected_severity and payload_severity != expected_severity.value:
                        continue
                    payload_type = str(payload.get("event_type", "")).upper()
                    # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre
                    # le flux fonctionnel.
                    if expected_type and payload_type != expected_type:
                        continue
                    timestamp = _payload_time(payload)
                    # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre
                    # le flux fonctionnel.
                    if start and timestamp < start:
                        continue
                    # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre
                    # le flux fonctionnel.
                    if end and timestamp > end:
                        continue
                    # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre
                    # le flux fonctionnel.
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

        # [BESOIN C/D/E/F/P] Route/fonction asynchrone `metrics` : expose les compteurs de
        # fonctionnement, d’erreur et de perte nécessaires à l’observabilité.
        @self.app.get("/metrics")
        async def metrics() -> Dict[str, Any]:
            sensor = self.metrics_provider() if self.metrics_provider else {}
            return {
                "sessions": len(self.sessions.list_sessions()),
                "active_sessions": len(self.sessions.get_active_sessions()),
                "sensor": sensor,
            }


# [BESOIN C/D/E/F/P] Fonction `create_api` : construit l’application FastAPI avec le runtime et les
# métriques fournis.
def create_api(
    sessions: Optional[SessionManager] = None,
    metrics_provider: Optional[Callable[[], Dict[str, Any]]] = None,
    runtime: Optional[AgentSightRuntime] = None,
) -> FastAPI:
    # [BESOIN C/D/E/F/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if runtime is None:
        runtime = AgentSightRuntime(sessions=sessions or SessionManager())
    return AgentSightAPI(runtime, metrics_provider).app
