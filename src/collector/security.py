"""Explainable detection rules for sensitive AI-agent actions."""
from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN D] Partie D - détection et explication des actions sensibles.
# Rôle du module : appliquer les règles de sécurité explicables aux actions de la session.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


import fnmatch
import ipaddress
from pathlib import Path
from typing import Iterable, Optional

from src.models import (
    BaseOSEvent,
    EventSeverity,
    FileAccessEvent,
    FileDeleteEvent,
    FileWriteEvent,
    NetworkConnectionEvent,
    ProcessExecutionEvent,
    SecurityEvent,
)


# [BESOIN D] Classe `SecurityEngine` : classe dédiée à l’opération `SecurityEngine` dans le flux qui
# consiste à appliquer les règles de sécurité explicables aux actions de la session.
class SecurityEngine:
    # [BESOIN D] Constante `SENSITIVE_COMMANDS` : fixe un paramètre stable et auditable utilisé par ce
    # module.
    SENSITIVE_COMMANDS = {
        "curl",
        "wget",
        "ssh",
        "scp",
        "sftp",
        "sudo",
        "chmod",
        "chown",
        "rm",
        "dd",
        "nc",
        "ncat",
        "telnet",
        "gpg",
        "openssl",
    }
    # [BESOIN D] Constante `SENSITIVE_PATH_PATTERNS` : fixe un paramètre stable et auditable utilisé par
    # ce module.
    SENSITIVE_PATH_PATTERNS = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh",
        "/root/.ssh/*",
        "/home/*/.ssh",
        "/home/*/.ssh/*",
        ".env",
        ".env.*",
        "*/.env",
        "*/.env.*",
        "*/.aws/*",
        "*/.kube/*",
        "*/.config/gcloud/*",
    }
    # [BESOIN D] Constante `CLOUD_METADATA_ADDRESSES` : fixe un paramètre stable et auditable utilisé
    # par ce module.
    CLOUD_METADATA_ADDRESSES = {
        "169.254.169.254",
        "100.100.100.200",
        "fd00:ec2::254",
    }
    # [BESOIN D] Constante `SENSITIVE_REMOTE_PORTS` : fixe un paramètre stable et auditable utilisé par
    # ce module.
    SENSITIVE_REMOTE_PORTS = {22, 23, 2375, 2376, 3306, 5432, 6379, 9200}

    # [BESOIN D] Fonction `_matches_path` : fonction dédiée à l’opération `_matches_path` dans le flux
    # qui consiste à appliquer les règles de sécurité explicables aux actions de la session.
    @classmethod
    def _matches_path(cls, path: str) -> bool:
        normalized = str(Path(path).expanduser())
        return any(fnmatch.fnmatch(normalized, pattern) for pattern in cls.SENSITIVE_PATH_PATTERNS)

    # [BESOIN D] Fonction `_security_event` : fonction dédiée à l’opération `_security_event` dans le
    # flux qui consiste à appliquer les règles de sécurité explicables aux actions de la
    # session.
    @staticmethod
    def _security_event(
        event: BaseOSEvent,
        session_id: str,
        *,
        severity: EventSeverity,
        action: str,
        target: str,
        rule_name: str,
        description: str,
    ) -> SecurityEvent:
        return SecurityEvent(
            timestamp=event.timestamp,
            severity=severity,
            session_id=session_id,
            pid=event.pid,
            ppid=event.ppid,
            action=action,
            target=target,
            rule_name=rule_name,
            rule_description=description,
            raw_events=[event.model_dump(mode="json")],
            correlation=event.correlation,
            metadata={"source_event_id": event.event_id, "source": event.source},
        )

    # [BESOIN D] Fonction `analyze_event` : évalue un événement contre les règles sensibles et construit
    # une alerte si nécessaire.
    def analyze_event(self, event: BaseOSEvent, session_id: str) -> Optional[SecurityEvent]:
        # [BESOIN D] Condition de garde : valide le cas courant avant de poursuivre le flux fonctionnel.
        if isinstance(event, ProcessExecutionEvent):
            command = event.command_name.lower()
            # [BESOIN D] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if command in self.SENSITIVE_COMMANDS:
                return self._security_event(
                    event,
                    session_id,
                    severity=EventSeverity.HIGH,
                    action="PROCESS_EXECUTION",
                    target=event.command,
                    rule_name="SENSITIVE_COMMAND_EXECUTION",
                    description=f"The agent executed the configured sensitive command '{command}'.",
                )

        # [BESOIN D] Condition de garde : valide le cas courant avant de poursuivre le flux fonctionnel.
        if isinstance(event, FileAccessEvent) and self._matches_path(event.path):
            severity = EventSeverity.CRITICAL if event.write_intent else EventSeverity.HIGH
            return self._security_event(
                event,
                session_id,
                severity=severity,
                action="FILE_ACCESS",
                target=event.path,
                rule_name="SENSITIVE_FILE_ACCESS",
                description=(
                    "The agent opened a configured sensitive path"
                    + (" with write intent." if event.write_intent else ".")
                ),
            )

        # [BESOIN D] Condition de garde : valide le cas courant avant de poursuivre le flux fonctionnel.
        if isinstance(event, FileWriteEvent) and self._matches_path(event.path):
            return self._security_event(
                event,
                session_id,
                severity=EventSeverity.CRITICAL,
                action="FILE_WRITE",
                target=event.path,
                rule_name="SENSITIVE_FILE_WRITE",
                description="The agent wrote to a configured sensitive path.",
            )

        # [BESOIN D] Condition de garde : valide le cas courant avant de poursuivre le flux fonctionnel.
        if isinstance(event, FileDeleteEvent):
            return self._security_event(
                event,
                session_id,
                severity=EventSeverity.CRITICAL if self._matches_path(event.path) else EventSeverity.HIGH,
                action="FILE_DELETE",
                target=event.path,
                rule_name="SENSITIVE_FILE_DELETE" if self._matches_path(event.path) else "FILE_DELETION",
                description="The agent successfully deleted a file.",
            )

        # [BESOIN D] Condition de garde : valide le cas courant avant de poursuivre le flux fonctionnel.
        if isinstance(event, NetworkConnectionEvent):
            # [BESOIN D] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
            # explicite.
            try:
                normalized_address = str(ipaddress.ip_address(event.remote_addr))
            except ValueError:
                normalized_address = event.remote_addr
            # [BESOIN D] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if normalized_address in self.CLOUD_METADATA_ADDRESSES:
                return self._security_event(
                    event,
                    session_id,
                    severity=EventSeverity.CRITICAL,
                    action="NETWORK_CONNECTION",
                    target=f"{event.remote_addr}:{event.remote_port}",
                    rule_name="CLOUD_METADATA_CONNECTION",
                    description="The agent connected to a cloud instance metadata endpoint.",
                )
            # [BESOIN D] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if event.remote_port in self.SENSITIVE_REMOTE_PORTS and normalized_address not in {
                "127.0.0.1",
                "::1",
            }:
                return self._security_event(
                    event,
                    session_id,
                    severity=EventSeverity.MEDIUM,
                    action="NETWORK_CONNECTION",
                    target=f"{event.remote_addr}:{event.remote_port}",
                    rule_name="SENSITIVE_REMOTE_PORT",
                    description="The agent connected to a configured security-sensitive remote port.",
                )
        return None

    # [BESOIN D] Fonction `analyze_many` : évalue un ensemble d’événements et retourne toutes les
    # alertes générées.
    def analyze_many(self, events: Iterable[BaseOSEvent], session_id: str) -> list[SecurityEvent]:
        return [alert for event in events if (alert := self.analyze_event(event, session_id))]
