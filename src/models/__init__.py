
# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN D] Partie D - détection et explication des actions sensibles.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# [BESOIN F] Partie F - exposition des données par l’API backend.
# Rôle du module : publier le contrat de données commun à toutes les couches.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================

from .events import (
    BaseOSEvent,
    CorrelationLink,
    EventSeverity,
    EventType,
    FileAccessEvent,
    FileDeleteEvent,
    FileWriteEvent,
    LLMInteractionEvent,
    NetworkConnectionEvent,
    ProcessExecutionEvent,
    ProcessExitEvent,
    ProcessForkEvent,
    SecurityEvent,
)
from .session import AgentSession, ProcessNode, SessionSummary, SessionTimeline

# [BESOIN B/C/D/E/F] Attribut `__all__` : porte une donnée nécessaire au rôle du composant.
__all__ = [
    "AgentSession",
    "BaseOSEvent",
    "CorrelationLink",
    "EventSeverity",
    "EventType",
    "FileAccessEvent",
    "FileDeleteEvent",
    "FileWriteEvent",
    "LLMInteractionEvent",
    "NetworkConnectionEvent",
    "ProcessExecutionEvent",
    "ProcessExitEvent",
    "ProcessForkEvent",
    "ProcessNode",
    "SecurityEvent",
    "SessionSummary",
    "SessionTimeline",
]
