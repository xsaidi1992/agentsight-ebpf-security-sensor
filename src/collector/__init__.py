
# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN A] Partie A - architecture AgentSight et chaîne Linux kernel vers collecteur userspace.
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN D] Partie D - détection et explication des actions sensibles.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# Rôle du module : publier les composants de collecte, de runtime et de détection.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================

from .collector import BPFEventCollector, CollectorMetrics
from .live_ebpf import LiveEBPFError, LiveExecCollector
from .runtime import AgentSightRuntime, SessionManager
from .security import SecurityEngine

# [BESOIN A/B/C/D/P] Attribut `__all__` : porte une donnée nécessaire au rôle du composant.
__all__ = [
    "AgentSightRuntime",
    "BPFEventCollector",
    "CollectorMetrics",
    "LiveEBPFError",
    "LiveExecCollector",
    "SecurityEngine",
    "SessionManager",
]
