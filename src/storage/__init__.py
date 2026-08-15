
# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN A] Partie A - architecture AgentSight et chaîne Linux kernel vers collecteur userspace.
# [BESOIN F] Partie F - exposition des données par l’API backend.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# Rôle du module : exposer la persistance JSONL append-only.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================

from .jsonl import JsonlEventStore

# [BESOIN A/F/P] Attribut `__all__` : porte une donnée nécessaire au rôle du composant.
__all__ = ["JsonlEventStore"]
