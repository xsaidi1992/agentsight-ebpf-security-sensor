
# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN F] Partie F - exposition des données par l’API backend.
# Rôle du module : exposer la fabrique de l’API backend.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================

from .server import AgentSightAPI, create_api

# [BESOIN F] Attribut `__all__` : porte une donnée nécessaire au rôle du composant.
__all__ = ["AgentSightAPI", "create_api"]
