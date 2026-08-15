# =============================================================================
# TRACEABILITE DU TECHNICAL ASSESSMENT - COMMANDES DE BUILD, TEST ET DEMO
# [BESOIN A/B/C/D/E/F] Ce Makefile offre un point d’entrée reproductible pour
# toutes les couches du projet.
# [BESOIN P] Les cibles preflight/validate rendent les prérequis et les pertes
# observables avant l’exécution privilégiée.
# [BESOIN T] Les cibles test-kernel et demo fournissent les preuves demandées.
# =============================================================================

# [BESOIN T] Interpréteur Python configurable pour CI, VM ou environnement local.
PYTHON ?= python3
# [BESOIN C/F] PID racine de l’agent lorsqu’on attache l’API à un processus existant.
ROOT_PID ?=
# [BESOIN C/E/F] Identifiant stable de la session créée par live-api.
SESSION_ID ?= agent-session
# [BESOIN C/F] Nom humain de l’agent exposé dans les réponses API.
AGENT_NAME ?= ai-agent

# [BESOIN T] Déclare toutes les commandes publiques comme cibles non-fichiers.
.PHONY: install preflight build test test-unit test-kernel validate demo live-api clean

# [BESOIN T] Installe uniquement les dépendances Python nécessaires au runtime et aux tests.
install:
	$(PYTHON) -m pip install -r requirements.txt

# [BESOIN B/P/T] Vérifie BTF, toolchain, libbpf, tracepoints et privilèges avant le kernel E2E.
preflight:
	$(PYTHON) -c 'import json; from src.collector import BPFEventCollector; print(json.dumps(BPFEventCollector.preflight(), indent=2))'

# [BESOIN A/B/T] Compile le probe CO-RE et le lecteur libbpf userspace avec l’ABI partagée.
build:
	$(PYTHON) -c 'from src.collector.live_ebpf import LiveExecCollector; print(LiveExecCollector().build())'

# [BESOIN T] Alias sûr : la cible test n’exige pas de privilèges kernel par défaut.
test: test-unit

# [BESOIN A/B/C/D/E/F/P/T] Exécute l’ensemble des tests non privilégiés.
test-unit:
	$(PYTHON) -m pytest -q -m 'not kernel'

# [BESOIN B/C/D/E/P/T] Exécute la preuve réelle kernel -> ring buffer -> session -> alerte.
test-kernel:
	sudo -E $(PYTHON) -m pytest -q -m kernel -rs

# [BESOIN T] Compile tout le Python puis lance les tests non privilégiés pour une validation rapide.
validate:
	$(PYTHON) -m compileall -q src scripts tests
	$(PYTHON) -m pytest -q -m 'not kernel'

# [BESOIN B/C/D/E/P/T] Lance la démonstration reproductible avec événements OS réels et rapport JSONL.
demo:
	sudo -E $(PYTHON) scripts/demo_live.py

# [BESOIN A/B/C/E/F/P] Attache le capteur à un PID existant et expose FastAPI.
live-api:
	@test -n "$(ROOT_PID)" || (echo "usage: make live-api ROOT_PID=<agent-pid> [SESSION_ID=...] [AGENT_NAME=...]" && exit 2)
	sudo -E $(PYTHON) scripts/run_live_api.py --root-pid $(ROOT_PID) --session-id $(SESSION_ID) --agent-name $(AGENT_NAME)

# [BESOIN P/T] Supprime uniquement les artefacts générés, caches et binaires de travail.
clean:
	rm -rf .build .pytest_cache artifacts .coverage htmlcov build dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
