PYTHON ?= python3
ROOT_PID ?=
SESSION_ID ?= agent-session
AGENT_NAME ?= ai-agent

.PHONY: install preflight build test test-unit test-kernel validate demo live-api clean

install:
	$(PYTHON) -m pip install -r requirements.txt

preflight:
	$(PYTHON) -c 'import json; from src.collector import BPFEventCollector; print(json.dumps(BPFEventCollector.preflight(), indent=2))'

build:
	$(PYTHON) -c 'from src.collector.live_ebpf import LiveExecCollector; print(LiveExecCollector().build())'

test: test-unit

test-unit:
	$(PYTHON) -m pytest -q -m 'not kernel'

test-kernel:
	sudo -E $(PYTHON) -m pytest -q -m kernel -rs

validate:
	$(PYTHON) -m compileall -q src scripts tests
	$(PYTHON) -m pytest -q -m 'not kernel'

demo:
	sudo -E $(PYTHON) scripts/demo_live.py

live-api:
	@test -n "$(ROOT_PID)" || (echo "usage: make live-api ROOT_PID=<agent-pid> [SESSION_ID=...] [AGENT_NAME=...]" && exit 2)
	sudo -E $(PYTHON) scripts/run_live_api.py --root-pid $(ROOT_PID) --session-id $(SESSION_ID) --agent-name $(AGENT_NAME)

clean:
	rm -rf .build .pytest_cache artifacts .coverage htmlcov build dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
