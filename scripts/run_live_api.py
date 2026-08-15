#!/usr/bin/env python3
"""Run the API while attaching to a PID or launching an agent command."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.api import create_api
from src.collector import AgentSightRuntime
from src.integrations import (
    AgentSightCLI,
    AgentSightImporter,
    AgentSightIntegrationError,
    AgentSightPromptPoller,
)
from src.service import LiveSensorService
from src.storage import JsonlEventStore


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-pid", type=int, help="PID of an already-running AI agent")
    parser.add_argument("--session-id", default="agent-session")
    parser.add_argument("--agent-name", default="ai-agent")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--agentsight-json", type=Path, help="AgentSight export/report JSON or JSONL")
    source.add_argument("--agentsight-db", type=Path, help="AgentSight SQLite recording database")
    parser.add_argument("--agentsight-bin", default="agentsight", help="AgentSight executable")
    parser.add_argument(
        "--agentsight-poll-interval",
        type=float,
        default=2.0,
        help="seconds between AgentSight prompts refreshes when --agentsight-db is used",
    )
    parser.add_argument("--output", type=Path, default=Path("artifacts/events.jsonl"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command to launch after --")
    args = parser.parse_args()

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if bool(args.root_pid) == bool(command):
        parser.error("provide exactly one of --root-pid or a command after --")

    runtime = AgentSightRuntime(store=JsonlEventStore(args.output))
    service = LiveSensorService(runtime=runtime)
    importer = AgentSightImporter()
    initial_import = None
    initial_import_warnings: list[str] = []
    agentsight_cli = None
    prompt_poller = None
    if args.agentsight_json:
        initial_import = importer.parse_file(args.agentsight_json, args.session_id)
    elif args.agentsight_db:
        agentsight_cli = AgentSightCLI(args.agentsight_bin)
        try:
            # Import both prompt/model activity and AgentSight's audit view at
            # startup. The local eBPF source remains authoritative for the live
            # OS stream; imported records retain source metadata and may enrich
            # a session when the upstream report exposes additional context.
            document = agentsight_cli.combined_report(args.agentsight_db)
        except AgentSightIntegrationError as exc:
            # Older AgentSight builds may not expose the audit subreport. Keep
            # prompt correlation available and surface the explicit fallback.
            document = agentsight_cli.prompts_json(args.agentsight_db)
            initial_import_warnings.append(
                f"AgentSight audit report unavailable; prompts-only fallback: {exc}"
            )
        initial_import = importer.parse(document, args.session_id)

    llm_events = initial_import.llm_events if initial_import else []

    if args.root_pid:
        service.start_existing(
            args.root_pid,
            args.session_id,
            args.agent_name,
            llm_events=llm_events,
        )
    else:
        service.start_command(
            command,
            args.session_id,
            args.agent_name,
            llm_events=llm_events,
        )

    initial_import_metrics = {
        "llm_events": len(initial_import.llm_events) if initial_import else 0,
        "os_events": len(initial_import.os_events) if initial_import else 0,
        "accepted_os_events": 0,
        "unmatched_os_events": 0,
        "security_events": 0,
        "ignored_records": initial_import.ignored_records if initial_import else 0,
        "warnings": [
            *initial_import_warnings,
            *(initial_import.warnings if initial_import else []),
        ],
    }
    if initial_import is not None:
        for event in initial_import.os_events:
            matched_session, alert, added = runtime.ingest_with_status(event)
            if matched_session is None:
                initial_import_metrics["unmatched_os_events"] += 1
            elif added:
                initial_import_metrics["accepted_os_events"] += 1
            if alert is not None:
                initial_import_metrics["security_events"] += 1

    try:
        if args.agentsight_db:
            prompt_poller = AgentSightPromptPoller(
                args.agentsight_db,
                runtime,
                args.session_id,
                interval_seconds=args.agentsight_poll_interval,
                executable=args.agentsight_bin,
                cli=agentsight_cli,
            )
            prompt_poller.start()

        def metrics():
            values = service.metrics()
            values["agentsight_initial_import"] = initial_import_metrics
            if prompt_poller is not None:
                values["agentsight_prompt_poller"] = prompt_poller.metrics()
            return values

        app = create_api(runtime=runtime, metrics_provider=metrics)
        uvicorn.run(app, host=args.host, port=args.port)
    finally:
        if prompt_poller is not None:
            prompt_poller.stop()
        # Attached processes are never owned by the service. A command launched
        # through start_command is owned and is terminated on API shutdown.
        service.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
