#!/usr/bin/env python3
"""Harmless deterministic agent used by the privileged end-to-end demo."""
from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--delay", type=float, default=0.25)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    time.sleep(max(0.0, args.delay))

    # Harmless read of a path explicitly listed by the assessment.  The
    # content is not emitted by the sensor; only the OS-level access is.
    with Path("/etc/passwd").open("r", encoding="utf-8", errors="replace") as handle:
        handle.readline()

    with socket.create_connection((args.host, args.port), timeout=3) as connection:
        connection.sendall(b"agentsight-demo\n")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        handle.write("AgentSight eBPF assessment demo\n")
        handle.flush()

    # Exercise unlink detection without deleting user data.
    disposable = args.output.with_name(args.output.name + ".delete-me")
    disposable.write_text("temporary AgentSight demo file\n", encoding="utf-8")
    disposable.unlink()

    rm = shutil.which("rm")
    if not rm:
        raise SystemExit("rm is unavailable")
    return subprocess.run(
        [rm, "--version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
