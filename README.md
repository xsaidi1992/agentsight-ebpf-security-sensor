# AgentSight eBPF OS-Level Security Sensor

A focused Linux implementation for the **Technical Assessment - AI Agent OS-Level Monitoring with eBPF & AgentSight**.

The sensor observes an AI-agent process tree from the operating-system boundary without modifying the monitored application. It captures real kernel events, sends them through a BPF ring buffer to userspace, reconstructs an Agent Session, correlates AgentSight LLM records with OS activity, detects sensitive actions, persists JSONL records, and exposes the required backend API.

## Validation status

The repository contains the complete implementation paths requested by the assessment.

Validated in the ordinary, non-privileged environment:

- Python compilation;
- model, collector, session, security, persistence, API, service, and AgentSight integration tests;
- shared native ABI checks;
- strict C syntax checks for both the eBPF source and the native libbpf reader;
- source-level checks for hook coverage, loss accounting, startup ordering, and process identity.

A privileged kernel end-to-end test is included. It performs a real:

```text
agent process
  -> kernel tracepoints
  -> eBPF maps and ring buffer
  -> native libbpf reader
  -> Python collector
  -> Agent Session
  -> security rule
  -> FastAPI query
```

That test can only execute on a compatible Linux host with kernel BTF, a Clang BPF backend, `bpftool`, libbpf development files, the required tracepoints, and BPF privileges. If those prerequisites are missing, the test is explicitly skipped with the complete reason; it is never replaced by a synthetic kernel event.

## Assessment coverage

| Assessment area | Implementation |
|---|---|
| AgentSight architecture | Upstream component mapping and reuse/implementation boundary in this README |
| Process execution | `execve` and optional `execveat`, bounded command arguments, successful-exec confirmation |
| Kernel-to-userspace transport | `BPF_MAP_TYPE_RINGBUF` plus native libbpf reader |
| Process tree | fork propagation, bounded ancestry recovery, PID plus process-start identity, exit tracking |
| Sensitive file activity | successful `openat`, optional `openat2`, `write`, `unlink`, and `unlinkat` |
| Network activity | successful or in-progress IPv4/IPv6 `connect` |
| Agent Session | process graph, files, network, LLM interactions, alerts, chronological timeline |
| Security event | sensitive commands, sensitive paths, deletion, cloud metadata, sensitive ports |
| LLM/OS correlation | AgentSight import plus explainable session-scoped temporal/PID correlation |
| Persistence | thread-safe append-only JSONL |
| Backend API | all required endpoints plus health, metrics, correlation, and import endpoints |
| Performance | kernel filtering, bounded maps/queues, batching, drop counters, sequence-gap accounting |
| Demonstration | real process, sensitive file read, local network connection, file write/delete, `rm --version`, alert |
| Automated tests | non-privileged suite and privileged kernel E2E test |

## Architecture

```text
                         AgentSight record/report/export
                         prompts + audit + snapshot JSON
                                      |
                                      v
                           AgentSight normalization
                                      |
                                      v
+-----------------------+      +------+---------------------------+
| Linux kernel          |      | Agent Session                    |
|                       |      |                                  |
| execve / execveat     |      | LLM request                      |
| fork / process exit   |      |   -> process tree                |
| openat / openat2      |----->|   -> file and network activity   |
| write / unlink        | ring |   -> explainable correlations    |
| IPv4 / IPv6 connect   |buffer|   -> security findings           |
+-----------+-----------+      +---------------+------------------+
            |                                  |
            v                                  v
      CO-RE eBPF probe                  JSONL + FastAPI
            |
            v
    native libbpf reader
            |
            v
 validated Python event models
```

Concrete data path:

```text
Linux tracepoint/raw tracepoint
  -> src/ebpf/probe.c
  -> src/ebpf/event.h shared ABI
  -> BPF ring buffer
  -> src/ebpf/native/collector.c
  -> newline-delimited JSON records
  -> bounded userspace queue
  -> src/collector/collector.py
  -> src/models/events.py
  -> src/models/session.py
  -> src/collector/security.py
  -> src/storage/jsonl.py
  -> src/api/server.py
```

## Relationship to upstream AgentSight

Official references:

- repository: `https://github.com/eunomia-bpf/agentsight`
- documentation: `https://eunomia.dev/agentsight/`

The upstream project is the architectural and event-model starting point. This assessment repository intentionally does not copy the complete Rust workspace, frontend, generated assets, or production database.

| Upstream AgentSight concern | Use in this assessment |
|---|---|
| `bpf/` | reference for independent kernel-level observation |
| `collector/` | reference for userspace event processing and correlation |
| `agent-session/` | reference for session-oriented process, prompt, file, and network views |
| `agentsight-capture/` | reference for reusable event sources, models, analyzers, and sinks |
| `agentsight report prompts --json` | imported as LLM interactions |
| `agentsight report audit --json` | imported as upstream process/file/network audit records when available |
| `agentsight report export -o ...` | accepted through the JSON/JSONL adapter |
| report and timeline concepts | exposed through the session timeline and API |

Reuse boundary:

- **Reused directly:** JSON/JSONL produced by official AgentSight CLI report/export commands.
- **Adapted conceptually:** kernel -> collector -> event model -> session -> timeline/report, and prompt-to-system-effect correlation.
- **Implemented locally:** assessment-specific eBPF programs, ABI, loader, event validation, process identity, session manager, security rules, persistence, API, tests, and demo.
- **Not claimed:** this repository is not a fork or replacement for AgentSight's complete capture stack, TLS tracing, UI, native-agent parsers, or production storage.

Every imported AgentSight record is preserved in event metadata. Import IDs are deterministic, repeated imports are idempotent, and missing or malformed source timestamps are rejected instead of being replaced with an invented time.

## Repository contents

```text
.
|-- README.md
|-- LICENSE
|-- Makefile
|-- requirements.txt
|-- pytest.ini
|-- scripts/
|   |-- demo_agent.py
|   |-- demo_live.py
|   `-- run_live_api.py
|-- src/
|   |-- api/
|   |   `-- server.py
|   |-- collector/
|   |   |-- collector.py
|   |   |-- live_ebpf.py
|   |   |-- runtime.py
|   |   `-- security.py
|   |-- ebpf/
|   |   |-- event.h
|   |   |-- probe.c
|   |   `-- native/collector.c
|   |-- integrations/
|   |   `-- agentsight.py
|   |-- models/
|   |   |-- events.py
|   |   `-- session.py
|   |-- storage/
|   |   `-- jsonl.py
|   `-- service.py
`-- tests/
```

The source archive excludes assessment PDFs, duplicate probes, remediation reports, generated binaries, caches, databases, virtual environments, and runtime artifacts.

## Shared event ABI

`src/ebpf/event.h` is the single C ABI used by both kernel and userspace code. The Python collector consumes JSON emitted by the native reader, so there is no independent Python `struct` definition that can silently diverge.

The fixed event header contains:

```text
schema version and event type
PID / PPID
UID / GID
monotonic kernel timestamp
sequence number
process start identity
parent start identity
comm
```

The payload union contains:

```text
EXEC
  filename, bounded argv, argument/filename truncation, execve kind
FORK
  child and parent PID/start identity, child comm
EXIT
  exit code, signal, observed duration
FILE_OPEN
  path, fd, dirfd, flags, result, path truncation
FILE_WRITE
  path or descriptor identity, byte count, result, path truncation
FILE_DELETE
  path, dirfd, result, path truncation
NETWORK_CONNECT
  address family, IPv4/IPv6 address, port, result
```

The ABI is versioned. Native static assertions and automated tests verify its size and offsets.

## eBPF design choices

### Process execution

The sensor combines syscall entry with scheduler confirmation:

1. `sys_enter_execve` or `sys_enter_execveat` reads the filename and bounded argument pointers while userspace memory is still available.
2. Pending state is stored in an LRU map.
3. `sched_process_exec` confirms that execution succeeded.
4. Only a confirmed execution is emitted.
5. `sys_exit_execve` and `sys_exit_execveat` remove pending state for failed executions.

This avoids reporting a failed `execve` as an action actually executed by the OS.

Command capture is bounded to six arguments and 128 bytes per argument. `argv_truncated` also covers an individually truncated argument. `filename_truncated` is reported separately. Userspace attempts to resolve the final executable through `/proc/<pid>/exe` and retains the kernel filename in metadata.

### Process tree and stable identity

- Userspace seeds a trusted root PID and any currently visible descendants.
- `sched_process_fork` propagates membership to future descendants.
- Thread creation is ignored by comparing parent and child TGIDs.
- On a tracking-map miss, the eBPF program performs a bounded 16-level ancestry walk to recover a descendant that raced with the userspace snapshot.
- The root PID is paired with its process start identity so a later reuse of the same numeric PID is not treated as the original session.
- Process generations are retained in userspace instead of overwriting history.
- Process exit is emitted only for the thread-group leader.

Linux `/proc/<pid>/stat` exposes process start time in userspace clock ticks, while the kernel stores `task_struct::start_boottime` in nanoseconds. The loader supplies the clock-tick period and the eBPF program quantizes the kernel value before comparison. This makes procfs seeds and kernel events use the same process identity.

For a newly launched command, `LiveSensorService` starts a temporary child that stops itself with `SIGSTOP` immediately before `exec`. The sensor is fully loaded and the root PID is configured before `SIGCONT`. The target program itself remains unchanged, and its first real `exec` is observable without relying on a sleep-based race.

### File events

The minimal file extension observes:

- successful `openat`;
- successful `openat2` when the tracepoint exists;
- successful `write`;
- successful `unlink` and `unlinkat`;
- successful `close` for descriptor-state cleanup.

`openat2` is treated as a versioned syscall structure: the probe reads only the initial flags field and checks the userspace-provided structure size instead of assuming a full fixed structure.

Open descriptors are indexed by TGID and FD. Writes through inherited or pre-existing descriptors are still emitted. If the kernel map has no path, userspace performs a best-effort `/proc/<pid>/fd/<fd>` lookup; if resolution is impossible, the event remains visible as `fd:<number>` rather than being discarded.

Relative paths are resolved through `/proc/<pid>/cwd` or `/proc/<pid>/fd/<dirfd>` when those references remain available. Truncation is explicit.

### Network events

`sys_enter_connect` captures IPv4 or IPv6 destination data. `sys_exit_connect` emits an event when the call succeeds or returns `-EINPROGRESS`, the expected result for a non-blocking connection attempt.

The sensor records the destination address, port, family, and return value. It does not inspect payload contents.

### Kernel filtering

When a root PID is configured, unrelated processes are rejected before pending state or ring-buffer records are created. This reduces CPU, memory, ring-buffer pressure, and userspace load compared with host-wide capture followed by userspace filtering.

The filter combines:

```text
seeded root/current descendants
+ fork propagation
+ bounded ancestry recovery
+ root PID start-time guard
```

### Ring buffer, backpressure, and event loss

The implementation uses a 4 MiB `BPF_MAP_TYPE_RINGBUF`.

A sequence number is allocated before `bpf_ringbuf_reserve()`. If reservation fails, the new event is not written and `kernel_ringbuf_drops` is incremented. A later sequence gap gives an independent estimate of missing records. Existing records are not described as being automatically evicted.

Kernel metrics:

```text
kernel_ringbuf_drops
pending_update_failures
failed_execs
missing_pending
tracking_state_failures
file_state_failures
network_state_failures
missing_file_pending
missing_network_pending
emitted_events
```

Userspace metrics:

```text
userspace_queue_drops
json_decode_errors
unknown_record_types
invalid_stats_records
invalid_records
sequence_gap_events
estimated_sequence_drops
out_of_order_records
queue depth
```

The native ring-buffer reader is created before probes are attached, removing the avoidable startup interval in which attached programs could emit without a reader. Optional file/network hooks are disabled with an explicit startup message when unavailable. Core exec, fork, and exit hooks are required; startup fails rather than silently losing the primary assessment path.

## Agent Session model

An `AgentSession` contains:

```text
session ID and agent name
root PID / PPID / executable / command / start time
current and historical process generations
parent/child graph
LLM interactions
chronological timeline
unique file paths
network events
security events
session start/end state
```

### Event association

For each event:

1. check an existing PID-to-session mapping;
2. validate process start identity when available;
3. otherwise validate a known parent PID and parent start identity;
4. register accepted fork/exec descendants for transitive correlation;
5. remove active PID mappings at exit while retaining historical nodes.

A mismatched start identity cannot terminate or update an older PID generation. A child observed before its parent can be adopted later when the matching parent identity arrives.

Example tree:

```text
python agent.py
|-- bash
|   `-- curl
|-- git
`-- python
```

### LLM-to-OS correlation

AgentSight prompt/model-call records become `LLMInteractionEvent` values. An OS or security event is associated with the nearest preceding LLM interaction in the same Agent Session when it falls inside the configured window, default 300 seconds.

The correlation records:

```text
LLM event ID
upstream request ID when available
time delta
method
confidence
human-readable rationale
causal_proof = false
```

If an AgentSight record contains a PID matching the OS event PID or PPID, the method and confidence reflect both PID and temporal evidence. If LLM data is imported after OS events, in-memory timeline correlations are backfilled. The source event IDs and raw AgentSight records remain unchanged.

This is an explainable association, not a claim that prompt semantics caused a syscall.

## AgentSight import

`src/integrations/agentsight.py` supports:

- strict JSON and JSONL;
- common envelopes such as `data`, `payload`, `event`, and `attributes`;
- LLM, process, file, and network records;
- records containing both an LLM semantic and an OS semantic;
- seconds, milliseconds, microseconds, nanoseconds, and ISO timestamps;
- rejection of monotonic `timestamp_ns` values that lack a boot-to-epoch mapping;
- deterministic IDs and idempotent re-import;
- preservation of every raw upstream record;
- CLI variants for `prompts`, `audit`, and `export`;
- live prompt polling without reading private AgentSight SQLite tables.

Using the official CLI as the schema boundary leaves AgentSight responsible for interpreting its own database version.

Record an agent with upstream AgentSight:

```bash
sudo agentsight record -- <your-agent-command>
```

Inspect the recording:

```bash
agentsight report --db run.db
agentsight report --db run.db prompts --json
agentsight report --db run.db audit --json
agentsight report --db run.db export -o snapshot.json
```

When `scripts/run_live_api.py --agentsight-db ...` is used, the initial import requests both prompts and audit data. If an older AgentSight build lacks the audit report, the service falls back to prompts only and exposes that fallback in metrics. Live polling subsequently imports new prompt/model records idempotently.

## Security rules

Rules detect and explain; they do not block.

Sensitive commands include:

```text
curl wget ssh scp sftp sudo chmod chown rm dd nc ncat telnet gpg openssl
```

Sensitive path patterns include:

```text
/etc/passwd
/etc/shadow
/etc/sudoers
/root/.ssh/*
/home/*/.ssh/*
.env and .env.*
*/.aws/*
*/.kube/*
*/.config/gcloud/*
```

Additional rules:

- every successful file deletion;
- cloud instance metadata addresses;
- configured non-loopback sensitive ports.

Example security event:

```json
{
  "event_type": "AI_AGENT_SECURITY_EVENT",
  "type": "AI_AGENT_SECURITY_EVENT",
  "severity": "HIGH",
  "session_id": "agent-42",
  "pid": 4312,
  "action": "PROCESS_EXECUTION",
  "target": "/usr/bin/curl https://example.test/report",
  "rule_name": "SENSITIVE_COMMAND_EXECUTION",
  "rule_description": "The agent executed the configured sensitive command 'curl'."
}
```

## Backend API

FastAPI provides the required endpoints:

```text
GET /agents
GET /agents/{id}
GET /agents/{id}/timeline
GET /agents/{id}/processes
GET /agents/{id}/security-events
GET /events?pid=4312
GET /events?severity=HIGH
```

Additional endpoints:

```text
GET  /health
GET  /metrics
GET  /agents/{id}/correlations
POST /agents/{id}/llm-interactions
POST /agents/{id}/imports/agentsight
```

`GET /events` also supports:

```text
event_type
from / to
query
limit / offset
```

Inputs are validated. Invalid severities, event types, time ranges, and malformed AgentSight imports return explicit client errors. Session serialization uses deep snapshots so API reads do not race with collector mutation.

## Linux prerequisites

A live privileged run requires:

- Linux with eBPF and kernel BTF at `/sys/kernel/btf/vmlinux`;
- required syscall and scheduler tracepoints;
- Clang/LLVM with the BPF target;
- `bpftool`;
- libbpf, libelf, and zlib development packages;
- root or suitable `CAP_BPF` plus `CAP_PERFMON`, or `CAP_SYS_ADMIN`;
- Python 3.10 or newer.

Debian/Ubuntu example:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev \
  python3 python3-venv python3-pip
```

Mount tracefs if needed:

```bash
sudo mount -t tracefs nodev /sys/kernel/tracing
```

## Installation

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Preflight and build

```bash
make preflight
make build
```

`make preflight` lists all missing prerequisites. `make build` generates:

```text
.build/ebpf/vmlinux.h
.build/ebpf/agentsight_probe.o
.build/ebpf/agentsight-ebpf-collector
```

The BPF object is compiled with CO-RE metadata and architecture-specific `__TARGET_ARCH_*` selection. The native helper is built with libbpf.

## Tests

Run all non-privileged tests:

```bash
make test
```

Run compilation plus the non-privileged suite:

```bash
make validate
```

Coverage includes:

- one shared native ABI and expected layout;
- strict C syntax for probe and native reader;
- hook presence and optional-hook behavior;
- all native record decoders;
- path and argument truncation metadata;
- sequence gaps, kernel drops, queue drops, and state failures;
- root filtering and startup ordering contracts;
- process generations, PID reuse, parent identity, fork/exec/exit, and session lifetime;
- temporal/PID LLM correlation and late backfill;
- sensitive command, file, deletion, metadata-address, and port rules;
- AgentSight JSON/JSONL, mixed records, CLI variants, polling, timestamp rejection, and failure paths;
- persistence and idempotency;
- required API endpoints and filters;
- controlled launch and existing-process attachment.

Run the real privileged test:

```bash
make test-kernel
```

The kernel E2E test:

1. starts a local TCP listener;
2. creates an Agent Session with an AgentSight-format LLM record;
3. launches the demo agent behind the pre-exec gate;
4. builds, loads, and attaches the real eBPF programs;
5. observes process, sensitive file, write, delete, network, and exit activity;
6. captures a real `rm --version` descendant;
7. verifies a HIGH command alert and process tree;
8. queries the resulting session and alert through FastAPI;
9. asserts zero kernel ring-buffer and userspace queue drops for the demo.

## Reproducible live demonstration

```bash
make demo
```

Equivalent command:

```bash
sudo -E .venv/bin/python scripts/demo_live.py
```

Use a real AgentSight source:

```bash
sudo -E .venv/bin/python scripts/demo_live.py --agentsight-json prompts.json
sudo -E .venv/bin/python scripts/demo_live.py --agentsight-db run.db
```

The deterministic OS workflow is:

```text
LLM interaction
  -> controlled agent exec
  -> read /etc/passwd
  -> connect to a local TCP listener
  -> open/write artifacts/demo-result.txt
  -> create and delete a disposable file
  -> child exec of rm --version
  -> sensitive-path, deletion, and command findings
  -> process exit events
  -> chronological timeline and JSONL report
```

`rm --version` is harmless and is used only to prove command detection. The disposable file is created by the demo immediately before deletion; no user data is removed.

Generated output is stored under `artifacts/`, which is excluded from the source ZIP.

## Run the live API

Attach to an existing process:

```bash
sudo -E .venv/bin/python scripts/run_live_api.py \
  --root-pid 4312 \
  --session-id agent-42 \
  --agent-name example-agent \
  --host 127.0.0.1 \
  --port 8000
```

Launch a command without missing its first exec:

```bash
sudo -E .venv/bin/python scripts/run_live_api.py \
  --session-id agent-42 \
  --agent-name example-agent \
  --host 127.0.0.1 \
  --port 8000 \
  -- python3 agent.py
```

Import an AgentSight report/export:

```bash
sudo -E .venv/bin/python scripts/run_live_api.py \
  --root-pid 4312 \
  --session-id agent-42 \
  --agentsight-json snapshot.json
```

Follow an AgentSight recording database:

```bash
sudo -E .venv/bin/python scripts/run_live_api.py \
  --root-pid 4312 \
  --session-id agent-42 \
  --agentsight-db run.db \
  --agentsight-poll-interval 2
```

Useful queries:

```bash
curl -s http://127.0.0.1:8000/agents | python -m json.tool
curl -s http://127.0.0.1:8000/agents/agent-42/timeline | python -m json.tool
curl -s http://127.0.0.1:8000/agents/agent-42/processes | python -m json.tool
curl -s http://127.0.0.1:8000/agents/agent-42/security-events | python -m json.tool
curl -s http://127.0.0.1:8000/agents/agent-42/correlations | python -m json.tool
curl -s 'http://127.0.0.1:8000/events?severity=HIGH' | python -m json.tool
curl -s http://127.0.0.1:8000/metrics | python -m json.tool
```

## Performance and scalability

Current behavior:

- kernel-space root-tree filtering;
- bounded LRU maps for pending state;
- bounded 4 MiB ring buffer;
- bounded userspace queue;
- batched queue polling;
- sequence-gap and explicit drop metrics;
- append-only thread-safe persistence;
- deep API snapshots for consistent reads;
- deterministic event IDs and idempotent AgentSight imports.

Under load, inspect first:

```text
kernel_ringbuf_drops
estimated_sequence_drops
userspace_queue_drops
missing_*_pending
state-map failure counters
queue depth
JSON decode/validation failures
runtime persistence errors
```

Production improvements should be driven by measurement and may include:

- ring-buffer sizing from burst-rate benchmarks;
- separate smaller native record layouts for non-exec events;
- cgroup, mount namespace, and PID-namespace identity;
- multiple concurrent session roots;
- asynchronous batched or database persistence;
- a durable queue and an explicit backpressure policy;
- Prometheus/OpenTelemetry metrics;
- rate limiting or aggregation for low-value file telemetry while preserving alerts;
- `writev`, `pwrite*`, `rename*`, `truncate*`, `send*`, UDP, and accepted-socket coverage;
- descriptor-table propagation or kernel file-object identity;
- fork/exec storms, descriptor churn, and network-burst benchmarks;
- verifier and integration CI across supported kernel versions.

## Limitations and assumptions

- The privileged object must still be compiled, verifier-loaded, attached, and executed on the target kernel. Static C checks cannot substitute for the kernel verifier.
- The primary required event is process execution. File and network coverage is intentionally useful but not a complete VFS or network audit implementation.
- File hooks cover `openat`, optional `openat2`, `write`, successful `close`, `unlink`, and `unlinkat`; they do not cover every mutation syscall.
- `write` can target a regular file, pipe, device, or socket. The event keeps descriptor/path evidence; production classification would inspect kernel file type or a richer VFS hook.
- Inherited/pre-existing descriptor writes are emitted, but `/proc/<pid>/fd/<fd>` resolution can fail if the descriptor closes or the process exits before userspace handles the record.
- A relative path can remain unresolved if the process exits before cwd/dirfd resolution.
- Network coverage is IPv4/IPv6 `connect`; it does not capture DNS semantics, UDP sends, accepted sockets, or payloads.
- Arguments and paths are bounded; truncation is explicit.
- Existing-process attachment cannot reconstruct events that happened before attachment. The ancestry fallback is bounded to 16 parent levels.
- PID/start-time identity is host-oriented. PID namespaces, time namespaces, and cgroups need additional production identity rules.
- Concurrent exec attempts from multiple threads of one TGID can overwrite the single pending-exec record; successful command capture is designed for normal agent process behavior.
- AgentSight schemas can evolve. The semantic importer preserves raw records and reports unrecognized/malformed records, but new upstream field names may require aliases.
- Late LLM imports backfill in-memory API correlations. Previously appended JSONL source records remain immutable; a production store would persist separate correlation-update/materialized-view records.
- JSONL locking is process-local and synchronous. Multiple writer processes or high-volume durability require a database or durable queue.
- The local API has no authentication or TLS. Bind to loopback for assessment use; add authentication, authorization, encryption, retention, and redaction in production.
- Correlation is temporal/session-based evidence, not semantic or causal proof.
- The sensor detects and reports; it does not block actions.

## Requirement traceability

| Requirement | Main implementation |
|---|---|
| Architecture description | this README |
| eBPF programs/probes | `src/ebpf/probe.c` |
| Shared event model | `src/ebpf/event.h` |
| Ring-buffer collection | `src/ebpf/native/collector.c`, `src/collector/live_ebpf.py` |
| Userspace normalization | `src/collector/collector.py` |
| Agent/session identification | `src/models/session.py`, `src/collector/runtime.py`, `src/service.py` |
| AgentSight and LLM integration | `src/integrations/agentsight.py` |
| Sensitive-action detection | `src/collector/security.py` |
| Persistence/export | `src/storage/jsonl.py` |
| Backend API | `src/api/server.py` |
| Reproducible demonstration | `scripts/demo_agent.py`, `scripts/demo_live.py` |
| Live API runner | `scripts/run_live_api.py` |
| Automated tests | `tests/` |
| Performance, assumptions, improvements | this README |

## Cleanup

```bash
make clean
```

This removes generated build output, caches, coverage files, and runtime artifacts while preserving source and tests.

## License

See `LICENSE`.
