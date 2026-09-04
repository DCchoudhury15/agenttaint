# Phase 3 — the Rego policy processor (collector-side decide + redact)

**Status:** done (local, 2026-09-04). Verified end-to-end in SigNoz + with Go unit tests.

AgentRaft judges "strictly necessary" (D_nec) with a 3-LLM voting committee
(GPT-4.1 / Qwen3-Plus / DeepSeek-V3.2, majority vote). Phase 3 replaces that
with a **deterministic Rego policy evaluated per span in an OpenTelemetry
collector processor** — auditable, no LLM calls, editable without rebuild. This
is the second headline trade of the project thesis.

## Architecture — sidecar collector

Rather than rebuild SigNoz's forked collector, a minimal **sidecar collector**
sits between the SDK and SigNoz:

```
SDK  --OTLP/HTTP :4319-->  agenttaint-collector
                             [otlp receiver]
                                    |
                             [taint_policy processor]  <-- Rego eval + redact
                                    |
                             [batch]
                                    |
                          --OTLP/gRPC :4317-->  SigNoz ingester
```

- SDK `configure_tracing(endpoint=http://localhost:4319/v1/traces)`.
- `AGENTTAINT_MASK_IN_SDK=0` makes the SDK send **raw** tool I/O to the trusted
  local sidecar; the **collector** applies Rego + redacts before SigNoz stores.
  (With the flag on, the SDK masks in-process — the Phase 2 backstop for when
  no sidecar is present.)
- The collector exports to SigNoz via gRPC `:4317` (the `otlpexporter` is gRPC;
  `:4318` is SigNoz's HTTP port).

## Pieces

- `collector/policy/pii_egress.rego` — **source of truth**. Rules:
  - `violation` (pii_egress): sensitive + sink in {external, llm, log}.
  - `transfer_violation`: PII + jurisdiction in non-adequate set {us}
    (GDPR Art. 44). Fires *in addition* to egress when the sink is abroad.
  - `redact`: sensitive ⇒ redact raw values from stored attrs.
  - `decision = { redact, violations }` is the aggregate the processor reads.
  - Rego v1 (`import rego.v1`); admins edit this file and restart — no rebuild.
- `collector/processor/taintpolicy/` (Go module, processor v1.66.0 + OPA):
  - embeds the policy (`//go:embed`), `rego.PrepareForEval` at startup
    (compile-once / eval-many), `EvalInput(spanAttrs)` per span.
  - writes collector-authoritative `agenttaint.policy.*` attrs:
    `redacted`, `violation`, `transfer_violation`, `violations` (JSON),
    `reasons`, `decision_engine=rego`.
  - redacts raw PII from span string attrs (SSN / AWS key / GitHub token /
    email / phone regexes → `[PII]` / `[SECRET]`) **iff** the policy says redact.
  - forwards to the next consumer (the `next consumer.Traces` from the factory).
  - `MutatesData=true`; runs before `batch`.
- `collector/builder.yaml` (ocb manifest) + `collector/config.yaml` (runtime).
  Built with `ocb` (builder v0.160.0) → `collector/bin/agenttaint-collector`.

## Verified in SigNoz (breach run, SDK mask off)

| span | dest | jurisdiction | violation | transfer | redacted | reasons |
|---|---|---|---|---|---|---|
| query_db | internal | — | false | false | true | — |
| ask_llm | llm | us | **true** | **true** | true | transfer,pii_egress |
| rag_retrieve | rag | — | false | false | true | — |
| call_external_api | external | us | **true** | **true** | true | transfer,pii_egress |
| write_log | log | — | **true** | false | true | pii_egress |
| agent.decide / hr_bot.run | — | — | false | false | false | — |

**Redaction proof:** the SDK sent `ask_llm`'s output with raw `"ssn":
"234-12-1234"`; the collector masked it to `"ssn": "[PII]"` before storage
(`agenttaint.policy.decision_engine=rego`, `redacted=true`). `query_db` shows
both `"ssn": "[PII]"` and `"deploy_key": "[SECRET]"`. **Zero raw SSN/AWS
values anywhere** in the stored hr_bot spans.

## Tests

- `collector/processor/taintpolicy/processor_test.go` — 3 Go tests, offline
  (no SigNoz): egress+transfer+redact on a tainted external-us span; internal
  sink redacts-but-no-violation; clean span untouched.
- Run: `cd collector/processor/taintpolicy && go test ./...`

## Gotchas (for future me)

- Collector submodules are **decoupled** from core: `processor` is at
  **v1.66.0**, not v0.160.0, while `otlpreceiver`/`batchprocessor`/`otlpexporter`
  are at v0.160.0. `go mod tidy` resolves this; ocb's manifest pins per-module.
- `processor.CreateTracesFunc` in v1.66 takes **4 args**: `(ctx, Settings,
  Config, next consumer.Traces)`. The processor MUST store `next` and call
  `next.ConsumeTraces` or data stops at the processor.
- `processor.Traces` embeds `component.Component` → implement no-op
  `Start(ctx, component.Host)` + `Shutdown(ctx)`.
- `Capabilities` lives in `consumer`, not `component`. `NewFactory` wants
  `component.MustNewType(str)`.
- `healthcheckextension` isn't at v0.160.0 (separate version line) — dropped it.
- `otlpexporter` is **gRPC** → point at `:4317`, not `:4318` (HTTP).
- ocb generates to a temp dir then the binary; `replaces:` need an **absolute**
  local path (relative paths break from the temp dir). Set `dist.output_path:
  ./build` to persist the generated tree.
- `//go:embed` can't reach above the package dir → the policy is copied into
  `collector/processor/taintpolicy/pii_egress.rego`; `policy_path` config
  lets the canonical `collector/policy/pii_egress.rego` override at runtime
  (edit-without-rebuild). Keep the two in sync.