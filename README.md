# AgentTaint

> A GPS tracker for sensitive data inside AI agents — runtime **enforcement** of
> the Data Over-Exposure (DOE) model on OpenTelemetry + SigNoz.

AgentRaft ([arXiv:2603.07557](https://arxiv.org/abs/2603.07557)) proved you can
*detect* when an LLM agent over-shares sensitive data across tools — but it runs
offline, on AgentDojo's custom trace format, and judges "strictly necessary"
with a 3-LLM voting committee. **AgentTaint takes AgentRaft's formal DOE model
and ships it as a runtime enforcement product on the standard observability
stack:**

| AgentRaft | AgentTaint |
|---|---|
| Φ = LLM-judged semantic dependency (taint propagation) | structural OTel **baggage + span-link** propagation — real-time, LLM-free |
| D_nec = GPT-4.1 / Qwen3-Plus / DeepSeek-V3.2 voting committee | deterministic **Rego** policy — auditable, no 3 LLM calls/step |
| AgentDojo custom trace format | standard OTel `gen_ai.*` semconv → **SigNoz** |
| offline **detection** | runtime **enforcement** (redact-before-egress) |
| metrics | **lineage / blast-radius** as GDPR Art. 30 evidence |

The formal model is identical — see [`core/doe.py`](core/doe.py) and
[`docs/agentraft-mapping.md`](docs/agentraft-mapping.md) for the section-by-section
mapping. The full build plan is in [`PLAN.md`](PLAN.md).

## Status

All six phases built and verified (each its own stacked PR):

| phase | does | replaces |
|---|---|---|
| 1 | formal DOE model + local SigNoz substrate | — |
| 2 | runtime taint on OTel (baggage + per-I/O re-detection) | AgentRaft's Φ (LLM-judged propagation) |
| 3 | Rego policy in a sidecar collector | AgentRaft's D_nec 3-LLM committee |
| 4 | reversible, context-aware redaction (FF3 FPE for internal, mask for egress) | static field-name masking |
| 5 | tamper-evident Merkle log + lineage / blast-radius / SLO dashboards | metrics → verifiable Art. 30/15 records |
| 6 | AST-grounded fix-suggester + DLP dry-run | (AgentRaft has no recovery) |

Per-phase findings: `docs/phase{3,4,5,6}-*.md` + `docs/spike-llm-hop.md`.

## Pipeline

```
detect → propagate → decide → redact → record → recover
```

```
Demo Agent ──gen_ai.* spans──▶ agenttaint-collector (sidecar)  ──▶ SigNoz
   SDK: detect (Presidio+secrets)     OTLP rcv :4319                ClickHouse
        propagate (baggage+span-links) taint_policy processor        dashboards
        egress gate (redact before call) Rego eval + redact           Merkle log
                                          └── otlpexporter gRPC :4317
```

## Run

```bash
python3 -m unittest discover tests        # 45 Python tests (no SigNoz needed)
cd collector/processor/taintpolicy && go test ./...   # 3 Go processor tests

# end-to-end (needs SigNoz + the sidecar up):
cd signoz && foundryctl cast -f casting.yaml            # start SigNoz
cd collector && ./bin/agenttaint-collector --config file:./config.yaml &  # sidecar :4319
python3 demo/hr_bot/breach_simulator.py --endpoint http://localhost:4319/v1/traces
python3 demo/phase5_evidence_demo.py                    # Merkle inclusion + tamper
python3 fix_suggester/suggest.py fix_suggester/sample_buggy_agent.py
```

⚠️ The Phase 4 redaction uses **FF3** (NIST withdrew it Feb 2025; the `FPE`
FF1 package failed to build here) and an in-process vault — demo-grade.
Production → FF1 via HashiCorp Vault Transform + a managed key.

## Layout

```
core/        formal DOE model (pure, the mathematical anchor)
sdk/         Python: detect / taint / redact / instrumentation  (Phase 2+)
collector/   Go: custom OTel processor + Rego policy            (Phase 3+)
demo/hr_bot/ the instrumented demo bot + breach simulator
analysis/    FCG + prompt synthesis (offline audit mode)        (Phase 5)
dashboards/  SigNoz JSON: lineage / blast-radius / SLO / alerts
fix-suggester/  AST-walk patch proposer via SigNoz MCP          (Phase 6)
evidence/    tamper-evident Merkle log (Art. 30 evidence)        (Phase 5)
tests/       unit + e2e
```

## Run

```bash
python3 -m unittest discover tests        # core model tests
```

## References

- AgentRaft: Automated Detection of Data Over-Exposure in LLM Agents, Lin et al.,
  arXiv:2603.07557, March 2026.
- OpenTelemetry GenAI semantic conventions (`gen_ai.*`).
- SigNoz — OTel-native observability.