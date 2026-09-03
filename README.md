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

Phase 1 — formal core + local SigNoz substrate. See [`PLAN.md`](PLAN.md).

## Pipeline

```
detect → propagate → decide → redact → record → recover
```

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