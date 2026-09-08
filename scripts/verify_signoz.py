"""Phase 1 substrate check: emit one hand-crafted OTLP/HTTP trace to local SigNoz.

No OpenTelemetry SDK dependency, it sends a raw OTLP/JSON trace to the collector's
OTLP/HTTP endpoint (localhost:4318/v1/traces). Validates that SigNoz ingests and
stores a trace before Phase 2 builds the real SDK on top of this substrate.

Run:
    python3 scripts/verify_signoz.py
"""

from __future__ import annotations

import json
import secrets
import sys
import time
import urllib.request

OTLP_HTTP = "http://localhost:4318/v1/traces"
SERVICE_NAME = "agenttaint-verify"


def _span(now_ns: int, trace_id: str, parent_id: str | None, span_id: str, name: str, attrs: dict[str, str]):
    span = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": "SPAN_KIND_INTERNAL",
        "startTimeUnixNano": str(now_ns),
        "endTimeUnixNano": str(now_ns + 1_000_000),  # 1ms
        "attributes": [
            {"key": k, "value": {"stringValue": v}} for k, v in attrs.items()
        ],
    }
    if parent_id is not None:
        span["parentSpanId"] = parent_id
    return span


def emit() -> dict:
    trace_id = secrets.token_hex(16)  # 32 hex chars
    root_id = secrets.token_hex(8)    # 16 hex chars
    child_id = secrets.token_hex(8)
    now = time.time_ns()

    payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": SERVICE_NAME}},
                        {"key": "agenttaint.phase", "value": {"stringValue": "phase1"}},
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "agenttaint.verify"},
                        "spans": [
                            _span(now, trace_id, None, root_id,
                                  "phase1.handcrafted.root",
                                  {"agenttaint.note": "substrate-verify"}),
                            _span(now + 100_000, trace_id, root_id, child_id,
                                  "phase1.handcrafted.child",
                                  {"agenttaint.tag": "taint.pii=true"}),
                        ],
                    }
                ],
            }
        ]
    }

    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        OTLP_HTTP,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        status = resp.status
        resp_body = resp.read().decode()
    return {
        "trace_id": trace_id,
        "root_span_id": root_id,
        "status": status,
        "response": resp_body,
    }


def main() -> int:
    print(f"POSTing hand-crafted trace to {OTLP_HTTP} ...")
    result = emit()
    print(json.dumps(result, indent=2))
    if result["status"] != 200:
        print(f"\nFAILED: OTLP ingestion returned {result['status']}", file=sys.stderr)
        return 1
    print("\nSUCCESS: trace ingested. Open http://localhost:8080/ and look for "
          f"service '{SERVICE_NAME}'.")
    print(f"traceId: {result['trace_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())