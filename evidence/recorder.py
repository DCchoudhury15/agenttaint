"""Record collector-policy violations from SigNoz/ClickHouse into the Merkle log.

This is the wire from the policy decision (Phase 3 collector) to the evidence
layer (Phase 5): every span the collector flagged ``agenttaint.policy.violation``
becomes a leaf in the tamper-evident log, turning the violation into
cryptographically verifiable GDPR Art. 30/15 evidence.

The query runs via the host's ``docker exec ... clickhouse-client`` (the same
path used throughout the project for inspecting SigNoz). It returns
JSONEachRow so the records parse cleanly.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# add repo root so `evidence.merkle` imports when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evidence.merkle import MerkleLog, violation_record

CONTAINER = "signoz-telemetrystore-clickhouse-0-0"
DATABASE = "signoz_traces"
TABLE = "distributed_signoz_index_v3"

_QUERY = """
SELECT
    trace_id, span_id, name AS tool,
    attributes_string['agenttaint.destination'] AS destination,
    attributes_string['agenttaint.jurisdiction'] AS jurisdiction,
    attributes_string['agenttaint.taint.classes'] AS classes,
    attributes_string['agenttaint.policy.reasons'] AS reasons,
    toInt64(toUnixTimestamp64Nano(timestamp)) AS timestamp_ns
FROM {db}.{tbl}
WHERE serviceName = '{svc}'
  AND attributes_bool['agenttaint.policy.violation'] = 1
  AND timestamp > now() - INTERVAL {mins} MINUTE
FORMAT JSONEachRow
"""


def _query_clickhouse(service: str, since_minutes: int) -> list[dict]:
    q = _QUERY.format(db=DATABASE, tbl=TABLE, svc=service, mins=since_minutes)
    proc = subprocess.run(
        ["docker", "exec", CONTAINER, "clickhouse-client", "-q", q],
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"clickhouse-client failed: {proc.stderr.strip()}")
    rows = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    return rows


def record_violations(log: MerkleLog, *, service: str = "agenttaint-hr-bot",
                      since_minutes: int = 5) -> int:
    """Append every recent collector violation to ``log``. Returns the count."""
    rows = _query_clickhouse(service, since_minutes)
    for r in rows:
        log.append(violation_record(
            trace_id=r["trace_id"], span_id=r["span_id"], tool=r["tool"],
            destination=r["destination"], jurisdiction=r["jurisdiction"],
            classes=r["classes"], reasons=r["reasons"],
            timestamp_ns=int(r["timestamp_ns"]),
        ))
    return len(rows)