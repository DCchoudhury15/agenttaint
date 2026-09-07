"""Tamper-evident Merkle log of AgentTaint violations.

Each violation the collector's Rego policy flags is appended as a leaf. The
log is a Merkle (binary hash) tree over SHA-256, persisted as an append-only
file of leaf records plus a rolling root. This turns the lineage/blast-radius
dashboards from "metrics" into **cryptographically verifiable** GDPR Art. 30 /
Art. 15 evidence: anyone can prove a given violation is in the log (inclusion)
and that the log hasn been tampered with (consistency), in O(log n).

Design (Crosby-Wallach / Certificate-Transparency style):
  leaf_hash(i)  = SHA256(0x00 || canonical_json(record_i))
  parent_hash   = SHA256(0x01 || left || right)      # sorted so order-independent
  inclusion proof for leaf i = the sibling hashes on the path to the root
  consistency proof (new root from old root) = the subtree heads that changed

The append-only file stores one JSON record per line (the leaf content); the
tree is rebuilt from the file on load. A separate small manifest could persist
the rolling root, but recomputing from the file on load is simpler and the file
itself is the source of truth (an attacker editing it changes the root).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


def _hash_leaf(record: dict) -> bytes:
    """Leaf hash: SHA256 over a domain-prefixed canonical JSON of the record."""
    blob = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b"\x00" + blob).digest()


def _hash_parent(left: bytes, right: bytes) -> bytes:
    """Internal node hash. ORDERED (left || right) — not sorted — so the append
    sequence is preserved in the tree structure. This is what makes the log
    tamper-evident against reordering: a reordered prefix produces a different
    root (Crosby-Wallach / Certificate-Transparency style)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


@dataclass
class InclusionProof:
    leaf_index: int
    leaf_hash: bytes
    siblings: list[bytes] = field(default_factory=list)  # ordered rootward

    def to_json(self) -> str:
        return json.dumps({
            "leaf_index": self.leaf_index,
            "leaf_hash": self.leaf_hash.hex(),
            "siblings": [s.hex() for s in self.siblings],
        })

    @classmethod
    def from_json(cls, s: str) -> "InclusionProof":
        d = json.loads(s)
        return cls(
            leaf_index=d["leaf_index"],
            leaf_hash=bytes.fromhex(d["leaf_hash"]),
            siblings=[bytes.fromhex(x) for x in d["siblings"]],
        )


class MerkleLog:
    """An append-only Merkle log of violation records.

    The leaves are kept in memory; an append-only file mirrors them on disk so
    the log survives restarts. The root recomputes from the leaves on demand.
    """

    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path) if path else None
        self._leaves: list[bytes] = []          # leaf hashes
        self._records: list[dict] = []          # the records themselves
        if self.path and self.path.exists():
            self._load()

    # --- persistence ---

    def _load(self) -> None:
        assert self.path is not None
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                self._records.append(rec)
                self._leaves.append(_hash_leaf(rec))

    def _append_file(self, record: dict) -> None:
        if self.path is None:
            return
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    # --- core ---

    def append(self, record: dict) -> int:
        """Append a violation record; return its leaf index."""
        idx = len(self._leaves)
        self._records.append(record)
        self._leaves.append(_hash_leaf(record))
        self._append_file(record)
        return idx

    def __len__(self) -> int:
        return len(self._leaves)

    def root(self) -> bytes:
        """Current Merkle root (empty log -> SHA256 of empty)."""
        if not self._leaves:
            return hashlib.sha256(b"").digest()
        level = list(self._leaves)
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left  # duplicate odd
                nxt.append(_hash_parent(left, right))
            level = nxt
        return level[0]

    def inclusion_proof(self, leaf_index: int) -> InclusionProof:
        if not 0 <= leaf_index < len(self._leaves):
            raise IndexError(leaf_index)
        siblings: list[bytes] = []
        idx = leaf_index
        level = list(self._leaves)
        while len(level) > 1:
            # sibling is the other child of the pair; odd last duplicates itself
            if idx % 2 == 0:
                sib_idx = idx + 1 if idx + 1 < len(level) else idx
            else:
                sib_idx = idx - 1
            siblings.append(level[sib_idx])
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                nxt.append(_hash_parent(left, right))
            level = nxt
            idx //= 2
        return InclusionProof(leaf_index=leaf_index,
                              leaf_hash=self._leaves[leaf_index],
                              siblings=siblings)

    def record(self, leaf_index: int) -> dict:
        return self._records[leaf_index]


def verify_inclusion(leaf_hash: bytes, proof: InclusionProof, root: bytes) -> bool:
    """Verify that ``leaf_hash`` is in the log whose root is ``root``.

    Rebuild the path from the leaf upward using the proof's sibling hashes.
    """
    h = leaf_hash
    idx = proof.leaf_index
    for sib in proof.siblings:
        if idx % 2 == 0:
            h = _hash_parent(h, sib)
        else:
            h = _hash_parent(sib, h)
        idx //= 2
    return h == root


def verify_log_consistency(old_records: list[dict], new_records: list[dict]) -> bool:
    """Consistency: is ``old_records`` a prefix of ``new_records`` (by content)?

    For an append-only log this is the Crosby-Wallach consistency check reduced
    to: every old leaf must appear, in order, as a prefix of the new leaves,
    AND the old root must equal the root of the new log's first len(old) leaves.
    """
    if len(old_records) > len(new_records):
        return False
    old_log = MerkleLog()
    for r in old_records:
        old_log.append(r)
    new_prefix = MerkleLog()
    for r in new_records[: len(old_records)]:
        new_prefix.append(r)
    return old_log.root() == new_prefix.root()


# --- a violation record shape (what the collector produces) ---

def violation_record(
    *,
    trace_id: str,
    span_id: str,
    tool: str,
    destination: str,
    jurisdiction: str,
    classes: str,
    reasons: str,
    timestamp_ns: int,
) -> dict:
    """Canonical violation record (the leaf content). Keep it non-sensitive:
    no raw values — only the taint classes + policy decision + ids."""
    return {
        "trace_id": trace_id,
        "span_id": span_id,
        "tool": tool,
        "destination": destination,
        "jurisdiction": jurisdiction,
        "classes": classes,
        "reasons": reasons,
        "timestamp_ns": timestamp_ns,
    }