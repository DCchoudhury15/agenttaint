"""Taint label + OpenTelemetry baggage propagation.

The taint tag is a compact, **non-sensitive** descriptor that rides with data
through the OTel pipeline. It NEVER carries the secret value — only:

    taint.id      a uuid identifying the taint origin
    taint.classes comma-joined sensitivity classes (e.g. ``pii,secret``)
    taint.level   coarse severity (``low`` | ``medium`` | ``high``)

Two propagation layers (see docs/agentraft-mapping.md §D, the core novelty):

1. **Call-chain taint (baggage).** A value-independent flag: "this execution
   chain has touched sensitive data." Because it is not tied to the secret's
   surface form, it survives any LLM transformation by construction — even if
   the LLM reformats, abbreviates, or paraphrases the value, the chain is
   still flagged.

2. **Field-level taint (detection re-fire).** Every tool input/output is
   re-scanned by ``sdk.detect``; specific fields carrying detectable PII get
   labeled. This survives reformatting *iff* the PII stays detectable.

The chain-level tag is a **safe over-approximation**: a PII-touched chain
reaching an external/LLM sink is a violation even when the specific field
can't be pinpointed post-transformation. The residual gap — PII transformed
into a non-detectable form that nonetheless "leaks" semantically — is exactly
where AgentRaft's Φ (LLM-judged semantic dependency) would be needed as a
Phase 6 fall-back. The LLM-hop spike (``spike/llm_hop.py``) demonstrates this.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping

from opentelemetry import baggage

from core.doe import Sensitivity

# Baggage keys (W3C baggage is a flat string→string map; keep keys short).
KEY_ID = "taint.id"
KEY_CLASSES = "taint.classes"
KEY_LEVEL = "taint.level"

# Span attribute prefixes (materialized on spans for SigNoz filtering).
ATTR_ID = "agenttaint.taint.id"
ATTR_CLASSES = "agenttaint.taint.classes"
ATTR_LEVEL = "agenttaint.taint.level"
ATTR_SENSITIVE = "agenttaint.sensitive"  # boolean, for cheap SigNoz filters


class TaintLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @classmethod
    def from_classes(cls, classes: Iterable[Sensitivity]) -> "TaintLevel":
        """Derive a coarse level from the set of sensitivity classes.

        SECRET ⇒ high; PII ⇒ medium; otherwise low.
        """
        s = set(classes)
        if Sensitivity.SECRET in s:
            return cls.HIGH
        if Sensitivity.PII in s:
            return cls.MEDIUM
        return cls.LOW


@dataclass(frozen=True)
class TaintLabel:
    """The non-sensitive taint descriptor that propagates through OTel.

    ``source_span_id`` is carried only for diagnostics/lineage and is not
    serialized into baggage (it would be stale across hops). ``value_fingerprint``
    is an optional short hash of the secret for correlation only — never the
    secret itself.
    """

    id: str
    classes: frozenset[Sensitivity]
    level: TaintLevel
    source_span_id: str | None = None
    value_fingerprint: str | None = None

    @classmethod
    def of(
        cls,
        classes: Iterable[Sensitivity],
        *,
        source_span_id: str | None = None,
        value_fingerprint: str | None = None,
        id: str | None = None,
    ) -> "TaintLabel":
        classes_f = frozenset(c for c in classes if c.is_sensitive)
        return cls(
            id=id or uuid.uuid4().hex,
            classes=classes_f,
            level=TaintLevel.from_classes(classes_f),
            source_span_id=source_span_id,
            value_fingerprint=value_fingerprint,
        )

    @property
    def is_tainted(self) -> bool:
        return bool(self.classes)

    def merge(self, other: "TaintLabel | None") -> "TaintLabel":
        """Merge two labels: union the classes, keep the higher level, keep
        the earliest id (origin) for lineage."""
        if other is None or not other.is_tainted:
            return self
        if not self.is_tainted:
            return other
        merged_classes = self.classes | other.classes
        return TaintLabel(
            id=self.id,  # keep origin
            classes=merged_classes,
            level=TaintLevel.from_classes(merged_classes),
            source_span_id=self.source_span_id,
            value_fingerprint=self.value_fingerprint or other.value_fingerprint,
        )

    # --- baggage (de)serialization ---

    def to_baggage(self) -> Mapping[str, str]:
        """Encode as W3C baggage entries. Never includes the secret."""
        if not self.is_tainted:
            return {}
        return {
            KEY_ID: self.id,
            KEY_CLASSES: ",".join(sorted(c.value for c in self.classes)),
            KEY_LEVEL: self.level.value,
        }

    @classmethod
    def from_baggage(
        cls, bag: Mapping[str, str] | None
    ) -> "TaintLabel | None":
        """Decode a taint label from a baggage map, or ``None`` if absent."""
        if not bag:
            return None
        if KEY_CLASSES not in bag:
            return None
        try:
            classes = frozenset(
                Sensitivity(c) for c in bag[KEY_CLASSES].split(",") if c
            )
        except ValueError:
            return None
        if not classes:
            return None
        level = TaintLevel(bag.get(KEY_LEVEL, TaintLevel.from_classes(classes).value))
        return cls(
            id=bag.get(KEY_ID, uuid.uuid4().hex),
            classes=classes,
            level=level,
        )

    # --- span attributes ---

    def to_span_attrs(self) -> Mapping[str, str | bool]:
        """Materialize the taint as span attributes for SigNoz filtering."""
        if not self.is_tainted:
            return {ATTR_SENSITIVE: False}
        return {
            ATTR_SENSITIVE: True,
            ATTR_ID: self.id,
            ATTR_CLASSES: ",".join(sorted(c.value for c in self.classes)),
            ATTR_LEVEL: self.level.value,
        }


def attach(label: TaintLabel, context=None):
    """Attach a taint label to the OTel context as baggage.

    Returns the new context. Use ``context_api.attach(ctx)`` to make it
    current, or pass it to ``start_as_current_span(context=...)``.
    """
    from opentelemetry import context as context_api

    ctx = context if context is not None else context_api.get_current()
    for k, v in label.to_baggage().items():
        ctx = baggage.set_baggage(k, v, context=ctx)
    return ctx


def current(context=None) -> TaintLabel | None:
    """Read the taint label from the current (or given) OTel context."""
    from opentelemetry import context as context_api

    ctx = context if context is not None else context_api.get_current()
    return TaintLabel.from_baggage(baggage.get_all(ctx))