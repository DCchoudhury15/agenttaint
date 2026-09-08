"""OTel instrumentation for agent tool calls: the runtime taint tracker.

Wraps each tool call in an OTel span using GenAI semantic conventions
(``gen_ai.tool.*``) and propagates the taint label via OTel baggage. This is
AgentRaft's LA-DTP (runtime taint tracking) on OpenTelemetry, with Φ replaced
by structural baggage propagation plus per-I/O detection re-fire (see
docs/agentraft-mapping.md sections D/E).

Per tool call the wrapper:

1. reads the incoming chain-level taint from baggage,
2. detects sensitive data in the tool's *input* (field-level taint),
3. merges input taint with the chain taint and attaches it to the context so
   nested calls inherit it (this is the value-independent propagation that
   survives any LLM transformation),
4. runs the tool,
5. detects sensitive data in the tool's *output* and merges again,
6. materializes the merged taint as span attributes,
7. stores the tool I/O on the span **masked** so SigNoz never stores raw PII,
8. tags the span with its ``destination`` (internal/external/llm/log/rag) and,
   for external/llm sinks, records an SDK-side egress violation when the chain
   is tainted (the Phase 4 redaction gate hardens this from "record" to "block").

Span *links* model fan-out/fan-in (one parent, many children, cross-trace),
used by the RAG tool's retrieval fan-out in the demo. Parent-child links for
linear flows are automatic via OTel context.
"""

from __future__ import annotations

import functools
import json
import logging
from typing import Any, Callable, Mapping

from opentelemetry import baggage, context as context_api, trace

from sdk import taint as tnt
from sdk.detect import detect_mapping, mask_value, taint_for
from sdk.redact import redact_payload

logger = logging.getLogger("agenttaint.sdk")

DEFAULT_OTLP_HTTP = "http://localhost:4318/v1/traces"

# Destination classes, Phase 3's Rego policy reads these.
from sdk.destinations import (  # noqa: E402 - leaf module to avoid circular imports
    DEST_INTERNAL, DEST_EXTERNAL, DEST_LLM, DEST_LOG, DEST_RAG,
)
# Sinks where raw sensitive data must not land. external/llm leave the system;
# log is routinely shipped to centralized/aggregated stores, so it is a leak
# surface too. Phase 3's Rego is the source of truth and can refine this (e.g.
# an internal-only log may redact-not-violate); the SDK gate is the backstop.
_EGRESS_SINKS = {DEST_EXTERNAL, DEST_LLM, DEST_LOG}

# Span attribute keys.
ATTR_DEST = "agenttaint.destination"
ATTR_JURISDICTION = "agenttaint.jurisdiction"  # GDPR Art. 44 (us|eu|""...)
ATTR_VIOLATION = "agenttaint.violation"
ATTR_TaintSource = "agenttaint.taint.source_span"  # noqa: N816 - keep readable

# When a Phase 3 sidecar collector applies the authoritative Rego redaction,
# set AGENTTAINT_MASK_IN_SDK=0 so the SDK sends raw tool I/O to the trusted
# local sidecar (which redacts before SigNoz). Default "1" masks in-process
# (the Phase 2 behavior, for when no sidecar is present).
import os as _os
MASK_IN_PROCESS = _os.environ.get("AGENTTAINT_MASK_IN_SDK", "1") != "0"
# DLP simulation mode (Phase 6): log the violation but DON'T redact args, an
# audit/dry-run for safe rollout (see what would be flagged before enforcing).
# When set, raw args flow to the tool and a agenttaint.dry_run=true attr is set.
DRY_RUN = _os.environ.get("AGENTTAINT_DRY_RUN", "") != ""


def configure_tracing(
    service_name: str,
    *,
    endpoint: str = DEFAULT_OTLP_HTTP,
    console: bool = False,
) -> trace.Tracer:
    """Set up the global TracerProvider with an OTLP/HTTP exporter to SigNoz.

    Call once at process start. Returns the tracer to pass to ``instrument_tool``
    (or use ``trace.get_tracer(...)`` elsewhere). ``console=True`` adds a
    console exporter for debugging without SigNoz.
    """
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    resource = Resource.create({
        "service.name": service_name,
        "service.namespace": "agenttaint",
    })
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    if console:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)
    return provider.get_tracer("agenttaint")


def _jsonable(obj: Any) -> str:
    """Best-effort JSON serialization for span attributes."""
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except Exception:
        return repr(obj)


def instrument_tool(
    name: str | None = None,
    *,
    destination: str = DEST_INTERNAL,
    jurisdiction: str = "",
    tracer: trace.Tracer | None = None,
):
    """Decorator that wraps a tool function with taint-aware OTel tracing.

    The wrapped function's positional/keyword args are treated as the tool's
    input payload; the return value as the output. The caller may pass an
    extra ``agenttaint_links=[span_context, ...]`` kwarg to add span links
    for fan-out/fan-in (consumed, not forwarded to the tool).
    """
    def decorator(fn: Callable) -> Callable:
        span_name = name or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # Pop our private link contexts (for fan-out/fan-in) before calling.
            link_ctxs = kwargs.pop("agenttaint_links", None) or []
            links = []
            for sc in link_ctxs:
                try:
                    links.append(trace.Link(sc))
                except Exception:
                    pass

            tr = tracer or trace.get_tracer("agenttaint")
            incoming = tnt.current()  # chain-level taint from baggage

            # Field-level taint on the tool's input (computed from the ORIGINAL
            # args so the taint label reflects what was actually requested).
            input_payload = [*args, *kwargs.values()] if (args or kwargs) else []
            in_detections = detect_mapping(input_payload) if input_payload else []
            input_label = taint_for(in_detections)

            # Phase 4 egress gate: redact the tool's ACTUAL input args for this
            # destination BEFORE the call. internal -> reversible FPE token;
            # external/llm/log/rag -> non-reversible mask. The tool operates on
            # redacted data, so raw PII never reaches the sink. The collector
            # remains the authoritative policy decider + redaction backstop.
            # DLP simulation mode (DRY_RUN) skips redaction (audit-only).
            if DRY_RUN:
                redacted_args, redacted_kwargs = list(args), dict(kwargs)
            else:
                redacted_args = [redact_payload(a, destination) for a in args]
                redacted_kwargs = {k: redact_payload(v, destination) for k, v in kwargs.items()}

            merged_in = (incoming or tnt.TaintLabel.of(set())).merge(input_label)
            # Attach merged taint to the context so nested calls inherit it.
            ctx = tnt.attach(merged_in)

            span_attrs = dict(merged_in.to_span_attrs())
            span_attrs[ATTR_DEST] = destination
            span_attrs[ATTR_JURISDICTION] = jurisdiction
            if merged_in.is_tainted:
                span_attrs[ATTR_TaintSource] = merged_in.source_span_id or ""

            with tr.start_as_current_span(
                span_name,
                kind=trace.SpanKind.INTERNAL,
                context=ctx,
                links=links,
                attributes={
                    "gen_ai.tool.name": span_name,
                    # Store what the tool actually received (already redacted).
                    "gen_ai.tool.call.arguments": _jsonable(
                        {"args": redacted_args, "kwargs": redacted_kwargs}
                    ),
                },
            ) as span:
                # Re-mark chain taint on the span after we have a span id for lineage.
                if merged_in.is_tainted:
                    span.set_attributes(merged_in.to_span_attrs())
                    span.set_attribute(ATTR_TaintSource, merged_in.source_span_id or "")
                span.set_attribute(ATTR_DEST, destination)
                span.set_attribute(ATTR_JURISDICTION, jurisdiction)
                if DRY_RUN:
                    span.set_attribute("agenttaint.dry_run", True)

                try:
                    result = fn(*redacted_args, **redacted_kwargs)
                except Exception as exc:
                    span.record_exception(exc)
                    span.set_attribute("agenttaint.tool.error", str(exc))
                    raise

                # Field-level taint on the tool's output.
                out_detections = detect_mapping([result])
                output_label = taint_for(
                    out_detections,
                    source_span_id=format(span.get_span_context().span_id, "016x"),
                )
                merged_out = merged_in.merge(output_label)
                if merged_out.is_tainted:
                    span.set_attributes(merged_out.to_span_attrs())

                stored_result = mask_value(result) if MASK_IN_PROCESS else result
                span.set_attribute("gen_ai.tool.call.result", _jsonable(stored_result))

                # SDK-side egress gate: the args above were already redacted
                # (Phase 4); this flag records that a tainted chain reached an
                # egress sink, the same policy decision the collector also makes.
                if destination in _EGRESS_SINKS and merged_out.is_tainted:
                    span.set_attribute(ATTR_VIOLATION, True)
                    span.set_attribute(
                        "agenttaint.violation.reason",
                        f"tainted chain reached {destination} sink",
                    )

            # Outside the span: attach the outgoing chain taint to the ambient
            # context so the *next* sibling tool inherits it. This is the
            # value-independent propagation that survives any LLM transformation
            # (the tag is not tied to the secret's surface form). Tokens are
            # tracked so end_run() can reset between independent agent runs.
            if merged_out.is_tainted:
                _attach_outgoing(merged_out)

            return result

        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Run scoping: one trace per run, clean taint slate per run
# ---------------------------------------------------------------------------

_ATTACH_TOKENS: list = []   # context_api.attach tokens, for end_run reset
_ROOT_SPANS: list = []      # root spans to end on end_run


def begin_run(name: str = "agent.run") -> object:
    """Start a run: attach a root span as current so every tool span in the
    run shares one trace, and reset the taint slate. Pair with ``end_run()``.
    """
    _ATTACH_TOKENS.clear()
    _ROOT_SPANS.clear()
    tracer = trace.get_tracer("agenttaint")
    root = tracer.start_span(name, kind=trace.SpanKind.INTERNAL)
    _ROOT_SPANS.append(root)
    tok = context_api.attach(trace.set_span_in_context(root))
    _ATTACH_TOKENS.append(tok)
    return root


def end_run() -> None:
    """End a run: detach all frames added during the run (clearing taint) and
    end the root span(s)."""
    for tok in reversed(_ATTACH_TOKENS):
        try:
            context_api.detach(tok)
        except Exception:
            pass
    _ATTACH_TOKENS.clear()
    for root in _ROOT_SPANS:
        try:
            root.end()
        except Exception:
            pass
    _ROOT_SPANS.clear()


def _attach_outgoing(label: tnt.TaintLabel) -> None:
    """Attach an outgoing taint label to the ambient context (frame leaks
    forward within the run by design); record the token for ``end_run``."""
    ctx = tnt.attach(label)  # base = current ambient; adds baggage
    tok = context_api.attach(ctx)
    _ATTACH_TOKENS.append(tok)


def current_taint() -> tnt.TaintLabel | None:
    """Convenience: the taint label on the current OTel context."""
    return tnt.current()