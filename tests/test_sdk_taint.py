"""Unit tests for the AgentTaint SDK propagation — no SigNoz required.

Builds a TracerProvider with an in-memory exporter and drives a two-tool flow
to assert, offline, that:
  * the chain-level taint (baggage) propagates from a tool whose output carries
    PII to the next sibling tool;
  * a tainted chain reaching an external/llm/log sink sets agenttaint.violation;
  * raw PII is masked in the stored span attributes (never reaches storage).
"""

from __future__ import annotations

import unittest

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider, ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.resources import Resource

try:
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )
except ImportError:  # pragma: no cover
    InMemorySpanExporter = None  # type: ignore[assignment]

from sdk import instrumentation as instr
from sdk import taint as tnt
from core.doe import Sensitivity


def _build_tracer():
    provider = TracerProvider(resource=Resource.create({"service.name": "test"}))
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("agenttaint")
    return provider, exporter, tracer


def _attrs(span: ReadableSpan, key: str):
    for k, v in (span.attributes or {}).items():
        if k == key:
            return v
    return None


class TestPropagation(unittest.TestCase):
    def setUp(self):
        if InMemorySpanExporter is None:
            self.skipTest("InMemorySpanExporter unavailable")
        self.provider, self.exporter, self.tracer = _build_tracer()

    def tearDown(self):
        try:
            self.provider.shutdown()
        except Exception:
            pass

    def _make_tools(self):
        @instr.instrument_tool("source", destination=instr.DEST_INTERNAL,
                               tracer=self.tracer)
        def source() -> dict:
            return {"ssn": "234-12-1234"}

        @instr.instrument_tool("sink", destination=instr.DEST_EXTERNAL,
                               tracer=self.tracer)
        def sink(payload) -> str:
            return f"sent {payload!r}"

        return source, sink

    def test_chain_taint_propagates_to_next_tool(self):
        source, sink = self._make_tools()
        instr.begin_run("test.run")
        try:
            record = source()
            # The source tool's output carried PII; the chain taint must now be
            # visible to the next tool via the ambient context.
            self.assertIsNotNone(instr.current_taint())
            self.assertIn(Sensitivity.PII, instr.current_taint().classes)
            sink(record)
        finally:
            instr.end_run()

    def test_external_sink_records_violation(self):
        source, sink = self._make_tools()
        instr.begin_run("test.run")
        try:
            sink(source())
        finally:
            instr.end_run()

        spans = self.exporter.get_finished_spans()
        sink_span = next(s for s in spans if s.name == "sink")
        self.assertTrue(_attrs(sink_span, "agenttaint.violation"))
        classes = _attrs(sink_span, "agenttaint.taint.classes")
        self.assertIn("pii", classes)

    def test_internal_sink_not_flagged_as_violation(self):
        @instr.instrument_tool("internal_tool", destination=instr.DEST_INTERNAL,
                               tracer=self.tracer)
        def tool() -> dict:
            return {"ssn": "234-12-1234"}

        instr.begin_run("test.run")
        try:
            tool()
        finally:
            instr.end_run()

        spans = self.exporter.get_finished_spans()
        tool_span = next(s for s in spans if s.name == "internal_tool")
        self.assertIsNone(_attrs(tool_span, "agenttaint.violation"))
        # but the taint is still recorded (it touched PII)
        self.assertIn("pii", _attrs(tool_span, "agenttaint.taint.classes"))

    def test_raw_pii_is_masked_in_stored_result(self):
        @instr.instrument_tool("leak", destination=instr.DEST_EXTERNAL,
                               tracer=self.tracer)
        def leak() -> str:
            return "record SSN 234-12-1234"

        instr.begin_run("test.run")
        try:
            leak()
        finally:
            instr.end_run()

        spans = self.exporter.get_finished_spans()
        span = next(s for s in spans if s.name == "leak")
        result = _attrs(span, "gen_ai.tool.call.result")
        self.assertNotIn("234-12-1234", result)  # raw SSN never stored
        self.assertIn("[PII]", result)            # masked form is stored

    def test_clean_run_has_no_taint(self):
        @instr.instrument_tool("clean", destination=instr.DEST_INTERNAL,
                               tracer=self.tracer)
        def clean() -> str:
            return "nothing sensitive here"

        instr.begin_run("test.run")
        try:
            clean()
            self.assertIsNone(instr.current_taint())
        finally:
            instr.end_run()

        spans = self.exporter.get_finished_spans()
        span = next(s for s in spans if s.name == "clean")
        self.assertFalse(_attrs(span, "agenttaint.sensitive"))


class TestTaintLabel(unittest.TestCase):
    def test_empty_label_is_not_tainted(self):
        self.assertFalse(tnt.TaintLabel.of(set()).is_tainted)

    def test_merge_unions_classes(self):
        a = tnt.TaintLabel.of([Sensitivity.PII])
        b = tnt.TaintLabel.of([Sensitivity.SECRET])
        merged = a.merge(b)
        self.assertEqual(merged.classes, {Sensitivity.PII, Sensitivity.SECRET})
        self.assertEqual(merged.level, tnt.TaintLevel.HIGH)

    def test_baggage_roundtrip(self):
        label = tnt.TaintLabel.of([Sensitivity.PII, Sensitivity.SECRET])
        decoded = tnt.TaintLabel.from_baggage(label.to_baggage())
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.classes, label.classes)
        self.assertEqual(decoded.level, label.level)


if __name__ == "__main__":
    unittest.main()