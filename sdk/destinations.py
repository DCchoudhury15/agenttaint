"""Sink-destination classes shared across the SDK and collector policy.

Kept in a leaf module to avoid circular imports between ``sdk.redact`` and
``sdk.instrumentation``.
"""

DEST_INTERNAL = "internal"
DEST_EXTERNAL = "external"
DEST_LLM = "llm"
DEST_LOG = "log"
DEST_RAG = "rag"