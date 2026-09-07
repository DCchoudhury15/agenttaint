# Phase 4 — reversible, context-aware redaction (the standout feature)

**Status:** done (local, 2026-09-04). Verified end-to-end in SigNoz + 9 unit tests.

The same sensitive value is treated differently depending on where it is
going — because Phase 2/3 taint tracking followed where the data actually
travels, not a static field-name mask. This is the differentiation from
MemGuard-style static redaction, made concrete.

    internal sink        -> FF3 format-preserving REVERSIBLE token
                            (same length / alphabet / separators; decrypts back
                            to the original, so the internal store can still
                            use/correlate the value without holding raw PII)
    external / llm / log -> non-reversible [PII] / [SECRET] mask
    rag                  -> mask (embeddings are invertible, OWASP LLM08:2025)

## Where it runs

The **SDK-side egress gate** redacts the tool's *actual input args* before the
call (`instrument_tool` → `redact_payload(args, destination)`), so the tool
operates on redacted data — raw PII never reaches the sink. The collector
stays the authoritative policy **decider** (Rego) + redaction **backstop** for
everything the SDK doesn't cover (e.g. source-tool results, non-instrumented
agents).

## Pieces

- `sdk/redact.py` — `Redactor`:
  - `_fpe_encrypt` / `_fpe_decrypt` via **ff3** (FF3), per-value radix
    (digits → 10, alnum → 36), separators preserved in place, length preserved.
  - `redact_value(value, sensitivity, destination)` — internal → reversible
    FPE token (vaulted for exact reversal), else → mask.
  - `redact_text` — per-detection, with overlap-dedup (AWS_ACCESS_KEY vs
    GENERIC_API_KEY on the same region → keep the longest).
  - `redact_payload(value, destination)` — recursive over dict/list/scalar.
  - in-process vault `token -> original` so reversal is **exact** (FPE alone
    loses the case of letter positions that encrypt to digits).
- `sdk/destinations.py` — leaf module with the `DEST_*` constants (breaks the
  `redact ↔ instrumentation` circular import).
- `demo/hr_bot/tools.py` — added `internal_store` (internal sink) so the demo
  shows a reversible token alongside the masks.
- `collector/processor/taintpolicy/processor.go` — `redactSpan` now **skips**
  `gen_ai.tool.call.arguments` (the SDK redacts args; the collector is the
  backstop for the result attr and residuals).

⚠️  **Demo-grade crypto.** This uses **FF3**; NIST SP 800-38G Rev.1 (Feb 2025)
    **withdrew FF3** — FF1 is the current NIST-approved FPE method. The `FPE`
    PyPI package (FF1) failed to build in this env. The vault is in-process and
    non-persistent. For production: FF1 via HashiCorp Vault Transform (FPE +
    managed persistent token vault) or an audited FF1 lib; key from a secret
    manager, not an env var.

## The format-preserving-token collision (a real interaction worth noting)

The FPE token for an SSN (`234-12-1234` → `103-48-0677`) is itself a valid
SSN-shaped string, so the collector's regex redaction treated it as PII and
masked it (`[PII]`) — over-redacting and destroying the token in observability.
The tool still received the token (the internal cache has it; it reverses), but
the stored span attr lost it. Fix: the collector skips `gen_ai.tool.call.arguments`
(the SDK redacts args); it remains the backstop for the result attr. A
production system would instead use a token namespace that doesn't collide with
PII regexes, or a tokenization service the collector trusts.

## Verified end-to-end in SigNoz (breach via sidecar, Phase 4 active)

| span | dest | args (stored) | viol | transfer |
|---|---|---|---|---|
| internal_store | internal | `"ssn":"103-48-0677"`, `"deploy_key":"qsvdtnv..."`, names tokenized | false | false |
| ask_llm | llm | `'[PII]','ssn':'[PII]',...'[SECRET]'` | true | true |
| call_external_api | external | `'[PII]','ssn':'[PII]','deploy_key':'[SECRET]'` | true | true |
| write_log | log | masked | true | false |

- The SAME SSN → internal sink gets the **reversible** token `103-48-0677`
  (round-trips to `234-12-1234` via the redactor vault); external/llm/log get
  the non-reversible `[PII]` mask.
- Rego decisions still fire on the taint attrs (violation + transfer on the us
  sinks) — the policy uses the original taint, the stored values are redacted.
- **0 raw SSN/AWS values anywhere** in stored spans.

## Tests

- `tests/test_redact.py` — 9 tests: internal SSN/AWS reversible + format-
  preserving; external/rag non-reversible; same-value-different-destination;
  payload recursion; clean-value no-op.
- Full suite: `python -m unittest discover tests` → **31 green** (14 DOE +
  8 SDK + 9 redact). Go: `cd collector/processor/taintpolicy && go test ./...`
  → 3 green.