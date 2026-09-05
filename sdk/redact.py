"""Destination-aware redaction — the Phase 4 standout feature.

The real "context-aware" redaction: the *same* sensitive value is treated
differently depending on where it is going, because Phase 2/3 taint tracking
followed where the data actually travels (not a static field-name mask).

    internal sink        -> format-preserving REVERSIBLE token
                            (the internal store can still use/correlate a value
                            of the same shape/length without holding raw PII;
                            the token reverses back to the original)
    external / llm / log -> non-reversible [PII] / [SECRET] mask
                            (the value must not leave, and cannot be recovered
                            from what is stored)
    rag                  -> mask (embeddings are invertible, OWASP LLM08:2025)

Implementation: FPE generates the format-preserving token (same length,
same alphabet, separators preserved); an in-process vault maps token -> exact
original so reversal is exact (FPE alone loses the case of letter positions
that encrypt to digits). This is FPE + tokenization — the plan's allowed pair.

⚠️  DEMO-GRADE. The FPE here is **FF3**; NIST SP 800-38G Rev.1 (Feb 2025)
    **withdrew FF3** — FF1 is the current NIST-approved method (the `FPE` PyPI
    package, FF1, failed to build in this env). The vault is in-process and
    non-persistent. For production: FF1 via HashiCorp Vault Transform (which
    pairs FPE with a managed, persistent token vault) or an audited FF1 lib,
    and source the key from a secret manager — not an env var.

The key (``AGENTTAINT_FPE_KEY``, 128/192/256-bit hex) must be kept secret.
"""

from __future__ import annotations

import os
import re
import string

from ff3 import FF3Cipher

from core.doe import Sensitivity
from sdk.destinations import DEST_INTERNAL

# Reversible redaction is only for trusted internal sinks. Everything else
# (external/llm/log/rag) gets a non-reversible mask.
_REVERSIBLE_SINKS = {DEST_INTERNAL}

_MASK_TOKEN = {
    Sensitivity.PII: "[PII]",
    Sensitivity.SECRET: "[SECRET]",
}

# Demo key — 128-bit hex. REPLACE for any real use. See module docstring.
_DEFAULT_DEMO_KEY = "EF4359D8D580AA4F7F036D6F04FB771B"
_DEFAULT_TWEAK = "AABBCCDDEEFF0011"  # hex tweak (ff3 requirement)

_ALPHA_RE = re.compile(r"[0-9A-Za-z]")


def _radix_for(s: str) -> int | None:
    """Pick the FF3 radix for the alphabet chars in s, or None if unsupported."""
    alpha = _ALPHA_RE.findall(s)
    if len(alpha) < 2:
        return None  # FF3 needs >= 2 alphabet chars
    if all(c in string.digits for c in alpha):
        return 10
    if all(c in string.digits + string.ascii_letters for c in alpha):
        return 36
    return None


class Redactor:
    """Destination-aware redactor: reversible FPE token for internal, mask elsewhere."""

    def __init__(self, key_hex: str | None = None, tweak_hex: str = _DEFAULT_TWEAK):
        self.key = key_hex or os.environ.get("AGENTTAINT_FPE_KEY") or _DEFAULT_DEMO_KEY
        self.tweak = tweak_hex
        self._ciphers: dict[int, FF3Cipher] = {}
        self._vault: dict[str, str] = {}  # token -> exact original (in-process, demo)

    def _cipher(self, radix: int) -> FF3Cipher:
        if radix not in self._ciphers:
            self._ciphers[radix] = FF3Cipher(self.key, self.tweak, radix=radix)
        return self._ciphers[radix]

    def _fpe_encrypt(self, s: str) -> str | None:
        """Format-preserving encrypt: alphabet chars -> same-length token chars,
        separators kept in place. Output alphabet chars are lowercase (ff3 radix
        36 uses 0-9a-z). Returns None if s can't be FPE'd."""
        radix = _radix_for(s)
        if radix is None:
            return None
        positions = [m.start() for m in _ALPHA_RE.finditer(s)]
        alpha = "".join(s[i] for i in positions).lower()
        try:
            enc = self._cipher(radix).encrypt(alpha)
        except Exception:
            return None
        result = list(s)
        for n, idx in enumerate(positions):
            result[idx] = enc[n]  # lowercase alnum; separators elsewhere untouched
        return "".join(result)

    def _fpe_decrypt(self, token: str) -> str | None:
        """Reverse _fpe_encrypt structurally (lowercase). Used only as a fallback
        when the vault misses (e.g. a token from a prior process)."""
        radix = _radix_for(token)
        if radix is None:
            return None
        positions = [m.start() for m in _ALPHA_RE.finditer(token)]
        alpha = "".join(token[i] for i in positions).lower()
        try:
            dec = self._cipher(radix).decrypt(alpha)
        except Exception:
            return None
        result = list(token)
        for n, idx in enumerate(positions):
            result[idx] = dec[n]
        return "".join(result)

    # --- public API ---

    def redact_value(self, value: str, sensitivity: Sensitivity,
                     destination: str) -> str:
        """Redact one value for a destination.

        internal -> reversible FPE token (vaulted for exact reversal; falls
        back to a mask if FPE can't handle the value); any other sink ->
        non-reversible mask.
        """
        if not sensitivity.is_sensitive or not value:
            return value
        if destination in _REVERSIBLE_SINKS:
            token = self._fpe_encrypt(value)
            if token is not None:
                self._vault[token] = value
                return token
        return _MASK_TOKEN.get(sensitivity, "[REDACTED]")

    def redact_text(self, text: str, detections, destination: str) -> str:
        """Apply redaction to each detected span in text (right-to-left).

        Overlapping detections (e.g. AWS_ACCESS_KEY and GENERIC_API_KEY on the
        same region) are deduped to the longest per region so the output is
        well-formed regardless of how many recognizers match.
        """
        if not text:
            return text
        sens = [d for d in detections if d.is_sensitive]
        # Keep the longest detection at any point; drop spans overlapping a
        # longer, already-kept span.
        sens.sort(key=lambda x: (x.start, -(x.end - x.start)))
        kept: list = []
        for d in sens:
            if kept and d.start < kept[-1].end:
                continue  # overlaps the previous (longer, same-start) kept span
            kept.append(d)
        out = text
        for d in sorted(kept, key=lambda x: x.start, reverse=True):
            original = text[d.start:d.end]
            redacted = self.redact_value(original, d.sensitivity, destination)
            out = out[:d.start] + redacted + out[d.end:]
        return out

    def reverse(self, token: str) -> str | None:
        """Reverse an internal-sink FPE token to the exact original.

        Returns None for masks or unknown tokens. Masks are non-reversible by
        construction — that is the whole point of the external/llm/log path.
        """
        if token in _MASK_TOKEN.values():
            return None
        if token in self._vault:
            return self._vault[token]
        return self._fpe_decrypt(token)  # fallback for digit-only tokens

    def is_reversible(self, destination: str) -> bool:
        return destination in _REVERSIBLE_SINKS


# Module-level singleton used by the SDK egress gate.
_DEFAULT: Redactor | None = None


def get_redactor() -> Redactor:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = Redactor()
    return _DEFAULT


def redact_value(value, sensitivity, destination) -> str:
    return get_redactor().redact_value(value, sensitivity, destination)


def redact_text(text, detections, destination) -> str:
    return get_redactor().redact_text(text, detections, destination)


def redact_payload(value, destination: str, redactor: "Redactor | None" = None):
    """Recursively redact sensitive scalar values in a structured payload
    (dict / list / scalar) for the given destination. Non-sensitive values and
    structure are preserved. Used by the SDK egress gate on tool input args.
    """
    from typing import Mapping
    r = redactor or get_redactor()
    if isinstance(value, str):
        from sdk.detect import detect_text
        ds = detect_text(value)
        if any(d.is_sensitive for d in ds):
            return r.redact_text(value, ds, destination)
        return value
    if isinstance(value, Mapping):
        return {k: redact_payload(v, destination, r) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_payload(v, destination, r) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_payload(v, destination, r) for v in value)
    return value