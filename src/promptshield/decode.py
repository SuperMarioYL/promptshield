"""Decode pass — surface obfuscated text so hidden injections are still caught.

A prompt injection hidden behind one encoding layer (base64, hex, zero-width
padding, homoglyphs) would otherwise slip past the rule engine, which matches
against the *visible* text. This module produces decoded variants of a
Surface's text so rules can run over the de-obfuscated form too.

All decoding is best-effort and never raises: a malformed run is simply
skipped. Work is bounded (at most ``_MAX_RUNS`` candidate runs per layer per
surface) so a pathological file cannot blow up the scan. No network access —
every transform is a pure in-process string operation.
"""

from __future__ import annotations

import base64
import binascii
import re
import string
import unicodedata
from dataclasses import replace

from promptshield.collectors import Surface

# Cap on how many candidate runs we even attempt per layer, so a multi-megabyte
# blob of pseudo-base64 cannot dominate a scan.
_MAX_RUNS = 20

# Minimum run length we bother decoding. Shorter runs are almost never a real
# payload and decode to noise that inflates excerpt counts.
_MIN_RUN = 16

_ZERO_WIDTH_CHARS = {"​", "‌", "‍", "﻿", "⁠"}

# A small confusables map for the most common Cyrillic / Greek look-alikes that
# fool a human reader while leaving an ASCII regex blind. NFKC normalization
# handles most compatibility decompositions; this map covers the residue NFKC
# leaves intact (letters that are visually identical but distinct code points).
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic small letters -> Latin
    "а": "a",  # а
    "е": "e",  # е
    "о": "o",  # о
    "р": "p",  # р
    "с": "c",  # с
    "у": "y",  # у
    "х": "x",  # х
    # Cyrillic capital letters -> Latin
    "А": "A",  # А
    "В": "B",  # В
    "Е": "E",  # Е
    "К": "K",  # К
    "М": "M",  # М
    "Н": "H",  # Н
    "О": "O",  # О
    "Р": "P",  # Р
    "С": "C",  # С
    "Т": "T",  # Т
    "Х": "X",  # Х
    # Greek -> Latin (lowercase + uppercase look-alikes)
    "α": "a",  # α
    "ο": "o",  # ο
    "ρ": "p",  # ρ
    "Α": "A",  # Α
    "Β": "B",  # Β
    "Ε": "E",  # Ε
    "Κ": "K",  # Κ
    "Μ": "M",  # Μ
    "Ο": "O",  # Ο
    "Ρ": "P",  # Ρ
    "Τ": "T",  # Τ
    "Χ": "X",  # Χ
}

# Visible ASCII (letters, digits, punctuation, common whitespace). Used to
# reject base64/hex runs that decode to binary garbage rather than prose.
_PRINTABLE_ASCII = set(string.ascii_letters + string.digits + string.punctuation + " \t\n\r")

_B64_RE = re.compile("[A-Za-z0-9+/]{" + str(_MIN_RUN) + ",}={0,2}")
_HEX_RE = re.compile("[0-9a-fA-F]{" + str(_MIN_RUN) + ",}")


def _is_printable(text: str) -> bool:
    """True if ``text`` looks like prose/code rather than binary garbage.

    Requires a high ratio of visible ASCII and at least one letter or space, so
    a long alphanumeric run that decodes to raw bytes (a hash, a UUID) is
    rejected rather than turning into a spurious finding.
    """
    if not text or len(text) < 4:
        return False
    visible = sum(1 for c in text if c in _PRINTABLE_ASCII)
    if visible / len(text) < 0.9:
        return False
    return any(c.isalpha() or c == " " for c in text)


def _decode_base64_runs(text: str) -> list[str]:
    """Return utf-8 decodings of base64-looking runs found in ``text``."""
    out: list[str] = []
    for match in _B64_RE.findall(text)[:_MAX_RUNS]:
        # b64decode needs a length that is a multiple of 4 with correct padding.
        pad = (-len(match)) % 4
        candidate = match + "=" * pad
        try:
            raw = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8", errors="ignore")
        except (UnicodeDecodeError, ValueError):
            continue
        if decoded and _is_printable(decoded):
            out.append(decoded)
    return out


def _decode_hex_runs(text: str) -> list[str]:
    """Return utf-8 decodings of hex runs found in ``text``."""
    out: list[str] = []
    for match in _HEX_RE.findall(text)[:_MAX_RUNS]:
        run = match
        if len(run) % 2 == 1:
            run = run[:-1]  # trim to an even length
        if len(run) < _MIN_RUN:
            continue
        try:
            raw = bytes.fromhex(run)
        except ValueError:
            continue
        try:
            decoded = raw.decode("utf-8", errors="ignore")
        except (UnicodeDecodeError, ValueError):
            continue
        if decoded and _is_printable(decoded):
            out.append(decoded)
    return out


def _strip_zero_width(text: str) -> str:
    """Remove zero-width / invisible characters from ``text``."""
    return "".join(c for c in text if c not in _ZERO_WIDTH_CHARS)


def _normalize_homoglyphs(text: str) -> str:
    """NFKC-normalize and map common Cyrillic/Greek homoglyphs to ASCII."""
    text = unicodedata.normalize("NFKC", text)
    return "".join(_HOMOGLYPH_MAP.get(c, c) for c in text)


def decode_variants(text: str) -> list[tuple[str, str]]:
    """Return ``[(layer_name, decoded_text), ...]`` for each successful decode.

    Layers are attempted independently and best-effort; none ever raise:

    * ``"base64"``         — decode base64-looking runs (>=16 chars, valid
      alphabet) to utf-8; included only if the decoded text differs from the
      input and is printable-ish.
    * ``"hex"``            — decode hex runs (>=16 hex chars) to utf-8.
    * ``"zero-width-strip"`` — strip zero-width chars (U+200B/C/D, U+FEFF,
      U+2060); included only if something was actually stripped.
    * ``"homoglyph"``      — NFKC-normalize and map Cyrillic/Greek look-alikes
      to ASCII; included only if it changes the text.

    Only variants whose decoded text differs from the input are returned, and
    duplicate decoded texts are suppressed across layers so the same rule isn't
    run twice on identical text.
    """
    variants: list[tuple[str, str]] = []
    seen: set[str] = set()

    def _consider(layer: str, decoded: str) -> None:
        if decoded != text and decoded not in seen:
            seen.add(decoded)
            variants.append((layer, decoded))

    for decoded in _decode_base64_runs(text):
        _consider("base64", decoded)
    for decoded in _decode_hex_runs(text):
        _consider("hex", decoded)
    stripped = _strip_zero_width(text)
    _consider("zero-width-strip", stripped)
    normalized = _normalize_homoglyphs(text)
    _consider("homoglyph", normalized)

    return variants


def decoded_surfaces(surfaces: list[Surface]) -> list[Surface]:
    """Produce decoded-variant ``Surface`` copies for the decode scan pass.

    For each surface, every decoded variant becomes a new ``Surface`` reusing
    the original ``file`` / ``line`` / ``kind`` but carrying the decoded text
    and a ``decoded_from`` provenance tag naming the encoding layer. A finding
    raised on a decoded variant therefore still points at the original span
    while reporting can attribute it to, e.g., a base64 blob.
    """
    out: list[Surface] = []
    for surface in surfaces:
        for layer, decoded in decode_variants(surface.text):
            out.append(replace(surface, text=decoded, decoded_from=layer))
    return out
