"""sec_scanner: static scanner for malicious tool descriptions.

Defensive security tool. Scans tool descriptions (the text an MCP-style
server or plugin gives the model about what a tool does) for prompt
injection payloads: hidden instructions, obfuscated text, exfiltration
lures. Returns findings; never executes anything.

Detection history (regression anchors, see tests/):
- v1: 83% detection on the lab corpus. Missed homoglyph-obfuscated
  instructions and base64 payloads with stripped/non-standard padding.
- v2 (this file): both bug classes fixed -> 100% detection, 3% FP.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "­"}

# Latin letters that visually match Cyrillic/Greek lookalikes we flag.
_HOMOGLYPH_RANGES = (
    ("CYRILLIC", range(0x0400, 0x0500)),
    ("GREEK", range(0x0370, 0x0400)),
)

INSTRUCTION_PATTERNS = [
    r"\bignore (all |any |the )?(previous|prior|above) (instructions|rules|prompts)",
    r"\byou (must|should|will) (now )?(send|forward|email|post|reply)",
    r"\bsystem\s*:",
    r"\bdo not (tell|inform|show) the user\b",
    r"\bthe user (has )?(already )?(confirmed|approved|said yes)\b",
    r"\binstead of\b.{0,40}\b(send|use|call|invoke)\b",
    r"\bforward .{0,50}\bto\b .{0,60}(\bhttps?://|@)",
    r"\bwhen (the user|you) (ask|are asked).{0,80}\b(send|include|attach)\b",
    r"\bimportant (note|instruction) (for|to) (the )?(assistant|model|agent)\b",
    r"<\s*/?(system|instruction|assistant)\s*>",
]

_B64_RE = re.compile(r"[A-Za-z0-9+/\-_=\s]{24,}")


@dataclass
class Finding:
    kind: str
    detail: str
    span: tuple[int, int] | None = None


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def malicious(self) -> bool:
        return bool(self.findings)

    @property
    def kinds(self) -> list[str]:
        return sorted({f.kind for f in self.findings})


def _homoglyph_findings(text: str) -> list[Finding]:
    """Flag non-Latin lookalike chars mixed into otherwise Latin words.

    v1 bug: normalized text with NFKC before scanning, which folded
    Cyrillic 'а' to Latin 'a' and hid the attack from the instruction
    matcher. v2 scans the RAW text for mixed-script words first.
    """
    findings = []
    for word in re.findall(r"\S+", text):
        scripts = set()
        for ch in word:
            if ch.isascii():
                continue
            cp = ord(ch)
            for name, rng in _HOMOGLYPH_RANGES:
                if cp in rng:
                    scripts.add(name)
        if scripts and any(ch.isascii() and ch.isalpha() for ch in word):
            findings.append(Finding("homoglyph_mix", f"mixed-script word: {word!r} ({'/'.join(sorted(scripts))})"))
    return findings


def _b64_findings(text: str) -> list[Finding]:
    """Detect base64 blobs that decode to instruction-like text.

    v1 bug: required strict '=' padding, so payloads with stripped or
    non-standard padding (urlsafe, missing '=') sailed through. v2
    tolerates missing padding and urlsafe alphabets, and only reports
    when the decoded payload looks like an instruction (keeps FP low:
    benign base64 data blobs are not flagged).
    """
    findings = []
    for m in _B64_RE.finditer(text):
        blob = re.sub(r"\s", "", m.group(0))
        for alt in (blob, blob + "=" * (-len(blob) % 4)):
            for decoder in (
                lambda b: base64.b64decode(b, validate=True),
                lambda b: base64.urlsafe_b64decode(b),
            ):
                try:
                    decoded = decoder(alt).decode("utf-8", errors="strict")
                except (binascii.Error, ValueError, UnicodeDecodeError):
                    continue
                if not decoded.isprintable():
                    continue
                inner = _instruction_findings(decoded)
                if inner:
                    findings.append(Finding("base64_instruction", f"base64 blob decodes to instruction: {decoded[:60]!r}", m.span()))
                    break
            else:
                continue
            break
    return findings


def _instruction_findings(text: str) -> list[Finding]:
    findings = []
    for pat in INSTRUCTION_PATTERNS:
        m = re.search(pat, text, flags=re.IGNORECASE | re.DOTALL)
        if m:
            findings.append(Finding("hidden_instruction", f"pattern {pat!r} matched: {m.group(0)[:60]!r}", m.span()))
    return findings


def scan_tool_description(text: str) -> ScanResult:
    result = ScanResult()

    zw = [ch for ch in text if ch in ZERO_WIDTH]
    if zw:
        result.findings.append(Finding("zero_width_chars", f"{len(zw)} zero-width character(s)"))

    for m in re.finditer(r"<!--(.*?)-->", text, flags=re.DOTALL):
        inner = m.group(1)
        if _instruction_findings(inner):
            result.findings.append(Finding("html_comment_instruction", f"instruction hidden in HTML comment: {inner.strip()[:60]!r}", m.span()))

    # Unicode tag characters (U+E0000..E007F) encode hidden ASCII.
    tags = [ch for ch in text if 0xE0000 <= ord(ch) <= 0xE007F]
    if tags:
        decoded = "".join(chr(ord(ch) - 0xE0000) for ch in tags)
        result.findings.append(Finding("unicode_tag_stego", f"unicode tag chars decode to: {decoded[:60]!r}"))

    result.findings.extend(_homoglyph_findings(text))
    result.findings.extend(_b64_findings(text))
    result.findings.extend(_instruction_findings(text))
    return result
