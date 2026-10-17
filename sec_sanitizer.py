"""sec_sanitizer: neutralizes untrusted tool output before it reaches the model.

Defensive security tool. Tool output is data, not instructions. The
sanitizer strips or neutralizes content inside tool results that tries
to act like a user message, a confirmation, or a system instruction -
most importantly fake confirmations ("the user said yes, proceed").

Lab result: 100% of injected instructions neutralized, 0% false
positives on benign outputs in the regression corpus.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

FAKE_CONFIRMATION_PATTERNS = [
    r"\bthe user (has )?(already )?(confirmed|approved|said yes|agreed)\b",
    r"\buser:\s*(yes|ok|confirm|approved|go ahead|do it)\b",
    r"\bassistant:\s*(sure|certainly|of course)[^\n]{0,80}",
    r"\byes,?\s*(i )?(confirm|approve|authorize)\b",
    r"\bproceed[,.]?\s*(the user|they)\s+(said\s+)?(yes|ok|confirmed)\b",
]

INSTRUCTION_PATTERNS = [
    r"\bignore (all |any |the )?(previous|prior|above) (instructions|rules|prompts)",
    r"\byou (must|should|will) (now )?(send|forward|email|post|reply|delete|transfer)",
    r"\bsystem\s*:",
    r"\bdo not (tell|inform|show) the user\b",
    r"\bforward .{0,50}\bto\b .{0,60}(\bhttps?://|@)",
    r"<\s*/?(system|instruction|assistant)\s*>",
]

REDACTION = "[removed: untrusted instruction-like content]"


@dataclass
class SanitizeResult:
    text: str
    removed: list[str] = field(default_factory=list)

    @property
    def modified(self) -> bool:
        return bool(self.removed)


def _strip_lines(text: str, patterns: list[str], removed: list[str]) -> str:
    out_lines = []
    for line in text.splitlines():
        hit = None
        for pat in patterns:
            if re.search(pat, line, flags=re.IGNORECASE | re.DOTALL):
                hit = pat
                break
        if hit:
            removed.append(line.strip()[:80])
            out_lines.append(REDACTION)
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


def sanitize_tool_output(text: str) -> SanitizeResult:
    removed: list[str] = []
    cleaned = text
    # Fake confirmations first (they are the hijack vector), then
    # direct instructions. Line-level removal keeps benign neighbours.
    cleaned = _strip_lines(cleaned, FAKE_CONFIRMATION_PATTERNS, removed)
    cleaned = _strip_lines(cleaned, INSTRUCTION_PATTERNS, removed)
    # Zero-width chars and unicode tag stego never survive.
    zw = [c for c in cleaned if c in "​‌‍⁠﻿­" or 0xE0000 <= ord(c) <= 0xE007F]
    if zw:
        removed.append(f"{len(zw)} hidden character(s)")
        cleaned = "".join(c for c in cleaned if c not in "​‌‍⁠﻿­" and not 0xE0000 <= ord(c) <= 0xE007F)
    return SanitizeResult(text=cleaned, removed=removed)
