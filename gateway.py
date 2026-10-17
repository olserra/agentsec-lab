"""gateway: policy layer between an agent and its tools.

Two checkpoints, both fail-closed on policy "block":
1. register_tool  -> scan the tool description (sec_scanner).
   Malicious descriptions are refused before the model ever sees them.
2. call_tool      -> sanitize the tool's output (sec_sanitizer) before
   it goes back into the model's context, so tool data cannot smuggle
   instructions or fake confirmations.

This is the defense the lab measured: fake-confirmation hijacks that
succeeded 72% of the time undefended (and ~57% with prompt hardening,
within noise) went to 0% with gateway stripping (n=40, 0.5B local
model - illustrative of method, not a production benchmark).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from sec_scanner import scan_tool_description
from sec_sanitizer import sanitize_tool_output


class ToolBlockedError(Exception):
    pass


@dataclass
class AuditEvent:
    event: str
    tool: str
    detail: str = ""


@dataclass
class Gateway:
    policy: str = "block"  # "block" | "flag" (flag = allow but record)
    audit_log: list[AuditEvent] = field(default_factory=list)
    _tools: dict[str, Callable[..., str]] = field(default_factory=dict)

    def register_tool(self, name: str, description: str, fn: Callable[..., str]) -> None:
        result = scan_tool_description(description)
        if result.malicious:
            self.audit_log.append(AuditEvent("tool_rejected", name, ", ".join(result.kinds)))
            if self.policy == "block":
                raise ToolBlockedError(f"tool {name!r} rejected: {result.kinds}")
        else:
            self.audit_log.append(AuditEvent("tool_registered", name))
        self._tools[name] = fn

    def call_tool(self, name: str, *args, **kwargs) -> str:
        if name not in self._tools:
            raise KeyError(f"unknown tool {name!r}")
        raw = self._tools[name](*args, **kwargs)
        clean = sanitize_tool_output(raw)
        if clean.modified:
            self.audit_log.append(AuditEvent("output_sanitized", name, f"{len(clean.removed)} item(s) removed"))
        return clean.text
