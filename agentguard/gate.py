from __future__ import annotations

from dataclasses import dataclass

from .models import Finding


@dataclass(frozen=True)
class GateDecision:
    escalate: bool
    reason: str


def decide(findings: list[Finding], *, llm_verdict: str | None = None,
           has_executable_content: bool = False) -> GateDecision:
    """Route static results to the dynamic stage without executing skill code.

    ``llm_verdict`` is intentionally unused until an LLM review stage exists.
    It is kept as the integration hook for that future stage.
    """
    if not findings or all(item.severity == "INFO" for item in findings):
        if has_executable_content:
            # Static analysis cannot prove an executable skill is clean (hidden payloads, runtime-built
            # code), so a clean static result with scripts still gets runtime verification.
            return GateDecision(True, "No static findings, but the skill ships executable scripts; "
                                      "runtime verification recommended.")
        return GateDecision(False, "No findings above INFO and no executable content; dynamic analysis skipped.")

    categories = [item.category.casefold() for item in findings]
    if any("obfuscat" in category for category in categories):
        return GateDecision(True, "Obfuscation evidence is ambiguous; dynamic analysis required.")

    if any(item.severity == "CRITICAL" for item in findings):
        return GateDecision(False, "CRITICAL static evidence is conclusive; dynamic analysis skipped.")

    high_sources = {item.tool for item in findings if item.severity == "HIGH"}
    if len(high_sources) >= 2:
        return GateDecision(False, "HIGH findings from at least two independent sources are conclusive; dynamic analysis skipped.")

    if any(item.severity == "MEDIUM" for item in findings):
        return GateDecision(True, "MEDIUM evidence is ambiguous; dynamic analysis required.")

    if len(high_sources) == 1:
        return GateDecision(True, "A single HIGH source is ambiguous; dynamic analysis required.")

    return GateDecision(False, "LOW-only evidence did not meet an escalation threshold.")
