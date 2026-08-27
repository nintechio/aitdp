"""Adapter for `llm-guard <https://github.com/protectai/llm-guard>`_ input scanners.

Install with ``pip install 'aitdp[llm-guard]'``.

Example::

    from llm_guard.input_scanners import PromptInjection
    from aitdp.adapters.llm_guard import LLMGuardDetector

    det = LLMGuardDetector([PromptInjection()])
    pipeline = Pipeline.default().add(det)
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..detector import Detector
from ..models import Action, Category, Context, Evidence, Message, References, Severity, ThreatEvent

_CATEGORY_MAP: dict[str, tuple[Category, list[str]]] = {
    "PromptInjection": (Category.prompt_injection, ["LLM01"]),
    "Jailbreak": (Category.jailbreak, ["LLM01"]),
    "Secrets": (Category.sensitive_data_leak, ["LLM02"]),
    "Anonymize": (Category.sensitive_data_leak, ["LLM02"]),
    "Sensitive": (Category.sensitive_data_leak, ["LLM02"]),
    "Code": (Category.insecure_output, ["LLM05"]),
    "InvisibleText": (Category.obfuscation, ["LLM01"]),
    "TokenLimit": (Category.resource_abuse, ["LLM10"]),
    "BanSubstrings": (Category.policy_violation, []),
    "BanTopics": (Category.policy_violation, []),
    "Toxicity": (Category.policy_violation, []),
}


class LLMGuardDetector(Detector):
    """Run one or more llm-guard scanners and emit AITDP events for failures."""

    name = "llm_guard"
    version = "adapter-0.1.0"

    def __init__(
        self,
        scanners: Iterable[Any],
        *,
        stages: Iterable[str] = ("user_input", "retrieved_content", "tool_output"),
        severity: Severity = Severity.high,
        action: Action = Action.block,
    ) -> None:
        self.scanners = list(scanners)
        self.stages = frozenset(stages)
        self.severity = severity
        self.action = action
        try:  # pragma: no cover - optional dependency
            import llm_guard  # noqa: F401

            self.version = f"adapter-0.1.0/llm-guard-{getattr(llm_guard, '__version__', '?')}"
        except ImportError as exc:  # pragma: no cover
            raise ImportError("llm-guard is not installed: pip install 'aitdp[llm-guard]'") from exc

    def detect(self, message: Message, context: Context) -> list[ThreatEvent]:
        text = message.searchable_text()
        events: list[ThreatEvent] = []
        for scanner in self.scanners:
            sname = type(scanner).__name__
            sanitized, is_valid, risk = scanner.scan(text)
            if is_valid:
                continue
            category, owasp = _CATEGORY_MAP.get(sname, (Category.other, []))
            events.append(
                ThreatEvent(
                    category=category,
                    severity=self.severity,
                    confidence=max(0.0, min(1.0, float(risk))),
                    stage=message.stage_name,
                    title=f"llm-guard {sname} flagged content",
                    detector=self.info,
                    evidence=[Evidence(match=sname, note=f"risk_score={risk}")],
                    references=References(owasp_llm=owasp),
                    recommended_action=self.action,
                    metadata={"scanner": sname, "sanitized_differs": sanitized != text},
                )
            )
        return events


__all__ = ["LLMGuardDetector"]
