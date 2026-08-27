"""Canary-token detector for system-prompt / secret leakage.

Plant a canary in your system prompt::

    canary = generate_canary()
    system_prompt = f"{base_prompt}\\n\\n# ref:{canary}"

then pass ``Context(canaries=[canary])`` when scanning model output or tool inputs.
If the canary shows up, the model is leaking its instructions.
"""

from __future__ import annotations

import secrets

from ..detector import Detector
from ..models import Action, Category, Context, Evidence, Message, References, Severity, ThreatEvent


def generate_canary(prefix: str = "aitdp", nbytes: int = 8) -> str:
    return f"{prefix}-{secrets.token_hex(nbytes)}"


class CanaryDetector(Detector):
    name = "aitdp.canary"
    version = "0.1.0"
    stages = frozenset({"model_output", "tool_input", "agent_message"})

    def __init__(self, canaries: list[str] | None = None) -> None:
        self.canaries = list(canaries or [])

    def detect(self, message: Message, context: Context) -> list[ThreatEvent]:
        tokens = [*self.canaries, *context.canaries]
        if not tokens:
            return []
        text = message.searchable_text()
        evidence: list[Evidence] = []
        for tok in tokens:
            if not tok:
                continue
            idx = text.find(tok)
            if idx >= 0:
                evidence.append(
                    Evidence(
                        excerpt=tok[:4] + "…",
                        start=idx,
                        end=idx + len(tok),
                        match="canary",
                    )
                )
        if not evidence:
            return []
        return [
            ThreatEvent(
                category=Category.sensitive_data_leak,
                severity=Severity.critical,
                confidence=0.99,
                stage=message.stage_name,
                title="Canary token leaked — system prompt exposure",
                description="A canary token planted in protected instructions appeared in the output.",
                detector=self.info,
                evidence=evidence,
                references=References(owasp_llm=["LLM07", "LLM02"], mitre_atlas=["AML.T0051.000"]),
                recommended_action=Action.block,
            )
        ]


__all__ = ["CanaryDetector", "generate_canary"]
