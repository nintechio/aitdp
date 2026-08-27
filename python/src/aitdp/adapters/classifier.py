"""Generic adapter: turn any ``text -> score`` classifier into an AITDP detector.

Works with HuggingFace pipelines, hosted APIs, or your own model::

    from aitdp.adapters.classifier import ClassifierDetector

    def score(text: str) -> float:      # 0.0 (benign) .. 1.0 (malicious)
        return my_model.predict_proba(text)

    det = ClassifierDetector(score, name="my-injection-model", threshold=0.8)
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from ..detector import Detector
from ..models import Action, Category, Context, Evidence, Message, References, Severity, ThreatEvent


class ClassifierDetector(Detector):
    def __init__(
        self,
        score_fn: Callable[[str], float],
        *,
        name: str,
        version: str = "0.0.0",
        category: Category = Category.prompt_injection,
        threshold: float = 0.5,
        stages: Iterable[str] = ("user_input", "retrieved_content", "tool_output", "agent_message"),
        severity: Severity = Severity.high,
        action: Action = Action.block,
        title: str | None = None,
        owasp: Iterable[str] = ("LLM01",),
        max_chars: int | None = 8000,
    ) -> None:
        self.score_fn = score_fn
        self.name = name
        self.version = version
        self.category = category
        self.threshold = threshold
        self.stages = frozenset(stages)
        self.severity = severity
        self.action = action
        self.title = title or f"{category.value.replace('_', ' ')} detected by {name}"
        self.owasp = list(owasp)
        self.max_chars = max_chars

    def detect(self, message: Message, context: Context) -> list[ThreatEvent]:
        text = message.searchable_text()
        if not text.strip():
            return []
        if self.max_chars:
            text = text[: self.max_chars]
        score = float(self.score_fn(text))
        if score < self.threshold:
            return []
        return [
            ThreatEvent(
                category=self.category,
                severity=self.severity,
                confidence=max(0.0, min(1.0, score)),
                stage=message.stage_name,
                title=self.title[:120],
                detector=self.info,
                evidence=[
                    Evidence(
                        match="classifier", note=f"score={score:.3f} threshold={self.threshold}"
                    )
                ],
                references=References(owasp_llm=self.owasp),
                recommended_action=self.action,
                metadata={"score": score},
            )
        ]


__all__ = ["ClassifierDetector"]
