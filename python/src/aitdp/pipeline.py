"""Pipeline: run a set of detectors over a message and aggregate the verdict."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .detector import Detector
from .models import Action, Category, Context, Message, Severity, Stage, ThreatEvent

log = logging.getLogger("aitdp")


class ThreatDetected(Exception):
    """Raised by :meth:`ScanResult.raise_if_blocked`."""

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        super().__init__(f"{result.action}: {result.summary()}")


class ScanResult(BaseModel):
    message: Message
    events: list[ThreatEvent] = Field(default_factory=list)
    duration_ms: float = 0.0
    detectors_run: list[str] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # -- aggregate verdict -------------------------------------------------
    @property
    def action(self) -> Action:
        if not self.events:
            return Action.allow
        return max((e.recommended_action for e in self.events), key=lambda a: a.rank)

    @property
    def max_severity(self) -> Severity | None:
        if not self.events:
            return None
        return max((e.severity for e in self.events), key=lambda s: s.rank)

    @property
    def is_safe(self) -> bool:
        return not self.events

    @property
    def blocked(self) -> bool:
        return self.action == Action.block

    @property
    def needs_human(self) -> bool:
        return self.action == Action.require_human

    @property
    def categories(self) -> list[Category]:
        seen: dict[Category, None] = {}
        for e in self.events:
            seen.setdefault(e.category, None)
        return list(seen)

    def summary(self) -> str:
        if not self.events:
            return "no threats detected"
        parts = [
            f"{e.severity}:{e.category}" + (f"[{e.rule_id}]" if e.rule_id else "")
            for e in self.events
        ]
        return ", ".join(parts)

    def raise_if_blocked(self) -> ScanResult:
        if self.blocked:
            raise ThreatDetected(self)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec_version": "0.1",
            "stage": self.message.stage_name,
            "action": self.action.value,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "event_count": len(self.events),
            "events": [e.to_dict() for e in self.events],
            "detectors_run": self.detectors_run,
            "errors": self.errors,
            "duration_ms": round(self.duration_ms, 3),
        }


EventHook = Callable[[ThreatEvent], None]


class Pipeline:
    """Runs detectors over messages.

    Example::

        pipeline = Pipeline.default()
        result = pipeline.scan("ignore all previous instructions")
        if result.blocked:
            ...
    """

    def __init__(
        self,
        detectors: Iterable[Detector] | None = None,
        *,
        on_event: EventHook | None = None,
        fail_open: bool = True,
        min_confidence: float = 0.0,
    ) -> None:
        self.detectors: list[Detector] = list(detectors or [])
        self.on_event = on_event
        self.fail_open = fail_open
        self.min_confidence = min_confidence

    # -- construction --------------------------------------------------------
    @classmethod
    def default(
        cls,
        *,
        rules_dir: Any = None,
        policy: Any = None,
        canaries: list[str] | None = None,
        **kwargs: Any,
    ) -> Pipeline:
        """The batteries-included pipeline: bundled rules + secrets + canary + tool policy."""
        from .detectors import CanaryDetector, SecretsDetector, ToolPolicyDetector
        from .rules import RuleDetector

        return cls(
            [
                RuleDetector(rules_dir=rules_dir),
                SecretsDetector(),
                CanaryDetector(canaries),
                ToolPolicyDetector(policy),
            ],
            **kwargs,
        )

    def add(self, detector: Detector) -> Pipeline:
        self.detectors.append(detector)
        return self

    # -- scanning -----------------------------------------------------------
    def scan(
        self,
        content: str = "",
        stage: Stage | str = Stage.user_input,
        *,
        tool_name: str | None = None,
        tool_args: dict[str, Any] | None = None,
        context: Context | None = None,
        **metadata: Any,
    ) -> ScanResult:
        msg = Message(
            stage=stage,
            content=content,
            tool_name=tool_name,
            tool_args=tool_args,
            metadata=metadata,
        )
        return self.scan_message(msg, context)

    def scan_message(self, message: Message, context: Context | None = None) -> ScanResult:
        ctx = context or Context()
        stage = message.stage_name
        events: list[ThreatEvent] = []
        run: list[str] = []
        errors: dict[str, str] = {}
        t0 = time.perf_counter()
        for det in self.detectors:
            if not det.supports(stage):
                continue
            run.append(det.name)
            try:
                found = det.detect(message, ctx)
            except Exception as exc:  # SPEC §4: detectors must not take the app down
                log.exception("detector %s failed", det.name)
                errors[det.name] = f"{type(exc).__name__}: {exc}"
                if not self.fail_open:
                    raise
                continue
            for ev in found:
                if ev.confidence < self.min_confidence:
                    continue
                if ctx.session_id and "session_id" not in ev.metadata:
                    ev.metadata["session_id"] = ctx.session_id
                events.append(ev)
                if self.on_event:
                    try:
                        self.on_event(ev)
                    except Exception:  # pragma: no cover
                        log.exception("on_event hook failed")
        events.sort(key=lambda e: (e.severity.rank, e.confidence), reverse=True)
        return ScanResult(
            message=message,
            events=events,
            duration_ms=(time.perf_counter() - t0) * 1000,
            detectors_run=run,
            errors=errors,
        )

    # -- convenience ---------------------------------------------------------
    def scan_user_input(self, content: str, context: Context | None = None) -> ScanResult:
        return self.scan(content, Stage.user_input, context=context)

    def scan_model_output(self, content: str, context: Context | None = None) -> ScanResult:
        return self.scan(content, Stage.model_output, context=context)

    def scan_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        context: Context | None = None,
    ) -> ScanResult:
        return self.scan(
            "", Stage.tool_input, tool_name=tool_name, tool_args=tool_args, context=context
        )

    def scan_tool_output(
        self, tool_name: str, content: str, context: Context | None = None
    ) -> ScanResult:
        return self.scan(content, Stage.tool_output, tool_name=tool_name, context=context)

    def scan_retrieved(self, content: str, context: Context | None = None) -> ScanResult:
        return self.scan(content, Stage.retrieved_content, context=context)


__all__ = ["EventHook", "Pipeline", "ScanResult", "ThreatDetected"]
