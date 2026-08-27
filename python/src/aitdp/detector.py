"""Detector interface (SPEC §4)."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable

from .models import Context, DetectorInfo, Message, Stage, ThreatEvent

log = logging.getLogger("aitdp")

ALL_STAGES: frozenset[str] = frozenset(s.value for s in Stage)


class Detector(ABC):
    """Base class for all detectors.

    Subclasses implement :meth:`detect`. Errors raised inside ``detect`` are caught by the
    pipeline (SPEC §4: a detector must never raise on untrusted input).
    """

    #: Unique detector name, e.g. ``"aitdp.rules"``.
    name: str = "aitdp.detector"
    #: Detector version string.
    version: str = "0.0.0"
    #: Stages this detector wants to see. ``ALL_STAGES`` by default.
    stages: frozenset[str] = ALL_STAGES

    @abstractmethod
    def detect(self, message: Message, context: Context) -> list[ThreatEvent]:
        """Inspect ``message`` and return zero or more threat events."""

    def supports(self, stage: str) -> bool:
        return stage in self.stages

    @property
    def info(self) -> DetectorInfo:
        return DetectorInfo(name=self.name, version=self.version)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<{type(self).__name__} {self.name}@{self.version}>"


DetectFn = Callable[[Message, Context], Iterable[ThreatEvent]]


class CallableDetector(Detector):
    """Wrap a plain function ``(message, context) -> Iterable[ThreatEvent]`` as a detector."""

    def __init__(
        self,
        fn: DetectFn,
        *,
        name: str,
        version: str = "0.0.0",
        stages: Iterable[str] | None = None,
    ) -> None:
        self._fn = fn
        self.name = name
        self.version = version
        self.stages = frozenset(str(s) for s in stages) if stages else ALL_STAGES

    def detect(self, message: Message, context: Context) -> list[ThreatEvent]:
        return list(self._fn(message, context))


__all__ = ["ALL_STAGES", "CallableDetector", "DetectFn", "Detector"]
