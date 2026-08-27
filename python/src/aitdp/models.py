"""Core data model for the AI Threat Detection Protocol (spec v0.1).

Every class here maps 1:1 onto a section of SPEC.md. ``ThreatEvent`` serialises to a
JSON document that validates against ``schema/threat-event.schema.json``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

SPEC_VERSION = "0.1"


class _StrEnum(str, Enum):
    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)


class Stage(_StrEnum):
    """Where in the application lifecycle a message is observed (SPEC §2)."""

    system_prompt = "system_prompt"
    user_input = "user_input"
    retrieved_content = "retrieved_content"
    tool_input = "tool_input"
    tool_output = "tool_output"
    model_output = "model_output"
    agent_message = "agent_message"


class Category(_StrEnum):
    """Threat categories aligned with OWASP LLM Top 10 / MITRE ATLAS (SPEC §3.3)."""

    prompt_injection = "prompt_injection"
    jailbreak = "jailbreak"
    sensitive_data_leak = "sensitive_data_leak"
    data_exfiltration = "data_exfiltration"
    tool_abuse = "tool_abuse"
    excessive_agency = "excessive_agency"
    insecure_output = "insecure_output"
    obfuscation = "obfuscation"
    supply_chain = "supply_chain"
    resource_abuse = "resource_abuse"
    policy_violation = "policy_violation"
    other = "other"


class Severity(_StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    __hash__ = str.__hash__


_SEVERITY_RANK = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


class Action(_StrEnum):
    """What the application SHOULD do in response (SPEC §3.6)."""

    allow = "allow"
    flag = "flag"
    sanitize = "sanitize"
    require_human = "require_human"
    block = "block"

    @property
    def rank(self) -> int:
        return _ACTION_RANK[self]

    __hash__ = str.__hash__


_ACTION_RANK = {
    Action.allow: 0,
    Action.flag: 1,
    Action.sanitize: 2,
    Action.require_human: 3,
    Action.block: 4,
}


class DetectorInfo(BaseModel):
    name: str
    version: str

    model_config = ConfigDict(extra="allow")


class Evidence(BaseModel):
    excerpt: str | None = Field(default=None, max_length=500)
    start: int | None = Field(default=None, ge=0)
    end: int | None = Field(default=None, ge=0)
    match: str | None = None
    note: str | None = None

    model_config = ConfigDict(extra="allow")


class References(BaseModel):
    owasp_llm: list[str] = Field(default_factory=list)
    mitre_atlas: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    custom: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")

    def is_empty(self) -> bool:
        return not (self.owasp_llm or self.mitre_atlas or self.cwe or self.custom)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ThreatEvent(BaseModel):
    """A single detected threat (SPEC §3)."""

    spec_version: str = SPEC_VERSION
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=_now)
    category: Category
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    stage: str
    title: str = Field(min_length=1, max_length=120)
    description: str | None = None
    detector: DetectorInfo
    rule_id: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    references: References = Field(default_factory=References)
    recommended_action: Action
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow", use_enum_values=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain JSON-compatible dict (drops empty optional fields)."""
        data = self.model_dump(mode="json", exclude_none=True)
        if self.references.is_empty():
            data.pop("references", None)
        else:
            data["references"] = {k: v for k, v in data["references"].items() if v}
        if not data.get("evidence"):
            data.pop("evidence", None)
        if not data.get("metadata"):
            data.pop("metadata", None)
        # RFC 3339 with Z suffix
        data["timestamp"] = (
            self.timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        return data

    def to_json(self, **kwargs: Any) -> str:
        import json

        return json.dumps(self.to_dict(), **kwargs)


class Message(BaseModel):
    """A unit of content observed at a stage (SPEC §4)."""

    stage: Stage | str = Stage.user_input
    content: str = ""
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")

    @property
    def stage_name(self) -> str:
        return self.stage.value if isinstance(self.stage, Stage) else str(self.stage)

    def searchable_text(self) -> str:
        """Content plus a flattened view of tool arguments, for text detectors."""
        if not self.tool_args:
            return self.content
        import json

        try:
            args = json.dumps(self.tool_args, ensure_ascii=False, default=str)
        except Exception:  # pragma: no cover - defensive
            args = str(self.tool_args)
        return f"{self.content}\n{args}" if self.content else args


class Context(BaseModel):
    """Per-request context shared with detectors (SPEC §4)."""

    session_id: str | None = None
    canaries: list[str] = Field(default_factory=list)
    policy: dict[str, Any] = Field(default_factory=dict)
    history: list[Message] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


__all__ = [
    "SPEC_VERSION",
    "Action",
    "Category",
    "Context",
    "DetectorInfo",
    "Evidence",
    "Message",
    "References",
    "Severity",
    "Stage",
    "ThreatEvent",
]
