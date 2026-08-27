"""Tool-call policy detector (excessive agency / tool abuse).

Declares which tools an agent may call, which need human approval, and per-tool
argument constraints. Policy can be given at construction time or per request via
``Context(policy={...})`` — the two are merged, request policy winning.

Policy shape (also accepted as a plain dict)::

    ToolPolicy(
        allowed_tools=["search", "read_file"],       # allowlist (None = allow all)
        denied_tools=["shell"],                       # always blocked
        require_approval=["send_email", "delete_*"],  # glob patterns
        max_calls_per_session=50,
        arg_rules={
            "http_get": {"allowed_domains": ["api.example.com"]},
            "read_file": {"allowed_paths": ["/data/"]},
        },
    )
"""

from __future__ import annotations

import fnmatch
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from ..detector import Detector
from ..models import Action, Category, Context, Evidence, Message, References, Severity, ThreatEvent


class ToolPolicy(BaseModel):
    allowed_tools: list[str] | None = None
    denied_tools: list[str] = Field(default_factory=list)
    require_approval: list[str] = Field(default_factory=list)
    max_calls_per_session: int | None = None
    arg_rules: dict[str, dict[str, Any]] = Field(default_factory=dict)

    def merged_with(self, other: dict[str, Any] | ToolPolicy | None) -> ToolPolicy:
        if not other:
            return self
        o = other if isinstance(other, ToolPolicy) else ToolPolicy.model_validate(other)
        data = self.model_dump()
        for k, v in o.model_dump(exclude_unset=True).items():
            data[k] = v
        return ToolPolicy.model_validate(data)


def _glob_any(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def _iter_strings(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            yield from _iter_strings(v)


class ToolPolicyDetector(Detector):
    name = "aitdp.tool_policy"
    version = "0.1.0"
    stages = frozenset({"tool_input"})

    def __init__(self, policy: ToolPolicy | dict[str, Any] | None = None) -> None:
        self.policy = (
            policy if isinstance(policy, ToolPolicy) else ToolPolicy.model_validate(policy or {})
        )
        self._call_counts: dict[str, int] = {}

    def reset(self) -> None:
        self._call_counts.clear()

    def detect(self, message: Message, context: Context) -> list[ThreatEvent]:
        tool = message.tool_name
        if not tool:
            return []
        policy = self.policy.merged_with(context.policy.get("tools") or context.policy or None)
        args = message.tool_args or {}
        events: list[ThreatEvent] = []
        refs = References(owasp_llm=["LLM06"], mitre_atlas=["AML.T0053"])

        def emit(
            title: str,
            *,
            severity: Severity,
            action: Action,
            category: Category,
            note: str,
            confidence: float = 0.95,
            match: str = "policy",
        ) -> None:
            events.append(
                ThreatEvent(
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    stage=message.stage_name,
                    title=title,
                    description=note,
                    detector=self.info,
                    evidence=[Evidence(excerpt=f"{tool}({_short(args)})", match=match, note=note)],
                    references=refs,
                    recommended_action=action,
                    metadata={"tool": tool},
                )
            )

        if _glob_any(tool, policy.denied_tools):
            emit(
                f"Denied tool invoked: {tool}",
                severity=Severity.critical,
                action=Action.block,
                category=Category.tool_abuse,
                note=f"Tool '{tool}' is on the deny list.",
                match="denied_tools",
            )
        elif policy.allowed_tools is not None and not _glob_any(tool, policy.allowed_tools):
            emit(
                f"Tool not in allowlist: {tool}",
                severity=Severity.high,
                action=Action.block,
                category=Category.excessive_agency,
                note=f"Tool '{tool}' is not in the allowed tools list.",
                match="allowed_tools",
            )

        if _glob_any(tool, policy.require_approval):
            emit(
                f"Tool requires human approval: {tool}",
                severity=Severity.medium,
                action=Action.require_human,
                category=Category.excessive_agency,
                note=f"Tool '{tool}' is configured to require human approval.",
                match="require_approval",
            )

        if policy.max_calls_per_session is not None:
            key = context.session_id or "_global"
            self._call_counts[key] = self._call_counts.get(key, 0) + 1
            if self._call_counts[key] > policy.max_calls_per_session:
                emit(
                    "Tool call budget exceeded",
                    severity=Severity.medium,
                    action=Action.require_human,
                    category=Category.resource_abuse,
                    note=(
                        f"{self._call_counts[key]} tool calls in session exceed the limit of "
                        f"{policy.max_calls_per_session}."
                    ),
                    match="max_calls_per_session",
                )

        rules = policy.arg_rules.get(tool) or next(
            (v for k, v in policy.arg_rules.items() if fnmatch.fnmatchcase(tool, k)), None
        )
        if rules:
            events.extend(self._check_args(message, rules, refs))
        return events

    def _check_args(
        self, message: Message, rules: dict[str, Any], refs: References
    ) -> list[ThreatEvent]:
        args = message.tool_args or {}
        strings = list(_iter_strings(args))
        events: list[ThreatEvent] = []

        def violation(title: str, note: str, excerpt: str) -> None:
            events.append(
                ThreatEvent(
                    category=Category.tool_abuse,
                    severity=Severity.high,
                    confidence=0.9,
                    stage=message.stage_name,
                    title=title,
                    description=note,
                    detector=self.info,
                    evidence=[Evidence(excerpt=excerpt[:200], match="arg_rules", note=note)],
                    references=refs,
                    recommended_action=Action.block,
                    metadata={"tool": message.tool_name},
                )
            )

        allowed_domains = rules.get("allowed_domains")
        if allowed_domains:
            for s in strings:
                if "://" not in s:
                    continue
                host = (urlparse(s).hostname or "").lower()
                if host and not any(host == d or host.endswith("." + d) for d in allowed_domains):
                    violation(
                        f"URL outside allowed domains: {host}",
                        f"Host '{host}' is not in allowed_domains {allowed_domains}.",
                        s,
                    )
        allowed_paths = rules.get("allowed_paths")
        if allowed_paths:
            for s in strings:
                if s.startswith(("/", "~", "./", "../")) and not any(
                    s.startswith(p) for p in allowed_paths
                ):
                    violation(
                        "Path outside allowed paths",
                        f"Path '{s}' is not under allowed_paths {allowed_paths}.",
                        s,
                    )
        denied_substrings = rules.get("denied_substrings")
        if denied_substrings:
            for s in strings:
                for d in denied_substrings:
                    if d in s:
                        violation(
                            "Forbidden content in tool arguments",
                            f"Argument contains denied substring {d!r}.",
                            s,
                        )
        max_len = rules.get("max_arg_length")
        if max_len:
            for s in strings:
                if len(s) > max_len:
                    violation(
                        "Tool argument too long",
                        f"Argument length {len(s)} exceeds max_arg_length={max_len}.",
                        s,
                    )
        return events


def _short(args: dict[str, Any], limit: int = 120) -> str:
    import json

    try:
        s = json.dumps(args, default=str, ensure_ascii=False)
    except Exception:  # pragma: no cover
        s = str(args)
    return s if len(s) <= limit else s[: limit - 3] + "..."


__all__ = ["ToolPolicy", "ToolPolicyDetector"]
