"""Secrets / credential leakage detector.

Complements the community ``AITDP-LEAK-*`` rules with generic assignment patterns
(``password=...``, ``api_key: ...``) and a Shannon-entropy check for opaque tokens.
Excerpts are always redacted.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ..detector import Detector
from ..models import Action, Category, Context, Evidence, Message, References, Severity, ThreatEvent

_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|private[_-]?key|bearer)\b\s*[:=]\s*[\"']?([^\s\"',;]{6,})",
)
_BEARER = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{20,}=*)")
_CONN_STRING = re.compile(
    r"(?i)\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp|mssql)://[^\s:@/]+:[^\s@/]+@[^\s]+"
)
_OPAQUE_TOKEN = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")
_PLACEHOLDER = re.compile(
    r"(?i)^(x+|\*+|<[^>]+>|\$\{[^}]+\}|your[_-]|example|changeme|redacted|\.\.\.)"
)

_DEFAULT_STAGES = frozenset(
    {"model_output", "tool_output", "retrieved_content", "system_prompt", "agent_message"}
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * min(12, len(value) - keep * 2)}{value[-keep:]}"


class SecretsDetector(Detector):
    name = "aitdp.secrets"
    version = "0.1.0"
    stages = _DEFAULT_STAGES

    def __init__(
        self,
        *,
        entropy_threshold: float = 4.2,
        stages: frozenset[str] | None = None,
        check_entropy: bool = True,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.check_entropy = check_entropy
        if stages:
            self.stages = frozenset(stages)

    def detect(self, message: Message, context: Context) -> list[ThreatEvent]:
        text = message.searchable_text()
        if not text:
            return []
        findings: list[Evidence] = []

        for m in _ASSIGNMENT.finditer(text):
            value = m.group(2)
            if _PLACEHOLDER.match(value):
                continue
            findings.append(
                Evidence(
                    excerpt=f"{m.group(1)}={redact(value)}",
                    start=m.start(),
                    end=m.end(),
                    match="credential-assignment",
                )
            )
        for m in _BEARER.finditer(text):
            findings.append(
                Evidence(
                    excerpt=f"Bearer {redact(m.group(1))}",
                    start=m.start(),
                    end=m.end(),
                    match="bearer-token",
                )
            )
        for m in _CONN_STRING.finditer(text):
            findings.append(
                Evidence(
                    excerpt=redact(m.group(0), keep=12),
                    start=m.start(),
                    end=m.end(),
                    match="connection-string-with-password",
                )
            )
        if self.check_entropy:
            covered = [(e.start or 0, e.end or 0) for e in findings]
            for m in _OPAQUE_TOKEN.finditer(text):
                if any(s <= m.start() < e for s, e in covered):
                    continue
                tok = m.group(0)
                if tok.isdigit() or tok.isalpha() and tok.islower() and "_" not in tok:
                    continue
                if shannon_entropy(tok) >= self.entropy_threshold:
                    findings.append(
                        Evidence(
                            excerpt=redact(tok),
                            start=m.start(),
                            end=m.end(),
                            match="high-entropy-token",
                            note=f"entropy={shannon_entropy(tok):.2f}",
                        )
                    )

        if not findings:
            return []
        strong = any(e.match != "high-entropy-token" for e in findings)
        return [
            ThreatEvent(
                category=Category.sensitive_data_leak,
                severity=Severity.high if strong else Severity.medium,
                confidence=0.85 if strong else 0.5,
                stage=message.stage_name,
                title="Possible credential or secret in content",
                description="Content contains what looks like credentials, tokens, or high-entropy secrets.",
                detector=self.info,
                evidence=findings[:10],
                references=References(owasp_llm=["LLM02"], cwe=["CWE-312", "CWE-798"]),
                recommended_action=Action.sanitize,
                metadata={"finding_count": len(findings)},
            )
        ]


__all__ = ["SecretsDetector", "redact", "shannon_entropy"]
