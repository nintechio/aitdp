"""Declarative YAML rules and the rule-based detector (SPEC §5)."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .detector import Detector
from .models import Action, Category, Context, Evidence, Message, References, Severity, ThreatEvent

RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*-[A-Z]+-\d{3,}$")
MAX_EXCERPT = 200


class Pattern(BaseModel):
    regex: str | None = None
    keywords: list[str] | None = None
    note: str | None = None

    model_config = ConfigDict(extra="forbid")


class RuleTests(BaseModel):
    match: list[str] = Field(default_factory=list)
    no_match: list[str] = Field(default_factory=list)


class Rule(BaseModel):
    """A detection rule as defined in SPEC §5 / ``schema/rule.schema.json``."""

    id: str = Field(pattern=RULE_ID_RE.pattern)
    title: str = Field(min_length=1, max_length=120)
    description: str | None = None
    category: Category
    severity: Severity
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    stages: list[str] = Field(min_length=1)
    references: References = Field(default_factory=References)
    recommended_action: Action = Action.flag
    match: str = "any"
    patterns: list[Pattern] = Field(min_length=1)
    tests: RuleTests = Field(default_factory=RuleTests)
    tags: list[str] = Field(default_factory=list)
    author: str | None = None
    enabled: bool = True

    model_config = ConfigDict(extra="forbid")

    # populated by loader
    source: str | None = Field(default=None, exclude=True)


@dataclass
class _Matcher:
    pattern: Pattern
    regex: re.Pattern[str] | None = None
    keywords: list[str] = field(default_factory=list)

    def find(self, text: str) -> tuple[int, int, str] | None:
        if self.regex is not None:
            m = self.regex.search(text)
            if m:
                return m.start(), m.end(), self.regex.pattern
            return None
        lowered = text.lower()
        for kw in self.keywords:
            idx = lowered.find(kw.lower())
            if idx >= 0:
                return idx, idx + len(kw), kw
        return None


@dataclass
class CompiledRule:
    rule: Rule
    matchers: list[_Matcher]

    def evaluate(self, text: str) -> list[tuple[int, int, str]]:
        hits: list[tuple[int, int, str]] = []
        for m in self.matchers:
            hit = m.find(text)
            if hit:
                hits.append(hit)
            elif self.rule.match == "all":
                return []
        return hits


class RuleError(ValueError):
    pass


def compile_rule(rule: Rule) -> CompiledRule:
    matchers: list[_Matcher] = []
    for p in rule.patterns:
        if p.regex:
            try:
                rx = re.compile(p.regex)
            except re.error as exc:  # pragma: no cover - exercised by rule tests
                raise RuleError(f"{rule.id}: invalid regex {p.regex!r}: {exc}") from exc
            matchers.append(_Matcher(pattern=p, regex=rx))
        elif p.keywords:
            matchers.append(_Matcher(pattern=p, keywords=list(p.keywords)))
        else:
            raise RuleError(f"{rule.id}: pattern must define 'regex' or 'keywords'")
    return CompiledRule(rule=rule, matchers=matchers)


# --------------------------------------------------------------------------- loading


def default_rules_dir() -> Path | None:
    """Locate the bundled ruleset.

    Order: ``$AITDP_RULES_DIR`` → ``aitdp/_bundled_rules`` (installed wheel) →
    ``<repo>/rules`` (editable / source checkout).
    """
    env = os.environ.get("AITDP_RULES_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve().parent
    repo = here.parents[2]
    if (repo / "SPEC.md").is_file() and (repo / "rules").is_dir():  # source checkout
        return repo / "rules"
    bundled = here / "_bundled_rules"
    return bundled if bundled.is_dir() else None


def iter_rule_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*.y*ml")):
        if p.is_file():
            yield p


def load_rule_file(path: Path) -> list[Rule]:
    with path.open("r", encoding="utf-8") as fh:
        docs = [d for d in yaml.safe_load_all(fh) if d]
    rules = []
    for doc in docs:
        if not isinstance(doc, dict):
            raise RuleError(f"{path}: expected a mapping, got {type(doc).__name__}")
        try:
            rule = Rule.model_validate(doc)
        except Exception as exc:
            raise RuleError(f"{path}: {exc}") from exc
        rule.source = str(path)
        rules.append(rule)
    return rules


def load_rules(paths: Path | str | Iterable[Path | str] | None = None) -> list[Rule]:
    """Load rules from a file, a directory tree, or several of them.

    ``None`` loads the bundled default ruleset.
    """
    if paths is None:
        root = default_rules_dir()
        if root is None:
            return []
        paths = [root]
    elif isinstance(paths, (str, Path)):
        paths = [paths]
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for p in paths:
        root = Path(p)
        if not root.exists():
            raise FileNotFoundError(root)
        for f in iter_rule_files(root):
            for r in load_rule_file(f):
                if r.id in seen:
                    raise RuleError(f"duplicate rule id {r.id} in {f} (already in {seen[r.id]})")
                seen[r.id] = str(f)
                rules.append(r)
    return rules


# --------------------------------------------------------------------------- self-test


@dataclass
class RuleTestResult:
    rule_id: str
    passed: bool
    failures: list[str] = field(default_factory=list)
    slowest_ms: float = 0.0


_PATHOLOGICAL_INPUTS = [
    "a" * 5000,
    "ignore " * 800,
    ("<img " * 300) + ("../" * 300),
    "x=" * 2000 + "'",
]


def run_rule_tests(rule: Rule, *, max_pattern_ms: float = 50.0) -> RuleTestResult:
    """Execute a rule's declared ``tests`` and a cheap ReDoS smoke test."""
    result = RuleTestResult(rule_id=rule.id, passed=True)
    try:
        compiled = compile_rule(rule)
    except RuleError as exc:
        result.passed = False
        result.failures.append(str(exc))
        return result

    for sample in rule.tests.match:
        if not compiled.evaluate(sample):
            result.passed = False
            result.failures.append(f"expected MATCH but did not: {sample!r}")
    for sample in rule.tests.no_match:
        if compiled.evaluate(sample):
            result.passed = False
            result.failures.append(f"expected NO MATCH but matched: {sample!r}")

    for m in compiled.matchers:
        for bad in _PATHOLOGICAL_INPUTS:
            t0 = time.perf_counter()
            m.find(bad)
            ms = (time.perf_counter() - t0) * 1000
            result.slowest_ms = max(result.slowest_ms, ms)
            if ms > max_pattern_ms:
                result.passed = False
                pat = m.regex.pattern if m.regex else m.keywords
                result.failures.append(
                    f"pattern too slow ({ms:.1f}ms > {max_pattern_ms}ms) on pathological input: {pat!r}"
                )
                break
    return result


# --------------------------------------------------------------------------- detector


class RuleDetector(Detector):
    """Executes AITDP YAML rules against message text."""

    name = "aitdp.rules"
    version = "0.1.0"

    def __init__(
        self,
        rules: Iterable[Rule] | None = None,
        *,
        rules_dir: Path | str | Iterable[Path | str] | None = None,
        max_events_per_rule: int = 1,
    ) -> None:
        if rules is None:
            rules = load_rules(rules_dir)
        self.rules: list[Rule] = [r for r in rules if r.enabled]
        self.compiled: list[CompiledRule] = [compile_rule(r) for r in self.rules]
        self.max_events_per_rule = max_events_per_rule
        self.stages = frozenset(s for r in self.rules for s in r.stages) or self.stages

    def __len__(self) -> int:
        return len(self.rules)

    def detect(self, message: Message, context: Context) -> list[ThreatEvent]:
        stage = message.stage_name
        text = message.searchable_text()
        if not text:
            return []
        events: list[ThreatEvent] = []
        for c in self.compiled:
            if stage not in c.rule.stages:
                continue
            hits = c.evaluate(text)
            if not hits:
                continue
            evidence = [
                Evidence(
                    excerpt=_excerpt(text, s, e),
                    start=s,
                    end=e,
                    match=pat if len(pat) <= 200 else pat[:197] + "...",
                )
                for s, e, pat in hits[: self.max_events_per_rule * 3]
            ]
            events.append(
                ThreatEvent(
                    category=c.rule.category,
                    severity=c.rule.severity,
                    confidence=c.rule.confidence,
                    stage=stage,
                    title=c.rule.title,
                    description=(c.rule.description or "").strip() or None,
                    detector=self.info,
                    rule_id=c.rule.id,
                    evidence=evidence,
                    references=c.rule.references,
                    recommended_action=c.rule.recommended_action,
                    metadata={"tags": c.rule.tags} if c.rule.tags else {},
                )
            )
        return events


def _excerpt(text: str, start: int, end: int, pad: int = 20) -> str:
    lo = max(0, start - pad)
    hi = min(len(text), end + pad)
    snippet = text[lo:hi].replace("\n", " ")
    if len(snippet) > MAX_EXCERPT:
        snippet = snippet[: MAX_EXCERPT - 3] + "..."
    return snippet


def rule_to_dict(rule: Rule) -> dict[str, Any]:
    return rule.model_dump(mode="json", exclude_none=True)


__all__ = [
    "CompiledRule",
    "Pattern",
    "Rule",
    "RuleDetector",
    "RuleError",
    "RuleTestResult",
    "compile_rule",
    "default_rules_dir",
    "load_rule_file",
    "load_rules",
    "run_rule_tests",
]
