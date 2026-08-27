import json

import jsonschema
import pytest

from aitdp import Action, Category, DetectorInfo, Evidence, References, Severity, Stage, ThreatEvent


def _event(**kw):
    base = dict(
        category=Category.prompt_injection,
        severity=Severity.high,
        confidence=0.9,
        stage=Stage.user_input.value,
        title="test",
        detector=DetectorInfo(name="t", version="1"),
        recommended_action=Action.block,
    )
    base.update(kw)
    return ThreatEvent(**base)


def test_event_validates_against_schema(event_schema):
    ev = _event(
        evidence=[Evidence(excerpt="x", start=0, end=1, match="m")],
        references=References(owasp_llm=["LLM01"], mitre_atlas=["AML.T0051.000"], cwe=["CWE-77"]),
        rule_id="AITDP-INJ-001",
        metadata={"k": "v"},
    )
    data = ev.to_dict()
    jsonschema.validate(data, event_schema, format_checker=jsonschema.FormatChecker())
    assert data["spec_version"] == "0.1"
    assert data["timestamp"].endswith("Z")
    # round trip via JSON
    assert json.loads(ev.to_json())["id"] == ev.id


def test_empty_optionals_are_dropped():
    data = _event().to_dict()
    assert "references" not in data
    assert "evidence" not in data
    assert "metadata" not in data
    assert "description" not in data


def test_severity_ordering():
    assert Severity.low < Severity.high
    assert Severity.critical >= Severity.critical
    assert (
        max([Severity.info, Severity.critical, Severity.medium], key=lambda s: s.rank)
        == Severity.critical
    )
    assert sorted([Severity.high, Severity.info]) == [Severity.info, Severity.high]


def test_confidence_bounds():
    with pytest.raises(ValueError):
        _event(confidence=1.5)


def test_title_length():
    with pytest.raises(ValueError):
        _event(title="x" * 121)
