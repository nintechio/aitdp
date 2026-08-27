import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
RULES_DIR = REPO / "rules"
SCHEMA_DIR = REPO / "schema"


@pytest.fixture(scope="session")
def rules_dir() -> Path:
    return RULES_DIR


@pytest.fixture(scope="session")
def event_schema() -> dict:
    return json.loads((SCHEMA_DIR / "threat-event.schema.json").read_text())


@pytest.fixture(scope="session")
def rule_schema() -> dict:
    return json.loads((SCHEMA_DIR / "rule.schema.json").read_text())


@pytest.fixture(scope="session")
def pipeline():
    from aitdp import Pipeline

    return Pipeline.default(rules_dir=RULES_DIR)
