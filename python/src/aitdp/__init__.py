"""aitdp — reference SDK for the AI Threat Detection Protocol.

Quick start::

    from aitdp import Pipeline, Stage

    pipeline = Pipeline.default()
    result = pipeline.scan("Ignore all previous instructions", stage=Stage.user_input)
    print(result.action, result.summary())
"""

from .detector import CallableDetector, Detector
from .detectors import (
    CanaryDetector,
    SecretsDetector,
    ToolPolicy,
    ToolPolicyDetector,
    generate_canary,
)
from .models import (
    SPEC_VERSION,
    Action,
    Category,
    Context,
    DetectorInfo,
    Evidence,
    Message,
    References,
    Severity,
    Stage,
    ThreatEvent,
)
from .pipeline import Pipeline, ScanResult, ThreatDetected
from .rules import Rule, RuleDetector, load_rules
from .sanitize import redact_spans, strip_invisible

__version__ = "0.1.0"

__all__ = [
    "SPEC_VERSION",
    "Action",
    "CallableDetector",
    "CanaryDetector",
    "Category",
    "Context",
    "Detector",
    "DetectorInfo",
    "Evidence",
    "Message",
    "Pipeline",
    "References",
    "Rule",
    "RuleDetector",
    "ScanResult",
    "SecretsDetector",
    "Severity",
    "Stage",
    "ThreatDetected",
    "ThreatEvent",
    "ToolPolicy",
    "ToolPolicyDetector",
    "__version__",
    "generate_canary",
    "load_rules",
    "redact_spans",
    "strip_invisible",
]
