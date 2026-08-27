from aitdp import (
    CanaryDetector,
    Context,
    Message,
    SecretsDetector,
    Stage,
    ToolPolicy,
    ToolPolicyDetector,
    generate_canary,
)


def test_secrets_assignment_and_redaction():
    det = SecretsDetector()
    msg = Message(
        stage=Stage.model_output, content="here you go: api_key=sk_live_ABCDEF1234567890XYZ"
    )
    events = det.detect(msg, Context())
    assert len(events) == 1
    ev = events[0]
    assert ev.category.value == "sensitive_data_leak"
    assert "sk_live_ABCDEF1234567890XYZ" not in ev.to_json()
    assert ev.evidence[0].excerpt.startswith("api_key=sk_l")


def test_secrets_ignores_placeholders_and_prose():
    det = SecretsDetector()
    assert not det.detect(
        Message(stage=Stage.model_output, content="password=<your-password>"), Context()
    )
    assert not det.detect(
        Message(stage=Stage.model_output, content="Set the password in the settings page."),
        Context(),
    )


def test_secrets_connection_string():
    det = SecretsDetector()
    ev = det.detect(
        Message(
            stage=Stage.tool_output,
            content="DATABASE_URL=postgres://admin:hunter2secret@db.internal:5432/app",
        ),
        Context(),
    )
    assert ev and any(e.match == "connection-string-with-password" for e in ev[0].evidence)


def test_secrets_entropy_token():
    det = SecretsDetector()
    ev = det.detect(
        Message(
            stage=Stage.model_output, content="token: q8Zx2pL9vB4nM7kR1tY6wE3uI0oP5aS8dF2gH4jK"
        ),
        Context(),
    )
    assert ev and ev[0].severity.value == "medium"


def test_canary_detector():
    canary = generate_canary()
    det = CanaryDetector()
    ctx = Context(canaries=[canary])
    leak = Message(stage=Stage.model_output, content=f"My instructions say: ref {canary}")
    events = det.detect(leak, ctx)
    assert events and events[0].severity.value == "critical"
    assert canary not in events[0].to_json()
    assert not det.detect(Message(stage=Stage.model_output, content="hello"), ctx)


def test_tool_policy_allow_deny_approval():
    det = ToolPolicyDetector(
        ToolPolicy(
            allowed_tools=["search", "read_*"],
            denied_tools=["shell"],
            require_approval=["send_email"],
        )
    )
    ok = det.detect(
        Message(stage=Stage.tool_input, tool_name="read_file", tool_args={"path": "a"}), Context()
    )
    assert ok == []
    denied = det.detect(
        Message(stage=Stage.tool_input, tool_name="shell", tool_args={"cmd": "ls"}), Context()
    )
    assert denied and denied[0].recommended_action.value == "block"
    not_allowed = det.detect(Message(stage=Stage.tool_input, tool_name="delete_db"), Context())
    assert not_allowed and not_allowed[0].category.value == "excessive_agency"


def test_tool_policy_requires_approval_via_context_policy():
    det = ToolPolicyDetector()
    ctx = Context(policy={"require_approval": ["send_*"]})
    ev = det.detect(Message(stage=Stage.tool_input, tool_name="send_email", tool_args={}), ctx)
    assert ev and ev[0].recommended_action.value == "require_human"


def test_tool_policy_arg_rules():
    det = ToolPolicyDetector(
        ToolPolicy(
            arg_rules={
                "http_get": {"allowed_domains": ["api.example.com"]},
                "read_file": {"allowed_paths": ["/data/"]},
            }
        )
    )
    ok = det.detect(
        Message(
            stage=Stage.tool_input,
            tool_name="http_get",
            tool_args={"url": "https://v1.api.example.com/x"},
        ),
        Context(),
    )
    assert ok == []
    bad = det.detect(
        Message(
            stage=Stage.tool_input,
            tool_name="http_get",
            tool_args={"url": "https://evil.example/x"},
        ),
        Context(),
    )
    assert bad and "evil.example" in bad[0].title
    path = det.detect(
        Message(stage=Stage.tool_input, tool_name="read_file", tool_args={"path": "/etc/passwd"}),
        Context(),
    )
    assert path and path[0].category.value == "tool_abuse"


def test_tool_policy_call_budget():
    det = ToolPolicyDetector(ToolPolicy(max_calls_per_session=2))
    ctx = Context(session_id="s1")
    m = Message(stage=Stage.tool_input, tool_name="search", tool_args={})
    assert det.detect(m, ctx) == []
    assert det.detect(m, ctx) == []
    over = det.detect(m, ctx)
    assert over and over[0].category.value == "resource_abuse"
