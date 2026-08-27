"""Enforce a tool policy inside an agent loop.

The loop below is framework-agnostic: ``propose_tool_call`` stands in for whatever
your agent framework produces (OpenAI function calls, Anthropic tool_use blocks,
LangGraph nodes...).
"""

from __future__ import annotations

from aitdp import Context, Pipeline, ToolPolicy

policy = ToolPolicy(
    allowed_tools=["search_web", "read_file", "http_get", "send_email", "shell"],
    denied_tools=["delete_*", "drop_*"],
    require_approval=["send_email", "shell"],
    max_calls_per_session=25,
    arg_rules={
        "http_get": {"allowed_domains": ["api.github.com", "docs.python.org"]},
        "read_file": {"allowed_paths": ["/workspace/"]},
    },
)
pipeline = Pipeline.default(policy=policy)
ctx = Context(session_id="agent-42")


def ask_human(tool: str, args: dict) -> bool:
    print(f"  ⚠ approval needed for {tool}({args}) — auto-approving for demo")
    return True


def execute(tool: str, args: dict) -> str:
    return f"<executed {tool}>"


def run_tool(tool: str, args: dict) -> str:
    result = pipeline.scan_tool_call(tool, args, context=ctx)
    if result.blocked:
        return f"BLOCKED: {result.summary()}"
    if result.needs_human and not ask_human(tool, args):
        return "DENIED by human"
    output = execute(tool, args)
    # Tool results are untrusted content: scan them for indirect injection too.
    scanned = pipeline.scan_tool_output(tool, output, context=ctx)
    if scanned.blocked:
        return f"BLOCKED tool output: {scanned.summary()}"
    return output


if __name__ == "__main__":
    calls = [
        ("search_web", {"q": "aitdp github"}),
        ("http_get", {"url": "https://api.github.com/repos/nintechio/aitdp"}),
        ("http_get", {"url": "http://169.254.169.254/latest/meta-data/"}),
        ("read_file", {"path": "/workspace/notes.md"}),
        ("read_file", {"path": "../../../../etc/passwd"}),
        ("shell", {"cmd": "ls -la"}),
        ("shell", {"cmd": "rm -rf / --no-preserve-root"}),
        ("delete_database", {"name": "prod"}),
    ]
    for tool, args in calls:
        print(f"{tool}({args}) -> {run_tool(tool, args)}")
