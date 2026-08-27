# Examples

| File | What it shows |
|---|---|
| [`quickstart.py`](quickstart.py) | Scan user input, tool calls and model output with the default pipeline. |
| [`openai_guard.py`](openai_guard.py) | Wrap an OpenAI-compatible chat call: scan input, plant a canary, scan output. |
| [`agent_tool_guard.py`](agent_tool_guard.py) | Enforce a tool policy in an agent loop; require human approval for risky tools. |
| [`fastapi_middleware.py`](fastapi_middleware.py) | Drop-in FastAPI dependency that blocks injected prompts before they hit the model. |
| [`langchain_callback.py`](langchain_callback.py) | LangChain callback handler that scans every LLM input, tool input and tool output. |
| [`mcp_server_guard.py`](mcp_server_guard.py) | Scan tool results in an MCP server before returning them to the client. |
| [`siem_export.py`](siem_export.py) | Stream Threat Events as JSON lines / to a webhook for your SIEM. |

Run any example with `python examples/<file>.py` after `pip install -e python[dev]`.
The framework-specific ones only need the framework installed if you actually call the model.
