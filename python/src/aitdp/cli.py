"""``aitdp`` command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .models import Context, Severity, Stage
from .pipeline import Pipeline, ScanResult
from .rules import default_rules_dir, load_rules, run_rule_tests

console = Console()
err_console = Console(stderr=True)

_SEV_STYLE = {
    "info": "dim",
    "low": "cyan",
    "medium": "yellow",
    "high": "red",
    "critical": "bold white on red",
}
_ACTION_STYLE = {
    "allow": "green",
    "flag": "yellow",
    "sanitize": "yellow",
    "require_human": "magenta",
    "block": "bold red",
}


def _read_input(args: argparse.Namespace) -> str:
    if args.file:
        return Path(args.file).read_text(encoding="utf-8")
    if args.text == "-" or args.text is None:
        return sys.stdin.read()
    return args.text


def render_result(result: ScanResult, *, show_evidence: bool = True) -> None:
    action = result.action.value
    sev = result.max_severity.value if result.max_severity else None
    header = f"[{_ACTION_STYLE[action]}]{action.upper()}[/]"
    if sev:
        header += f"  ·  max severity [{_SEV_STYLE[sev]}]{sev}[/]"
    header += f"  ·  {len(result.events)} event(s)  ·  {result.duration_ms:.1f} ms"
    console.print(
        Panel(header, title=f"aitdp scan · stage={result.message.stage_name}", expand=False)
    )

    if not result.events:
        console.print("[green]✔ No threats detected.[/]")
        return

    table = Table(show_lines=False, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Title", ratio=3, min_width=24)
    table.add_column("Action", no_wrap=True)
    table.add_column("Refs", overflow="fold")
    for ev in result.events:
        refs = ", ".join([*ev.references.owasp_llm, *ev.references.mitre_atlas])
        table.add_row(
            f"[{_SEV_STYLE[ev.severity.value]}]{ev.severity.value}[/]",
            ev.category.value,
            ev.rule_id or ev.detector.name,
            ev.title,
            f"[{_ACTION_STYLE[ev.recommended_action.value]}]{ev.recommended_action.value}[/]",
            refs,
        )
    console.print(table)
    if show_evidence:
        for ev in result.events:
            for e in ev.evidence[:3]:
                if e.excerpt:
                    console.print(f"  [dim]{ev.rule_id or ev.detector.name} ›[/] {e.excerpt!r}")
    if result.errors:
        for name, msg in result.errors.items():
            err_console.print(f"[yellow]detector {name} errored:[/] {msg}")


def cmd_scan(args: argparse.Namespace) -> int:
    text = _read_input(args)
    stage = args.stage
    pipeline = Pipeline.default(rules_dir=args.rules, canaries=args.canary or None)
    ctx = Context(canaries=args.canary or [], session_id=args.session)
    tool_args = json.loads(args.tool_args) if args.tool_args else None
    result = pipeline.scan(text, stage, tool_name=args.tool, tool_args=tool_args, context=ctx)
    if args.json:
        print(json.dumps(result.to_dict(), indent=None if args.compact else 2))
    else:
        render_result(result, show_evidence=not args.no_evidence)
    if (
        args.fail_on
        and result.max_severity is not None
        and result.max_severity >= Severity(args.fail_on)
    ):
        return 2
    return 0


def cmd_rules_list(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    if args.json:
        print(
            json.dumps(
                [r.model_dump(mode="json", exclude={"tests", "patterns"}) for r in rules], indent=2
            )
        )
        return 0
    table = Table(title=f"{len(rules)} rules")
    table.add_column("ID", no_wrap=True, min_width=15)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Stages", overflow="fold")
    table.add_column("Title", overflow="fold")
    for r in rules:
        table.add_row(
            r.id,
            f"[{_SEV_STYLE[r.severity.value]}]{r.severity.value}[/]",
            r.category.value,
            ",".join(s.replace("_", "-") for s in r.stages),
            r.title,
        )
    console.print(table)
    return 0


def cmd_rules_test(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    failed = 0
    for r in rules:
        res = run_rule_tests(r, max_pattern_ms=args.max_ms)
        if res.passed:
            console.print(f"[green]PASS[/] {r.id:<16} {r.title}  [dim]({res.slowest_ms:.1f}ms)[/]")
        else:
            failed += 1
            console.print(f"[red]FAIL[/] {r.id:<16} {r.title}")
            for f in res.failures:
                console.print(f"       [red]-[/] {f}")
    console.print(f"\n{len(rules) - failed}/{len(rules)} rules passed")
    return 1 if failed else 0


def cmd_rules_validate(args: argparse.Namespace) -> int:
    try:
        import jsonschema
    except ImportError:  # pragma: no cover
        err_console.print(r"jsonschema not installed; run: pip install 'aitdp\[dev]'")
        return 1
    import yaml

    from .rules import iter_rule_files

    schema_path = Path(__file__).parent / "_schema" / "rule.schema.json"
    if not schema_path.exists():
        schema_path = Path(__file__).resolve().parents[3] / "schema" / "rule.schema.json"
    schema = json.loads(schema_path.read_text())
    root = Path(args.rules) if args.rules else default_rules_dir()
    if root is None:
        err_console.print("no rules directory found")
        return 1
    bad = 0
    for f in iter_rule_files(root):
        for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if not doc:
                continue
            errors = list(jsonschema.Draft202012Validator(schema).iter_errors(doc))
            if errors:
                bad += 1
                console.print(f"[red]INVALID[/] {f}")
                for e in errors:
                    console.print(f"    - {'/'.join(map(str, e.path)) or '<root>'}: {e.message}")
            else:
                console.print(f"[green]OK[/] {f.name}")
    return 1 if bad else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aitdp", description="AI Threat Detection Protocol CLI")
    p.add_argument("--version", action="version", version=f"aitdp {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan text (or stdin) for AI threats")
    s.add_argument("text", nargs="?", help="text to scan; '-' or omitted reads stdin")
    s.add_argument("-f", "--file", help="read input from file")
    s.add_argument(
        "-s",
        "--stage",
        default=Stage.user_input.value,
        choices=[st.value for st in Stage],
        help="stage the content was observed at (default: user_input)",
    )
    s.add_argument("--tool", help="tool name (for tool_input / tool_output stages)")
    s.add_argument("--tool-args", help="JSON object of tool arguments (tool_input stage)")
    s.add_argument("--canary", action="append", help="canary token to watch for (repeatable)")
    s.add_argument("--session", help="session id to attach to events")
    s.add_argument("--rules", help="rules file or directory (default: bundled ruleset)")
    s.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    s.add_argument("--compact", action="store_true", help="single-line JSON")
    s.add_argument("--no-evidence", action="store_true", help="hide evidence excerpts")
    s.add_argument(
        "--fail-on",
        choices=[sv.value for sv in Severity],
        help="exit with code 2 if max severity >= this (for CI)",
    )
    s.set_defaults(fn=cmd_scan)

    r = sub.add_parser("rules", help="manage detection rules")
    rsub = r.add_subparsers(dest="rules_cmd", required=True)
    rl = rsub.add_parser("list", help="list rules")
    rl.add_argument("--rules")
    rl.add_argument("--json", action="store_true")
    rl.set_defaults(fn=cmd_rules_list)
    rt = rsub.add_parser("test", help="run each rule's embedded tests + ReDoS smoke test")
    rt.add_argument("--rules")
    rt.add_argument("--max-ms", type=float, default=50.0)
    rt.set_defaults(fn=cmd_rules_test)
    rv = rsub.add_parser("validate", help="validate rule files against the JSON schema")
    rv.add_argument("--rules")
    rv.set_defaults(fn=cmd_rules_validate)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.fn(args))
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    except FileNotFoundError as exc:
        err_console.print(f"[red]error:[/] file not found: {exc}")
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
