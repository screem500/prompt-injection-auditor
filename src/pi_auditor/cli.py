"""Unified command-line interface for Prompt Injection Auditor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, mcp_guard, scanner, shield
from .session import SessionPolicy, SessionRiskState


def _run_scan(args: argparse.Namespace) -> int:
    argv = ["pi_scan", args.target]
    if args.json_path:
        argv.extend(["--json", args.json_path])
    if args.md_path:
        argv.extend(["--md", args.md_path])
    old_argv = sys.argv
    try:
        sys.argv = argv
        scanner.main()
    except SystemExit as exc:
        return int(exc.code or 0)
    finally:
        sys.argv = old_argv


def _read_input(path: str | None) -> str:
    if path:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    return sys.stdin.read()


def _run_shield(args: argparse.Namespace) -> int:
    text = _read_input(args.input)
    if not text.strip():
        print("error: input is empty", file=sys.stderr)
        return 2
    result = shield.shield_input(text, warn_at=args.warn_at, block_at=args.block_at)
    print(f"Decision: {result.decision}\nThreat score: {result.score}/100")
    for finding in result.findings:
        print(f"- {finding}")
    return 1 if result.decision == shield.BLOCK else 0


def _run_mcp(args: argparse.Namespace) -> int:
    text = _read_input(args.input)
    if not text.strip():
        print("error: input is empty", file=sys.stderr)
        return 2
    if args.definition:
        result = mcp_guard.guard_tool_definition(text, warn_at=args.warn_at, block_at=args.block_at)
    else:
        result = mcp_guard.guard_tool_response(
            text,
            tool_name=args.tool_name,
            warn_at=args.warn_at,
            block_at=args.block_at,
        )
    print(f"Decision: {result.decision}\nThreat score: {result.score}/100")
    for finding in result.findings:
        print(f"- {finding}")
    return 1 if result.decision == mcp_guard.BLOCK else 0



def _run_session(args: argparse.Namespace) -> int:
    text = _read_input(args.input)
    turns = [line.strip() for line in text.splitlines() if line.strip()]
    if not turns:
        print("error: session input is empty", file=sys.stderr)
        return 2
    policy = SessionPolicy(
        warn_at=args.warn_at,
        block_at=args.block_at,
        max_turns=args.max_turns,
        ttl_seconds=args.ttl_seconds,
        turn_decay=args.turn_decay,
    )
    state = SessionRiskState(args.session_id, policy)
    results = [state.observe(turn) for turn in turns]
    if args.json_output:
        print(json.dumps({
            "session": state.to_dict(),
            "results": [result.to_dict() for result in results],
        }, ensure_ascii=False, indent=2))
    else:
        for index, result in enumerate(results, start=1):
            print(
                f"Turn {index}: current={result.current.decision} "
                f"session={result.decision} score={result.score}/100"
            )
            for note in result.notes:
                print(f"  - {note}")
        final = results[-1]
        print(f"Final decision: {final.decision}")
    return 1 if results[-1].decision == shield.BLOCK else 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pi-audit", description="Prompt-injection auditing and runtime guards")
    parser.add_argument("--version", action="version", version=f"pi-audit {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan_parser = commands.add_parser("scan", help="Audit a system prompt or agent instruction file")
    scan_parser.add_argument("target")
    scan_parser.add_argument("--json", dest="json_path")
    scan_parser.add_argument("--md", dest="md_path")
    scan_parser.set_defaults(handler=_run_scan)

    shield_parser = commands.add_parser("shield", help="Analyze untrusted user input")
    shield_parser.add_argument("input", nargs="?", help="Input file; omit to read stdin")
    shield_parser.add_argument("--warn-at", type=int, default=30)
    shield_parser.add_argument("--block-at", type=int, default=60)
    shield_parser.set_defaults(handler=_run_shield)

    mcp_parser = commands.add_parser("mcp", help="Analyze an MCP response or tool definition")
    mcp_parser.add_argument("input", nargs="?", help="Input file; omit to read stdin")
    mcp_parser.add_argument("--tool-name", default="")
    mcp_parser.add_argument("--definition", action="store_true", help="Treat input as a tool definition")
    mcp_parser.add_argument("--warn-at", type=int, default=30)
    mcp_parser.add_argument("--block-at", type=int, default=60)
    mcp_parser.set_defaults(handler=_run_mcp)

    session_parser = commands.add_parser("session", help="Analyze a multi-turn conversation from one line per turn")
    session_parser.add_argument("input", nargs="?", help="Text file; each non-empty line is one user turn")
    session_parser.add_argument("--session-id", default="cli-session")
    session_parser.add_argument("--warn-at", type=int, default=30)
    session_parser.add_argument("--block-at", type=int, default=60)
    session_parser.add_argument("--max-turns", type=int, default=12)
    session_parser.add_argument("--ttl-seconds", type=int, default=1800)
    session_parser.add_argument("--turn-decay", type=float, default=0.82)
    session_parser.add_argument("--json", dest="json_output", action="store_true")
    session_parser.set_defaults(handler=_run_session)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    raise SystemExit(args.handler(args))


if __name__ == "__main__":
    main()
