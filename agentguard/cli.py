from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .comparison import build_comparison
from .ingest import IngestionError
from .orchestrator import scan, scan_all, write_result
from .web import serve


def _exit_code(result, threshold: str) -> int:
    if result.scan_status == "error":
        return 2
    if result.scan_status == "incomplete":
        return 2
    if any(f.rule_id == "AG003" for f in result.findings):
        return 2
    ranks = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return 1 if ranks.get(result.aggregate_severity, 0) >= ranks[threshold] else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentguard")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="Run a static scan")
    scan_parser.add_argument("source")
    scan_parser.add_argument("--no-external", action="store_true")
    scan_parser.add_argument("--output", type=Path, required=True)
    scan_parser.add_argument("--fail-on-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], default="MEDIUM")
    batch_parser = commands.add_parser("scan-all", help="Scan fixture directories")
    batch_parser.add_argument("source")
    batch_parser.add_argument("--no-external", action="store_true")
    batch_parser.add_argument("--output", type=Path, required=True)
    compare_parser = commands.add_parser("compare", help="Build comparison.json")
    compare_parser.add_argument("--input", type=Path, required=True)
    compare_parser.add_argument("--output", type=Path, required=True)
    web_parser = commands.add_parser("web", help="Start the local findings viewer")
    web_parser.add_argument("--host", default="127.0.0.1")
    web_parser.add_argument("--port", type=int, default=8080)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "web":
            serve(args.host, args.port)
            return 0
        if args.command == "scan":
            result = scan(args.source, include_external=not args.no_external, output_dir=args.output)
            path = write_result(result, args.output)
            print(json.dumps({"scan_id": result.scan_id, "findings": len(result.findings), "scan_status": result.scan_status, "report": str(path)}, indent=2))
            return _exit_code(result, args.fail_on_severity)
        if args.command == "scan-all":
            paths = scan_all(args.source, args.output, include_external=not args.no_external)
            print(json.dumps({"reports": [str(path) for path in paths]}, indent=2))
            return 0
        path = build_comparison(args.input, args.output)
        print(json.dumps({"comparison": str(path)}, indent=2))
        return 0
    except (IngestionError, OSError, ValueError) as exc:
        print(f"agentguard: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
