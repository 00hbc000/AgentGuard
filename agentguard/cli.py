from __future__ import annotations

import argparse
import json
import signal
import sys
import tempfile
import time
from pathlib import Path

from .comparison import build_comparison
from .ingest import IngestionError, list_skills
from .orchestrator import scan, scan_all, write_result

MODES = ("quick", "sandbox", "deep")


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
    scan_parser = commands.add_parser("scan", help="Scan one skill (static, or static + Kubernetes sandbox)")
    scan_parser.add_argument("source")
    scan_parser.add_argument("--no-external", action="store_true")
    scan_parser.add_argument("--output", type=Path, required=True)
    scan_parser.add_argument("--fail-on-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], default="MEDIUM")
    scan_parser.add_argument("--mode", "--scan-mode", dest="mode", choices=MODES,
                             help="quick = static only; sandbox/deep = static + Kubernetes runtime analysis")
    scan_parser.add_argument("--progress-file", type=Path,
                             help="Append one JSON progress line per stage (used by the dashboard)")
    dynamic_group = scan_parser.add_mutually_exclusive_group()
    dynamic_group.add_argument("--dynamic", action="store_true", help="Run dynamic analysis when the decision gate escalates")
    dynamic_group.add_argument("--force-dynamic", action="store_true", help="Run dynamic analysis without the decision gate")
    scan_parser.add_argument("--demo-dynamic", action="store_true", help="Show a synthetic dynamic result; never executes the skill")
    batch_parser = commands.add_parser("scan-all", help="Scan every skill directory inside a folder")
    batch_parser.add_argument("source")
    batch_parser.add_argument("--no-external", action="store_true")
    batch_parser.add_argument("--output", type=Path, required=True)
    batch_parser.add_argument("--mode", "--scan-mode", dest="mode", choices=MODES)
    compare_parser = commands.add_parser("compare", help="Build comparison.json")
    compare_parser.add_argument("--input", type=Path, required=True)
    compare_parser.add_argument("--output", type=Path, required=True)
    web_parser = commands.add_parser("web", help="Start the dashboard")
    web_parser.add_argument("--host", default="127.0.0.1")
    web_parser.add_argument("--port", type=int, default=8080)
    web_parser.add_argument("--data-dir", type=Path, help="Where job history and reports are stored")
    list_parser = commands.add_parser("list-skills", help="List the skills inside a remote repository URL")
    list_parser.add_argument("source")
    commands.add_parser("scanners", help="Show which external scanners (Cisco, NVIDIA) AgentGuard can find")
    commands.add_parser("prepare-sandbox", help="Build the sandbox/sink images and load them into kind; prints the tag")
    return parser


def _progress_writer(path: Path | None):
    if path is None:
        return None

    def write(stage: str, message: str) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"time": time.time(), "stage": stage, "message": message}) + "\n")

    return write


def _terminate(signum, frame):  # noqa: ARG001
    # Raise so `finally` blocks run and the sandbox pod is deleted when a scan is cancelled.
    raise SystemExit(143)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    signal.signal(signal.SIGTERM, _terminate)
    try:
        if args.command == "web":
            from .web import serve  # imported lazily so CLI scans do not load the dashboard

            serve(args.host, args.port, data_dir=args.data_dir)
            return 0
        if args.command == "scanners":
            from . import scanners

            info = scanners.status()
            for tool, entry in info.items():
                print(f"{tool:7} {'AVAILABLE' if entry['available'] else 'missing  '}  {entry['source']}"
                      + (f"  -> {' '.join(entry['command'])}" if entry["command"] else ""))
            return 0 if all(entry["available"] for entry in info.values()) else 3
        if args.command == "prepare-sandbox":
            from .dynamic.runner import prepare_images

            tag = prepare_images(lambda message: print(message, file=sys.stderr))
            print(tag)
            return 0
        if args.command == "list-skills":
            with tempfile.TemporaryDirectory(prefix="agentguard-list-") as workspace:
                print(json.dumps(list_skills(args.source, Path(workspace)), indent=2))
            return 0
        if args.command == "scan":
            result = scan(
                args.source,
                include_external=not args.no_external,
                output_dir=args.output,
                dynamic=args.dynamic or args.force_dynamic,
                force_dynamic=args.force_dynamic,
                demo_dynamic=args.demo_dynamic,
                scan_mode=args.mode,
                progress=_progress_writer(args.progress_file),
            )
            path = write_result(result, args.output)
            print(json.dumps({"scan_id": result.scan_id, "findings": len(result.findings),
                              "scan_status": result.scan_status, "report": str(path),
                              "verdict": result.to_dict()["verdict"]["label"]}, indent=2))
            return _exit_code(result, args.fail_on_severity)
        if args.command == "scan-all":
            paths = scan_all(args.source, args.output, include_external=not args.no_external, scan_mode=args.mode)
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
