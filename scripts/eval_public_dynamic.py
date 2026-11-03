#!/usr/bin/env python3
"""Run public malicious skills (MalSkillBench) through the Sandbox Scan and REPORT what happened.

    python scripts/eval_public_dynamic.py                 # all 12 skills, static + sandbox
    python scripts/eval_public_dynamic.py --no-external   # skip Cisco/NVIDIA (much faster)
    python scripts/eval_public_dynamic.py --only msb-gen-docs --only msb-docker-expert

Run it on the machine with docker, kind and kubectl (after `prepare-sandbox`). The skills are
downloaded from GitHub and executed ONLY inside the locked-down pod. Unlike verify_sandbox.py this
script makes no pass/fail assertions about detection: some skills are deliberate limit cases, and
the point is to see honestly what the static engines and the sandbox each observed.

Results are written to runs/public-dynamic/results.md and results.json.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard import samples  # noqa: E402

RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
STATIC_TOOLS = ("agentguard", "cisco", "nvidia")


def top(findings: list[dict]) -> str:
    if not findings:
        return "-"
    best = max(findings, key=lambda f: RANK.get(f["severity"], 0))["severity"]
    return best


def scan_one(item: dict, mode: str, external: bool) -> dict:
    out = Path(tempfile.mkdtemp(prefix="agentguard-public-"))
    command = [sys.executable, "-m", "agentguard.cli", "scan", item["url"], "--mode", mode, "--output", str(out)]
    if not external:
        command.append("--no-external")
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=1800, check=False)
    reports = sorted(out.glob("*.json"))
    if not reports:
        return {"error": (done.stderr or done.stdout).strip()[-500:]}
    return json.loads(reports[0].read_text(encoding="utf-8"))


def summarize(item: dict, report: dict) -> dict:
    row = {"id": item["id"], "name": item["label"], "behavior": item["shows"].split("]")[0].lstrip("["),
           "dataset_label": item["expected"]}
    if "error" in report:
        row["error"] = report["error"]
        return row
    findings = report.get("findings", [])
    by_tool: dict[str, list[dict]] = defaultdict(list)
    for finding in findings:
        by_tool[finding["tool"]].append(finding)
    row["static"] = {tool: top(by_tool.get(tool, [])) for tool in STATIC_TOOLS}
    dyn = by_tool.get("agentguard_sandbox", [])
    row["dynamic"] = sorted({"%s:%s" % (f["rule_id"], f["severity"]) for f in dyn})
    stage = report.get("stages", {}).get("dynamic", {})
    row["sandbox_stage"] = stage.get("status")
    coverage = (report.get("dynamic") or {}).get("coverage", {})
    row["commands_run"] = coverage.get("commands_run")
    row["commands_failed"] = coverage.get("commands_failed")
    row["timed_out"] = coverage.get("timed_out")
    row["verdict"] = report.get("verdict", {}).get("label")
    return row


def render(rows: list[dict]) -> str:
    lines = ["| Skill | Behaviour (dataset) | Native | Cisco | NVIDIA | Sandbox findings | Cmds run/failed | Verdict |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        if "error" in r:
            lines.append("| %s | %s | scan failed: %s |||||| |" % (r["name"], r["behavior"], r["error"][:80].replace("|", "/")))
            continue
        s = r["static"]
        lines.append("| %s | %s | %s | %s | %s | %s | %s/%s | %s |" % (
            r["name"], r["behavior"], s["agentguard"], s["cisco"], s["nvidia"],
            "<br>".join(r["dynamic"]) or "none", r["commands_run"], r["commands_failed"], r["verdict"]))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", action="append", help="sample id (repeatable)")
    parser.add_argument("--mode", default="sandbox", choices=["sandbox", "deep"])
    parser.add_argument("--no-external", action="store_true", help="skip Cisco and NVIDIA (native rules only)")
    args = parser.parse_args()
    items = [s for s in samples.SAMPLES if s.get("runtime") and (not args.only or s["id"] in args.only)]
    if not items:
        print("no matching samples; ids:", ", ".join(s["id"] for s in samples.SAMPLES if s.get("runtime")))
        return 2
    rows, hard_failures = [], 0
    for index, item in enumerate(items, 1):
        print("[%d/%d] %s - %s" % (index, len(items), item["id"], item["shows"]), flush=True)
        row = summarize(item, scan_one(item, args.mode, not args.no_external))
        rows.append(row)
        if "error" in row or row.get("sandbox_stage") != "complete":
            hard_failures += 1
            print("      sandbox did not complete: %s" % (row.get("error") or row.get("sandbox_stage")))
        else:
            print("      static %s | sandbox %s | verdict %s" % (row["static"], row["dynamic"] or "no findings", row["verdict"]))
    table = render(rows)
    outdir = ROOT / "runs" / "public-dynamic"
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (outdir / "results.md").write_text(
        "# Public malicious skills in the sandbox\n\nSource: MalSkillBench (dataset labels, not AgentGuard's).\n\n"
        + table + "\n", encoding="utf-8")
    print("\n" + table)
    print("\nWrote %s" % (outdir / "results.md"))
    if hard_failures:
        print("%d scan(s) did not reach a completed sandbox stage - check the cluster (demo_start.sh --check)." % hard_failures)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
