#!/usr/bin/env python3
"""Acceptance check for the Kubernetes sandbox. Run on a machine with docker, kind and kubectl.

    python scripts/verify_sandbox.py            # all controlled samples, Sandbox mode
    python scripts/verify_sandbox.py --only runtime-exfil-evasive

Each sample is a synthetic fixture from samples/. The script prints PASS/FAIL per expectation and
exits non-zero if any fail. It also confirms that no sandbox pod is left behind.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# sample -> {runtime rule: minimum severity} that must appear, rules that must NOT appear, verdicts allowed
EXPECTATIONS = {
    "benign-csv-stats": {"require": {}, "forbid": {"DYN_HONEYPOT_EXFIL", "DYN_EXFIL_ATTEMPT", "DYN_ENV_EXPOSED"},
                         "verdicts": {"no_findings"}, "min_commands": 1},
    "runtime-exfil-sink": {"require": {"DYN_HONEYPOT_EXFIL": "CRITICAL"}, "forbid": set(), "verdicts": {"malicious"}},
    "runtime-exfil-evasive": {"require": {"DYN_HONEYPOT_EXFIL": "CRITICAL"}, "forbid": set(),
                              "verdicts": {"malicious"}, "static_clean": True},
    "runtime-exfil-external": {"require": {"DYN_EXFIL_ATTEMPT": "HIGH"}, "forbid": {"DYN_HONEYPOT_EXFIL"},
                               "verdicts": {"high_risk"}},
    "runtime-env-dump": {"require": {"DYN_ENV_EXPOSED": "HIGH"}, "forbid": set(), "verdicts": {"high_risk"}},
}
RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def run_sample(name: str, mode: str) -> dict:
    out = Path(tempfile.mkdtemp(prefix="agentguard-verify-"))
    command = [sys.executable, "-m", "agentguard.cli", "scan", str(ROOT / "samples" / name), "--no-external",
               "--mode", mode, "--output", str(out), "--fail-on-severity", "CRITICAL"]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=900, check=False)
    reports = sorted(out.glob("*.json"))
    if not reports:
        return {"error": (done.stderr or done.stdout).strip()[-600:]}
    report = json.loads(reports[0].read_text(encoding="utf-8"))
    shutil.rmtree(out, ignore_errors=True)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", action="append", help="sample name (repeatable)")
    parser.add_argument("--mode", default="sandbox", choices=["sandbox", "deep"])
    args = parser.parse_args()
    failures = 0

    def check(ok: bool, label: str, detail: str = "") -> None:
        nonlocal failures
        failures += 0 if ok else 1
        print("%s  %s%s" % ("PASS" if ok else "FAIL", label, ("  - " + detail) if detail and not ok else ""))

    for name, expect in EXPECTATIONS.items():
        if args.only and name not in args.only:
            continue
        print("\n== %s (%s)" % (name, args.mode))
        report = run_sample(name, args.mode)
        if "error" in report:
            check(False, "scan produced a report", report["error"])
            continue
        dynamic_stage = report.get("stages", {}).get("dynamic", {})
        check(dynamic_stage.get("status") == "complete", "sandbox stage completed",
              "%s: %s" % (dynamic_stage.get("status"), dynamic_stage.get("reason")))
        if dynamic_stage.get("status") != "complete":
            continue
        findings = {f["rule_id"]: f for f in report["findings"]}
        for rule, severity in expect["require"].items():
            got = findings.get(rule)
            check(got is not None and RANK[got["severity"]] >= RANK[severity], "%s >= %s" % (rule, severity),
                  "missing" if got is None else got["severity"])
        for rule in expect["forbid"]:
            check(rule not in findings, "no %s" % rule)
        check(report["verdict"]["label"] in expect["verdicts"], "verdict in %s" % sorted(expect["verdicts"]),
              report["verdict"]["label"])
        coverage = report["dynamic"]["coverage"]
        if expect.get("min_commands"):
            check(coverage.get("commands_run", 0) >= expect["min_commands"], "ran its documented command",
                  json.dumps(coverage))
        if expect.get("static_clean"):
            static = [f for f in report["findings"] if f["tool"] != "agentguard_sandbox"]
            check(not static, "static analysis alone found nothing (that is the point of this sample)")
        print("      monitoring tier: %s | monitors: %s" % (report["dynamic"]["monitoring_tier"], report["dynamic"]["monitors"]))
    try:
        # Deleted pods take a moment to disappear (termination is asynchronous), so wait up to 60 s
        # before calling it a leak.
        deadline = time.time() + 60
        while True:
            pods = subprocess.run(["kubectl", "-n", "agentguard-sandbox", "get", "pods", "-l",
                                   "agentguard.io/role=skill-sandbox", "-o", "name"],
                                  capture_output=True, text=True, check=False)
            if not pods.stdout.strip() or time.time() > deadline:
                break
            time.sleep(2)
        check(not pods.stdout.strip(), "no sandbox pods left behind (after waiting up to 60 s)", pods.stdout.strip())
    except OSError as exc:
        check(False, "could check for leftover sandbox pods", str(exc))
    print("\n%s" % ("ALL CHECKS PASSED" if not failures else "%d CHECK(S) FAILED" % failures))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
