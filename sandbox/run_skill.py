from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import execution  # noqa: E402  (sibling module copied into the image next to this file)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("prepare", "execute"), required=True)
    parser.add_argument("--command", default="")
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("AGENTGUARD_COMMAND_TIMEOUT", "30")))
    args = parser.parse_args()
    token = os.environ.get("AGENTGUARD_SCAN_TOKEN", "")
    if args.phase == "prepare":
        if len(token) != 32:
            print("AGENTGUARD_SCAN_TOKEN must be a 32-character scan token", file=sys.stderr)
            return 2
        created = execution.create_honeypots(token)
        print(f"AGENTGUARD_PHASE=prepare honeypots={len(created)}", flush=True)
        return 0
    if os.environ.get("AGENTGUARD_AGENT_MODE") == "ollama":
        # The LLM-driven executor. Its run_python tool launches the skill through the same
        # guarded environment (decoy HOME, canary env, audit hook, strace) as scripted runs.
        import subprocess

        completed = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_executor.py")],
            cwd=str(execution.SKILL_DIR), check=False,
        )
        print(f"AGENTGUARD_EXIT_CODE={completed.returncode}", flush=True)
        return 0
    command = args.command or os.environ.get("AGENTGUARD_ENTRYPOINT", "")
    code = execution.execute(token, command=command, timeout=args.timeout)
    print(f"AGENTGUARD_PHASE=execute harness_exit={code}", flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
