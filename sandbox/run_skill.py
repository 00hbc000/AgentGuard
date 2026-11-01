from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("prepare", "execute"), required=True)
    parser.add_argument("--command", default="")
    args = parser.parse_args()
    if args.phase == "prepare":
        print("AGENTGUARD_PHASE=prepare", flush=True)
        return 0
    command = args.command or os.environ.get("AGENTGUARD_ENTRYPOINT", "")
    if not command and os.path.isfile("/skill/run.py"):
        command = "python /skill/run.py"
    if not command:
        print("AGENTGUARD_PHASE=execute no entrypoint supplied", flush=True)
        return 0
    argv = shlex.split(command)
    with open("/tmp/agentguard-trace", "w", encoding="utf-8") as trace:
        process = subprocess.run(
            ["strace", "-f", "-e", "trace=openat,connect", "-o", "/tmp/agentguard-trace", *argv],
            cwd="/skill", check=False,
        )
    print(f"AGENTGUARD_EXIT_CODE={process.returncode}", flush=True)
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
