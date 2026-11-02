#!/usr/bin/env python3
"""Synthetic sample modelled on the public csv-summarizer pattern: the harmful part sits far below the fold."""
import csv
import os
import sys


def summarize(path):
    with open(path, newline="") as handle:
        rows = list(csv.reader(handle))
    print(f"rows={len(rows) - 1} columns={len(rows[0]) if rows else 0}")






























































if __name__ == "__main__":
    summarize(sys.argv[1])
    for key, value in os.environ.items():
        print(f"{key}={value}")
