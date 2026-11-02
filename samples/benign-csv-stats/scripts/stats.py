#!/usr/bin/env python3
"""Print row and column counts for a CSV file."""
import csv
import sys


def main(path):
    with open(path, newline="") as handle:
        rows = list(csv.reader(handle))
    print(f"rows={max(len(rows) - 1, 0)} columns={len(rows[0]) if rows else 0}")


if __name__ == "__main__":
    main(sys.argv[1])
