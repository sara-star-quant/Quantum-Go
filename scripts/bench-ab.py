#!/usr/bin/env python3
"""Compare two Go benchmark outputs taken interleaved on one machine.

usage: bench-ab.py A.txt B.txt [labelA labelB]

Prints, per benchmark, the median ns/op of each side, the ratio B/A, and the spread
(max/min) of each side, so a ratio inside the noise is visible as such.
"""
import re
import statistics
import sys


def load(path):
    out = {}
    for line in open(path):
        m = re.match(r"Benchmark(\S+?)(?:-\d+)?\s+\d+\s+([\d.]+) ns/op", line)
        if m:
            out.setdefault(m.group(1), []).append(float(m.group(2)))
    return out


def main():
    a, b = load(sys.argv[1]), load(sys.argv[2])
    la = sys.argv[3] if len(sys.argv) > 3 else "A"
    lb = sys.argv[4] if len(sys.argv) > 4 else "B"
    print(f"{'benchmark':36} {la+' us':>10} {lb+' us':>10} {'ratio':>7} {'spread '+la:>10} {'spread '+lb:>10}  n")
    for name in sorted(a):
        if name not in b:
            continue
        ma, mb = statistics.median(a[name]), statistics.median(b[name])
        sa, sb = max(a[name]) / min(a[name]), max(b[name]) / min(b[name])
        print(f"{name:36} {ma/1000:10.1f} {mb/1000:10.1f} {mb/ma:6.2f}x {sa:9.2f}x {sb:9.2f}x  {len(a[name])}")


if __name__ == "__main__":
    main()
