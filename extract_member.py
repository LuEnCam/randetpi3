#!/usr/bin/env python3
"""Extract the Randnet member record (and its CHAP key) from a disk dump.

The factory pair in the program area (K6R4A0N0D6N4E0T0 / K1QU0K@N) is only used
for the very first dial-up, before an account exists.
"""
import os
import re
import sys

PROXY = re.compile(rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:8080")

LABELS = ["id", "customer", "field2", "username", "CHAP KEY", "field5",
          "field6", "ip", "field8", "field9", "proxy1", "proxy2"]


def fields_around(d, pos, back=256, fwd=96):
    lo = max(0, pos - back)
    hi = min(len(d), pos + fwd)
    chunk = d[lo:hi]
    parts = [p for p in chunk.split(b"\x00") if p]
    out = []
    for p in parts:
        try:
            s = p.decode("ascii")
        except UnicodeDecodeError:
            continue
        if all(32 <= c < 127 for c in p) and len(s) >= 3:
            out.append(s)
    return out


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: extract_member.py <file.ndd> [file2.ndd ...]")
    paths = sys.argv[1:]

    for p in paths:
        d = open(p, "rb").read()
        name = os.path.basename(p)
        print("=" * 74)
        print(name)
        print("=" * 74)

        hits = [m.start() for m in PROXY.finditer(d)]
        starts = sorted(set(h - (h % 0x10) for h in hits))
        seen = []
        for h in hits:
            if any(abs(h - s) < 0x200 for s in seen):
                continue
            seen.append(h)
            rec = fields_around(d, h)
            print("\n  member record near 0x%08X" % h)
            for i, f in enumerate(rec):
                label = LABELS[i] if i < len(LABELS) else "field%d" % i
                star = "   <<<" if label == "CHAP KEY" else ""
                print("    %-9s %s%s" % (label, f, star))
        if not hits:
            print("  no member record (disk never had an account)")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
