#!/usr/bin/env python3
"""Merge LCOV tracefiles by summing hit counts.

The Coverage job runs as four nextest hash shards on four runners (AAASM-6410),
so each shard produces an lcov.info covering only its own tests. Codecov sums
separate uploads itself; SonarCloud reads exactly one `lcov.info`, so this sums
the shards into that one file.

Handles the records `cargo llvm-cov --lcov` emits: SF, FN, FNDA, FNF, FNH, DA,
LF, LH, BRF, BRH, end_of_record. That command writes BRF/BRH totals of zero and
no BRDA lines. A BRDA line, or a non-zero BRF/BRH, is rejected rather than
silently dropped, so a future switch to branch coverage fails here instead of
understating coverage.

LF/LH/FNF/FNH are recomputed from the summed DA/FN records, as the lcov tool
does. They are not copied from the inputs, and they can differ from the totals
`llvm-cov` prints for the same file: Codecov and SonarCloud both read the DA
lines, which this preserves (hit counts add exactly).
"""

import argparse
import sys
from collections import defaultdict


class Record:
    def __init__(self):
        self.fn_line = {}
        self.fn_hits = defaultdict(int)
        self.da = defaultdict(int)


def parse(path, files):
    current = None
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if not line:
                continue
            tag, _, value = line.partition(":")
            if tag == "SF":
                current = files.setdefault(value, Record())
            elif tag == "end_of_record":
                current = None
            elif tag == "TN":
                continue
            elif current is None:
                raise ValueError(f"{path}: {tag!r} outside a record")
            elif tag == "FN":
                number, _, name = value.partition(",")
                current.fn_line.setdefault(name, int(number))
            elif tag == "FNDA":
                count, _, name = value.partition(",")
                current.fn_hits[name] += int(count)
            elif tag == "DA":
                number, _, rest = value.partition(",")
                count = rest.split(",", 1)[0]
                current.da[int(number)] += int(count)
            elif tag in ("FNF", "FNH", "LF", "LH"):
                continue  # recomputed from the summed data
            elif tag in ("BRF", "BRH"):
                if int(value) != 0:
                    raise ValueError(f"{path}: branch coverage is not supported")
            else:
                raise ValueError(f"{path}: unsupported LCOV record {tag!r}")


def render(files):
    out = []
    for source in sorted(files):
        record = files[source]
        out.append("TN:")
        out.append(f"SF:{source}")
        names = sorted(record.fn_line, key=lambda n: (record.fn_line[n], n))
        for name in names:
            out.append(f"FN:{record.fn_line[name]},{name}")
        for name in names:
            out.append(f"FNDA:{record.fn_hits.get(name, 0)},{name}")
        out.append(f"FNF:{len(names)}")
        out.append(f"FNH:{sum(1 for n in names if record.fn_hits.get(n, 0) > 0)}")
        for number in sorted(record.da):
            out.append(f"DA:{number},{record.da[number]}")
        out.append(f"LF:{len(record.da)}")
        out.append(f"LH:{sum(1 for c in record.da.values() if c > 0)}")
        out.append("BRF:0")
        out.append("BRH:0")
        out.append("end_of_record")
    return "\n".join(out) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("inputs", nargs="+")
    args = parser.parse_args(argv)
    files = {}
    for path in args.inputs:
        parse(path, files)
    if not files:
        print("merge_lcov: no records in any input", file=sys.stderr)
        return 1
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(render(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
