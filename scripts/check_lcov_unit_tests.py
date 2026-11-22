#!/usr/bin/env python3
"""Fail when an LCOV report holds no (or too few) unit-test functions.

AAASM-6479: with cargo-llvm-cov 0.8.5 on rustc 1.100.0 the report step found
only the instrumented non-test binaries, so every unit test's coverage was
dropped while the job stayed green and `codecov/patch` fell below its target
for every PR. The report command exits 0 in that state, so the only way to see
it is in the data: an LCOV built from the nextest run lists the `tests` module
functions of every instrumented crate, and a report that lost the test
binaries lists none.

The count is of function records (FN:) whose mangled name contains the `tests`
path segment (length-prefixed, `5tests`), i.e. `#[cfg(test)] mod tests`
bodies, whichever hash or crate they come from. Functions that never ran still
appear with a zero hit count, so the count does not depend on which shard ran
which test.
"""

import argparse
import sys

TEST_MODULE_SEGMENT = "5tests"


def count_test_functions(lines):
    """Count FN records naming a function inside a `tests` module."""
    count = 0
    for line in lines:
        if line.startswith("FN:") and TEST_MODULE_SEGMENT in line.split(",", 1)[-1]:
            count += 1
    return count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("lcov", help="LCOV tracefile to check")
    parser.add_argument(
        "--min",
        type=int,
        default=1000,
        help="fewest unit-test functions a healthy report holds (default: %(default)s)",
    )
    args = parser.parse_args(argv)
    with open(args.lcov, encoding="utf-8", errors="replace") as handle:
        found = count_test_functions(handle)
    if found < args.min:
        print(
            f"{args.lcov}: {found} unit-test functions, expected at least {args.min}. "
            "The report step lost the test binaries (AAASM-6479): check that "
            "cargo-llvm-cov supports the installed rustc.",
            file=sys.stderr,
        )
        return 1
    print(f"{args.lcov}: {found} unit-test functions (minimum {args.min})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
