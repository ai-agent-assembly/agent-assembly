#!/usr/bin/env sh
# Python package and test activity: generate a small package, byte-compile it,
# then discover and run its unittest suite.
#
# unittest rather than pytest so the family is hermetic — no install step, no
# network, and no dependence on which test runner happens to be present on the
# host. What is being timed is interpreter startup, the import machinery and
# test discovery, which pytest would exercise the same way but less portably.
set -eu
scratch="$1"

pkg="$scratch/aabench_pkg"
mkdir -p "$pkg"
: > "$pkg/__init__.py"

i=0
while [ "$i" -lt 10 ]; do
    cat > "$pkg/mod$i.py" <<PYEOF
"""Generated module $i."""


def value():
    return $i


def double():
    return value() * 2
PYEOF
    i=$((i + 1))
done

j=0
while [ "$j" -lt 3 ]; do
    cat > "$scratch/test_gen$j.py" <<PYEOF
import unittest

from aabench_pkg import mod$j


class Gen${j}Test(unittest.TestCase):
    def test_value(self):
        self.assertEqual(mod$j.value(), $j)

    def test_double(self):
        self.assertEqual(mod$j.double(), $j * 2)
PYEOF
    j=$((j + 1))
done

cd "$scratch"
python3 -m compileall -q aabench_pkg >/dev/null
python3 -m unittest discover -s . -p 'test_*.py' >/dev/null 2>&1
