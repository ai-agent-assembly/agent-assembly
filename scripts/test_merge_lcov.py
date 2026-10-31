#!/usr/bin/env python3
"""Tests for merge_lcov.py: counts add, sets union, totals are recomputed."""

import os
import tempfile
import unittest

import merge_lcov


def _write(directory, name, text):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


SHARD_A = """TN:
SF:src/a.rs
FN:1,fa
FNDA:2,fa
FNF:1
FNH:1
DA:1,2
DA:2,0
LF:2
LH:1
end_of_record
"""

SHARD_B = """TN:
SF:src/a.rs
FN:1,fa
FN:5,fb
FNDA:0,fa
FNDA:3,fb
FNF:2
FNH:1
DA:1,0
DA:2,4
DA:6,1
LF:3
LH:2
end_of_record
TN:
SF:src/b.rs
DA:1,1
LF:1
LH:1
end_of_record
"""


class MergeLcovTest(unittest.TestCase):
    def _merge(self, *shards):
        with tempfile.TemporaryDirectory() as directory:
            paths = [_write(directory, f"s{i}.info", text) for i, text in enumerate(shards)]
            output = os.path.join(directory, "out.info")
            self.assertEqual(merge_lcov.main(["-o", output, *paths]), 0)
            with open(output, encoding="utf-8") as handle:
                return handle.read()

    def test_line_counts_add_across_shards(self):
        merged = self._merge(SHARD_A, SHARD_B)
        self.assertIn("DA:1,2\n", merged)  # 2 + 0
        self.assertIn("DA:2,4\n", merged)  # 0 + 4
        self.assertIn("DA:6,1\n", merged)  # only in B

    def test_the_same_line_hit_in_both_shards_adds_not_maxes(self):
        # Guards the core invariant: 2 + 3 must be 5 (a max or an overwrite gives 3),
        # for lines and for function hits.
        left = "SF:src/d.rs\nFN:1,f\nFNDA:2,f\nDA:7,2\nend_of_record\n"
        right = "SF:src/d.rs\nFN:1,f\nFNDA:3,f\nDA:7,3\nend_of_record\n"
        merged = self._merge(left, right)
        self.assertIn("DA:7,5\n", merged)
        self.assertIn("FNDA:5,f\n", merged)

    def test_totals_are_recomputed_not_copied(self):
        merged = self._merge(SHARD_A, SHARD_B)
        a_record = merged.split("end_of_record")[0]
        self.assertIn("LF:3\n", a_record)
        self.assertIn("LH:3\n", a_record)
        self.assertIn("FNF:2\n", a_record)
        self.assertIn("FNH:2\n", a_record)

    def test_a_file_seen_in_one_shard_survives(self):
        self.assertIn("SF:src/b.rs\n", self._merge(SHARD_A, SHARD_B))

    def test_merge_is_order_independent(self):
        self.assertEqual(self._merge(SHARD_A, SHARD_B), self._merge(SHARD_B, SHARD_A))

    def test_zero_branch_totals_are_accepted(self):
        zero = "SF:src/c.rs\nDA:1,1\nBRF:0\nBRH:0\nend_of_record\n"
        self.assertIn("DA:1,1\n", self._merge(zero))

    def test_nonzero_branch_totals_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write(directory, "b.info", "SF:src/c.rs\nBRF:2\nBRH:1\nend_of_record\n")
            with self.assertRaises(ValueError):
                merge_lcov.main(["-o", os.path.join(directory, "o.info"), path])

    def test_branch_records_are_refused_not_dropped(self):
        branchy = "SF:src/c.rs\nBRDA:1,0,0,1\nend_of_record\n"
        with tempfile.TemporaryDirectory() as directory:
            path = _write(directory, "b.info", branchy)
            with self.assertRaises(ValueError):
                merge_lcov.main(["-o", os.path.join(directory, "o.info"), path])

    def test_empty_input_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write(directory, "e.info", "")
            self.assertEqual(merge_lcov.main(["-o", os.path.join(directory, "o.info"), path]), 1)


if __name__ == "__main__":
    unittest.main()
