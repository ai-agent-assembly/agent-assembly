#!/usr/bin/env python3
"""Tests for check_lcov_unit_tests.py: a report without test functions fails."""

import os
import tempfile
import unittest

import check_lcov_unit_tests as check

WITH_TESTS = """SF:src/a.rs
FN:10,_RNvCs1_6aa_cli3foo
FNDA:3,_RNvCs1_6aa_cli3foo
FN:30,_RNvNtCs1_6aa_cli5tests7a_test
FNDA:0,_RNvNtCs1_6aa_cli5tests7a_test
FN:40,_RNvNtCs1_6aa_cli5tests9another
FNDA:1,_RNvNtCs1_6aa_cli5tests9another
end_of_record
"""

WITHOUT_TESTS = """SF:src/a.rs
FN:10,_RNvCs1_6aa_cli3foo
FNDA:3,_RNvCs1_6aa_cli3foo
end_of_record
"""


def _run(text, minimum):
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "lcov.info")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return check.main([path, "--min", str(minimum)])


class CheckLcovUnitTests(unittest.TestCase):
    def test_counts_test_functions_including_unhit_ones(self):
        self.assertEqual(check.count_test_functions(WITH_TESTS.splitlines()), 2)

    def test_a_report_with_enough_test_functions_passes(self):
        self.assertEqual(_run(WITH_TESTS, 2), 0)

    def test_a_report_that_lost_the_test_binaries_fails(self):
        self.assertEqual(_run(WITHOUT_TESTS, 1), 1)

    def test_fewer_than_the_minimum_fails(self):
        self.assertEqual(_run(WITH_TESTS, 3), 1)

    def test_a_hit_count_line_alone_is_not_a_function_record(self):
        self.assertEqual(check.count_test_functions(["FNDA:1,_RNvNtCs1_6aa_cli5tests7a_test"]), 0)


if __name__ == "__main__":
    unittest.main()
