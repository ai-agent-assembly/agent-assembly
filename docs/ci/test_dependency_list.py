import unittest

from dependency_list import PAGE, rendered_list


class DependencyListTests(unittest.TestCase):
    def test_real_graph_preserves_all_edges_and_group_label(self):
        result = rendered_list(PAGE.read_text())
        self.assertEqual(len(result.strip().splitlines()), 27)
        self.assertIn("`aa-sdk-client` → `aa-security` (dotted preflight relationship)", result)
        self.assertIn("`aa-storage-{memory,postgres,redis,sqlite-buffer}` → `aa-storage`", result)

    def test_unlabelled_endpoint_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Missing node label"):
            rendered_list("```mermaid\ngraph TD\n a[A]\n a --> b\n```\n")


if __name__ == "__main__":
    unittest.main()
