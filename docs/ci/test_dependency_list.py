import unittest
from html.parser import HTMLParser

from dependency_list import PAGE, rendered_list


class DependencyListTests(unittest.TestCase):
    def test_responsive_role_table_keeps_explicit_cell_associations(self):
        class Table(HTMLParser):
            active = False

            def __init__(self):
                super().__init__()
                self.rows, self.cells, self.labels = [], [], 0

            def handle_starttag(self, tag, attributes):
                attrs = dict(attributes)
                if tag == 'table' and attrs.get('class') == 'aa-role-table':
                    self.active = True
                if not self.active:
                    return
                if tag == 'th' and attrs.get('scope') == 'row':
                    self.rows.append(attrs['id'])
                if tag == 'td':
                    self.cells.append(attrs)
                if tag == 'span' and attrs.get('class') == 'aa-role-field':
                    self.labels += 1

            def handle_endtag(self, tag):
                if tag == 'table':
                    self.active = False

        table = Table()
        table.feed(PAGE.read_text())
        self.assertEqual(len(table.rows), 6)
        self.assertEqual(len(table.cells), 12)
        self.assertEqual(table.labels, 12)
        for cell in table.cells:
            row, column = cell['headers'].split()
            self.assertIn(row, table.rows)
            self.assertIn(column, ('role-crates', 'role-owns'))
            self.assertEqual(cell['role'], 'cell')

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
