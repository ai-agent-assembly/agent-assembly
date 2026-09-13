import tempfile
from pathlib import Path
import unittest

from mirror_context import NOTICE, STYLE, VERSION, apply, decorate


class MirrorContextTests(unittest.TestCase):
    def test_exact_preservation_and_idempotence(self):
        source = '<html><head></head><body><main id="content"><h1>Frozen</h1><pre>x &lt; y</pre></main></body></html>'
        result = decorate(source)
        self.assertEqual(result.replace(STYLE, '').replace(NOTICE, ''), source)
        self.assertEqual(decorate(result), result)

    def test_unknown_page_does_not_partially_modify_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / VERSION
            root.mkdir()
            first = root / 'index.html'
            first.write_text('<head></head><main>Original</main>')
            (root / 'bad.html').write_text('<main>Missing head</main>')
            with self.assertRaises(ValueError):
                apply(root)
            self.assertEqual(first.read_text(), '<head></head><main>Original</main>')

    def test_other_archive_is_rejected(self):
        with self.assertRaises(ValueError):
            apply(Path('/tmp/v0.0.1-rc.5'))

    def test_native_sidebar_iframe_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / VERSION
            root.mkdir()
            (root / 'index.html').write_text('<head></head><main>Original</main>')
            iframe = '<head><!-- sidebar iframe generated using mdBook --></head><body>Navigation</body>'
            (root / 'toc.html').write_text(iframe)
            self.assertEqual(apply(root), 1)
            self.assertEqual((root / 'toc.html').read_text(), iframe)


if __name__ == '__main__':
    unittest.main()
