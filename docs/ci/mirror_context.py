"""Add current navigation context to the explicitly audited rc6 mirror only."""

import argparse
from pathlib import Path
import re

VERSION = "v0.0.1-rc.6"
MARKER = '<!-- aaasm-mirror-context -->'
STYLE = MARKER + '''<style>
.aaasm-mirror-context { font-size: 16px; line-height: 1.5; margin-block: 0 1rem; padding: .75rem; border: 1px solid currentColor; }
@media (max-width: 767px) { .menu-bar .menu-title { display: none; } }
</style>'''
NOTICE = MARKER + f'''<p class="aaasm-mirror-context" role="note">Viewing archived documentation: <strong>{VERSION}</strong>.
<a href="https://docs.agent-assembly.com/core/{VERSION}/">Open this version in the Docs Hub</a>.</p>'''


def decorate(source):
    if MARKER in source:
        if source.count(STYLE) != 1 or source.count(NOTICE) != 1:
            raise ValueError("Unknown or partial mirror overlay")
        return source
    main = re.search(r"<main(?:\s[^>]*)?>", source)
    if source.count('</head>') != 1 or not main:
        raise ValueError("Unknown mirror document structure")
    result = source[:main.end()] + NOTICE + source[main.end():]
    result = result.replace('</head>', STYLE + '</head>', 1)
    if result.replace(STYLE, '', 1).replace(NOTICE, '', 1) != source:
        raise ValueError("Mirror content preservation failed")
    return result


def apply(root):
    if root.name != VERSION or root.is_symlink() or not root.is_dir():
        raise ValueError("Only a physical, explicitly audited rc6 output is allowed")
    changes = []
    for file in root.rglob('*.html'):
        if file.is_symlink():
            raise ValueError("Symlink HTML is not an isolated output")
        source = file.read_text()
        # mdBook's no-JS sidebar iframe is navigation, not an article surface.
        if file.relative_to(root).as_posix() == 'toc.html' and 'sidebar iframe generated using mdBook' in source:
            continue
        try:
            changes.append((file, decorate(source)))
        except ValueError as error:
            raise ValueError(f"{file.relative_to(root)}: {error}") from error
    if not changes:
        raise ValueError("No mirror pages found")
    # Validate every document before writing any output.
    for file, result in changes:
        file.write_text(result)
    return len(changes)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    print(f'Mirror context verified on {apply(args.root)} pages')
