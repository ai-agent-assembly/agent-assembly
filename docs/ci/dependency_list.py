"""Keep the accessible dependency list tied to the displayed Mermaid source."""

import argparse
from pathlib import Path
import re

PAGE = Path(__file__).resolve().parents[1] / "src/architecture/system-architecture.md"
START = "<!-- dependency-list:start -->"
END = "<!-- dependency-list:end -->"


def rendered_list(source):
    graph = source.split("```mermaid\n", 1)[1].split("```", 1)[0]
    names = {}
    for line in graph.splitlines():
        match = re.match(r"\s*(\w+)\[(.+)\](?:[:]{3}\w+)?\s*$", line)
        if match:
            label = match[2].strip('"').split("<i>", 1)[0]
            names[match[1]] = re.sub(r"<br\s*/?>", "", label).strip()
    rows = []
    for line in graph.splitlines():
        match = re.fullmatch(r"\s*(\w+)\s+(-->|-\. preflight \.->)\s+(\w+)\s*", line)
        if not match:
            continue
        source_id, edge, target_id = match.groups()
        if source_id not in names or target_id not in names:
            raise ValueError(f"Missing node label: {line}")
        suffix = " (dotted preflight relationship)" if edge != "-->" else ""
        rows.append(f"- `{names[source_id]}` → `{names[target_id]}`{suffix}")
    if not rows:
        raise ValueError("No dependency edges found")
    return "\n\n" + "\n".join(rows) + "\n\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source = PAGE.read_text()
    before, tail = source.split(START, 1)
    current, after = tail.split(END, 1)
    generated = rendered_list(source)
    if args.check:
        if current != generated:
            raise SystemExit("Dependency list drift: run python3 docs/ci/dependency_list.py")
    else:
        PAGE.write_text(before + START + generated + END + after)


if __name__ == "__main__":
    main()
