#!/usr/bin/env python3
"""
Adds a blank line before list items (numbered or bullet) that directly
follow a prose paragraph line with no blank separator. This is required
for pandoc to recognise them as list environments rather than inline text.

Only modifies lines that exactly match the pattern:
  - previous line is non-empty, not a list item, not a heading, not blank
  - current line starts with  N.  or  -  or  *
Does NOT touch any list item that already has a blank line before it.
"""
import re
import sys

LIST_ITEM = re.compile(r'^(\d+\.|[-*])\s')
HEADING   = re.compile(r'^#{1,6}\s')

def fix(path):
    with open(path, encoding='utf-8') as f:
        lines = f.readlines()

    out = []
    changed = 0
    in_code = False

    for i, line in enumerate(lines):
        stripped = line.rstrip('\n')

        # track fenced code blocks - never touch lines inside them
        if re.match(r'^\s*(`{3,}|~{3,})', stripped):
            in_code = not in_code

        if not in_code and LIST_ITEM.match(stripped):
            prev = out[-1].rstrip('\n') if out else ''
            # prev is non-empty, not already blank, not a list item, not a heading
            if (prev
                    and not LIST_ITEM.match(prev)
                    and not HEADING.match(prev)
                    and not re.match(r'^\s*(`{3,}|~{3,})', prev)):
                out.append('\n')      # insert the missing blank line
                changed += 1

        out.append(line)

    with open(path, 'w', encoding='utf-8') as f:
        f.writelines(out)

    print(f'{path}: {changed} blank lines inserted')

if __name__ == '__main__':
    for p in sys.argv[1:]:
        fix(p)
