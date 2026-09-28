#!/usr/bin/env python3
"""
Preprocesses combined.md before pandoc:
- Wraps bare Windows paths (C:\...) in code spans if not already in one
- Fixes other common LaTeX-unsafe patterns in plain text
"""
import re
import sys

def process(infile, outfile):
    with open(infile, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    in_code_block = False
    result = []

    for line in lines:
        stripped = line.rstrip('\n')

        # Track fenced code blocks (``` or ~~~)
        if re.match(r'^\s*(`{3,}|~{3,})', stripped):
            in_code_block = not in_code_block
            result.append(line)
            continue

        # Inside code block - leave completely alone
        if in_code_block:
            result.append(line)
            continue

        # Plain text line - fix bare Windows paths not already in backticks
        # Strategy: tokenise the line into backtick-spans and plain segments,
        # then only process the plain segments.
        processed = wrap_paths_in_backticks(stripped)
        result.append(processed + '\n')

    with open(outfile, 'w', encoding='utf-8') as f:
        f.writelines(result)


def wrap_paths_in_backticks(line):
    """
    For a plain-text line, find Windows path patterns like C:\Foo\Bar
    that are NOT already inside backtick spans, and wrap them.
    """
    # Split line into alternating: plain, `code`, plain, `code`, ...
    # Pattern: backtick-delimited spans
    parts = re.split(r'(`[^`]+`)', line)
    result = []
    for i, part in enumerate(parts):
        if part.startswith('`') and part.endswith('`'):
            # Already a code span - leave it
            result.append(part)
        else:
            # Plain text - wrap Windows paths
            # Match Windows drive paths: C:\Users\...
            fixed = re.sub(
                r'([A-Za-z]:\\[\w.\-\\]+)',
                lambda m: '`' + m.group(0) + '`',
                part
            )
            # Match Windows registry paths: HKCU\..., HKLM\..., HKEY_...\...
            fixed = re.sub(
                r'(HK(?:CU|LM|CR|U|CC)|HKEY_\w+)(\\[\w.\-\\]+)',
                lambda m: '`' + m.group(0) + '`',
                fixed
            )
            result.append(fixed)
    return ''.join(result)


if __name__ == '__main__':
    process(sys.argv[1], sys.argv[2])
