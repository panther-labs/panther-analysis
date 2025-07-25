#!/usr/bin/env python3

import sys
import os
from typing import List, NamedTuple

# Invisible characters database from https://github.com/flopp/invisible-characters/blob/main/characters.json
INVISIBLE_CHARS = {
  "000B": "LINE TABULATION",
  "000C": "FORM FEED",
  "00A0": "NO-BREAK SPACE",
  "00AD": "SOFT HYPHEN",
  "034F": "COMBINING GRAPHEME JOINER",
  "061C": "ARABIC LETTER MARK",
  "115F": "HANGUL CHOSEONG FILLER",
  "1160": "HANGUL JUNGSEONG FILLER",
  "17B4": "KHMER VOWEL INHERENT AQ",
  "17B5": "KHMER VOWEL INHERENT AA",
  "180E": "MONGOLIAN VOWEL SEPARATOR",
  "1D000": "GLAGOLITIC CAPITAL LETTER BUKY",
  "1D0F0": "GLAGOLITIC SMALL LETTER YERU",
  "1D100": "GLAGOLITIC CAPITAL LETTER AZU",
  "1D129": "GLAGOLITIC SMALL LETTER YUS",
  "1D130": "GLAGOLITIC CAPITAL LETTER IZHITSA",
  "1D13F": "GLAGOLITIC SMALL LETTER YAT",
  "1D140": "GLAGOLITIC CAPITAL LETTER FITA",
  "1D145": "GLAGOLITIC SMALL LETTER FITA",
  "1D150": "MUSICAL SYMBOL BEGIN BEAM",
  "1D159": "MUSICAL SYMBOL NULL NOTEHEAD",
  "1D173": "MUSICAL SYMBOL BEGIN BEAM",
  "1D174": "MUSICAL SYMBOL END BEAM",
  "1D175": "MUSICAL SYMBOL BEGIN TIE",
  "1D176": "MUSICAL SYMBOL END TIE",
  "1D177": "MUSICAL SYMBOL BEGIN SLUR",
  "1D178": "MUSICAL SYMBOL END SLUR",
  "1D179": "MUSICAL SYMBOL BEGIN PHRASE",
  "1D17A": "MUSICAL SYMBOL END PHRASE",
  "2000": "EN QUAD",
  "2001": "EM QUAD",
  "2002": "EN SPACE",
  "2003": "EM SPACE",
  "2004": "THREE-PER-EM SPACE",
  "2005": "FOUR-PER-EM SPACE",
  "2006": "SIX-PER-EM SPACE",
  "2007": "FIGURE SPACE",
  "2008": "PUNCTUATION SPACE",
  "2009": "THIN SPACE",
  "200A": "HAIR SPACE",
  "200B": "ZERO WIDTH SPACE",
  "200C": "ZERO WIDTH NON-JOINER",
  "200D": "ZERO WIDTH JOINER",
  "200E": "LEFT-TO-RIGHT MARK",
  "200F": "RIGHT-TO-LEFT MARK",
  "202F": "NARROW NO-BREAK SPACE",
  "205F": "MEDIUM MATHEMATICAL SPACE",
  "2060": "WORD JOINER",
  "2061": "FUNCTION APPLICATION",
  "2062": "INVISIBLE TIMES",
  "2063": "INVISIBLE SEPARATOR",
  "2064": "INVISIBLE PLUS",
  "2065": "Invisible operators - undefined",
  "206A": "INHIBIT SYMMETRIC SWAPPING",
  "206B": "ACTIVATE SYMMETRIC SWAPPING",
  "206C": "INHIBIT ARABIC FORM SHAPING",
  "206D": "ACTIVATE ARABIC FORM SHAPING",
  "206E": "NATIONAL DIGIT SHAPES",
  "206F": "NOMINAL DIGIT SHAPES",
  "2800": "BRAILLE PATTERN BLANK",
  "3000": "IDEOGRAPHIC SPACE",
  "3164": "HANGUL FILLER",
  "E0020": "TAG SPACE",
  "FEFF": "ZERO WIDTH NO-BREAK SPACE",
  "FFA0": "HALFWIDTH HANGUL FILLER",
  "FFFC": "OBJECT REPLACEMENT CHARACTER"
}

# Characters to ignore (common legitimate whitespace)
ALLOWED_CHARS = {"0009", "000A", "000D", "0020"}  # TAB, LF, CR, SPACE


class Issue(NamedTuple):
    file: str
    line: int
    column: int
    hex: str
    name: str
    codepoint: int


def scan_file_for_invisible_chars(file_path: str) -> List[Issue]:
    """Scan a file for invisible characters and return list of issues."""
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}", file=sys.stderr)
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
        return []

    lines = content.splitlines()
    issues = []
    
    for line_num, line in enumerate(lines):
        for char_pos, char in enumerate(line):
            codepoint = ord(char)
            hex_code = f"{codepoint:04X}"
            
            if hex_code in INVISIBLE_CHARS and hex_code not in ALLOWED_CHARS:
                issues.append(Issue(
                    file=file_path,
                    line=line_num + 1,
                    column=char_pos + 1,
                    hex=hex_code,
                    name=INVISIBLE_CHARS[hex_code],
                    codepoint=codepoint
                ))
    
    return issues


def should_ignore_file(file_path: str, ignore_patterns: List[str]) -> bool:
    """Check if a file should be ignored based on patterns."""
    for pattern in ignore_patterns:
        if pattern in file_path:
            return True
    return False


def main() -> None:
    """Main entry point for the linter."""
    args = sys.argv[1:]
    if len(args) == 0:
        print("Usage: lint-invisible.py <file1> <file2> ... --ignore <pattern1>,<pattern2>...")
        return
    
    ignore_patterns = []
    file_paths = []
    
    # Parse arguments
    i = 0
    while i < len(args):
        if args[i] == '--ignore' and i + 1 < len(args):
            ignore_patterns = [p.strip() for p in args[i + 1].split(',')]
            i += 2
        else:
            file_paths.append(args[i])
            i += 1
    
    if not file_paths:
        print("Ignored path matchers: ", ignore_patterns)
        print("Changed files: ", file_paths)
        print("No files eligible for invisible character linting", file=sys.stdout)
        return
    
    total_issues = 0
    scanned_files = 0
    
    for file_path in file_paths:
        if should_ignore_file(file_path, ignore_patterns):
            continue
            
        scanned_files += 1
        issues = scan_file_for_invisible_chars(file_path)
        
        for issue in issues:
            print(f"{issue.file}:{issue.line}:{issue.column}: Found invisible character U+{issue.hex} ({issue.name})")
            total_issues += 1
    
    if total_issues > 0:
        print(f"\nFound {total_issues} invisible character(s) in {scanned_files} file(s)", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"Scanned {scanned_files} file(s): no invisible characters found")


if __name__ == "__main__":
    main()