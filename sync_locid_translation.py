#!/usr/bin/env python3
"""CLI tool to merge legacy translated localization XML files with a new English template.

This script preserves the structure of the provided new English XML template while
injecting translations from an older localization file. It supports a strict
validation mode, detailed reporting, and debug utilities to diagnose malformed
XML input.
"""
from __future__ import annotations

import argparse
import codecs
import io
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
import xml.etree.ElementTree as ET

# Illegal XML 1.0 characters (control chars) that must be removed from text nodes.
_ILLEGAL_XML_RE = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x84\x86-\x9F\uD800-\uDFFF\uFEFF]"
)


def detect_bom_and_encoding(raw: bytes) -> Tuple[str, bool]:
    """Detect BOM and choose a matching encoding.

    Returns a tuple of (encoding, has_bom).
    """
    for enc, bom in [
        ("utf-8-sig", codecs.BOM_UTF8),
        ("utf-16-le", codecs.BOM_UTF16_LE),
        ("utf-16-be", codecs.BOM_UTF16_BE),
        ("utf-32-le", codecs.BOM_UTF32_LE),
        ("utf-32-be", codecs.BOM_UTF32_BE),
    ]:
        if raw.startswith(bom):
            return enc, True
    return "utf-8", False


def strip_illegal_chars(text: str) -> str:
    """Remove characters that are not allowed in XML 1.0 text nodes."""
    return _ILLEGAL_XML_RE.sub("", text)


def repair_comment_tokens(text: str) -> str:
    """Fix unbalanced comment tokens without swallowing tags.

    Unmatched closings ("-->") are removed. Unmatched openings ("<!--") are
    escaped to "&lt;!--" so they do not turn the remainder of the document into a
    comment block.
    """
    matches = list(re.finditer(r"<!--|-->", text))
    stack: List[int] = []
    unmatched_closings: List[int] = []
    for m in matches:
        token = m.group(0)
        if token == "<!--":
            stack.append(m.start())
        else:
            if stack:
                stack.pop()
            else:
                unmatched_closings.append(m.start())

    replacements: List[Tuple[int, int, str]] = []
    for pos in stack:
        replacements.append((pos, pos + 4, "&lt;!--"))
    for pos in unmatched_closings:
        replacements.append((pos, pos + 3, ""))

    if not replacements:
        return text

    # Apply replacements from the end to maintain positions.
    repaired = text
    for start, end, rep in sorted(replacements, key=lambda r: r[0], reverse=True):
        repaired = repaired[:start] + rep + repaired[end:]
    return repaired


def read_xml_text(path: Path) -> Tuple[str, str, bool, bool]:
    """Read XML as text, repairing comments and stripping illegal characters.

    Returns (text, encoding, has_bom, has_declaration).
    """
    raw = path.read_bytes()
    encoding, has_bom = detect_bom_and_encoding(raw)
    text = raw.decode(encoding)
    has_declaration = text.lstrip().startswith("<?xml")
    sanitized = strip_illegal_chars(repair_comment_tokens(text))
    return sanitized, encoding, has_bom, has_declaration


def parse_xml(text: str, debug: bool, label: str) -> ET.Element:
    """Parse XML text and provide rich debug output on failure."""
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:  # pragma: no cover - defensive path
        if debug:
            emit_debug_context(text, exc, label)
        raise


def iter_locid_map(xml_text: str, debug: bool, label: str) -> Dict[str, str]:
    """Extract a map of _locID -> text from an XML string efficiently."""
    mapping: Dict[str, str] = {}
    try:
        for event, elem in ET.iterparse(io.StringIO(xml_text)):
            if is_string_element(elem):
                loc_id = elem.get("_locID")
                if loc_id:
                    mapping[loc_id] = strip_illegal_chars(elem.text or "")
            elem.clear()
    except ET.ParseError as exc:  # pragma: no cover - defensive path
        if debug:
            emit_debug_context(xml_text, exc, f"{label} (iterparse)")
        raise
    return mapping


def is_string_element(elem: ET.Element) -> bool:
    return elem.tag.split('}')[-1] == "String"


def clean_language_text(language: ET.Element) -> None:
    """Remove stray text/tail content inside <Language> nodes."""
    if language.text and not language.text.isspace():
        language.text = None
    for child in list(language):
        if child.tail and not child.tail.isspace():
            child.tail = "\n"
        if isinstance(child.tag, str) and child.tag.split('}')[-1] == "Language":
            clean_language_text(child)


def emit_debug_context(xml_text: str, exc: ET.ParseError, label: str) -> None:
    """Print debug details around a parsing error."""
    position = getattr(exc, "position", (None, None))
    line, column = position if position else (None, None)
    sys.stderr.write(f"[DEBUG] Parse error in {label}: {exc}\n")
    offset = None
    if line is not None and column is not None:
        lines = xml_text.splitlines(keepends=True)
        if 0 <= line - 1 < len(lines):
            offset = sum(len(l) for l in lines[: line - 1]) + column
            sys.stderr.write(f"[DEBUG] Line {line}, column {column}\n")
    if offset is not None:
        nearest = find_nearest_locid(xml_text, offset)
        if nearest:
            sys.stderr.write(f"[DEBUG] Nearest _locID before error: {nearest}\n")
        window_start = max(0, offset - 200)
        window_end = min(len(xml_text), offset + 200)
        snippet = xml_text[window_start:window_end]
        snippet = snippet.replace("\n", "\\n").replace("\r", "\\r")
        sys.stderr.write(f"[DEBUG] Surrounding content: {snippet}\n")


def find_nearest_locid(xml_text: str, offset: int) -> Optional[str]:
    """Find the nearest _locID attribute before the given character offset."""
    pattern = re.compile(r"_locID\s*=\s*\"([^\"]+)\"")
    last_id = None
    for match in pattern.finditer(xml_text, 0, offset):
        last_id = match.group(1)
    return last_id


def apply_translations(
    new_tree: ET.Element,
    translation_map: Dict[str, str],
    new_en_map: Dict[str, str],
    old_en_map: Optional[Dict[str, str]],
    mode: str,
    report: Dict[str, List[str]],
) -> None:
    """Mutate the new_tree in-place by inserting translations according to mode."""
    for string_elem in new_tree.iter():
        if not is_string_element(string_elem):
            continue
        loc_id = string_elem.get("_locID")
        if not loc_id:
            continue
        if loc_id in translation_map:
            translation = translation_map[loc_id]
            if mode == "force":
                string_elem.text = translation
                report["applied_force"].append(loc_id)
            else:
                if old_en_map and loc_id in old_en_map:
                    if normalize_text(old_en_map[loc_id]) == normalize_text(new_en_map.get(loc_id, "")):
                        string_elem.text = translation
                        report["applied_safe"].append(loc_id)
                    else:
                        report["needs_retranslate"].append(loc_id)
                else:
                    report["unknown_change"].append(loc_id)
        else:
            report["new_untranslated"].append(loc_id)


def normalize_text(text: str) -> str:
    return (text or "").replace("\r\n", "\n")


def sanitize_language_nodes(root: ET.Element) -> None:
    """Ensure Language nodes do not have stray text and are clean."""
    for elem in root.iter():
        if elem.tag.split('}')[-1] == "Language":
            clean_language_text(elem)


def validate_output(
    output_text: str,
    expected_strings: int,
    debug: bool,
    new_label: str,
) -> None:
    """Validate the output XML according to strict rules."""
    try:
        root = ET.fromstring(output_text)
    except ET.ParseError as exc:
        if debug:
            emit_debug_context(output_text, exc, "output validation")
        raise

    count_strings = sum(1 for _ in root.iter() if is_string_element(_))
    if count_strings != expected_strings:
        raise ValueError(
            f"Validation failed: expected {expected_strings} <String> nodes, found {count_strings}"
        )

    for lang in root.iter():
        if lang.tag.split('}')[-1] == "Language":
            if lang.text and not lang.text.isspace():
                raise ValueError("Validation failed: non-whitespace text inside <Language> element")
            for child in list(lang):
                if child.tail and not child.tail.isspace():
                    raise ValueError("Validation failed: non-whitespace tail inside <Language> element")


def write_output(
    root: ET.Element,
    output_path: Path,
    encoding: str,
    has_bom: bool,
    include_declaration: bool,
) -> str:
    """Serialize XML tree to a string and write to file respecting BOM/declaration."""
    xml_bytes_io = io.BytesIO()
    tree = ET.ElementTree(root)
    tree.write(
        xml_bytes_io,
        encoding=encoding if has_bom else (encoding or "utf-8"),
        xml_declaration=include_declaration,
    )
    data = xml_bytes_io.getvalue()
    output_path.write_bytes(data)
    return data.decode(encoding if has_bom else (encoding or "utf-8"))


def build_report(report: Dict[str, List[str]], output_path: Path) -> None:
    summary = {k: sorted(v) for k, v in report.items()}
    summary_counts = {f"{k}_count": len(v) for k, v in summary.items()}
    summary.update(summary_counts)
    output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Synchronize localization translations by _locID.")
    parser.add_argument("--new", required=True, help="Path to new English XML template")
    parser.add_argument("--old-trans", required=True, help="Path to old translated XML")
    parser.add_argument("--old-en", help="Path to old English XML (for safe mode)")
    parser.add_argument("--out", required=True, help="Path to write updated translation XML")
    parser.add_argument("--report", required=True, help="Path to write merge report JSON")
    parser.add_argument("--mode", choices=["safe", "force"], default="safe", help="Translation merge mode")
    parser.add_argument("--strict", action="store_true", help="Enable strict validation")
    parser.add_argument("--debug", action="store_true", help="Enable debug output on parse errors")
    parser.add_argument(
        "--debug-dump",
        help="Path to write intermediate output even if strict validation fails",
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    new_path = Path(args.new)
    old_trans_path = Path(args.old_trans)
    old_en_path = Path(args.old_en) if args.old_en else None
    out_path = Path(args.out)
    report_path = Path(args.report)

    new_text, new_encoding, new_has_bom, has_declaration = read_xml_text(new_path)
    new_root = parse_xml(new_text, args.debug, "new template")

    new_en_map = iter_locid_map(new_text, args.debug, "new template map")
    old_en_map = None
    if old_en_path:
        old_en_text, _, _, _ = read_xml_text(old_en_path)
        old_en_map = iter_locid_map(old_en_text, args.debug, "old English map")

    old_trans_text, _, _, _ = read_xml_text(old_trans_path)
    old_trans_map = iter_locid_map(old_trans_text, args.debug, "old translation map")

    report: Dict[str, List[str]] = {
        "applied_safe": [],
        "applied_force": [],
        "needs_retranslate": [],
        "new_untranslated": [],
        "unknown_change": [],
        "orphan_old_trans_ids": [],
    }

    apply_translations(
        new_root,
        old_trans_map,
        new_en_map,
        old_en_map,
        args.mode,
        report,
    )

    # Track orphan translations not present in the new template.
    report["orphan_old_trans_ids"] = [loc for loc in old_trans_map.keys() if loc not in new_en_map]

    sanitize_language_nodes(new_root)

    xml_bytes_io = io.BytesIO()
    tree = ET.ElementTree(new_root)
    tree.write(
        xml_bytes_io,
        encoding=new_encoding if new_has_bom else (new_encoding or "utf-8"),
        xml_declaration=has_declaration,
    )
    output_text = xml_bytes_io.getvalue().decode(new_encoding if new_has_bom else (new_encoding or "utf-8"))

    if args.strict:
        try:
            validate_output(output_text, len(new_en_map), args.debug, "output")
        except Exception as exc:  # pragma: no cover - strict failure path
            if args.debug_dump:
                Path(args.debug_dump).write_text(output_text, encoding=new_encoding or "utf-8")
            if args.debug:
                sys.stderr.write(f"[DEBUG] Validation failed: {exc}\n")
            else:
                sys.stderr.write(f"Validation failed: {exc}\n")
            return 1

    write_output(new_root, out_path, new_encoding, new_has_bom, has_declaration)
    build_report(report, report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
