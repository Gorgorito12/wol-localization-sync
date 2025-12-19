#!/usr/bin/env python3
"""
CLI tool to merge localization XML files by _locID while preserving the
structure of the new canonical file.

Usage:
    python merge_translation_locid.py --new "new_en.xml" --old-trans "old_trans.xml" --out "out_trans_updated.xml" --report "report.json"
Optional:
    --old-en "old_en.xml"
    --mode "safe"|"force" (default: safe)
    --dry-run
    --strict
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from xml.etree import ElementTree as ET


STRING_PATTERN = re.compile(
    r'<String\b[^>]*\s_locID\s*=\s*"([^"]+)"[^>]*>(.*?)</String>',
    re.DOTALL | re.IGNORECASE,
)


@dataclass
class TemplateString:
    loc_id: str
    inner_text: str
    start: int
    end: int
    inner_start: int
    inner_end: int


@dataclass
class MergeResult:
    output_text: str
    report: dict


def detect_encoding(text: str, default: str = "utf-8") -> str:
    declaration = re.search(r'<\?xml[^>]*encoding=["\']([^"\']+)["\']', text, re.IGNORECASE)
    if declaration:
        return declaration.group(1)
    return default


def read_text_with_bom(path: Path) -> Tuple[str, bool, str]:
    raw = path.read_bytes()

    bom_encodings: List[Tuple[bytes, str, str]] = [
        (b"\xef\xbb\xbf", "utf-8-sig", "utf-8"),
        (b"\xff\xfe\x00\x00", "utf-32", "utf-32-le"),
        (b"\x00\x00\xfe\xff", "utf-32", "utf-32-be"),
        (b"\xff\xfe", "utf-16", "utf-16-le"),
        (b"\xfe\xff", "utf-16", "utf-16-be"),
    ]

    has_bom = False
    decode_encoding = "utf-8"
    write_encoding = "utf-8"

    for bom, dec_enc, wr_enc in bom_encodings:
        if raw.startswith(bom):
            has_bom = True
            decode_encoding = dec_enc
            write_encoding = wr_enc
            break

    text = raw.decode(decode_encoding)
    return text, has_bom, write_encoding


def write_text_with_bom(path: Path, text: str, encoding: str, has_bom: bool) -> None:
    normalized = encoding.lower().replace("-", "")
    data = text.encode(encoding)

    if has_bom:
        bom_map = {
            "utf8": b"\xef\xbb\xbf",
            "utf16": b"\xff\xfe",
            "utf16le": b"\xff\xfe",
            "utf16be": b"\xfe\xff",
            "utf32": b"\xff\xfe\x00\x00",
            "utf32le": b"\xff\xfe\x00\x00",
            "utf32be": b"\x00\x00\xfe\xff",
        }
        bom = bom_map.get(normalized)
        if bom and not data.startswith(bom):
            data = bom + data

    path.write_bytes(data)


def parse_string_map(xml_text: str) -> Dict[str, str]:
    cleaned = xml_text.lstrip("\ufeff")
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError as exc:
        raise ValueError(f"Failed to parse XML: {exc}") from exc

    mapping: Dict[str, str] = {}
    for string_elem in root.iter():
        if string_elem.tag.endswith("String") and "_locID" in string_elem.attrib:
            mapping[string_elem.attrib["_locID"]] = string_elem.text or ""
    return mapping


def escape_xml_text(text: str) -> str:
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    return text


def collect_template_strings(template: str) -> List[TemplateString]:
    strings: List[TemplateString] = []
    for match in STRING_PATTERN.finditer(template):
        loc_id = match.group(1)
        inner_text = match.group(2)
        strings.append(
            TemplateString(
                loc_id=loc_id,
                inner_text=inner_text,
                start=match.start(),
                end=match.end(),
                inner_start=match.start(2),
                inner_end=match.end(2),
            )
        )
    return strings


def merge_translations(
    template_text: str,
    new_en_map: Dict[str, str],
    old_trans_map: Dict[str, str],
    old_en_map: Optional[Dict[str, str]],
    mode: str,
) -> MergeResult:
    template_strings = collect_template_strings(template_text)

    total_new_strings = len(template_strings)
    total_old_translated_strings = len(old_trans_map)
    orphan_old_trans = sorted(set(old_trans_map) - {ts.loc_id for ts in template_strings})

    output_parts: List[str] = []
    last_index = 0

    safe_applied_translation = 0
    new_untranslated = 0
    needs_retranslate = 0
    unknown_change = 0
    forced_applied = 0

    needs_retranslate_ids: List[str] = []
    new_untranslated_ids: List[str] = []
    unknown_change_ids: List[str] = []
    forced_applied_ids: List[str] = []
    safe_applied_ids: List[str] = []

    for ts in template_strings:
        output_parts.append(template_text[last_index : ts.inner_start])

        replacement_text = ts.inner_text
        if ts.loc_id in old_trans_map:
            old_translation_text = old_trans_map[ts.loc_id]
            escaped_translation = escape_xml_text(old_translation_text)

            if mode == "force":
                replacement_text = escaped_translation
                forced_applied += 1
                forced_applied_ids.append(ts.loc_id)
            else:
                if old_en_map and ts.loc_id in old_en_map:
                    old_en_text = old_en_map[ts.loc_id]
                    new_en_text = new_en_map.get(ts.loc_id, ts.inner_text)
                    if new_en_text == old_en_text:
                        replacement_text = escaped_translation
                        safe_applied_translation += 1
                        safe_applied_ids.append(ts.loc_id)
                    else:
                        needs_retranslate += 1
                        needs_retranslate_ids.append(ts.loc_id)
                else:
                    replacement_text = escaped_translation
                    unknown_change += 1
                    unknown_change_ids.append(ts.loc_id)
        else:
            new_untranslated += 1
            new_untranslated_ids.append(ts.loc_id)

        output_parts.append(replacement_text)
        last_index = ts.inner_end

    output_parts.append(template_text[last_index:])
    merged_text = "".join(output_parts)

    report = {
        "mode": mode,
        "total_new_strings": total_new_strings,
        "total_old_translated_strings": total_old_translated_strings,
        "safe_applied_translation": safe_applied_translation,
        "new_untranslated": new_untranslated,
        "needs_retranslate": needs_retranslate,
        "unknown_change": unknown_change,
        "forced_applied": forced_applied,
        "orphan_old_trans": orphan_old_trans,
        "new_untranslated_ids": new_untranslated_ids,
        "needs_retranslate_ids": needs_retranslate_ids,
        "unknown_change_ids": unknown_change_ids,
        "forced_applied_ids": forced_applied_ids,
        "safe_applied_ids": safe_applied_ids,
    }

    return MergeResult(output_text=merged_text, report=report)


def validate_output(template_text: str, output_text: str) -> List[str]:
    errors: List[str] = []

    def count_strings(text: str) -> int:
        try:
            root = ET.fromstring(text.lstrip("\ufeff"))
        except ET.ParseError as exc:
            errors.append(f"Output XML is invalid: {exc}")
            return -1
        count = 0
        for elem in root.iter():
            if elem.tag.endswith("String") and "_locID" in elem.attrib:
                count += 1
        language_elements = [elem for elem in root.iter() if elem.tag.endswith("Language")]
        for lang in language_elements:
            if lang.text and lang.text.strip():
                errors.append("Found stray text inside <Language> element.")
            for child in lang:
                if child.tail and child.tail.strip():
                    errors.append("Found stray tail text inside <Language> element.")
        return count

    new_count = count_strings(template_text)
    out_count = count_strings(output_text)
    if new_count != -1 and out_count != -1 and new_count != out_count:
        errors.append(
            f"String count mismatch: new template has {new_count}, output has {out_count}."
        )

    return errors


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge localization XML files by _locID while preserving the new template structure."
    )
    parser.add_argument("--new", required=True, help="Path to the new English XML (template).")
    parser.add_argument("--old-trans", required=True, help="Path to the old translated XML.")
    parser.add_argument("--out", required=True, help="Path to write the updated translation XML.")
    parser.add_argument("--report", required=True, help="Path to write the merge report JSON.")
    parser.add_argument("--old-en", help="Optional path to the old English XML for change detection.")
    parser.add_argument(
        "--mode",
        choices=["safe", "force"],
        default="safe",
        help="Safe: only apply translations when English text is unchanged. Force: always apply translations.",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Run the merge without writing output files."
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enable validations (XML parse, string counts, stray text) and fail on errors.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)

    new_path = Path(args.new)
    old_trans_path = Path(args.old_trans)
    out_path = Path(args.out)
    report_path = Path(args.report)
    old_en_path = Path(args.old_en) if args.old_en else None

    template_text, has_bom, read_encoding = read_text_with_bom(new_path)
    encoding = detect_encoding(template_text, default=read_encoding)

    try:
        new_en_map = parse_string_map(template_text)
    except ValueError as exc:
        print(f"[error] Failed to parse new English XML: {exc}", file=sys.stderr)
        return 1

    try:
        old_trans_text, _, _ = read_text_with_bom(old_trans_path)
        old_trans_map = parse_string_map(old_trans_text)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[error] Failed to load old translated XML: {exc}", file=sys.stderr)
        return 1

    old_en_map = None
    if old_en_path:
        try:
            old_en_text, _, _ = read_text_with_bom(old_en_path)
            old_en_map = parse_string_map(old_en_text)
        except (FileNotFoundError, ValueError) as exc:
            print(f"[error] Failed to load old English XML: {exc}", file=sys.stderr)
            return 1

    merge_result = merge_translations(
        template_text=template_text,
        new_en_map=new_en_map,
        old_trans_map=old_trans_map,
        old_en_map=old_en_map,
        mode=args.mode,
    )

    if args.strict:
        validation_errors = validate_output(template_text, merge_result.output_text)
        if validation_errors:
            for err in validation_errors:
                print(f"[validation-error] {err}", file=sys.stderr)
            return 1

    if args.dry_run:
        print("[dry-run] Merge completed. Output not written.")
    else:
        write_text_with_bom(out_path, merge_result.output_text, encoding, has_bom)
        report_path.write_text(json.dumps(merge_result.report, indent=2), encoding="utf-8")

    print(json.dumps(merge_result.report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
