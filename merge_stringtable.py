#!/usr/bin/env python3
"""Merge StringTable XML files by preserving the new file formatting.

The script keeps the new XML as the exact template and only replaces the
inner text of <String> nodes when a matching `_locID` is found in the old
translation file. Formatting, order, attributes, comments, whitespace, and
XML headers of the new file are preserved.
"""

from __future__ import annotations

import argparse
import codecs
import json
import logging
import bisect
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


StringMatch = Tuple[int, int, int, int, str]
CommentSpan = Tuple[int, int]

COMMENT_PATTERN = re.compile(r"<!--.*?-->", re.DOTALL)


def compute_line_col(text: str, index: int) -> Tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    last_nl = text.rfind("\n", 0, index)
    col = index + 1 if last_nl == -1 else index - last_nl
    return line, col


def scan_malformed_comments(label: str, xml_text: str) -> List[str]:
    errors: List[str] = []

    for match in re.finditer(r"<!\s+--", xml_text):
        line, col = compute_line_col(xml_text, match.start())
        errors.append(
            f"{label}: malformed comment start '<! --' at line {line}, column {col}"
        )

    for match in re.finditer(r"--\s+>", xml_text):
        line, col = compute_line_col(xml_text, match.start())
        errors.append(f"{label}: malformed comment end '-- >' at line {line}, column {col}")

    start_stack: List[int] = []
    for start in re.finditer(r"<!--", xml_text):
        start_stack.append(start.start())
    for end in re.finditer(r"-->", xml_text):
        if start_stack:
            start_stack.pop()
        else:
            line, col = compute_line_col(xml_text, end.start())
            errors.append(
                f"{label}: unexpected comment terminator '-->' at line {line}, column {col}"
            )
    for start_index in start_stack:
        line, col = compute_line_col(xml_text, start_index)
        errors.append(
            f"{label}: unterminated comment starting at line {line}, column {col}"
        )

    return errors


def detect_encoding_and_text(path: Path) -> Tuple[str, bytes, str]:
    """Read a file preserving BOM and return encoding, bom bytes, and text.

    The function detects UTF BOMs when present. If there is no BOM, it looks
    for an XML declaration encoding attribute; otherwise it falls back to
    UTF-8. The returned text is decoded without the BOM, which is provided in
    the second element of the tuple.
    """

    raw = path.read_bytes()
    bom = b""
    encoding = "utf-8"

    if raw.startswith(codecs.BOM_UTF8):
        bom = codecs.BOM_UTF8
        encoding = "utf-8"
    elif raw.startswith(codecs.BOM_UTF16_LE):
        bom = codecs.BOM_UTF16_LE
        encoding = "utf-16-le"
    elif raw.startswith(codecs.BOM_UTF16_BE):
        bom = codecs.BOM_UTF16_BE
        encoding = "utf-16-be"
    else:
        head = raw[:200].decode("ascii", errors="ignore")
        header_match = re.search(r'<\?xml[^>]*encoding=["\']([^"\']+)["\']', head)
        if header_match:
            encoding = header_match.group(1)

    text = raw[len(bom) :].decode(encoding)
    return encoding, bom, text


def extract_locid(attributes: str) -> str | None:
    match = re.search(r"_locID\s*=\s*(['\"])(.*?)\1", attributes)
    if match:
        return match.group(2)
    return None


def find_comment_spans(xml_text: str) -> List[CommentSpan]:
    return [(m.start(), m.end()) for m in COMMENT_PATTERN.finditer(xml_text)]


def is_within_comment_spans(index: int, spans: List[CommentSpan]) -> bool:
    starts = [span[0] for span in spans]
    pos = bisect.bisect_right(starts, index) - 1
    if pos < 0:
        return False
    start, end = spans[pos]
    return start <= index < end


def parse_stringtable_mapping(xml_text: str) -> Dict[str, str]:
    """Extract a mapping of _locID to raw inner text from a StringTable XML."""

    mapping: Dict[str, str] = {}
    string_pattern = re.compile(r"<String\b([^>]*)>(.*?)</String>", re.DOTALL | re.IGNORECASE)
    comment_spans = find_comment_spans(xml_text)

    for match in string_pattern.finditer(xml_text):
        if is_within_comment_spans(match.start(), comment_spans):
            continue
        attrs = match.group(1)
        locid = extract_locid(attrs)
        if not locid:
            continue
        content = match.group(2)
        cleaned_content, cleaned = clean_translation_content(locid, content)
        if cleaned:
            logging.warning(
                "Translation for locID %s contained embedded <String> tags; tags were stripped",
                locid,
            )
        mapping[locid] = cleaned_content

    return mapping


def find_string_elements(xml_text: str) -> Iterable[StringMatch]:
    """Yield matches for String elements with their spans and locID.

    Returns tuples: (content_start, content_end, match_start, match_end, locid)
    """

    string_pattern = re.compile(r"<String\b([^>]*)>(.*?)</String>", re.DOTALL | re.IGNORECASE)
    comment_spans = find_comment_spans(xml_text)

    for match in string_pattern.finditer(xml_text):
        if is_within_comment_spans(match.start(), comment_spans):
            continue
        attrs = match.group(1)
        locid = extract_locid(attrs)
        if locid is None:
            continue
        content_start = match.start(2)
        content_end = match.end(2)
        yield (content_start, content_end, match.start(), match.end(), locid)


def merge_content(original: str, translation: str) -> str:
    """Preserve surrounding whitespace while replacing the inner content."""

    whitespace_match = re.match(r"(\s*)(.*?)(\s*)$", original, re.DOTALL)
    if whitespace_match:
        prefix, _, suffix = whitespace_match.groups()
        return f"{prefix}{translation}{suffix}"
    return translation


def escape_translation_text(text: str) -> str:
    """Escape unsafe characters while preserving valid entities."""

    text = re.sub(
        r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9A-Fa-f]+);)",
        "&amp;",
        text,
    )
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return text


def clean_translation_content(locid: str, text: str) -> Tuple[str, bool]:
    """Remove stray String tags accidentally embedded inside translations.

    Some malformed inputs include serialized `<String>` nodes inside the
    translation content (for example `&lt;String ...>text</String>`), which
    later break XML validation when merged. This helper strips both escaped
    and unescaped `<String>` opening/closing tags while leaving the inner
    translated text intact.
    """

    cleaned = False
    patterns = [
        r"&lt;String\b[^>]*&gt;",  # escaped opening tag
        r"&lt;/String&gt;",  # escaped closing tag
        r"<String\b[^>]*>",  # raw opening tag
        r"</String>",  # raw closing tag
        r"&lt;String\b[^>]*/&gt;",  # escaped self-closing
        r"<String\b[^>]*/>",  # raw self-closing
    ]

    cleaned_text = text
    for pattern in patterns:
        cleaned_text, count = re.subn(pattern, "", cleaned_text, flags=re.IGNORECASE | re.DOTALL)
        if count:
            cleaned = True

    if cleaned:
        cleaned_text = cleaned_text.strip()

    return cleaned_text, cleaned


def replace_strings(new_text: str, translations: Dict[str, str]) -> Tuple[str, int, int]:
    """Replace String inner text in the new template with translations."""

    result_parts: List[str] = []
    last_index = 0
    matched = 0
    missing = 0

    for content_start, content_end, _, _, locid in find_string_elements(new_text):
        result_parts.append(new_text[last_index:content_start])
        if locid in translations:
            matched += 1
            safe_translation = escape_translation_text(translations[locid])
            new_content = merge_content(new_text[content_start:content_end], safe_translation)
        else:
            missing += 1
            new_content = new_text[content_start:content_end]
        result_parts.append(new_content)
        last_index = content_end

    result_parts.append(new_text[last_index:])
    merged_text = "".join(result_parts)
    return merged_text, matched, missing


def validate_output(new_text: str, merged_text: str) -> List[str]:
    """Run required validations, returning a list of error messages."""

    import xml.etree.ElementTree as ET

    errors: List[str] = []

    errors.extend(scan_malformed_comments("New template", new_text))
    errors.extend(scan_malformed_comments("Merged output", merged_text))

    try:
        new_root = ET.fromstring(new_text)
    except ET.ParseError as exc:  # pragma: no cover - defensive
        errors.append(f"Failed to parse new template XML: {exc}")
        return errors

    try:
        merged_root = ET.fromstring(merged_text)
    except ET.ParseError as exc:
        line, col = exc.position
        errors.append(f"Merged XML is not well-formed: {exc} (line {line}, column {col})")
        error_line_index = line - 1
        lines = merged_text.splitlines()
        start = max(0, error_line_index - 2)
        end = min(len(lines), error_line_index + 3)
        context_lines = lines[start:end]
        for offset, ctx_line in enumerate(context_lines, start=start + 1):
            prefix = ">>" if offset == line else "  "
            errors.append(f"{prefix} {offset}: {ctx_line}")
        return errors

    new_strings = sum(1 for _ in new_root.iter("String"))
    merged_strings = sum(1 for _ in merged_root.iter("String"))
    if new_strings != merged_strings:
        errors.append(
            f"String count mismatch: new={new_strings}, merged={merged_strings}"
        )

    for language in merged_root.iter("Language"):
        if language.text and language.text.strip():
            errors.append("Unexpected text inside <Language> element (text node).")
            break
        for child in language:
            if child.tail and child.tail.strip():
                errors.append("Unexpected text tail inside <Language> element.")
                break

    return errors


def write_output(path: Path, text: str, encoding: str, bom: bytes) -> None:
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    payload = text.encode(encoding)
    if bom:
        payload = bom + payload
    path.write_bytes(payload)


def build_report(
    total_new: int, total_old: int, matched: int, missing: int, report_path: Path
) -> None:
    if report_path.parent and not report_path.parent.exists():
        report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "total_new_strings": total_new,
        "total_old_translated_strings": total_old,
        "matched_by_locid": matched,
        "missing_in_old_translation": missing,
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--new", dest="new", required=True, help="Ruta del XML nuevo (plantilla)")
    parser.add_argument(
        "--old-trans", dest="old_trans", required=True, help="Ruta del XML traducido viejo"
    )
    parser.add_argument("--out", dest="out", required=True, help="Ruta del XML de salida")
    parser.add_argument("--report", dest="report", required=True, help="Ruta del reporte JSON")
    parser.add_argument("--dry-run", action="store_true", help="No escribe el archivo de salida")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Falla con código distinto de cero si alguna validación falla",
    )

    args = parser.parse_args(argv)
    configure_logging()

    new_path = Path(args.new)
    old_path = Path(args.old_trans)
    out_path = Path(args.out)
    report_path = Path(args.report)

    new_encoding, new_bom, new_text = detect_encoding_and_text(new_path)
    _, _, old_text = detect_encoding_and_text(old_path)

    translations = parse_stringtable_mapping(old_text)
    logging.info("Traducciones encontradas en archivo viejo: %s", len(translations))

    merged_text, matched, missing = replace_strings(new_text, translations)

    errors = validate_output(new_text, merged_text)
    exit_code = 0
    if errors:
        for err in errors:
            logging.error(err)
        exit_code = 1
    else:
        logging.info("Validaciones completadas sin errores")

    if not errors and not args.dry_run:
        write_output(out_path, merged_text, new_encoding, new_bom)
        logging.info("Archivo de salida escrito en %s", out_path)
    elif args.dry_run:
        logging.info("Ejecución en modo dry-run: no se escribió archivo de salida")
    else:
        logging.error("Se omitió la escritura de salida debido a errores de validación")

    total_new_strings = len(list(find_string_elements(new_text)))
    total_old_strings = len(translations)
    build_report(total_new_strings, total_old_strings, matched, missing, report_path)
    logging.info("Reporte escrito en %s", report_path)

    logging.info("Strings actualizados: %s | Strings sin traducción: %s", matched, missing)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
