import argparse
import json
import logging
import re
import sys
from collections import defaultdict
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Dict, Tuple, Optional, List, Iterable, Tuple as TypingTuple


def detect_encoding_bom(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe"):
        return "utf-16le"
    if raw.startswith(b"\xfe\xff"):
        return "utf-16be"
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


def has_xml_declaration(text: str) -> bool:
    return text.lstrip().startswith("<?xml")


def read_text_auto(path: Path) -> Tuple[str, str, bool]:
    raw = path.read_bytes()
    enc = detect_encoding_bom(raw)
    text = raw.decode(enc)
    return text, enc, has_xml_declaration(text)


def parse_xml(path: Path) -> TypingTuple[ET.ElementTree, str, bool]:
    text, enc, has_decl = read_text_auto(path)
    # ElementTree parse from string to keep auto-decoding simple
    return ET.ElementTree(ET.fromstring(text)), enc, has_decl


def local_name(tag: str) -> str:
    # handle namespaces: {ns}String -> String
    return tag.split("}")[-1]


def key_for_element(elem: ET.Element, path: str, key_attrs: List[str]) -> str:
    # Try user-provided key attributes in order; fall back to a path-based key
    for attr in key_attrs:
        if attr in elem.attrib:
            return f"{attr}:{elem.attrib[attr]}"
    # last resort: path-based identifier (stable as long as structure is unchanged)
    return f"path:{path}"


def normalize_text(s: Optional[str]) -> str:
    # Normalize whitespace lightly (don’t change escaped sequences like \n)
    if s is None:
        return ""
    # collapse runs of whitespace except keep literal backslash sequences intact
    return re.sub(r"[ \t]+", " ", s).strip()


def iter_elements_with_paths(root: ET.Element, match_tag: Optional[str]) -> Iterable[TypingTuple[str, ET.Element]]:
    """Yield (path, element) pairs for elements whose local name matches match_tag (or all)."""

    def walk(elem: ET.Element, path: str):
        counts: Dict[str, int] = defaultdict(int)
        for child in elem:
            child_local = local_name(child.tag)
            counts[child_local] += 1
            child_path = f"{path}/{child_local}[{counts[child_local]}]"
            if match_tag is None or child_local.lower() == match_tag.lower():
                yield child_path, child
            yield from walk(child, child_path)

    root_local = local_name(root.tag)
    root_path = f"/{root_local}[1]"
    if match_tag is None or root_local.lower() == match_tag.lower():
        yield root_path, root
    yield from walk(root, root_path)


def build_map_by_key(
    root: ET.Element, match_tag: Optional[str], key_attrs: List[str]
) -> TypingTuple[Dict[str, Dict[str, object]], List[Dict[str, object]]]:
    m: Dict[str, Dict[str, object]] = {}
    duplicates: Dict[str, List[Dict[str, object]]] = defaultdict(list)

    for path, e in iter_elements_with_paths(root, match_tag):
        k = key_for_element(e, path, key_attrs)
        entry = {"path": path, "line": getattr(e, "sourceline", None)}

        if k not in m:
            m[k] = {"element": e, "path": path}
        else:
            if not duplicates[k]:
                first = m[k]
                duplicates[k].append(
                    {"path": first["path"], "line": getattr(first["element"], "sourceline", None)}
                )
            duplicates[k].append(entry)

    duplicate_list = [
        {
            "key": key,
            "occurrences": occurrences,
        }
        for key, occurrences in duplicates.items()
    ]

    return m, duplicate_list


def ensure_parent_dir(path: Path) -> None:
    parent = path.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)


def write_xml(path: Path, root: ET.Element, encoding: str, include_declaration: bool):
    tree = ET.ElementTree(root)
    # ElementTree will include XML declaration when xml_declaration=True
    tree.write(path, encoding=encoding, xml_declaration=include_declaration)


def main():
    p = argparse.ArgumentParser(
        description=(
            "Sync an older translated XML with a newer source XML.\n"
            "Keeps existing translations where possible and reports what changed."
        )
    )
    p.add_argument("--new-en", required=True, help="New source XML (typically English).")
    p.add_argument("--old-trans", required=True, help="Old translated XML (e.g., Spanish from older version).")
    p.add_argument(
        "--old-en",
        required=False,
        help="Optional: old source XML matching the translation version to detect changed strings.",
    )
    p.add_argument("--out", required=True, help="Output updated translated XML.")
    p.add_argument("--report", required=True, help="Output JSON report of entries needing translation.")
    p.add_argument(
        "--match-tag",
        required=False,
        help=(
            "Limit processing to elements with this local tag name (case-insensitive). "
            "If omitted, every element with text is considered."
        ),
    )
    p.add_argument(
        "--key-attr",
        action="append",
        default=None,
        help=(
            "Attribute name used to identify elements (can be passed multiple times). "
            "Order matters; the first matching attribute wins. Defaults to symbol, _locID, id, name, key."
        ),
    )
    p.add_argument("--out-encoding", default="auto",
                   choices=["auto", "utf-8", "utf-8-sig", "utf-16le", "utf-16be"],
                   help="Encoding for output XML (default: original translation encoding).")
    verbosity = p.add_mutually_exclusive_group()
    verbosity.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    verbosity.add_argument("--quiet", action="store_true", help="Reduce logging to warnings only.")
    args = p.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")
    logger = logging.getLogger(__name__)

    key_attrs = args.key_attr or ["symbol", "_locID", "id", "name", "key"]

    def validate_input_file(path: Path, label: str):
        if not path.exists() or not path.is_file():
            p.error(f"{label} does not exist or is not a file: {path}")

    new_en_path = Path(args.new_en)
    old_tr_path = Path(args.old_trans)
    old_en_path = Path(args.old_en) if args.old_en else None
    out_path = Path(args.out)
    report_path = Path(args.report)

    validate_input_file(new_en_path, "--new-en")
    validate_input_file(old_tr_path, "--old-trans")
    if old_en_path:
        validate_input_file(old_en_path, "--old-en")

    try:
        ensure_parent_dir(out_path)
        ensure_parent_dir(report_path)
    except OSError as exc:
        logger.error("Failed to prepare output directories: %s", exc)
        sys.exit(1)

    new_en_tree, _, _ = parse_xml(new_en_path)
    old_tr_tree, old_tr_encoding, old_tr_has_decl = parse_xml(old_tr_path)

    new_root = new_en_tree.getroot()
    old_tr_root = old_tr_tree.getroot()

    new_map, new_duplicates = build_map_by_key(new_root, args.match_tag, key_attrs)
    old_tr_map, old_tr_duplicates = build_map_by_key(old_tr_root, args.match_tag, key_attrs)

    old_en_map = None
    old_en_duplicates: List[Dict[str, object]] = []
    if old_en_path:
        old_en_tree, _, _ = parse_xml(old_en_path)
        old_en_map, old_en_duplicates = build_map_by_key(old_en_tree.getroot(), args.match_tag, key_attrs)

    for label, dup_list in (
        ("new source", new_duplicates),
        ("old translation", old_tr_duplicates),
        ("old source", old_en_duplicates if old_en_path else []),
    ):
        if dup_list:
            logger.warning("Detected %d duplicate key(s) in %s XML", len(dup_list), label)

    changed = []
    added = []
    missing_in_new = []

    # Useful: entries that exist in old translation but no longer exist in new
    for k, info in old_tr_map.items():
        if k not in new_map:
            missing_in_new.append({
                "key": k,
                "path": info["path"],
                "line_in_old_translation": getattr(info["element"], "sourceline", None)
            })

    # Update elements in-place on NEW_EN tree (keeps structure intact)
    new_strings = list(iter_elements_with_paths(new_root, args.match_tag))
    for path_new, e_new in new_strings:
        k = key_for_element(e_new, path_new, key_attrs)
        new_text = e_new.text or ""

        if k in old_tr_map:
            # Candidate: keep Spanish
            old_tr_text = old_tr_map[k]["element"].text or ""

            # If we have OLD_EN, detect changes in source English text
            if old_en_map and k in old_en_map:
                old_en_text = old_en_map[k]["element"].text or ""
                if normalize_text(new_text) != normalize_text(old_en_text):
                    # Source changed -> leave English (flag for re-translation)
                    e_new.text = new_text
                    changed.append({
                        "key": k,
                        "path": path_new,
                        "line_in_new": getattr(e_new, "sourceline", None),
                        "line_in_old_en": getattr(old_en_map[k]["element"], "sourceline", None),
                        "line_in_old_translation": getattr(old_tr_map[k]["element"], "sourceline", None),
                        "old_en": old_en_text,
                        "new_en": new_text
                    })
                else:
                    # Source same -> keep translation
                    e_new.text = old_tr_text
            else:
                # Without old_en we can't reliably detect changed source.
                # So we keep translation if key exists.
                e_new.text = old_tr_text
        else:
            # New key -> leave English
            e_new.text = new_text
            added.append({
                "key": k,
                "path": path_new,
                "line_in_new": getattr(e_new, "sourceline", None),
                "new_en": new_text
            })

    report = {
        "summary": {
            "total_new_strings": len(new_strings),
            "kept_translations": len(new_strings) - len(added) - len(changed),
            "added_new_english": len(added),
            "changed_left_in_english": len(changed),
            "removed_from_new": len(missing_in_new),
            "old_en_provided": bool(old_en_map),
            "match_tag": args.match_tag,
            "key_attrs": key_attrs,
            "percent_changed": (len(changed) / len(new_strings) * 100) if new_strings else 0,
            "percent_added": (len(added) / len(new_strings) * 100) if new_strings else 0,
            "duplicate_keys_new": len(new_duplicates),
            "duplicate_keys_old_translation": len(old_tr_duplicates),
            "duplicate_keys_old_source": len(old_en_duplicates) if old_en_path else 0,
        },
        "added_new_keys_left_in_english": added,
        "changed_keys_left_in_english": changed,
        "keys_removed_from_new_version": missing_in_new,
        "diagnostics": {
            "duplicate_keys": {
                "new_source": new_duplicates,
                "old_translation": old_tr_duplicates,
                "old_source": old_en_duplicates,
            }
        },
    }

    ensure_parent_dir(out_path)
    ensure_parent_dir(report_path)

    out_encoding = old_tr_encoding if args.out_encoding == "auto" else args.out_encoding
    try:
        write_xml(out_path, new_root, out_encoding, include_declaration=old_tr_has_decl)
    except OSError as exc:
        logger.error("Failed to write output XML %s: %s", out_path, exc)
        sys.exit(1)

    try:
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as exc:
        logger.error("Failed to write report JSON %s: %s", report_path, exc)
        sys.exit(1)

    logger.info("Done!")
    logger.info("Output XML: %s", out_path)
    logger.info("Report JSON: %s", report_path)
    logger.info(json.dumps(report["summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
