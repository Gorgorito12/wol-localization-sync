import argparse
import json
import re
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Dict, Tuple, Optional, List


def detect_encoding_bom(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe"):
        return "utf-16le"
    if raw.startswith(b"\xfe\xff"):
        return "utf-16be"
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


def read_text_auto(path: Path) -> Tuple[str, str]:
    raw = path.read_bytes()
    enc = detect_encoding_bom(raw)
    return raw.decode(enc), enc


def parse_xml(path: Path) -> ET.ElementTree:
    text, _ = read_text_auto(path)
    # ElementTree parse from string to keep auto-decoding simple
    return ET.ElementTree(ET.fromstring(text))


def local_name(tag: str) -> str:
    # handle namespaces: {ns}String -> String
    return tag.split("}")[-1]


def key_for_string(elem: ET.Element) -> str:
    # Prefer 'symbol' (usually stable), else _locID
    symbol = elem.attrib.get("symbol")
    if symbol:
        return f"symbol:{symbol}"
    loc = elem.attrib.get("_locID")
    if loc:
        return f"locid:{loc}"
    # last resort: tag + index-ish fallback (not great, but prevents crash)
    return f"fallback:{id(elem)}"


def normalize_text(s: Optional[str]) -> str:
    # Normalize whitespace lightly (don’t change escaped sequences like \n)
    if s is None:
        return ""
    # collapse runs of whitespace except keep literal backslash sequences intact
    return re.sub(r"[ \t]+", " ", s).strip()


def collect_strings(root: ET.Element) -> List[ET.Element]:
    # Collect <String> elements (case-insensitive), ignoring namespace
    out = []
    for e in root.iter():
        if local_name(e.tag).lower() == "string":
            out.append(e)
    return out


def build_map_by_key(root: ET.Element) -> Dict[str, ET.Element]:
    m = {}
    for e in collect_strings(root):
        k = key_for_string(e)
        # keep first occurrence if duplicates
        if k not in m:
            m[k] = e
    return m


def clone_root_without_children(src_root: ET.Element) -> ET.Element:
    new_root = ET.Element(src_root.tag, attrib=dict(src_root.attrib))
    return new_root


def ensure_parent_dir(path: Path) -> None:
    parent = path.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)


def write_xml(path: Path, root: ET.Element, encoding: str):
    tree = ET.ElementTree(root)
    # ElementTree will include XML declaration when xml_declaration=True
    tree.write(path, encoding=encoding, xml_declaration=True)


def main():
    p = argparse.ArgumentParser(
        description="Sync old translated StringTable with a newer English StringTable.\n"
                    "Keeps old translations where possible; leaves new/changed entries in English."
    )
    p.add_argument("--new-en", required=True, help="New English XML (latest mod version).")
    p.add_argument("--old-trans", required=True, help="Old translated XML (e.g., Spanish from older version).")
    p.add_argument("--old-en", required=False, help="Old English XML matching the old translation version (recommended).")
    p.add_argument("--out", required=True, help="Output updated translated XML.")
    p.add_argument("--report", required=True, help="Output JSON report of entries needing translation.")
    p.add_argument("--out-encoding", default="utf-8",
                   choices=["utf-8", "utf-8-sig", "utf-16le", "utf-16be"],
                   help="Encoding for output XML (default utf-8).")
    args = p.parse_args()

    new_en_path = Path(args.new_en)
    old_tr_path = Path(args.old_trans)
    old_en_path = Path(args.old_en) if args.old_en else None
    out_path = Path(args.out)
    report_path = Path(args.report)

    new_en_tree = parse_xml(new_en_path)
    old_tr_tree = parse_xml(old_tr_path)

    new_root = new_en_tree.getroot()
    old_tr_root = old_tr_tree.getroot()

    new_map = build_map_by_key(new_root)
    old_tr_map = build_map_by_key(old_tr_root)

    old_en_map = None
    if old_en_path:
        old_en_tree = parse_xml(old_en_path)
        old_en_map = build_map_by_key(old_en_tree.getroot())

    # Build output root based on NEW_EN root (preserve version/attrs)
    out_root = clone_root_without_children(new_root)

    changed = []
    added = []
    missing_in_new = []

    # Useful: entries that exist in old translation but no longer exist in new
    for k in old_tr_map.keys():
        if k not in new_map:
            missing_in_new.append(k)

    # Recreate strings in the same order as NEW_EN
    new_strings = collect_strings(new_root)
    for e_new in new_strings:
        k = key_for_string(e_new)
        new_text = e_new.text or ""

        # Clone element (tag + attributes)
        e_out = ET.Element(e_new.tag, attrib=dict(e_new.attrib))

        if k in old_tr_map:
            # Candidate: keep Spanish
            old_tr_text = old_tr_map[k].text or ""

            # If we have OLD_EN, detect changes in source English text
            if old_en_map and k in old_en_map:
                old_en_text = old_en_map[k].text or ""
                if normalize_text(new_text) != normalize_text(old_en_text):
                    # Source changed -> leave English (flag for re-translation)
                    e_out.text = new_text
                    changed.append({
                        "key": k,
                        "old_en": old_en_text,
                        "new_en": new_text
                    })
                else:
                    # Source same -> keep translation
                    e_out.text = old_tr_text
            else:
                # Without old_en we can't reliably detect changed source.
                # So we keep translation if key exists.
                e_out.text = old_tr_text
        else:
            # New key -> leave English
            e_out.text = new_text
            added.append({
                "key": k,
                "new_en": new_text
            })

        out_root.append(e_out)

    report = {
        "summary": {
            "total_new_strings": len(new_strings),
            "kept_translations": len(new_strings) - len(added) - len(changed),
            "added_new_english": len(added),
            "changed_left_in_english": len(changed),
            "removed_from_new": len(missing_in_new),
            "old_en_provided": bool(old_en_map),
        },
        "added_new_keys_left_in_english": added,
        "changed_keys_left_in_english": changed,
        "keys_removed_from_new_version": missing_in_new
    }

    ensure_parent_dir(out_path)
    ensure_parent_dir(report_path)

    write_xml(out_path, out_root, args.out_encoding)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("Done!")
    print(f"Output XML: {out_path}")
    print(f"Report JSON: {report_path}")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
