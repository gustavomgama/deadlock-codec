import argparse
import base64
import json
import pathlib
import struct
import sys
from typing import Any

_MAX_INPUT_BYTES = 16 * 1024 * 1024
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024


def _compressor(level: int | None = None) -> Any:
    """Build a zstd compressor for the requested level."""
    try:
        import zstandard
    except ImportError as exc:
        raise RuntimeError(
            "encoding real build codes requires the optional 'zstandard' package"
        ) from exc
    if level is None:
        return zstandard.ZstdCompressor()
    return zstandard.ZstdCompressor(level=level)


def encode_varint(value: Any) -> bytes:
    """Encode an integer as a protobuf varint."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("value must be an integer")
    v = value
    if v < 0:
        v += 1 << 64
    out = bytearray()
    while v > 0x7F:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v & 0x7F)
    return bytes(out)


def encode_field(field: int, wire: int, value_bytes: bytes) -> bytes:
    """Encode a protobuf field tag followed by its value bytes."""
    return encode_varint((field << 3) | wire) + value_bytes


def encode_string(s: str) -> bytes:
    """Encode a UTF-8 string as a length-delimited field value."""
    b = s.encode("utf-8")
    return encode_varint(len(b)) + b


def encode_mod(mid: int) -> bytes:
    """Encode a single mod id inside a category."""
    return encode_field(1, 0, encode_varint(mid))


def encode_category(cat: dict[str, Any]) -> bytes:
    """Encode a mod category message."""
    parts = bytearray()
    for mid in cat.get("mods") or []:
        mod_msg = encode_mod(mid)
        parts += encode_field(1, 2, encode_varint(len(mod_msg)) + mod_msg)
    if cat.get("name") is not None:
        parts += encode_field(2, 2, encode_string(cat["name"]))
    if cat.get("description") is not None:
        parts += encode_field(3, 2, encode_string(cat["description"]))
    if cat.get("height") is not None:
        parts += encode_field(4, 5, struct.pack("<f", float(cat["height"])))
    if cat.get("width") is not None:
        parts += encode_field(5, 5, struct.pack("<f", float(cat["width"])))
    if cat.get("optional"):
        parts += encode_field(6, 0, encode_varint(1))
    return bytes(parts)


def encode_cc(cc: dict[str, Any]) -> bytes:
    """Encode a currency change message."""
    parts = bytearray()
    if cc.get("ability_id") is not None:
        parts += encode_field(1, 0, encode_varint(cc["ability_id"]))
    if cc.get("currency_type") is not None:
        parts += encode_field(2, 0, encode_varint(cc["currency_type"]))
    if cc.get("delta") is not None:
        parts += encode_field(3, 0, encode_varint(cc["delta"]))
    if cc.get("annotation"):
        parts += encode_field(4, 2, encode_string(cc["annotation"]))
    return bytes(parts)


def encode_details(details: dict[str, Any]) -> bytes:
    """Encode the details message containing categories and ability order."""
    parts = bytearray()
    for cat in details.get("mod_categories") or []:
        cat_bytes = encode_category(cat)
        parts += encode_field(1, 2, encode_varint(len(cat_bytes)) + cat_bytes)
    ao = details.get("ability_order")
    if ao and ao.get("currency_changes"):
        cc_bytes = bytearray()
        for cc in ao["currency_changes"]:
            ccb = encode_cc(cc)
            cc_bytes += encode_field(1, 2, encode_varint(len(ccb)) + ccb)
        parts += encode_field(2, 2, encode_varint(len(cc_bytes)) + bytes(cc_bytes))
    return bytes(parts)


def encode_build(obj: dict[str, Any], level: int | None = None) -> str:
    """Encode a build dictionary into a Deadlock build code."""
    layout = obj.get("layout")
    cached = layout == "cached"
    target = bytearray()  # fields go here; wrapped if cached
    if cached:
        if obj.get("hero_build_id") is not None:
            target += encode_field(1, 0, encode_varint(obj["hero_build_id"]))
        if obj.get("hero") is not None or obj.get("hero_id") is not None:
            hid = (
                obj.get("hero_id")
                if obj.get("hero_id") is not None
                else obj.get("hero")
            )
            target += encode_field(2, 0, encode_varint(hid))
    else:
        if obj.get("hero_id") is not None:
            target += encode_field(1, 0, encode_varint(obj["hero_id"]))
        if obj.get("version") is not None:
            target += encode_field(2, 0, encode_varint(obj["version"]))
    if obj.get("hero_build_id") is not None and not cached:
        target += encode_field(3, 0, encode_varint(obj["hero_build_id"]))
    if obj.get("author_account_id") is not None and not cached:
        target += encode_field(4, 0, encode_varint(obj["author_account_id"]))
    if obj.get("name") is not None:
        target += encode_field(5, 2, encode_string(obj["name"]))
    if obj.get("description") is not None:
        target += encode_field(6, 2, encode_string(obj["description"]))
    if obj.get("language") is not None:
        target += encode_field(7, 0, encode_varint(obj["language"]))
    if obj.get("origin_build_id") is not None:
        target += encode_field(8, 0, encode_varint(obj["origin_build_id"]))
    if obj.get("field_9") is not None:
        target += encode_field(9, 0, encode_varint(obj["field_9"]))
    if obj.get("details"):
        db = encode_details(obj["details"])
        target += encode_field(10, 2, encode_varint(len(db)) + db)
    for t in obj.get("tags") or []:
        target += encode_field(11, 0, encode_varint(t))
    if obj.get("field_13") is not None:
        target += encode_field(13, 0, encode_varint(obj["field_13"]))
    if cached:
        # wrap inner fields in a message as field 1 of top-level
        parts = encode_field(1, 2, encode_varint(len(target)) + bytes(target))
    else:
        parts = bytes(target)
    comp = _compressor(level).compress(bytes(parts))
    return base64.b64encode(comp).decode()


def read_input(arg: str) -> str:
    """Read JSON input from stdin, a file, or a literal argument."""
    if arg == "-":
        data = sys.stdin.read(_MAX_INPUT_BYTES + 1)
        if len(data) > _MAX_INPUT_BYTES:
            raise ValueError("stdin input too large")
        return data
    p = pathlib.Path(arg)
    if not (p.exists() and p.is_file()):
        return arg
    if p.stat().st_size > _MAX_INPUT_BYTES:
        raise ValueError("input file too large")
    with pathlib.Path(arg).open(encoding="utf-8") as fh:
        data = fh.read(_MAX_INPUT_BYTES + 1)
    if len(data) > _MAX_INPUT_BYTES:
        raise ValueError("input file too large")
    return data


def self_test() -> None:
    """Round-trip the bundled example build code through decode and encode."""
    import pathlib as _pathlib
    import sys as _sys

    _sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
    try:
        import decode_build_code as D
    except ImportError as exc:
        raise SystemExit("self-test requires decode_build_code.py") from exc

    example = (
        _pathlib.Path(__file__).resolve().parent / "data" / "examplecodefromgame.md"
    )
    if not example.exists():
        raise SystemExit(f"self-test needs {example}")
    code = D.read_input(str(example))
    decoded = D.decode_build_code(code)
    encoded = encode_build(decoded)
    roundtripped = D.decode_build_code(encoded)
    if decoded != roundtripped:
        raise AssertionError("encode/decode round-trip mismatch")
    print("SELF_TEST_OK")


def main() -> None:
    """Command-line entry point for encoding build codes."""
    ap = argparse.ArgumentParser(
        description="Encode a build JSON into a Deadlock build code"
    )
    ap.add_argument("path", nargs="?", help="JSON file, - for stdin")
    ap.add_argument("--out", help="write code to this file")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--url-safe", action="store_true", help="emit URL-safe base64")
    ap.add_argument("--level", type=int, default=None)
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    try:
        if args.path:
            text = read_input(args.path)
        else:
            text = sys.stdin.read(_MAX_INPUT_BYTES + 1)
            if len(text) > _MAX_INPUT_BYTES:
                raise ValueError("stdin input too large")
        if not text or not text.strip():
            raise ValueError("empty input")
        obj = json.loads(text)
        code = encode_build(obj, level=args.level)
        if len(code) > _MAX_OUTPUT_BYTES:
            raise ValueError("output too large")
        if args.url_safe:
            import base64 as _b64

            raw = _b64.b64decode(code)
            code = _b64.urlsafe_b64encode(raw).decode().rstrip("=")
        if args.out:
            p = pathlib.Path(args.out)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(code + "\n", encoding="utf-8")
        else:
            print(code)
    except (
        ValueError,
        OSError,
        RuntimeError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
    ) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
