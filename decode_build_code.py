import argparse
import base64
import io
import json
import pathlib
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_DEFAULT_BUILD_HERO_OFFSET = 1000
_MAX_INPUT_BYTES = 16 * 1024 * 1024
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024


def read_varint(data: bytes, i: int) -> Tuple[Optional[int], int]:
    """Read a protobuf-style varint from data starting at offset i."""
    res = 0
    shift = 0
    n = len(data)
    while i < n:
        if shift > 63:
            return None, i
        byte = data[i]
        i += 1
        res |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return res, i
        shift += 7
    return None, i


def _is_text(chunk: bytes) -> bool:
    """Return True if chunk decodes as printable UTF-8 text."""
    if not chunk:
        return True
    try:
        text = chunk.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if "\x00" in text:
        return False
    if any(ord(c) < 0x20 and c not in "\n\r\t" for c in text):
        return False
    return (
        text.isprintable()
        or text.replace("\n", "").replace("\r", "").replace("\t", "").isprintable()
    )


def parse_message(
    data: bytes,
    issues: Optional[List[Dict[str, Any]]] = None,
    depth: int = 0,
    max_depth: int = 64,
) -> List[Tuple[int, int, Any]]:
    """Parse protobuf bytes into a list of (field_number, wire_type, value) tuples."""
    if depth > max_depth:
        if issues is not None:
            issues.append({"offset": 0, "reason": "max recursion depth exceeded"})
        raise ValueError("max recursion depth exceeded")
    out = []
    append = out.append
    read = read_varint
    i = 0
    n = len(data)
    _MAX_FIELDS = 100000
    field_count = 0
    while i < n and field_count < _MAX_FIELDS:
        field_count += 1
        tag_start = i
        tag = data[i]
        if tag < 0x80:
            i += 1
        else:
            res = read(data, i)
            first = res[0]
            if first is None:
                if issues is not None:
                    issues.append(
                        {
                            "offset": tag_start,
                            "reason": "unterminated or over-long varint",
                        }
                    )
                break
            tag = first
            i = res[1]
        if tag == 0:
            if issues is not None:
                issues.append({"offset": tag_start, "reason": "zero tag"})
            break
        field = tag >> 3
        wire = tag & 7
        if field == 0:
            if issues is not None:
                issues.append({"offset": tag_start, "reason": "invalid field number 0"})
            break
        if wire in (3, 4):
            if issues is not None:
                issues.append(
                    {
                        "offset": tag_start,
                        "reason": "deprecated group wire type %d" % wire,
                    }
                )
            continue
        if wire == 2:
            if i < n:
                length = data[i]
                if length < 0x80:
                    i += 1
                else:
                    rl = read(data, i)
                    first_rl = rl[0]
                    if first_rl is None:
                        if issues is not None:
                            issues.append(
                                {
                                    "offset": i,
                                    "reason": "unterminated or over-long varint",
                                }
                            )
                        i = n
                        length = 0
                    else:
                        length = first_rl
                        i = rl[1]
            else:
                length = 0
                if issues is not None:
                    issues.append({"offset": i, "reason": "truncated length"})
            if i + length > n:
                if issues is not None:
                    issues.append(
                        {
                            "offset": i,
                            "reason": (
                                "truncated length-delimited field: "
                                "declared %d, available %d" % (length, n - i)
                            ),
                        }
                    )
                length = n - i
            end = i + length
            chunk = data[i:end]
            i = end
            if field != 11 and _is_text(chunk):
                append((field, wire, ("str", chunk.decode("utf-8"))))
                continue
            try:
                nested = parse_message(chunk, issues, depth + 1, max_depth)
            except (struct.error, IndexError, ValueError):
                nested = None
            if nested is None or (chunk and not nested):
                append((field, wire, ("bytes", chunk)))
            else:
                append((field, wire, ("msg", nested)))
        elif wire == 0:
            if i < n:
                value = data[i]
                if value < 0x80:
                    i += 1
                else:
                    rv = read(data, i)
                    if rv[0] is None:
                        if issues is not None:
                            issues.append(
                                {
                                    "offset": i,
                                    "reason": "unterminated or over-long varint",
                                }
                            )
                        i = n
                        value = 0
                    else:
                        value, i = rv
            else:
                value = None
                if issues is not None:
                    issues.append({"offset": i, "reason": "truncated varint"})
            append((field, wire, value))
        elif wire == 5:
            if i + 4 > n:
                if issues is not None:
                    issues.append({"offset": i, "reason": "truncated fixed32"})
                break
            append((field, wire, struct.unpack("<f", data[i : i + 4])[0]))
            i += 4
        elif wire == 1:
            if i + 8 > n:
                if issues is not None:
                    issues.append({"offset": i, "reason": "truncated fixed64"})
                break
            append((field, wire, struct.unpack("<d", data[i : i + 8])[0]))
            i += 8
        else:
            if issues is not None:
                issues.append(
                    {"offset": tag_start, "reason": "unsupported wire type %d" % wire}
                )
            break
    if field_count >= _MAX_FIELDS and i < n:
        if issues is not None:
            issues.append({"offset": i, "reason": "field count limit reached"})
    return out


def get_str(fields: List[Tuple[int, int, Any]], num: int) -> Optional[str]:
    """Return the first string value for field num, if present."""
    for f, w, v in fields:
        if f == num and isinstance(v, tuple) and v[0] == "str":
            return v[1]
    return None


def get_int(fields: List[Tuple[int, int, Any]], num: int) -> Optional[int]:
    """Return the first integer value for field num, if present."""
    for f, w, v in fields:
        if f == num and w in (0, 1) and isinstance(v, int) and not isinstance(v, bool):
            return v
    return None


def get_float(fields: List[Tuple[int, int, Any]], num: int) -> Optional[float]:
    """Return the first float value for field num, if present."""
    for f, w, v in fields:
        if f == num and isinstance(v, float):
            return v
    return None


def get_msgs(
    fields: List[Tuple[int, int, Any]], num: int
) -> List[List[Tuple[int, int, Any]]]:
    """Return nested messages stored under field num."""
    res = []
    for f, w, v in fields:
        if f == num and isinstance(v, tuple) and v[0] == "msg":
            res.append(v[1])
    return res


def _signed(value: Any) -> Any:
    """Convert an unsigned 64-bit value to its signed representation."""
    if isinstance(value, int) and not isinstance(value, bool):
        value = value & ((1 << 64) - 1)
        if value >= (1 << 63):
            return value - (1 << 64)
    return value


_WIRE_NAMES = {0: "varint", 1: "fixed64", 2: "bytes", 5: "fixed32"}


def _raw_fields(fields: List[Tuple[int, int, Any]]) -> List[Dict[str, Any]]:
    """Render parsed fields as lossless dictionaries."""
    out = []
    for field, wire, value in fields:
        node = {
            "field": field,
            "wire": wire,
            "wire_type": _WIRE_NAMES.get(wire, str(wire)),
        }
        if isinstance(value, tuple):
            kind, payload = value
            node["length"] = len(payload)
            if kind == "str":
                node["text"] = payload
            elif kind == "msg":
                node["message"] = _raw_fields(payload)
            else:
                node["bytes_base64"] = base64.b64encode(payload).decode("ascii")
        else:
            node["value"] = value
        out.append(node)
    return out


def _decompress(raw: bytes, max_output_size: int = 10 * 1024 * 1024) -> bytes:
    """Decompress a zstd payload, falling back to streaming reads on failure."""
    import zstandard

    decompressor = zstandard.ZstdDecompressor()
    try:
        return decompressor.decompress(raw, max_output_size=max_output_size)
    except Exception:
        with decompressor.stream_reader(io.BytesIO(raw)) as reader:
            result = reader.read(max_output_size + 1)
            if len(result) > max_output_size:
                raise ValueError("decompressed output exceeds limit")
            return result


def _payload(code: str) -> Tuple[bytes, bool, int, str, str, bool]:
    """Decode the base64/zstd envelope of a build code."""
    if not isinstance(code, str):
        raise ValueError("input must be a string")
    normalized = "".join(code.split())
    if not normalized:
        raise ValueError("empty input")
    if len(normalized) > 1024 * 1024:
        raise ValueError("input too large")
    alphabet = "standard"
    padding = False
    try:
        raw = base64.b64decode(normalized, validate=True)
    except Exception as e1:
        try:
            raw = base64.b64decode(
                normalized + "=" * (-len(normalized) % 4), altchars=b"-_", validate=True
            )
            alphabet = "urlsafe"
            padding = len(normalized) % 4 != 0
        except Exception as e2:
            raise ValueError("invalid base64: %s; urlsafe: %s" % (e1, e2))
    if not raw:
        raise ValueError("invalid base64")
    if len(raw) > _MAX_INPUT_BYTES:
        raise ValueError("decoded payload too large")
    compressed = raw[:4] == _ZSTD_MAGIC
    stored = len(raw)
    if compressed:
        try:
            raw = _decompress(raw)
        except Exception as e:
            raise ValueError("zstd decompress failed: %s" % e)
    return raw, compressed, stored, normalized, alphabet, padding


def _field_map(fields: List[Tuple[int, int, Any]]) -> Dict[str, List[Any]]:
    """Group parsed fields by field number for JSON output."""
    out = {}
    for field, wire, value in fields:
        key = str(field)
        if isinstance(value, tuple):
            kind, payload = value
            if kind == "msg":
                item = {"message": _field_map(payload)}
            elif kind == "str":
                item = payload
            else:
                item = {"bytes_base64": base64.b64encode(payload).decode("ascii")}
        else:
            item = value
        out.setdefault(key, []).append(item)
    return out


def _cached_candidate(
    message: List[Tuple[int, int, Any]],
    issues: Optional[List[Dict[str, Any]]] = None,
) -> bool:
    """Detect whether a message uses the cached build layout."""
    hero = get_int(message, 2)
    if hero is None:
        return False
    if hero == 0:
        if issues is not None:
            issues.append(
                {"offset": 0, "reason": "inconclusive cached-layout hero id 0"}
            )
        return False
    if hero >= _DEFAULT_BUILD_HERO_OFFSET:
        return False
    return True


def decode_build_code(code: str, layout: str = "auto") -> Dict[str, Any]:
    """Decode a Deadlock build code into a structured dictionary."""
    if not isinstance(code, str):
        raise ValueError("code must be a string")
    raw, _, _, normalized, _, _ = _payload(code)
    issues = []
    top = parse_message(raw, issues)
    hero_field = 1
    nested = get_msgs(top, 1)
    if layout == "auto":
        cached = (
            get_int(top, 1) is None
            and nested
            and _cached_candidate(nested[0], issues)
            and get_int(nested[0], 3) is None
        )
        layout = "cached" if cached else "shared"
    if layout == "cached":
        if not nested:
            raise ValueError("cached layout needs a wrapper message in field 1")
        top = nested[0]
        hero_field = 2
    hero_id = _signed(get_int(top, hero_field))
    is_default_build = bool(
        layout == "shared"
        and hero_id is not None
        and hero_id >= _DEFAULT_BUILD_HERO_OFFSET
    )
    if is_default_build:
        assert hero_id is not None
        resolved_hero_id = hero_id - _DEFAULT_BUILD_HERO_OFFSET
    else:
        resolved_hero_id = hero_id
    version = _signed(get_int(top, 2))
    if hero_field == 2:
        hero_build_id = _signed(get_int(top, 1))
    else:
        hero_build_id = _signed(get_int(top, 3))
    author_account_id = _signed(get_int(top, 4))
    name = get_str(top, 5)
    description = get_str(top, 6)
    language = _signed(get_int(top, 7))
    origin_build_id = _signed(get_int(top, 8))
    field_9 = _signed(get_int(top, 9))
    field_13 = _signed(get_int(top, 13))
    tags = []
    for f, w, v in top:
        if f == 11 and not isinstance(v, tuple):
            tags.append(_signed(v))
        elif f == 11 and isinstance(v, tuple) and v[0] == "bytes":
            tags.extend(_signed(n) for n in _packed_varints(v[1]))
    if layout == "cached":
        author_account_id = None
    detail_msgs = [
        v[1] for f, w, v in top if f == 10 and isinstance(v, tuple) and v[0] == "msg"
    ]
    mod_categories = []
    ability_order = None
    for details in detail_msgs:
        for cat_msg in get_msgs(details, 1):
            mods = []
            for f, w, v in cat_msg:
                if f == 1:
                    if isinstance(v, tuple) and v[0] == "msg":
                        aid = get_int(v[1], 1)
                        if aid is not None:
                            mods.append(_signed(aid))
                    elif not isinstance(v, tuple):
                        mods.append(_signed(v))
            cat = {
                "name": get_str(cat_msg, 2),
                "description": get_str(cat_msg, 3),
                "height": get_float(cat_msg, 4),
                "width": get_float(cat_msg, 5),
                "mods": mods,
            }
            if any(f == 6 and not isinstance(v, tuple) and v for f, w, v in cat_msg):
                cat["optional"] = True
            mod_categories.append(cat)
        for f, w, v in details:
            if f == 2 and isinstance(v, tuple) and v[0] == "msg":
                ability_order = v[1]
    ability_changes = []
    if ability_order is not None:
        for cc in get_msgs(ability_order, 1):
            raw_delta = _signed(get_int(cc, 3))
            ability_changes.append(
                {
                    "ability_id": _signed(get_int(cc, 1)),
                    "currency_type": _signed(get_int(cc, 2)),
                    "delta": raw_delta,
                    "annotation": get_str(cc, 4),
                }
            )
    return {
        "schema_version": 1,
        "hero_id": hero_id,
        "hero": resolved_hero_id,
        "is_default_build": is_default_build,
        "version": version,
        "hero_build_id": hero_build_id,
        "author_account_id": author_account_id,
        "name": name,
        "description": description,
        "language": language,
        "origin_build_id": origin_build_id,
        "field_9": field_9,
        "tags": tags,
        "field_13": field_13,
        "issues": issues,
        "layout": layout,
        "details": {
            "mod_categories": mod_categories,
            "ability_order": {"currency_changes": ability_changes}
            if ability_changes
            else None,
        },
    }


def raw_document(code: str, include_payload_base64: bool = True) -> Dict[str, Any]:
    """Build a lossless protobuf dump of a build code."""
    raw, compressed, stored, normalized, alphabet, padding = _payload(code)
    issues = []
    fields = parse_message(raw, issues)
    inp = {
        "base64": normalized,
        "base64_chars": len(normalized),
        "stored_bytes": stored,
        "zstd": compressed,
        "decoded_bytes": len(raw),
        "base64_alphabet": alphabet,
        "base64_padding_added": padding,
    }
    if include_payload_base64:
        inp["payload_base64"] = base64.b64encode(raw).decode("ascii")
    return {
        "schema_version": 1,
        "input": inp,
        "issues": issues,
        "tree": _raw_fields(fields),
    }


def _packed_varints(data: bytes) -> List[int]:
    """Decode a packed repeated varint field."""
    out = []
    i = 0
    n = len(data)
    while i < n:
        r = read_varint(data, i)
        if r[0] is None:
            break
        value, i = r
        out.append(value)
    return out


def read_input(arg: str) -> str:
    """Read a build code from stdin, a file, or a literal argument."""
    if arg == "-":
        data = sys.stdin.read(_MAX_INPUT_BYTES + 1)
        if len(data) > _MAX_INPUT_BYTES:
            raise ValueError("stdin input too large")
        return data
    path = pathlib.Path(arg)
    if not path.exists():
        return arg
    if not path.is_file():
        return arg
    if path.stat().st_size > _MAX_INPUT_BYTES:
        raise ValueError("input file too large")
    try:
        with open(arg, "r", encoding="utf-8") as fh:
            data = fh.read(_MAX_INPUT_BYTES + 1)
            if len(data) > _MAX_INPUT_BYTES:
                raise ValueError("input file too large")
            return data
    except UnicodeDecodeError:
        try:
            with open(arg, "r", encoding="utf-16") as fh:
                data = fh.read(_MAX_INPUT_BYTES + 1)
                if len(data) > _MAX_INPUT_BYTES:
                    raise ValueError("input file too large")
                return data
        except (OSError, UnicodeDecodeError):
            return arg
    except OSError:
        raise


def self_test() -> None:
    """Validate the decoder against the bundled example build code."""
    example = (
        pathlib.Path(__file__).resolve().parent
        / "data"
        / "examplecodefromgame.md"
    )
    if not example.exists():
        raise SystemExit("self-test needs %s" % example)
    code = read_input(str(example))
    shared = decode_build_code(code)
    if shared["hero_id"] != 1034:
        raise AssertionError("hero_id %s" % shared["hero_id"])
    if shared["hero"] != 34:
        raise AssertionError("hero %s" % shared["hero"])
    if shared["is_default_build"] is not True:
        raise AssertionError("is_default_build")
    if shared["layout"] != "shared":
        raise AssertionError("layout %s" % shared["layout"])
    if shared["issues"]:
        raise AssertionError("issues %s" % shared["issues"])
    if len(shared["details"]["mod_categories"]) != 3:
        raise AssertionError("categories %s" % shared["details"])
    if not raw_document(code)["input"]["zstd"]:
        raise AssertionError("zstd")
    try:
        decode_build_code("!!!")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid base64 accepted")
    print("SELF_TEST_OK")


def main() -> None:
    """Command-line entry point for decoding build codes."""
    ap = argparse.ArgumentParser(description="Decode a Deadlock build code into JSON")
    ap.add_argument(
        "code",
        nargs="?",
        help="base64 code, '-' for stdin, or a path to a file containing it",
    )
    ap.add_argument("--raw", action="store_true", help="lossless protobuf dump")
    ap.add_argument(
        "--no-payload-base64",
        action="store_true",
        help="omit payload_base64 from --raw output",
    )
    ap.add_argument("--out", help="write JSON to this file instead of stdout")
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="check the decoder against the sample code",
    )
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.code:
        ap.error("a build code, file path or - is required")
    try:
        code = read_input(args.code)
        if not code or not code.strip():
            raise ValueError("empty input")
        doc = (
            raw_document(code, include_payload_base64=not args.no_payload_base64)
            if args.raw
            else decode_build_code(code)
        )
        text = json.dumps(doc, indent=2)
        if len(text) > _MAX_OUTPUT_BYTES:
            raise ValueError("output too large")
        if args.out:
            p = pathlib.Path(args.out)
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
                fh.write("\n")
        else:
            print(text)
    except Exception as e:
        print("ERROR: %s" % e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
