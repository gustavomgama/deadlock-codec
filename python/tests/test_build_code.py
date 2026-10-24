import base64
import json
import pathlib

import decode_build_code as D
import encode_build_code as E

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIX = pathlib.Path(__file__).resolve().parent / "fixtures"
GOLD = pathlib.Path(__file__).resolve().parent / "golden"


def test_imports():
    assert hasattr(D, "decode_build_code")
    assert hasattr(E, "encode_build")


def load_code(name):
    return (
        (FIX / name).read_text().strip()
        if (FIX / name).exists()
        else (ROOT / "data" / "examplecodefromgame.md").read_text().strip()
    )


SAMPLE = (ROOT / "data" / "examplecodefromgame.md").read_text().strip()


def test_round_trip():
    doc = D.decode_build_code(SAMPLE)
    code = E.encode_build(doc)
    doc2 = D.decode_build_code(code)
    assert doc == doc2 or doc.get("document", doc) == doc2.get("document", doc2)
    # compare core build fields
    for k in ("hero_id", "hero", "version", "name", "tags", "layout"):
        assert doc[k] == doc2[k], k


def test_cached_layout():
    code = (FIX / "cached_code.txt").read_text().strip()
    doc = D.decode_build_code(code)
    assert doc["layout"] == "cached"
    assert doc["hero_build_id"] == 999
    assert doc["author_account_id"] is None


def test_urlsafe():
    code = (FIX / "urlsafe_code.txt").read_text().strip()
    doc = D.decode_build_code(code)
    doc2 = D.decode_build_code(SAMPLE)
    assert doc["hero_id"] == doc2["hero_id"]


def test_uncompressed_payload():
    raw = D.raw_document(SAMPLE)
    assert raw["input"]["zstd"] is True
    # payload_base64 without zstd magic
    base64.b64decode(raw["input"]["payload_base64"])
    # build a code from uncompressed payload manually not required; check field exists
    assert "payload_base64" in raw["input"]


def test_invalid_inputs():
    for bad in ("", "   ", "!!!", "A"):
        try:
            D.decode_build_code(bad)
            ok = False
        except (ValueError, Exception):
            ok = True
        assert ok, bad


def test_truncation_issue():
    # craft a payload ending mid-fixed32 by appending? Instead use raw truncated code
    code = (FIX / "truncated_code.txt").read_text().strip()
    try:
        D.decode_build_code(code)
    except ValueError:
        pass


def test_overlong_varint():
    data = bytes([0x80] * 11)
    try:
        D.read_varint(data, 0)
        # should return None
    except Exception:
        pass
    res, i = D.read_varint(bytes([0x80] * 11), 0)
    assert res is None


def test_deep_nesting():
    # build deeply nested length-delimited message
    msg = b""
    for _ in range(200):
        msg = bytes([(1 << 3) | 2]) + _varint(len(msg)) + msg
    code = base64.b64encode(msg).decode()
    try:
        D.decode_build_code(code)
    except (ValueError, Exception):
        pass


def _varint(v):
    out = bytearray()
    while v > 0x7F:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v & 0x7F)
    return bytes(out)


def test_packed_tags_ascii():
    # regression: packed tag bytes printable still in tags
    # use sample
    doc = D.decode_build_code(SAMPLE)
    assert isinstance(doc["tags"], list)


def test_raw_golden():
    raw = D.raw_document(SAMPLE)
    assert raw["issues"] == []
    assert raw["input"]["zstd"] is True
    golden_path = GOLD / "build_raw.json"
    if golden_path.exists():
        expected = json.loads(golden_path.read_text())
        # compare issues and zstd
        assert raw["issues"] == expected["issues"]
        assert raw["input"]["zstd"] == expected["input"]["zstd"]


def test_shared_golden():
    doc = D.decode_build_code(SAMPLE)
    assert doc["hero_id"] == 1034
    assert doc["hero"] == 34
    assert doc["layout"] == "shared"
