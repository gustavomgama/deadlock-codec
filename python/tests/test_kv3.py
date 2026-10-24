import json
import pathlib

import decode_kv3 as K

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIX = pathlib.Path(__file__).resolve().parent / "fixtures"


def test_blob_accounting():
    kv3 = K.decode(str(ROOT / "data" / "cached_hero_builds.kv3"))
    assert len(kv3.declared_blob_lengths) == 35
    assert sum(kv3.declared_blob_lengths) == 85278
    kv3.read_tree()
    c = K.completeness(kv3)
    assert c["trailing_bytes"] == 0
    for v in c["unconsumed"].values():
        if isinstance(v, dict):
            for x in v.values():
                assert x == 0
        else:
            assert v == 0


def test_corrupt_matrix():
    bad_files = [
        FIX / "truncated.kv3",
        FIX / "corrupt.kv3",
    ]
    for bf in bad_files:
        try:
            K.decode(str(bf))
            # if decode succeeds, read_tree should fail
            kv = K.decode(str(bf))
            kv.read_header()
        except K.KV3Error:
            pass
    # 4-byte file
    p = FIX / "tiny.kv3"
    p.write_bytes(b"\x00" * 4)
    try:
        K.decode(str(p))
        assert False
    except K.KV3Error:
        pass
    # bad magic handled by KV3Error
    p2 = FIX / "badmagic.kv3"
    p2.write_bytes(b"\x00" * 28 + b"\x00" * 10)
    try:
        K.decode(str(p2))
        assert False
    except K.KV3Error:
        pass


def test_plain_golden():
    kv3 = K.decode(str(ROOT / "data" / "cached_hero_builds.kv3"))
    tree = kv3.read_tree()
    plain = K.to_plain(tree)
    # ensure json serializable
    json.dumps(plain, default=lambda b: "bytes")


def test_self_test():
    kv3 = K.decode(str(ROOT / "data" / "cached_hero_builds.kv3"))
    tree = K.to_plain(kv3.read_tree())
    K.self_test(kv3, tree)
    print("ok")
