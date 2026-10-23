#!/usr/bin/env python3
"""Decode Valve binary KeyValues3 (KV3 binary, magic KV3\\x05) into JSON.

The Deadlock client stores its saved hero builds in
  %LOCALAPPDATA%/../Steam/userdata/<id>/1422450/remote/cfg/cached_hero_builds.kv3
which is binary KeyValues3 version 5 (magic 0x4B563305), LZ4 block compressed.

Layout implemented here follows ValveResourceFormat's BinaryKV3 reader:
  header, LZ4 compressed "buffer 1" (string table), LZ4 compressed "buffer 2"
  (object lengths, value lanes, type bytes, blob lengths) and LZ4 chained
  binary blobs.

Usage:
    python decode_kv3.py <file.kv3> [--out out.json] [--strings-only] [--builds]
    python decode_kv3.py <file.kv3> --self-test
"""
import argparse
import base64
import json
import pathlib
import struct
import sys

MAGIC0 = 0x03564B56
MAGIC5 = 0x4B563305

# KV3BinaryNodeType
NULL, BOOLEAN, INT64, UINT64, DOUBLE, STRING, BINARY_BLOB, ARRAY, OBJECT = range(1, 10)
ARRAY_TYPED, INT32, UINT32, BOOLEAN_TRUE, BOOLEAN_FALSE = range(10, 15)
INT64_ZERO, INT64_ONE, DOUBLE_ZERO, DOUBLE_ONE, FLOAT = range(15, 20)
INT16, UINT16, INT8, UINT8 = range(20, 24)
ARRAY_TYPE_BYTE_LENGTH, ARRAY_TYPE_AUXILIARY_BUFFER = 24, 25
UINT32_ZERO, UINT32_ONE = 26, 27


class KV3Error(Exception):
    pass


class Lanes:
    """Fixed-width value lanes used by the KV3 binary encoding."""

    def __init__(self):
        self.b1 = bytearray()
        self.b2 = bytearray()
        self.b4 = bytearray()
        self.b8 = bytearray()

    def take1(self):
        v = self.b1[0]
        del self.b1[0]
        return v

    def take2(self):
        v = struct.unpack_from("<H", self.b2, 0)[0]
        del self.b2[:2]
        return v

    def take4(self):
        v = struct.unpack_from("<I", self.b4, 0)[0]
        del self.b4[:4]
        return v

    def take4s(self):
        v = struct.unpack_from("<i", self.b4, 0)[0]
        del self.b4[:4]
        return v

    def take8(self):
        v = struct.unpack_from("<Q", self.b8, 0)[0]
        del self.b8[:8]
        return v

    def take8f(self):
        v = struct.unpack_from("<d", self.b8, 0)[0]
        del self.b8[:8]
        return v


def align_up(offset, alignment):
    return (offset + alignment - 1) // alignment * alignment


def lz4_block_decode(src, start, in_len, out):
    """Decode one LZ4 block into `out` (bytearray). Matches may reference any
    earlier byte already present in `out` (LZ4 chained frames)."""
    ip = start
    end = start + in_len
    while ip < end:
        token = src[ip]
        ip += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[ip]
                ip += 1
                lit += b
                if b != 255:
                    break
        if ip + lit > end:
            raise KV3Error("literal run overruns input at %d" % ip)
        out += src[ip:ip + lit]
        ip += lit
        if ip >= end:
            break
        offset = src[ip] | (src[ip + 1] << 8)
        ip += 2
        mlen = token & 0x0F
        if mlen == 15:
            while True:
                b = src[ip]
                ip += 1
                mlen += b
                if b != 255:
                    break
        mlen += 4
        if offset == 0 or offset > len(out):
            raise KV3Error("invalid LZ4 match offset %d" % offset)
        sp = len(out) - offset
        for i in range(mlen):
            out.append(out[sp + i])
    return ip - start


class BinaryKV3:
    def __init__(self, data):
        self.data = data
        self.strings = []
        self.types = bytearray()
        self.object_lengths = bytearray()
        self.blob_lengths = []
        self.blobs = bytearray()
        self.main = Lanes()
        self.aux = Lanes()

    # -- header -----------------------------------------------------------
    def read_header(self):
        d = self.data
        magic = struct.unpack_from("<I", d, 0)[0]
        if magic == MAGIC0:
            raise KV3Error("VKV3 block-compressed KV3 is not supported")
        if magic & 0xFFFFFF00 != 0x4B563300:
            raise KV3Error("not a binary KV3 file (magic %08x)" % magic)
        self.version = magic & 0xFF
        if not 1 <= self.version <= 5:
            raise KV3Error("unsupported KV3 version %d" % self.version)
        self.guid = d[4:20].hex()
        self.compression = struct.unpack_from("<I", d, 20)[0]
        self.dictionary_id = struct.unpack_from("<H", d, 24)[0]
        self.frame_size = struct.unpack_from("<H", d, 26)[0]
        off = 28
        (self.count_bytes1, self.count_bytes4, self.count_bytes8, self.count_types) = \
            struct.unpack_from("<iiii", d, off)
        off += 16
        self.count_objects, self.count_arrays = struct.unpack_from("<HH", d, off)
        off += 4
        (self.size_uncompressed_total, self.size_compressed_total,
         self.count_blocks, self.size_binary_blobs) = struct.unpack_from("<iiii", d, off)
        off += 16
        if self.version >= 4:
            self.count_bytes2, self.size_block_compressed_sizes = struct.unpack_from("<ii", d, off)
            off += 8
        if self.version >= 5:
            (self.size_uncompressed_buffer1, self.size_compressed_buffer1,
             self.size_uncompressed_buffer2, self.size_compressed_buffer2,
             self.count_bytes1_buffer2, self.count_bytes2_buffer2,
             self.count_bytes4_buffer2, self.count_bytes8_buffer2,
             self.count_nodes, self.count_objects_buffer2,
             self.count_arrays_buffer2, self.count_array_elements) = struct.unpack_from("<12i", d, off)
            off += 48
        else:
            self.count_bytes2 = 0
            self.size_block_compressed_sizes = 0
            self.size_uncompressed_buffer1 = self.size_uncompressed_total
            self.size_compressed_buffer1 = self.size_compressed_total
            self.size_uncompressed_buffer2 = 0
            self.size_compressed_buffer2 = 0
            self.count_bytes1_buffer2 = 0
            self.count_bytes2_buffer2 = 0
            self.count_bytes4_buffer2 = 0
            self.count_bytes8_buffer2 = 0
            self.count_nodes = 0
            self.count_objects_buffer2 = 0
            self.count_arrays_buffer2 = 0
            self.count_array_elements = 0
        self.data_offset = off
        return off

    # -- payload ----------------------------------------------------------
    def read_payload(self):
        d = self.data
        off = self.data_offset
        if self.compression != 1:
            raise KV3Error("only LZ4 compressed KV3 is supported (got %d)" % self.compression)
        buf1 = bytearray()
        used = lz4_block_decode(d, off, self.size_compressed_buffer1, buf1)
        off += used
        if len(buf1) != self.size_uncompressed_buffer1:
            raise KV3Error("buffer1 size mismatch: %d != %d" % (len(buf1), self.size_uncompressed_buffer1))
        buf2 = bytearray()
        used = lz4_block_decode(d, off, self.size_compressed_buffer2, buf2)
        off += used
        if len(buf2) != self.size_uncompressed_buffer2:
            raise KV3Error("buffer2 size mismatch: %d != %d" % (len(buf2), self.size_uncompressed_buffer2))
        self.blob_data_offset = off
        self.split_buffer1(buf1)
        self.split_buffer2(buf2)
        self.read_blobs(off)

    def split_buffer1(self, buf):
        off = 0
        if self.count_bytes1:
            self.aux.b1 = bytearray(buf[off:off + self.count_bytes1])
            off += self.count_bytes1
        if self.count_bytes2:
            off = align_up(off, 2)
            self.aux.b2 = bytearray(buf[off:off + self.count_bytes2 * 2])
            off += self.count_bytes2 * 2
        if self.count_bytes4:
            off = align_up(off, 4)
            self.aux.b4 = bytearray(buf[off:off + self.count_bytes4 * 4])
            off += self.count_bytes4 * 4
        if self.count_bytes8:
            off = align_up(off, 8)
            self.aux.b8 = bytearray(buf[off:off + self.count_bytes8 * 8])
            off += self.count_bytes8 * 8
        count = struct.unpack_from("<i", self.aux.b4, 0)[0]
        del self.aux.b4[:4]
        blob = bytes(self.aux.b1)
        self.aux.b1 = bytearray()
        strings = []
        pos = 0
        for _ in range(count):
            end = blob.index(b"\x00", pos)
            strings.append(blob[pos:end].decode("utf-8", "replace"))
            pos = end + 1
        self.strings = strings

    def split_buffer2(self, buf):
        off = 0
        end = self.count_objects_buffer2 * 4
        self.object_lengths = bytearray(buf[:end])
        off = end
        if self.count_bytes1_buffer2:
            self.main.b1 = bytearray(buf[off:off + self.count_bytes1_buffer2])
            off += self.count_bytes1_buffer2
        if self.count_bytes2_buffer2:
            off = align_up(off, 2)
            self.main.b2 = bytearray(buf[off:off + self.count_bytes2_buffer2 * 2])
            off += self.count_bytes2_buffer2 * 2
        if self.count_bytes4_buffer2:
            off = align_up(off, 4)
            self.main.b4 = bytearray(buf[off:off + self.count_bytes4_buffer2 * 4])
            off += self.count_bytes4_buffer2 * 4
        if self.count_bytes8_buffer2:
            off = align_up(off, 8)
            self.main.b8 = bytearray(buf[off:off + self.count_bytes8_buffer2 * 8])
            off += self.count_bytes8_buffer2 * 8
        self.types = bytearray(buf[off:off + self.count_types])
        off += self.count_types
        if self.count_blocks:
            blob_len_bytes = buf[off:off + self.count_blocks * 4]
            self.blob_lengths = list(struct.unpack_from("<%di" % self.count_blocks, blob_len_bytes, 0))
            off += self.count_blocks * 4
            trailer = struct.unpack_from("<I", buf, off)[0]
            off += 4
            if trailer != 0xFFEEDD00:
                raise KV3Error("bad KV3 trailer %08x" % trailer)
            self.block_sizes = list(struct.unpack_from("<%dH" % self.count_blocks, buf, off))
            off += self.count_blocks * 2

    def read_blobs(self, off):
        d = self.data
        blocks = getattr(self, "block_sizes", [])
        bi = 0
        out = self.blobs
        for length in self.blob_lengths:
            end = len(out) + length
            while len(out) < end:
                if bi >= len(blocks):
                    raise KV3Error("ran out of blob frames")
                size = blocks[bi]
                bi += 1
                lz4_block_decode(d, off, size, out)
                off += size
        self.blob_data_end = off

    # -- tree -------------------------------------------------------------
    def read_type(self):
        b = self.types[0]
        del self.types[0]
        flags = 0
        if self.version >= 3:
            if b & 0x80:
                flags = self.types[0]
                del self.types[0]
            if b & 0x40:
                del self.types[0]
            b &= 0x3F
        else:
            if b & 0x80:
                del self.types[0]
            b &= 0x7F
        return b, flags

    def get_string(self, sid):
        if 0 <= sid < len(self.strings):
            return self.strings[sid]
        return ""

    def read_value(self, dtype, lane):
        if dtype == NULL:
            return None
        if dtype == BOOLEAN:
            return lane.take1() != 0
        if dtype == INT64:
            return struct.unpack("<q", struct.pack("<Q", lane.take8()))[0]
        if dtype == UINT64:
            return lane.take8()
        if dtype == DOUBLE:
            return lane.take8f()
        if dtype == STRING:
            return self.get_string(self.main.take4s())
        if dtype == BINARY_BLOB:
            length = self.blob_lengths.pop(0)
            value = bytes(self.blobs[:length])
            del self.blobs[:length]
            return value
        if dtype == ARRAY:
            n = self.main.take4s()
            return [self.read_member(item=True) for item in range(n)]
        if dtype == ARRAY_TYPED:
            n = self.main.take4s()
            sub, _ = self.read_type()
            return [self.read_typed(sub, self.main) for _ in range(n)]
        if dtype == ARRAY_TYPE_BYTE_LENGTH:
            n = lane.take1()
            sub, _ = self.read_type()
            return [self.read_typed(sub, self.main) for _ in range(n)]
        if dtype == ARRAY_TYPE_AUXILIARY_BUFFER:
            n = lane.take1()
            sub, _ = self.read_type()
            return [self.read_typed(sub, self.aux) for _ in range(n)]
        if dtype == OBJECT:
            n = struct.unpack_from("<i", self.object_lengths, 0)[0]
            del self.object_lengths[:4]
            out = {}
            for _ in range(n):
                name, value = self.read_member(item=False)
                out[name] = value
            return out
        if dtype == INT32:
            v = struct.unpack_from("<i", lane.b4, 0)[0]
            lane.take4()
            return v
        if dtype == UINT32:
            v = struct.unpack_from("<I", lane.b4, 0)[0]
            lane.take4()
            return v
        if dtype == BOOLEAN_TRUE:
            return True
        if dtype == BOOLEAN_FALSE:
            return False
        if dtype == INT64_ZERO:
            return 0
        if dtype == INT64_ONE:
            return 1
        if dtype == DOUBLE_ZERO:
            return 0.0
        if dtype == DOUBLE_ONE:
            return 1.0
        if dtype == FLOAT:
            v = struct.unpack_from("<f", lane.b4, 0)[0]
            lane.take4()
            return v
        if dtype == INT16:
            v = struct.unpack_from("<h", lane.b2, 0)[0]
            lane.take2()
            return v
        if dtype == UINT16:
            v = struct.unpack_from("<H", lane.b2, 0)[0]
            lane.take2()
            return v
        if dtype == INT8:
            v = struct.unpack_from("<b", lane.b1, 0)[0]
            lane.take1()
            return v
        if dtype == UINT8:
            return lane.take1()
        if dtype == UINT32_ZERO:
            return 0
        if dtype == UINT32_ONE:
            return 1
        raise KV3Error("unknown KV3 node type %d" % dtype)

    def read_typed(self, dtype, lane):
        return self.read_value(dtype, lane)

    def read_member(self, item):
        dtype, _flags = self.read_type()
        if item:
            return self.read_value(dtype, self.main)
        name = self.get_string(self.main.take4s())
        return name, self.read_value(dtype, self.main)

    def read_tree(self):
        dtype, _flags = self.read_type()
        return self.read_value(dtype, self.main)


def decode(path):
    data = pathlib.Path(path).read_bytes()
    kv3 = BinaryKV3(data)
    kv3.read_header()
    kv3.read_payload()
    return kv3


def load_items():
    path = pathlib.Path(__file__).resolve().parent.parent / "data" / "items_raw.json"
    if not path.exists():
        return {}
    return {i["id"]: i for i in json.loads(path.read_text(encoding="utf-8"))}


def build_summary(kv3, tree):
    """Summarise the saved hero builds stored in the client's build cache."""
    import decode_build_code as D

    items = load_items()

    def resolve(item_id):
        item = items.get(item_id)
        if not item:
            return None
        return {"name": item.get("name"), "class_name": item.get("class_name"), "type": item.get("type")}

    builds = []
    categories = {}
    ladder = {}
    for key in ("Favorites", "Unpublished", "SavedLastUsed"):
        for index, blob in enumerate(tree.get(key) or []):
            wrapper = D.parse_message(blob)
            inner = D.get_msgs(wrapper, 1)
            if not inner:
                continue
            build = inner[0]
            details = D.get_msgs(build, 10)
            det = details[0] if details else []
            cats = []
            for cat in D.get_msgs(det, 1):
                name = D.get_str(cat, 2)
                mods = []
                for mod in D.get_msgs(cat, 1):
                    mid = D.get_int(mod, 1)
                    if mid is not None:
                        mods.append(mid)
                for f, w, v in cat:
                    if f == 1 and not isinstance(v, tuple):
                        mods.append(v)
                entry = {
                    "name": name,
                    "description": D.get_str(cat, 3),
                    "optional": any(f == 6 and not isinstance(v, tuple) for f, w, v in cat),
                    "height": next((v for f, w, v in cat if f == 4 and not isinstance(v, tuple)), None),
                    "width": next((v for f, w, v in cat if f == 5 and not isinstance(v, tuple)), None),
                    "mods": mods,
                    "mod_names": [resolve(m) for m in mods],
                }
                cats.append(entry)
                slot = categories.setdefault(name or "", {"count": 0, "description": entry["description"]})
                slot["count"] += 1
            changes = []
            for order in D.get_msgs(det, 2):
                for cc in D.get_msgs(order, 1):
                    delta = D.get_int(cc, 3)
                    if delta is not None and delta >= (1 << 63):
                        delta -= 1 << 64
                    ctype = D.get_int(cc, 2)
                    changes.append({"ability_id": D.get_int(cc, 1), "currency_type": ctype, "delta": delta})
                    key2 = "%d/%s" % (ctype, delta)
                    ladder[key2] = ladder.get(key2, 0) + 1
            builds.append({
                "list": key,
                "index": index,
                "field_1": D.get_int(build, 1),
                "field_2": D.get_int(build, 2),
                "hero_id": D.get_int(build, 2),
                "field_3": D.get_int(build, 3),
                "field_4": D.get_int(build, 4),
                "name": D.get_str(build, 5),
                "categories": cats,
                "ability_order": changes,
            })
    return {
        "kv3": {
            "magic": "0x%08X" % kv3.version,
            "version": kv3.version,
            "compression": "lz4" if kv3.compression == 1 else kv3.compression,
            "guid": kv3.guid,
            "count_strings": len(kv3.strings),
            "size_uncompressed_total": kv3.size_uncompressed_total,
            "count_blocks": kv3.count_blocks,
        },
        "root_keys": list(tree.keys()),
        "last_used_builds": tree.get("LastUsedBuilds"),
        "builds": builds,
        "category_names": categories,
        "currency_delta_counts": ladder,
    }


def self_test(kv3, tree):
    """Check the decoder against the structure of the client's build cache."""
    summary = build_summary(kv3, tree)
    assert kv3.version == 5, "not KV3 v5"
    assert kv3.compression == 1, "not LZ4 compressed"
    assert list(tree) == ["LastUsedBuilds", "Favorites", "Unpublished", "SavedLastUsed"], list(tree)
    # the client rewrites this file whenever a build is saved, so the counts move:
    # check the shape of the file, not the size of the player's library
    for key in ("Favorites", "Unpublished", "SavedLastUsed"):
        assert len(tree[key]) >= 1, key
    assert len(summary["builds"]) == sum(len(tree[k]) for k in ("Favorites", "Unpublished", "SavedLastUsed"))
    tokens = {n for n in summary["category_names"] if n.startswith("#Citadel_HeroBuilds")}
    assert tokens == {
        "#Citadel_HeroBuilds_Early", "#Citadel_HeroBuilds_EarlyGame", "#Citadel_HeroBuilds_Lane",
        "#Citadel_HeroBuilds_Late", "#Citadel_HeroBuilds_LateGame", "#Citadel_HeroBuilds_Mid",
        "#Citadel_HeroBuilds_MidGame",
    }, tokens
    assert set(summary["currency_delta_counts"]) == {"1/-1", "1/-2", "1/-5", "2/-1"}, summary["currency_delta_counts"]
    print("SELF_TEST_OK")


def main():
    ap = argparse.ArgumentParser(description="Decode binary KeyValues3 into JSON")
    ap.add_argument("path")
    ap.add_argument("--out")
    ap.add_argument("--strings-only", action="store_true")
    ap.add_argument("--builds", action="store_true", help="summarise the saved hero builds")
    ap.add_argument("--self-test", action="store_true", help="check the decoder against the build cache")
    args = ap.parse_args()
    kv3 = decode(args.path)
    if args.self_test:
        self_test(kv3, kv3.read_tree())
        return
    if args.strings_only:
        for i, s in enumerate(kv3.strings):
            print("%d\t%s" % (i, s))
        return
    tree = kv3.read_tree()
    if args.builds:
        text = json.dumps(build_summary(kv3, tree), indent=2, ensure_ascii=False)
    else:
        text = json.dumps(tree, indent=2, ensure_ascii=False,
                          default=lambda b: {"bytes_base64": base64.b64encode(b).decode()})
    if args.out:
        pathlib.Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(text)


if __name__ == "__main__":
    try:
        main()
    except KV3Error as exc:
        print("KV3_ERROR %s" % exc, file=sys.stderr)
        sys.exit(1)
