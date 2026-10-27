#!/usr/bin/env python3
"""Decode Valve binary KeyValues3 (KV3 binary, magic KV3\\x05) into JSON.

The Deadlock client stores its saved hero builds in
  %LOCALAPPDATA%/../Steam/userdata/<id>/1422450/remote/cfg/cached_hero_builds.kv3
which is binary KeyValues3 version 5 (magic 0x4B563305), LZ4 block compressed.

Layout implemented here follows ValveResourceFormat's BinaryKV3 reader:
  header, LZ4 compressed "buffer 1" (string table), LZ4 compressed "buffer 2"
  (object lengths, value lanes, type bytes, blob lengths) and LZ4 chained
  binary blobs.

Output is lossless by default: every header field, the payload metadata, the
string table, every tree node with its KV3 type byte and flags, duplicate
object keys in file order, and a completeness block that accounts for every
input byte and lists anything left unconsumed. Non-ASCII text is JSON-escaped
so the document is always valid JSON. Pass --plain for the old compact tree of
plain Python values.

Usage:
    python decode_kv3.py <file.kv3> [--out out.json] [--plain] [--strings-only]
    [--builds] [--blobs DIR]
    python decode_kv3.py <file.kv3> --self-test
"""

import argparse
import base64
import json
import pathlib
import struct
import sys
from typing import Any

MAGIC0 = 0x03564B56
_MAX_INPUT_BYTES = 64 * 1024 * 1024
_MAX_OUTPUT_BYTES = 256 * 1024 * 1024

COMPRESSION_NAMES = {0: "none", 1: "lz4"}

# KV3BinaryNodeType
NULL, BOOLEAN, INT64, UINT64, DOUBLE, STRING, BINARY_BLOB, ARRAY, OBJECT = range(1, 10)
ARRAY_TYPED, INT32, UINT32, BOOLEAN_TRUE, BOOLEAN_FALSE = range(10, 15)
INT64_ZERO, INT64_ONE, DOUBLE_ZERO, DOUBLE_ONE, FLOAT = range(15, 20)
INT16, UINT16, INT8, UINT8 = range(20, 24)
ARRAY_TYPE_BYTE_LENGTH, ARRAY_TYPE_AUXILIARY_BUFFER = 24, 25
UINT32_ZERO, UINT32_ONE = 26, 27

TYPE_NAMES = {
    NULL: "NULL",
    BOOLEAN: "BOOLEAN",
    INT64: "INT64",
    UINT64: "UINT64",
    DOUBLE: "DOUBLE",
    STRING: "STRING",
    BINARY_BLOB: "BINARY_BLOB",
    ARRAY: "ARRAY",
    OBJECT: "OBJECT",
    ARRAY_TYPED: "ARRAY_TYPED",
    INT32: "INT32",
    UINT32: "UINT32",
    BOOLEAN_TRUE: "BOOLEAN_TRUE",
    BOOLEAN_FALSE: "BOOLEAN_FALSE",
    INT64_ZERO: "INT64_ZERO",
    INT64_ONE: "INT64_ONE",
    DOUBLE_ZERO: "DOUBLE_ZERO",
    DOUBLE_ONE: "DOUBLE_ONE",
    FLOAT: "FLOAT",
    INT16: "INT16",
    UINT16: "UINT16",
    INT8: "INT8",
    UINT8: "UINT8",
    ARRAY_TYPE_BYTE_LENGTH: "ARRAY_TYPE_BYTE_LENGTH",
    ARRAY_TYPE_AUXILIARY_BUFFER: "ARRAY_TYPE_AUXILIARY_BUFFER",
    UINT32_ZERO: "UINT32_ZERO",
    UINT32_ONE: "UINT32_ONE",
}
TYPED_ARRAYS = frozenset(
    (ARRAY_TYPED, ARRAY_TYPE_BYTE_LENGTH, ARRAY_TYPE_AUXILIARY_BUFFER)
)


def descriptor(
    dtype: int, flags: int | None, extra: int | None
) -> dict[str, Any]:
    """Build a descriptor dict for a KV3 node type byte."""
    node: dict[str, Any] = {"type": TYPE_NAMES.get(dtype, f"UNKNOWN_{dtype}")}
    if flags is not None:
        node["flags"] = flags
    if extra is not None:
        node["extra"] = extra
    return node


class KV3Error(Exception):
    """Exception raised for malformed or unsupported KV3 input."""


class Lanes:
    """Fixed-width value lanes used by the KV3 binary encoding."""

    def __init__(self) -> None:
        """Initialize empty fixed-width value lanes."""
        self.b1 = bytearray()
        self.b2 = bytearray()
        self.b4 = bytearray()
        self.b8 = bytearray()
        self._i1 = 0
        self._i2 = 0
        self._i4 = 0
        self._i8 = 0

    def _trim(self) -> None:
        """Compact consumed lane prefixes to bound memory usage."""
        if self._i1 > len(self.b1) // 2 and self._i1 > 0:
            self.b1 = self.b1[self._i1 :]
            self._i1 = 0
        if self._i2 > len(self.b2) // 2 and self._i2 > 0:
            self.b2 = self.b2[self._i2 :]
            self._i2 = 0
        if self._i4 > len(self.b4) // 2 and self._i4 > 0:
            self.b4 = self.b4[self._i4 :]
            self._i4 = 0
        if self._i8 > len(self.b8) // 2 and self._i8 > 0:
            self.b8 = self.b8[self._i8 :]
            self._i8 = 0

    def take1(self) -> int:
        """Consume and return one byte from the 1-byte lane."""
        if self._i1 >= len(self.b1):
            raise KV3Error("truncated 1-byte lane")
        v = self.b1[self._i1]
        self._i1 += 1
        self._trim()
        return v

    def take2(self) -> int:
        """Consume and return an unsigned 16-bit value from the 2-byte lane."""
        if self._i2 + 2 > len(self.b2):
            raise KV3Error("truncated 2-byte lane")
        v = struct.unpack_from("<H", self.b2, self._i2)[0]
        self._i2 += 2
        self._trim()
        return v

    def take4(self) -> int:
        """Consume and return an unsigned 32-bit value from the 4-byte lane."""
        if self._i4 + 4 > len(self.b4):
            raise KV3Error("truncated 4-byte lane")
        v = struct.unpack_from("<I", self.b4, self._i4)[0]
        self._i4 += 4
        self._trim()
        return v

    def take4s(self) -> int:
        """Consume and return a signed 32-bit value from the 4-byte lane."""
        if self._i4 + 4 > len(self.b4):
            raise KV3Error("truncated 4-byte lane")
        v = struct.unpack_from("<i", self.b4, self._i4)[0]
        self._i4 += 4
        self._trim()
        return v

    def take8(self) -> int:
        """Consume and return an unsigned 64-bit value from the 8-byte lane."""
        if self._i8 + 8 > len(self.b8):
            raise KV3Error("truncated 8-byte lane")
        v = struct.unpack_from("<Q", self.b8, self._i8)[0]
        self._i8 += 8
        self._trim()
        return v

    def take8f(self) -> float:
        """Consume and return a double-precision value from the 8-byte lane."""
        if self._i8 + 8 > len(self.b8):
            raise KV3Error("truncated 8-byte lane")
        v = struct.unpack_from("<d", self.b8, self._i8)[0]
        self._i8 += 8
        self._trim()
        return v

    @property
    def remaining1(self) -> int:
        """Number of unconsumed bytes in the 1-byte lane."""
        return len(self.b1) - self._i1

    @property
    def remaining2(self) -> int:
        """Number of unconsumed bytes in the 2-byte lane."""
        return len(self.b2) - self._i2

    @property
    def remaining4(self) -> int:
        """Number of unconsumed bytes in the 4-byte lane."""
        return len(self.b4) - self._i4

    @property
    def remaining8(self) -> int:
        """Number of unconsumed bytes in the 8-byte lane."""
        return len(self.b8) - self._i8


def align_up(offset: int, alignment: int) -> int:
    """Round offset up to the next multiple of alignment."""
    return (offset + alignment - 1) // alignment * alignment


def lz4_block_decode(src: bytes, start: int, in_len: int, out: bytearray) -> int:
    """Decode one LZ4 block into `out` (bytearray). Matches may reference any
    earlier byte already present in `out` (LZ4 chained frames)."""
    ip = start
    end = start + in_len
    while ip < end:
        if len(out) > 256 * 1024 * 1024:
            raise KV3Error("LZ4 output exceeds limit")
        if ip >= len(src):
            raise KV3Error(f"truncated LZ4 block at {ip}")
        token = src[ip]
        ip += 1
        lit = token >> 4
        if lit == 15:
            while True:
                if ip >= len(src):
                    raise KV3Error(f"truncated LZ4 literal length at {ip}")
                b = src[ip]
                ip += 1
                lit += b
                if b != 255:
                    break
        if ip + lit > end or ip + lit > len(src):
            raise KV3Error(f"literal run overruns input at {ip}")
        out += src[ip : ip + lit]
        if len(out) > 256 * 1024 * 1024:
            raise KV3Error("LZ4 output exceeds limit")
        ip += lit
        if ip >= end:
            break
        if ip + 2 > len(src):
            raise KV3Error(f"truncated LZ4 offset at {ip}")
        offset = src[ip] | (src[ip + 1] << 8)
        ip += 2
        mlen = token & 0x0F
        if mlen == 15:
            while True:
                if ip >= len(src):
                    raise KV3Error(f"truncated LZ4 match length at {ip}")
                b = src[ip]
                ip += 1
                mlen += b
                if b != 255:
                    break
        mlen += 4
        if offset == 0 or offset > len(out):
            raise KV3Error(f"invalid LZ4 match offset {offset}")
        if mlen > 1024 * 1024:
            raise KV3Error("LZ4 match too long")
        sp = len(out) - offset
        for _ in range(mlen):
            out.append(out[sp])
            sp += 1
    return ip - start


class BinaryKV3:
    """Parser for a binary KeyValues3 (KV3) document."""
    def __init__(self, data: bytes) -> None:
        """Initialize parser state from raw file bytes."""
        self.data = data
        self.strings = []
        self.types = bytearray()
        self.object_lengths = bytearray()
        self.blob_lengths = []
        self.blobs = bytearray()
        self.main = Lanes()
        self.aux = Lanes()
        self.declared_blob_lengths = []
        self.declared_block_sizes = []
        self.blob_frames_used = 0
        self.buffer1_consumed = 0
        self.buffer2_consumed = 0
        self.buffer1_trailing = 0
        self.buffer2_trailing = 0
        self.string_count_declared = 0
        self.string_bytes = 0
        self.string_bytes_used = 0
        self.trailer_offset = 0
        self.trailer = b""

    # -- header -----------------------------------------------------------
    def read_header(self) -> int:
        """Parse and validate the KV3 file header, returning data offset."""
        d = self.data
        if len(d) < 28:
            raise KV3Error("truncated KV3 header")
        magic = struct.unpack_from("<I", d, 0)[0]
        if magic == MAGIC0:
            raise KV3Error("VKV3 block-compressed KV3 is not supported")
        if magic & 0xFFFFFF00 != 0x4B563300:
            raise KV3Error(f"not a binary KV3 file (magic {magic:08x})")
        self.version = magic & 0xFF
        self.magic = magic
        if not 1 <= self.version <= 5:
            raise KV3Error(f"unsupported KV3 version {self.version}")
        self.guid = d[4:20].hex()
        self.compression = struct.unpack_from("<I", d, 20)[0]
        self.dictionary_id = struct.unpack_from("<H", d, 24)[0]
        self.frame_size = struct.unpack_from("<H", d, 26)[0]
        off = 28
        (self.count_bytes1, self.count_bytes4, self.count_bytes8, self.count_types) = (
            struct.unpack_from("<iiii", d, off)
        )
        off += 16
        self.count_objects, self.count_arrays = struct.unpack_from("<HH", d, off)
        off += 4
        (
            self.size_uncompressed_total,
            self.size_compressed_total,
            self.count_blocks,
            self.size_binary_blobs,
        ) = struct.unpack_from("<iiii", d, off)
        off += 16
        if self.version >= 4:
            self.count_bytes2, self.size_block_compressed_sizes = struct.unpack_from(
                "<ii", d, off
            )
            off += 8
        if self.version >= 5:
            (
                self.size_uncompressed_buffer1,
                self.size_compressed_buffer1,
                self.size_uncompressed_buffer2,
                self.size_compressed_buffer2,
                self.count_bytes1_buffer2,
                self.count_bytes2_buffer2,
                self.count_bytes4_buffer2,
                self.count_bytes8_buffer2,
                self.count_nodes,
                self.count_objects_buffer2,
                self.count_arrays_buffer2,
                self.count_array_elements,
            ) = struct.unpack_from("<12i", d, off)
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
    def read_payload(self) -> None:
        """Decompress and split the KV3 payload buffers and blobs."""
        d = self.data
        off = self.data_offset
        if self.compression != 1:
            raise KV3Error(
                "only LZ4 compressed KV3 is supported "
                f"(got {COMPRESSION_NAMES.get(self.compression, self.compression)})"
            )
        buf1 = bytearray()
        used = lz4_block_decode(d, off, self.size_compressed_buffer1, buf1)
        if used != self.size_compressed_buffer1:
            raise KV3Error(
                f"buffer1 consumed {used} != declared {self.size_compressed_buffer1}"
            )
        off += used
        self.buffer1_consumed = used
        if len(buf1) != self.size_uncompressed_buffer1:
            raise KV3Error(
                f"buffer1 size mismatch: {len(buf1)} != {self.size_uncompressed_buffer1}"
            )
        buf2 = bytearray()
        used = lz4_block_decode(d, off, self.size_compressed_buffer2, buf2)
        if used != self.size_compressed_buffer2:
            raise KV3Error(
                f"buffer2 consumed {used} != declared {self.size_compressed_buffer2}"
            )
        off += used
        self.buffer2_consumed = used
        if len(buf2) != self.size_uncompressed_buffer2:
            raise KV3Error(
                f"buffer2 size mismatch: {len(buf2)} != {self.size_uncompressed_buffer2}"
            )
        self.blob_data_offset = off
        self.split_buffer1(buf1)
        self.split_buffer2(buf2)
        self.read_blobs(off)

    def split_buffer1(self, buf: bytearray) -> None:
        """Split buffer 1 into the string table and auxiliary lanes."""
        off = 0
        if self.count_bytes4 < 1:
            raise KV3Error("count_bytes4 must be >= 1")
        if self.count_bytes1:
            self.aux.b1 = bytearray(buf[off : off + self.count_bytes1])
            self.aux._i1 = 0
            off += self.count_bytes1
        if self.count_bytes2:
            off = align_up(off, 2)
            self.aux.b2 = bytearray(buf[off : off + self.count_bytes2 * 2])
            self.aux._i2 = 0
            off += self.count_bytes2 * 2
        if self.count_bytes4:
            off = align_up(off, 4)
            self.aux.b4 = bytearray(buf[off : off + self.count_bytes4 * 4])
            self.aux._i4 = 0
            off += self.count_bytes4 * 4
        if self.count_bytes8:
            off = align_up(off, 8)
            self.aux.b8 = bytearray(buf[off : off + self.count_bytes8 * 8])
            self.aux._i8 = 0
            off += self.count_bytes8 * 8
        if self.aux.remaining4 < 4:
            raise KV3Error("missing string count in aux buffer")
        count = struct.unpack_from("<i", self.aux.b4, self.aux._i4)[0]
        self.aux._i4 += 4
        if count < 1:
            raise KV3Error(f"string count must be >= 1, got {count}")
        blob = bytes(self.aux.b1[self.aux._i1 :])
        self.aux.b1 = bytearray()
        strings = []
        pos = 0
        for idx in range(count):
            try:
                end = blob.index(b"\x00", pos)
            except ValueError:
                raise KV3Error(f"unterminated string at index {idx}")
            strings.append(blob[pos:end].decode("utf-8", "surrogateescape"))
            pos = end + 1
        if pos != len(blob):
            raise KV3Error(f"string table has {len(blob) - pos} trailing bytes")
        self.strings = strings
        self.string_count_declared = count
        self.string_bytes = len(blob)
        self.string_bytes_used = pos
        self.buffer1_trailing = len(buf) - off

    def split_buffer2(self, buf: bytearray) -> None:
        """Split buffer 2 into object lengths, lanes, types, and blob metadata."""
        off = 0
        end = self.count_objects_buffer2 * 4
        self.object_lengths = bytearray(buf[:end])
        off = end
        if self.count_bytes1_buffer2:
            self.main.b1 = bytearray(buf[off : off + self.count_bytes1_buffer2])
            self.main._i1 = 0
            off += self.count_bytes1_buffer2
        if self.count_bytes2_buffer2:
            off = align_up(off, 2)
            self.main.b2 = bytearray(buf[off : off + self.count_bytes2_buffer2 * 2])
            self.main._i2 = 0
            off += self.count_bytes2_buffer2 * 2
        if self.count_bytes4_buffer2:
            off = align_up(off, 4)
            self.main.b4 = bytearray(buf[off : off + self.count_bytes4_buffer2 * 4])
            self.main._i4 = 0
            off += self.count_bytes4_buffer2 * 4
        if self.count_bytes8_buffer2:
            off = align_up(off, 8)
            self.main.b8 = bytearray(buf[off : off + self.count_bytes8_buffer2 * 8])
            self.main._i8 = 0
            off += self.count_bytes8_buffer2 * 8
        self.types = bytearray(buf[off : off + self.count_types])
        off += self.count_types
        if self.count_blocks:
            blob_len_bytes = buf[off : off + self.count_blocks * 4]
            self.blob_lengths = list(
                struct.unpack_from(f"<{self.count_blocks}i", blob_len_bytes, 0)
            )
            self.declared_blob_lengths = list(self.blob_lengths)
            off += self.count_blocks * 4
            trailer = struct.unpack_from("<I", buf, off)[0]
            off += 4
            if trailer != 0xFFEEDD00:
                raise KV3Error(f"bad KV3 trailer {trailer:08x}")
            self.block_sizes = list(
                struct.unpack_from(f"<{self.count_blocks}H", buf, off)
            )
            self.declared_block_sizes = list(self.block_sizes)
            off += self.count_blocks * 2
        self.buffer2_trailing = len(buf) - off

    def read_blobs(self, off: int) -> None:
        """Read chained LZ4 blob frames into the blob buffer."""
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
                used = lz4_block_decode(d, off, size, out)
                if used != size:
                    raise KV3Error(
                        f"blob frame consumed {used} != declared {size}"
                    )
                off += used
        self.blob_frames_used = bi
        self.blob_data_end = off
        self.trailer_offset = off
        self.trailer = d[off : off + 4]

    # -- tree -------------------------------------------------------------
    def read_type(self) -> tuple[int, int | None, int | None]:
        """Read and decode one KV3 node type byte with flags/extra."""
        if not self.types:
            raise KV3Error("truncated type stream")
        b = self.types[0]
        del self.types[0]
        flags = extra = None
        if self.version >= 3:
            if b & 0x80:
                if not self.types:
                    raise KV3Error("truncated type flags")
                flags = self.types[0]
                del self.types[0]
            if b & 0x40:
                if not self.types:
                    raise KV3Error("truncated type extra")
                extra = self.types[0]
                del self.types[0]
            b &= 0x3F
        else:
            if b & 0x80:
                if not self.types:
                    raise KV3Error("truncated type flags")
                flags = self.types[0]
                del self.types[0]
            b &= 0x7F
        return b, flags, extra

    def get_string(self, sid: int) -> str | None:
        """Look up a string by its table id."""
        if 0 <= sid < len(self.strings):
            return self.strings[sid]
        return None

    def read_tree(self) -> dict[str, Any]:
        """Read the root KV3 node as a document tree."""
        return self.read_node(self.main)

    def read_node(
        self,
        lane: "Lanes",
        declared: tuple[int, int | None, int | None] | None = None,
        depth: int = 0,
    ) -> dict[str, Any]:
        """Read one KV3 node from the given value lane."""
        if depth > 64:
            raise KV3Error("max recursion depth exceeded")
        if declared is None:
            declared = self.read_type()
        dtype, flags, extra = declared
        node: dict[str, Any] = descriptor(dtype, flags, extra)
        if dtype == OBJECT:
            if len(self.object_lengths) < 4:
                raise KV3Error("truncated object length")
            n = struct.unpack_from("<i", self.object_lengths, 0)[0]
            del self.object_lengths[:4]
            if n < 0:
                raise KV3Error(f"negative object count {n}")
            if n > 1000000:
                raise KV3Error(f"object count too large {n}")
            entries = []
            for _ in range(n):
                key_id = self.main.take4s()
                entries.append(
                    {
                        "string_id": key_id,
                        "key": self.get_string(key_id),
                        "value": self.read_node(self.main, depth=depth + 1),
                    }
                )
            node["value"] = entries
        elif dtype == ARRAY:
            n = self.main.take4s()
            if n < 0:
                raise KV3Error(f"negative array count {n}")
            if n > 1000000:
                raise KV3Error(f"array count too large {n}")
            node["value"] = [
                self.read_node(self.main, depth=depth + 1) for _ in range(n)
            ]
        elif dtype in TYPED_ARRAYS:
            if dtype == ARRAY_TYPED:
                n = self.main.take4s()
                buf = self.main
            elif dtype == ARRAY_TYPE_BYTE_LENGTH:
                n = lane.take1()
                buf = self.main
            else:
                n = lane.take1()
                buf = self.aux
            if n < 0:
                raise KV3Error(f"negative array count {n}")
            sub = self.read_type()
            node["element"] = descriptor(*sub)
            node["value"] = [
                self.read_node(buf, sub, depth=depth + 1) for _ in range(n)
            ]
        elif dtype == STRING:
            sid = self.main.take4s()
            node["string_id"] = sid
            node["value"] = self.get_string(sid)
        elif dtype == BINARY_BLOB:
            if not self.blob_lengths:
                raise KV3Error("missing blob length")
            length = self.blob_lengths.pop(0)
            value = bytes(self.blobs[:length])
            del self.blobs[:length]
            node["value"] = {"bytes_base64": base64.b64encode(value).decode("ascii")}
        else:
            node["value"] = self.read_scalar(dtype, lane)
        return node

    def read_scalar(self, dtype: int, lane: "Lanes") -> Any:
        """Read a scalar KV3 value from the given value lane."""
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
        if dtype == INT32:
            if lane._i4 + 4 > len(lane.b4):
                raise KV3Error("truncated int32 lane")
            v = struct.unpack_from("<i", lane.b4, lane._i4)[0]
            lane.take4()
            return v
        if dtype == UINT32:
            if lane._i4 + 4 > len(lane.b4):
                raise KV3Error("truncated uint32 lane")
            v = struct.unpack_from("<I", lane.b4, lane._i4)[0]
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
            if lane._i4 + 4 > len(lane.b4):
                raise KV3Error("truncated float lane")
            v = struct.unpack_from("<f", lane.b4, lane._i4)[0]
            lane.take4()
            return v
        if dtype == INT16:
            if lane._i2 + 2 > len(lane.b2):
                raise KV3Error("truncated int16 lane")
            v = struct.unpack_from("<h", lane.b2, lane._i2)[0]
            lane.take2()
            return v
        if dtype == UINT16:
            if lane._i2 + 2 > len(lane.b2):
                raise KV3Error("truncated uint16 lane")
            v = struct.unpack_from("<H", lane.b2, lane._i2)[0]
            lane.take2()
            return v
        if dtype == INT8:
            if lane._i1 >= len(lane.b1):
                raise KV3Error("truncated int8 lane")
            v = struct.unpack_from("<b", lane.b1, lane._i1)[0]
            lane.take1()
            return v
        if dtype == UINT8:
            return lane.take1()
        if dtype == UINT32_ZERO:
            return 0
        if dtype == UINT32_ONE:
            return 1
        raise KV3Error(f"unknown KV3 node type {dtype}")


def legacy_text(text: str | None) -> str:
    """Coerce a string to a legacy UTF-8-safe representation."""
    if text is None:
        return ""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return text


def to_plain(node: dict[str, Any]) -> Any:
    """Convert a typed KV3 node tree into plain Python values."""
    dtype = node["type"]
    value: Any = node.get("value")
    if dtype == "OBJECT":
        keys = [legacy_text(entry["key"]) for entry in value]
        if len(keys) != len(set(keys)):
            msg = "WARNING: duplicate object keys dropped in --plain mode"
            print(msg, file=sys.stderr)
        return {legacy_text(entry["key"]): to_plain(entry["value"]) for entry in value}
    if dtype == "BINARY_BLOB":
        return base64.b64decode(value["bytes_base64"])
    if dtype == "STRING":
        return legacy_text(value)
    if dtype.startswith("ARRAY"):
        return [to_plain(item) for item in value]
    return value


def header_document(kv3: BinaryKV3) -> dict[str, Any]:
    """Build the JSON header section for a decoded KV3 document."""
    return {
        "magic": f"0x{kv3.magic:08X}",
        "version": kv3.version,
        "guid": kv3.guid,
        "compression": kv3.compression,
        "dictionary_id": kv3.dictionary_id,
        "frame_size": kv3.frame_size,
        "count_bytes1": kv3.count_bytes1,
        "count_bytes2": kv3.count_bytes2,
        "count_bytes4": kv3.count_bytes4,
        "count_bytes8": kv3.count_bytes8,
        "count_types": kv3.count_types,
        "count_objects": kv3.count_objects,
        "count_arrays": kv3.count_arrays,
        "size_uncompressed_total": kv3.size_uncompressed_total,
        "size_compressed_total": kv3.size_compressed_total,
        "count_blocks": kv3.count_blocks,
        "size_binary_blobs": kv3.size_binary_blobs,
        "size_block_compressed_sizes": kv3.size_block_compressed_sizes,
        "size_uncompressed_buffer1": kv3.size_uncompressed_buffer1,
        "size_compressed_buffer1": kv3.size_compressed_buffer1,
        "size_uncompressed_buffer2": kv3.size_uncompressed_buffer2,
        "size_compressed_buffer2": kv3.size_compressed_buffer2,
        "count_bytes1_buffer2": kv3.count_bytes1_buffer2,
        "count_bytes2_buffer2": kv3.count_bytes2_buffer2,
        "count_bytes4_buffer2": kv3.count_bytes4_buffer2,
        "count_bytes8_buffer2": kv3.count_bytes8_buffer2,
        "count_nodes": kv3.count_nodes,
        "count_objects_buffer2": kv3.count_objects_buffer2,
        "count_arrays_buffer2": kv3.count_arrays_buffer2,
        "count_array_elements": kv3.count_array_elements,
        "data_offset": kv3.data_offset,
    }


def payload_document(kv3: BinaryKV3) -> dict[str, Any]:
    """Build the JSON payload metadata section for a decoded KV3 document."""
    return {
        "string_count": len(kv3.strings),
        "blob_lengths": kv3.declared_blob_lengths,
        "blob_frame_sizes": kv3.declared_block_sizes,
    }


def lane_usage(lanes: Lanes) -> dict[str, int]:
    """Report remaining unconsumed bytes across all lanes."""
    return {
        "b1": lanes.remaining1,
        "b2": lanes.remaining2,
        "b4": lanes.remaining4,
        "b8": lanes.remaining8,
    }


def completeness(kv3: BinaryKV3) -> dict[str, Any]:
    """Build the completeness/accounting section for a decoded KV3 document."""
    return {
        "file_size": len(kv3.data),
        "header_bytes": kv3.data_offset,
        "buffer1": {
            "declared_compressed": kv3.size_compressed_buffer1,
            "consumed_compressed": kv3.buffer1_consumed,
            "declared_uncompressed": kv3.size_uncompressed_buffer1,
            "trailing_bytes": kv3.buffer1_trailing,
        },
        "buffer2": {
            "declared_compressed": kv3.size_compressed_buffer2,
            "consumed_compressed": kv3.buffer2_consumed,
            "declared_uncompressed": kv3.size_uncompressed_buffer2,
            "trailing_bytes": kv3.buffer2_trailing,
        },
        "string_table": {
            "declared": kv3.string_count_declared,
            "parsed": len(kv3.strings),
            "buffer_bytes": kv3.string_bytes,
            "used_bytes": kv3.string_bytes_used,
        },
        "blob_frames": {
            "declared": len(kv3.declared_block_sizes),
            "consumed": kv3.blob_frames_used,
        },
        "blob_bytes": kv3.blob_data_end - kv3.blob_data_offset,
        "trailer": {
            "offset": kv3.trailer_offset,
            "bytes_hex": kv3.trailer.hex(),
            "matches_marker": len(kv3.trailer) == 4
            and struct.unpack("<I", kv3.trailer)[0] == 0xFFEEDD00,
        },
        "trailing_bytes": len(kv3.data) - kv3.trailer_offset - len(kv3.trailer),
        "unconsumed": {
            "type_bytes": len(kv3.types),
            "object_lengths": len(kv3.object_lengths),
            "blob_lengths": len(kv3.blob_lengths),
            "blob_bytes": len(kv3.blobs),
            "main_lanes": lane_usage(kv3.main),
            "aux_lanes": lane_usage(kv3.aux),
        },
    }


def document(kv3: BinaryKV3, tree: dict[str, Any]) -> dict[str, Any]:
    """Assemble the full JSON document for a decoded KV3 file."""
    return {
        "schema_version": 1,
        "header": header_document(kv3),
        "payload": payload_document(kv3),
        "strings": kv3.strings,
        "tree": tree,
        "completeness": completeness(kv3),
    }


def decode(path: str) -> BinaryKV3:
    """Decode a binary KV3 file from disk."""
    p = pathlib.Path(path)
    if not p.exists():
        raise KV3Error(f"file not found: {path}")
    if not p.is_file():
        raise KV3Error(f"not a file: {path}")
    if p.stat().st_size > _MAX_INPUT_BYTES:
        raise KV3Error("input file too large")
    data = p.read_bytes()
    if len(data) > _MAX_INPUT_BYTES:
        raise KV3Error("input too large")
    if not data:
        raise KV3Error("empty input")
    kv3 = BinaryKV3(data)
    try:
        kv3.read_header()
        kv3.read_payload()
    except struct.error as e:
        raise KV3Error(f"truncated KV3 file: {e}")
    return kv3


decode_kv3 = decode


def load_items() -> dict[int, dict[str, Any]]:
    """Load the item reference table from data/items_raw.json."""
    path = pathlib.Path(__file__).resolve().parent / "data" / "items_raw.json"
    if not path.exists():
        return {}
    return {i["id"]: i for i in json.loads(path.read_text(encoding="utf-8"))}


def build_summary(kv3: BinaryKV3, tree: dict[str, Any]) -> dict[str, Any]:
    """Summarise the saved hero builds stored in the client's build cache."""
    import pathlib as _pathlib

    sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
    import decode_build_code as D

    items = load_items()

    def resolve(item_id: int) -> dict[str, Any] | None:
        """Resolve an item id to its name, class, and type."""
        item = items.get(item_id)
        if not item:
            return None
        return {
            "name": item.get("name"),
            "class_name": item.get("class_name"),
            "type": item.get("type"),
        }

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
                    "optional": any(
                        f == 6 and not isinstance(v, tuple) for f, w, v in cat
                    ),
                    "height": next(
                        (v for f, w, v in cat if f == 4 and not isinstance(v, tuple)),
                        None,
                    ),
                    "width": next(
                        (v for f, w, v in cat if f == 5 and not isinstance(v, tuple)),
                        None,
                    ),
                    "mods": mods,
                    "mod_names": [resolve(m) for m in mods],
                }
                cats.append(entry)
                slot = categories.setdefault(
                    name or "", {"count": 0, "description": entry["description"]}
                )
                slot["count"] += 1
            changes = []
            for order in D.get_msgs(det, 2):
                for cc in D.get_msgs(order, 1):
                    delta = D.get_int(cc, 3)
                    if delta is not None and delta >= (1 << 63):
                        delta -= 1 << 64
                    ctype = D.get_int(cc, 2)
                    changes.append(
                        {
                            "ability_id": D.get_int(cc, 1),
                            "currency_type": ctype,
                            "delta": delta,
                        }
                    )
                    key2 = f"{ctype}/{delta}"
                    ladder[key2] = ladder.get(key2, 0) + 1
            builds.append(
                {
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
                }
            )
    return {
        "kv3": {
            "magic": f"0x{kv3.magic:08X}",
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


def self_test(kv3: BinaryKV3, tree: dict[str, Any]) -> None:
    """Check the decoder against the structure of the client's build cache."""
    summary = build_summary(kv3, tree)
    assert kv3.version == 5, "not KV3 v5"
    assert kv3.compression == 1, "not LZ4 compressed"
    assert list(tree) == [
        "LastUsedBuilds",
        "Favorites",
        "Unpublished",
        "SavedLastUsed",
    ], list(tree)
    # the client rewrites this file whenever a build is saved, so the counts move:
    # check the shape of the file, not the size of the player's library
    for key in ("Favorites", "Unpublished", "SavedLastUsed"):
        assert len(tree[key]) >= 1, key
    assert len(summary["builds"]) == sum(
        len(tree[k]) for k in ("Favorites", "Unpublished", "SavedLastUsed")
    )
    tokens = {
        n for n in summary["category_names"] if n.startswith("#Citadel_HeroBuilds")
    }
    assert tokens == {
        "#Citadel_HeroBuilds_Early",
        "#Citadel_HeroBuilds_EarlyGame",
        "#Citadel_HeroBuilds_Lane",
        "#Citadel_HeroBuilds_Late",
        "#Citadel_HeroBuilds_LateGame",
        "#Citadel_HeroBuilds_Mid",
        "#Citadel_HeroBuilds_MidGame",
    }, tokens
    assert set(summary["currency_delta_counts"]) == {"1/-1", "1/-2", "1/-5", "2/-1"}, (
        summary["currency_delta_counts"]
    )
    print("SELF_TEST_OK")


def main() -> None:
    """Command-line entry point for decoding KV3 files."""
    ap = argparse.ArgumentParser(description="Decode binary KeyValues3 into JSON")
    ap.add_argument("path", nargs="?")
    ap.add_argument("--out")
    ap.add_argument(
        "--plain",
        action="store_true",
        help="legacy compact tree without types, flags or header",
    )
    ap.add_argument("--strings-only", action="store_true")
    ap.add_argument("--blobs", help="write the binary blobs to this directory")
    ap.add_argument(
        "--builds", action="store_true", help="summarise the saved hero builds"
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="check the decoder against the build cache",
    )
    args = ap.parse_args()
    if args.plain and args.builds:
        ap.error("--plain and --builds are mutually exclusive")
    if args.strings_only and args.blobs:
        ap.error("--strings-only and --blobs are mutually exclusive")
    if args.blobs and (args.plain or args.builds):
        ap.error("--blobs is mutually exclusive with --plain/--builds")
    if args.self_test and not args.path:
        args.path = str(
            pathlib.Path(__file__).resolve().parent
            / "data"
            / "cached_hero_builds.kv3"
        )
    if not args.path:
        ap.error("a path is required")
    kv3 = decode(args.path)
    if args.self_test:
        self_test(kv3, to_plain(kv3.read_tree()))
        return
    if args.strings_only:
        reconfigure = getattr(sys.stdout, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
        text = "\n".join(f"{i}\t{s}" for i, s in enumerate(kv3.strings))
        if len(text) > _MAX_OUTPUT_BYTES:
            raise KV3Error("output too large")
        if args.out:
            p = pathlib.Path(args.out)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return
    if args.blobs:
        target = pathlib.Path(args.blobs)
        target.mkdir(parents=True, exist_ok=True)
        for index, length in enumerate(kv3.declared_blob_lengths):
            data = bytes(kv3.blobs[:length])
            del kv3.blobs[:length]
            (target / f"blob_{index:02d}.bin").write_bytes(data)
        print(f"{len(kv3.declared_blob_lengths)} blobs written to {target}")
        return
    tree = kv3.read_tree()
    if args.builds:
        text = json.dumps(
            build_summary(kv3, to_plain(tree)), indent=2, ensure_ascii=False
        )
    elif args.plain:
        text = json.dumps(
            to_plain(tree),
            indent=2,
            ensure_ascii=False,
            default=lambda b: {"bytes_base64": base64.b64encode(b).decode()},
        )
    else:
        text = json.dumps(document(kv3, tree), indent=2, ensure_ascii=True)
    if len(text) > _MAX_OUTPUT_BYTES:
        raise KV3Error("output too large")
    if args.out:
        p = pathlib.Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text + "\n", encoding="utf-8")
    else:
        reconfigure = getattr(sys.stdout, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
        print(text)


if __name__ == "__main__":
    try:
        main()
    except KV3Error as exc:
        print(f"KV3_ERROR {exc}", file=sys.stderr)
        sys.exit(1)
    except struct.error as exc:
        print(f"KV3_ERROR {exc}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, RuntimeError, TypeError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
