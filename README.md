# Deadlock Build Codec

Standalone Ruby implementation of the Deadlock build-code encoder/decoder.

Extracted from [codec-site](https://github.com/gustavomgama/deadlock-build-codes-converter).

## Usage

```sh
cd ruby
bundle install
bundle exec ruby bin/deadlock-codec decode <CODE>
bundle exec ruby bin/deadlock-codec encode ../build.json
```

## Library

```sh
cd ruby
ruby -Ilib -rdeadlock_codec -e 'puts DeadlockCodec.decode(ARGV[0]).inspect' <CODE>
```

```ruby
require "deadlock_codec"
decoded = DeadlockCodec.decode(code)
encoded = DeadlockCodec.encode(hash)
```

## Dependencies

- Ruby >= 3.0
- zstd-ruby

## Python scripts

Python 3.9+. `decode_build_code.py` imports `zstandard` only for zstd-compressed
codes (`pip install zstandard`). Commands below run from the repository root.

### decode_build_code.py

Decodes a base64 build code (standard or URL-safe, optionally zstd-compressed)
into JSON.

```sh
python python/decode_build_code.py <CODE>
python python/decode_build_code.py data/examplecodefromgame.md
Get-Content data/examplecodefromgame.md -Raw | python python/decode_build_code.py -
```

Output (abridged):

```json
{
  "hero_id": 1034,
  "hero": 34,
  "is_default_build": true,
  "version": 77,
  "name": "Copy of [Default Apollo Build]",
  "description": "#Citadel_HeroBuilds_DefaultHeroBuildDesc",
  "tags": [1150155374, 147493976, 36498494],
  "details": {"mod_categories": ["..."], "ability_order": {"currency_changes": ["..."]}}
}
```

`hero_id` is the raw field 1 value and `hero` the resolved hero id, because
Valve default builds store `1000 + hero` (`is_default_build`). Invalid input
prints `ERROR: ...` to stderr and exits 1.

Add `--raw` for the lossless protobuf dump instead of the interpreted build:

```sh
python python/decode_build_code.py data/examplecodefromgame.md --raw
```

```json
{
  "input": {"base64": "...", "base64_chars": 544, "stored_bytes": 406, "zstd": true,
            "decoded_bytes": 759, "payload_base64": "..."},
  "tree": [
    {"field": 1, "wire": 0, "wire_type": "varint", "value": 1034}
  ]
}
```

Abridged: every field follows in wire order with its number, wire type and
value — varint/fixed32/fixed64 raw, length-delimited chunks as `text`, nested
`message`, or `bytes_base64`. The cached `.kv3` blobs decode in the same mode.

`--out FILE` writes the JSON to a file, `--self-test` checks the decoder
against `data/examplecodefromgame.md`, and the output carries `layout`
(`shared` or `cached`) plus an `issues` list for malformed input.

### decode_kv3.py

Decodes the client's binary KeyValues3 v5 build cache (LZ4) into JSON. The
client writes it to
`%LOCALAPPDATA%/../Steam/userdata/<id>/1422450/remote/cfg/cached_hero_builds.kv3`;
a copy is committed at `data/cached_hero_builds.kv3`.

```sh
python python/decode_kv3.py data/cached_hero_builds.kv3
python python/decode_kv3.py data/cached_hero_builds.kv3 --out cached.json
python python/decode_kv3.py data/cached_hero_builds.kv3 --builds
python python/decode_kv3.py data/cached_hero_builds.kv3 --self-test
```

| Flag | Output |
| --- | --- |
| *(none)* | Lossless document: `header`, `payload`, `strings`, typed `tree`, `completeness` |
| `--plain` | Old compact tree of plain values (no types, flags or header) |
| `--builds` | Summary of the saved hero builds, decoded through `decode_build_code.py` |
| `--strings-only` | The string table, one `id<TAB>string` per line |
| `--self-test` | Asserts the file shape and prints `SELF_TEST_OK` |
| `--blobs DIR` | Writes the binary blobs as `blob_NN.bin` |
| `--out FILE` | Write to a file instead of stdout |

The default document keeps every node's KV3 type, flags, duplicate object keys
and string ids, and its `completeness` block accounts for every byte: header,
both compressed buffers, string table, blob frames, the trailing `0xFFEEDD00`
marker, plus anything left unconsumed. `--plain` output is byte-identical to
the previous decoder, and `--builds`/`--self-test` run on top of it.

### Other scripts

```sh
python python/encode_build_code.py build.json
python python/reencode_build_code.py <CODE-or-file>
python python/validate_build.py <build.json-or-CODE>
python python/verify_build.py <build.json-or-CODE>
python python/build_from_json.py <build.json>
```

Legacy one-off debug scripts are in `python/legacy/`.

## Example

A real in-game build code is included at `data/examplecodefromgame.md` (Apollo, "Copy of [Default Apollo Build]").

```sh
# bash
python python/decode_build_code.py "$(cat data/examplecodefromgame.md)"
# PowerShell
python python/decode_build_code.py (Get-Content data/examplecodefromgame.md)
```
