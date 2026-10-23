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

```sh
python python/encode_build_code.py build.json
python python/decode_build_code.py <CODE>
python python/reencode_build_code.py <CODE-or-file>
python python/validate_build.py <build.json-or-CODE>
python python/verify_build.py <build.json-or-CODE>
python python/build_from_json.py <build.json>
python python/decode_kv3.py <cached_hero_builds.kv3>
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
