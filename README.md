# Deadlock Build Codec

Standalone Ruby implementation of the Deadlock build-code encoder/decoder.

Extracted from [codec-site](https://github.com/gustavomgama/deadlock-build-codes-converter).

## Usage

```sh
bundle install
bundle exec ruby bin/deadlock-codec decode <CODE>
bundle exec ruby bin/deadlock-codec encode build.json
```

## Library

```ruby
require "deadlock_codec"
decoded = DeadlockCodec.decode(code)
encoded = DeadlockCodec.encode(hash)
```

## Dependencies

- Ruby >= 3.0
- zstd-ruby

## Python scripts

`sh
python encode_build_code.py build.json
python decode_build_code.py <CODE>
python reencode_build_code.py <CODE-or-file>
python validate_build.py <build.json-or-CODE>
python verify_build.py <build.json-or-CODE>
python build_from_json.py <build.json>
python decode_kv3.py <cached_hero_builds.kv3>
`
