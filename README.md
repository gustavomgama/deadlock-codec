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
