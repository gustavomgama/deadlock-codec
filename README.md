# deadlock-codec

Decode and encode Deadlock build codes, and decode the client's binary KeyValues3 build cache.

## Requirements

- Python 3.x
- `zstandard>=0.25.0`

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Decode a build code:

```bash
python decode_build_code.py <code>
```

Lossless protobuf dump:

```bash
python decode_build_code.py <code> --raw
```

Encode a build JSON:

```bash
python encode_build_code.py build.json
```

Decode a binary KV3 file:

```bash
python decode_kv3.py file.kv3
```

Summarise saved hero builds:

```bash
python decode_kv3.py file.kv3 --builds
```

## Self-tests

```bash
python decode_build_code.py --self-test
python decode_kv3.py --self-test
python encode_build_code.py --self-test
```

## Verification

```bash
python -m ruff check --select E,F,I .
npx --yes pyright decode_build_code.py decode_kv3.py encode_build_code.py
```
