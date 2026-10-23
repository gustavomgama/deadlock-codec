import json
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import validate_build
import encode_build_code


def main():
    if len(sys.argv) < 2:
        print("usage: build_from_json.py <file.json>", file=sys.stderr)
        sys.exit(1)
    p = pathlib.Path(sys.argv[1])
    obj = json.loads(p.read_text(encoding="utf-8"))
    errors, warnings = validate_build.validate(obj)
    for w in warnings:
        print(f"WARN: {w}", file=sys.stderr)
    for e in errors:
        print(f"ERROR: {e}", file=sys.stderr)
    if errors:
        sys.exit(1)
    code = encode_build_code.encode_build(obj)
    # verify round-trip
    import decode_build_code
    dec = decode_build_code.decode_build_code(code)
    if dec.get("hero_id") != obj.get("hero_id"):
        print("ERROR: round-trip mismatch", file=sys.stderr)
        sys.exit(1)
    print(code)
    sys.exit(0)


if __name__ == "__main__":
    main()
