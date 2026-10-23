import base64, sys, zstandard

def main():
    if len(sys.argv) < 2:
        print('usage: reencode_build_code.py <base64-code-or-file>', file=sys.stderr)
        sys.exit(1)
    arg = sys.argv[1]
    try:
        with open(arg, 'r', encoding='utf-8') as fh:
            code = fh.read()
    except OSError:
        code = arg
    code = ''.join(code.split())
    raw = None
    for alt in (None, '-_'):
        try:
            if alt is None:
                raw = base64.b64decode(code, validate=True)
            else:
                raw = base64.urlsafe_b64decode(code + '=' * (-len(code) % 4))
            break
        except Exception:
            raw = None
    if raw is None:
        raise ValueError('invalid base64')
    if raw[:4] == b'\x28\xb5/\xfd':
        raw = zstandard.ZstdDecompressor().decompress(raw)
    comp = zstandard.ZstdCompressor().compress(raw)
    print(base64.b64encode(comp).decode())

if __name__ == '__main__':
    main()
