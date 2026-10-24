import base64, json, struct, sys
import argparse
import io
import pathlib

_ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'
_ZSTD_DECOMPRESSOR = None
_DEFAULT_BUILD_HERO_OFFSET = 1000


def read_varint(data, i):
    res = 0; shift = 0
    n = len(data)
    while i < n:
        byte = data[i]; i += 1
        res |= (byte & 0x7f) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return res, i


def parse_message(data, issues=None):
    """Parse protobuf bytes into list of (field_number, wire_type, value)."""
    out = []
    append = out.append
    read = read_varint
    i = 0
    n = len(data)
    while i < n:
        tag = data[i]
        if tag < 0x80:
            i += 1
        else:
            tag, i = read(data, i)
        if tag == 0:
            if issues is not None:
                issues.append({"offset": i - 1, "reason": "zero tag"})
            break
        field = tag >> 3
        wire = tag & 7
        if wire == 2:
            if i < n:
                length = data[i]
                if length < 0x80:
                    i += 1
                else:
                    length, i = read(data, i)
            else:
                length = 0
                if issues is not None:
                    issues.append({"offset": i, "reason": "truncated length"})
            end = i + length
            chunk = data[i:end]
            i = end
            try:
                text = chunk.decode('utf-8')
            except UnicodeDecodeError:
                text = None
            if text is not None and (text.isprintable() or not text
                                     or text.replace('\n', '').replace('\r', '').replace('\t', '').isprintable()):
                append((field, wire, ('str', text)))
                continue
            try:
                nested = parse_message(chunk, issues)
            except Exception:
                nested = None
            if nested is None or (chunk and not nested):
                append((field, wire, ('bytes', chunk)))
            else:
                append((field, wire, ('msg', nested)))
        elif wire == 0:
            if i < n:
                value = data[i]
                if value < 0x80:
                    i += 1
                else:
                    value, i = read(data, i)
            else:
                value = 0
                if issues is not None:
                    issues.append({"offset": i, "reason": "truncated varint"})
            append((field, wire, value))
        elif wire == 5:
            append((field, wire, struct.unpack('<f', data[i:i+4])[0]))
            i += 4
        elif wire == 1:
            append((field, wire, struct.unpack('<d', data[i:i+8])[0]))
            i += 8
        else:
            if issues is not None:
                issues.append({"offset": i - 1, "reason": "unsupported wire type %d" % wire})
            break
    return out


def get_str(fields, num):
    for f, w, v in fields:
        if f == num and isinstance(v, tuple) and v[0] == 'str':
            return v[1]
    return None


def get_int(fields, num):
    for f, w, v in fields:
        if f == num and not isinstance(v, tuple):
            return v
    return None


def get_float(fields, num):
    for f, w, v in fields:
        if f == num and isinstance(v, float):
            return v
    return None


def get_msgs(fields, num):
    res = []
    for f, w, v in fields:
        if f == num and isinstance(v, tuple) and v[0] == 'msg':
            res.append(v[1])
    return res


def _signed(value):
    if isinstance(value, int) and value >= (1 << 63):
        return value - (1 << 64)
    return value


_WIRE_NAMES = {0: "varint", 1: "fixed64", 2: "bytes", 5: "fixed32"}


def _raw_fields(fields):
    out = []
    for field, wire, value in fields:
        node = {"field": field, "wire": wire, "wire_type": _WIRE_NAMES.get(wire, str(wire))}
        if isinstance(value, tuple):
            kind, payload = value
            node["length"] = len(payload)
            if kind == "str":
                node["text"] = payload
            elif kind == "msg":
                node["message"] = _raw_fields(payload)
            else:
                node["bytes_base64"] = base64.b64encode(payload).decode("ascii")
        else:
            node["value"] = value
        out.append(node)
    return out


def _decompress(raw):
    global _ZSTD_DECOMPRESSOR
    if _ZSTD_DECOMPRESSOR is None:
        import zstandard
        _ZSTD_DECOMPRESSOR = zstandard.ZstdDecompressor()
    try:
        return _ZSTD_DECOMPRESSOR.decompress(raw)
    except Exception:
        with _ZSTD_DECOMPRESSOR.stream_reader(io.BytesIO(raw)) as reader:
            return reader.read()


def _payload(code):
    code = ''.join(code.split())
    try:
        raw = base64.b64decode(code, validate=True)
    except Exception:
        try:
            raw = base64.b64decode(code + '=' * (-len(code) % 4), altchars=b'-_', validate=True)
        except Exception:
            raw = None
    if not raw:
        raise ValueError('invalid base64')
    compressed = raw[:4] == _ZSTD_MAGIC
    stored = len(raw)
    if compressed:
        try:
            raw = _decompress(raw)
        except Exception as e:
            raise ValueError('zstd decompress failed: %s' % e)
    return raw, compressed, stored


def _field_map(fields):
    out = {}
    for field, wire, value in fields:
        key = str(field)
        if isinstance(value, tuple):
            kind, payload = value
            if kind == 'msg':
                item = {'message': _field_map(payload)}
            elif kind == 'str':
                item = payload
            else:
                item = {'bytes_base64': base64.b64encode(payload).decode('ascii')}
        else:
            item = value
        out.setdefault(key, []).append(item)
    return out


def _cached_candidate(message):
    hero = get_int(message, 2)
    return hero is not None and 0 < hero < _DEFAULT_BUILD_HERO_OFFSET


def decode_build_code(code, layout='auto'):
    raw, _, _ = _payload(code)
    issues = []
    top = parse_message(raw, issues)
    hero_field = 1
    nested = get_msgs(top, 1)
    if layout == 'auto':
        layout = 'cached' if (get_int(top, 1) is None and nested and _cached_candidate(nested[0])) else 'shared'
    if layout == 'cached':
        if not nested:
            raise ValueError('cached layout needs a wrapper message in field 1')
        top = nested[0]
        hero_field = 2
    hero_id = _signed(get_int(top, hero_field))
    is_default_build = bool(hero_id is not None and hero_id >= _DEFAULT_BUILD_HERO_OFFSET)
    if is_default_build:
        resolved_hero_id = hero_id - _DEFAULT_BUILD_HERO_OFFSET
    else:
        resolved_hero_id = hero_id
    version = _signed(get_int(top, 2))
    hero_build_id = _signed(get_int(top, 3))
    if hero_field == 2:
        hero_build_id = _signed(get_int(top, 1))
    author_account_id = _signed(get_int(top, 4))
    name = get_str(top, 5)
    description = get_str(top, 6)
    language = _signed(get_int(top, 7))
    origin_build_id = _signed(get_int(top, 8))
    field_9 = _signed(get_int(top, 9))
    field_13 = _signed(get_int(top, 13))
    tags = []
    for f, w, v in top:
        if f == 11 and not isinstance(v, tuple):
            tags.append(_signed(v))
        elif f == 11 and isinstance(v, tuple) and v[0] == 'bytes':
            tags.extend(_signed(n) for n in _packed_varints(v[1]))
    if layout == 'cached':
        version = author_account_id = language = origin_build_id = field_9 = field_13 = None
    details = None
    for f, w, v in top:
        if f == 10 and isinstance(v, tuple) and v[0] == 'msg':
            details = v[1]; break
    mod_categories = []
    ability_order = None
    if details is not None:
        for cat_msg in get_msgs(details, 1):
            mods = []
            for m in get_msgs(cat_msg, 1):
                aid = get_int(m, 1)
                if aid is not None:
                    mods.append(aid)
            for f, w, v in cat_msg:
                if f == 1 and not isinstance(v, tuple):
                    mods.append(v)
            cat = {
                'name': get_str(cat_msg, 2),
                'description': get_str(cat_msg, 3),
                'height': get_float(cat_msg, 4),
                'width': get_float(cat_msg, 5),
                'mods': mods,
            }
            if any(f == 6 and not isinstance(v, tuple) and v for f, w, v in cat_msg):
                cat['optional'] = True
            mod_categories.append(cat)
        for f, w, v in details:
            if f == 2 and isinstance(v, tuple) and v[0] == 'msg':
                ability_order = v[1]
    ability_changes = []
    if ability_order is not None:
        for cc in get_msgs(ability_order, 1):
            raw_delta = _signed(get_int(cc, 3))
            ability_changes.append({
                'ability_id': _signed(get_int(cc, 1)),
                'currency_type': _signed(get_int(cc, 2)),
                'delta': raw_delta,
                'annotation': get_str(cc, 4),
            })
    return {
        'hero_id': hero_id,
        'hero': resolved_hero_id,
        'is_default_build': is_default_build,
        'version': version,
        'hero_build_id': hero_build_id,
        'author_account_id': author_account_id,
        'name': name,
        'description': description,
        'language': language,
        'origin_build_id': origin_build_id,
        'field_9': field_9,
        'tags': tags,
        'field_13': field_13,
        'issues': issues,
        'layout': layout,
        'details': {
            'mod_categories': mod_categories,
            'ability_order': {'currency_changes': ability_changes} if ability_changes else None,
        },
    }


def raw_document(code):
    raw, compressed, stored = _payload(code)
    issues = []
    fields = parse_message(raw, issues)
    return {
        'input': {
            'base64': ''.join(code.split()),
            'base64_chars': len(''.join(code.split())),
            'stored_bytes': stored,
            'zstd': compressed,
            'decoded_bytes': len(raw),
            'payload_base64': base64.b64encode(raw).decode('ascii'),
        },
        'issues': issues,
        'tree': _raw_fields(fields),
    }


def _packed_varints(data):
    out = []
    i = 0
    while i < len(data):
        value, i = read_varint(data, i)
        out.append(value)
    return out


def read_input(arg):
    if arg == '-':
        return sys.stdin.read()
    try:
        with open(arg, 'r', encoding='utf-8') as fh:
            return fh.read()
    except UnicodeDecodeError:
        try:
            with open(arg, 'r', encoding='utf-16') as fh:
                return fh.read()
        except OSError:
            return arg
    except OSError:
        return arg


def self_test():
    example = pathlib.Path(__file__).resolve().parent.parent / 'data' / 'examplecodefromgame.md'
    if not example.exists():
        raise SystemExit('self-test needs %s' % example)
    code = read_input(str(example))
    shared = decode_build_code(code)
    assert shared['hero_id'] == 1034, shared['hero_id']
    assert shared['hero'] == 34, shared['hero']
    assert shared['is_default_build'] is True
    assert shared['layout'] == 'shared', shared['layout']
    assert not shared['issues'], shared['issues']
    assert len(shared['details']['mod_categories']) == 3, shared['details']
    assert raw_document(code)['input']['zstd'] is True
    try:
        decode_build_code('!!!')
    except ValueError:
        pass
    else:
        raise AssertionError('invalid base64 accepted')
    print('SELF_TEST_OK')


def main():
    ap = argparse.ArgumentParser(description='Decode a Deadlock build code into JSON')
    ap.add_argument('code', nargs='?', help="base64 code, '-' for stdin, or a path to a file containing it")
    ap.add_argument('--raw', action='store_true', help='lossless protobuf dump')
    ap.add_argument('--out', help='write JSON to this file instead of stdout')
    ap.add_argument('--self-test', action='store_true', help='check the decoder against the sample code')
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.code:
        ap.error('a build code, file path or - is required')
    try:
        code = read_input(args.code)
        doc = raw_document(code) if args.raw else decode_build_code(code)
        text = json.dumps(doc, indent=2)
        if args.out:
            pathlib.Path(args.out).write_text(text, encoding='utf-8')
        else:
            print(text)
    except Exception as e:
        print('ERROR: %s' % e, file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
