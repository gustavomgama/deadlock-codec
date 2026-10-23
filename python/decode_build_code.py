import base64, json, struct, sys

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


def parse_message(data):
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
                append((field, wire, ('msg', parse_message(chunk))))
            except Exception:
                append((field, wire, ('bytes', chunk)))
        elif wire == 0:
            if i < n:
                value = data[i]
                if value < 0x80:
                    i += 1
                else:
                    value, i = read(data, i)
            else:
                value = 0
            append((field, wire, value))
        elif wire == 5:
            append((field, wire, struct.unpack('<f', data[i:i+4])[0]))
            i += 4
        elif wire == 1:
            append((field, wire, struct.unpack('<d', data[i:i+8])[0]))
            i += 8
        else:
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


def _decompress(raw):
    global _ZSTD_DECOMPRESSOR
    if _ZSTD_DECOMPRESSOR is None:
        import zstandard
        _ZSTD_DECOMPRESSOR = zstandard.ZstdDecompressor()
    return _ZSTD_DECOMPRESSOR.decompress(raw)


def decode_build_code(code):
    code = ''.join(code.split())
    try:
        raw = base64.b64decode(code, validate=True)
    except Exception:
        try:
            raw = base64.urlsafe_b64decode(code + '=' * (-len(code) % 4))
        except Exception:
            raw = None
    if raw is None:
        raise ValueError('invalid base64')
    if raw[:4] == _ZSTD_MAGIC:
        try:
            raw = _decompress(raw)
        except Exception as e:
            raise ValueError('zstd decompress failed: %s' % e)
    top = parse_message(raw)
    hero_field = 1
    nested = get_msgs(top, 1)
    if get_int(top, 1) is None and nested:
        top = nested[0]
        hero_field = 2
    hero_id = get_int(top, hero_field)
    is_default_build = bool(hero_id is not None and hero_id >= _DEFAULT_BUILD_HERO_OFFSET)
    if is_default_build:
        resolved_hero_id = hero_id - _DEFAULT_BUILD_HERO_OFFSET
    else:
        resolved_hero_id = hero_id
    version = get_int(top, 2)
    hero_build_id = get_int(top, 3)
    if hero_field == 2:
        hero_build_id = get_int(top, 1)
    author_account_id = get_int(top, 4)
    name = get_str(top, 5)
    description = get_str(top, 6)
    language = get_int(top, 7)
    origin_build_id = get_int(top, 8)
    field_9 = get_int(top, 9)
    field_13 = get_int(top, 13)
    tags = []
    for f, w, v in top:
        if f == 11 and not isinstance(v, tuple):
            tags.append(v)
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
            raw_delta = get_int(cc, 3)
            if raw_delta is not None and raw_delta >= (1 << 63):
                raw_delta -= (1 << 64)
            ability_changes.append({
                'ability_id': get_int(cc, 1),
                'currency_type': get_int(cc, 2),
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
        'details': {
            'mod_categories': mod_categories,
            'ability_order': {'currency_changes': ability_changes} if ability_changes else None,
        },
    }


def main():
    if len(sys.argv) < 2:
        print('usage: decode_build_code.py <base64-code-or-file>', file=sys.stderr)
        sys.exit(1)
    arg = sys.argv[1]
    if arg == "-":
        code = sys.stdin.read()
    else:
        try:
            with open(arg, 'r', encoding='utf-8') as fh:
                code = fh.read()
        except UnicodeDecodeError:
            try:
                with open(arg, 'r', encoding='utf-16') as fh:
                    code = fh.read()
            except OSError:
                code = arg
        except OSError:
            code = arg
    try:
        res = decode_build_code(code)
        print(json.dumps(res, indent=2))
    except Exception as e:
        print('ERROR: %s' % e, file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
