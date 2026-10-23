import base64, struct, sys, json, zlib, os

def read_varint(data, i):
    res = 0; shift = 0
    while i < len(data):
        byte = data[i]; i += 1
        res |= (byte & 0x7f) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return res, i

def parse_message(data):
    """Parse protobuf bytes into list of (field_number, wire_type, value)."""
    out = []
    i = 0; n = len(data)
    while i < n:
        tag, i = read_varint(data, i)
        if tag == 0:
            break
        field = tag >> 3
        wire = tag & 7
        if wire == 0:
            val, i = read_varint(data, i)
            out.append((field, wire, val))
        elif wire == 1:
            val = struct.unpack('<d', data[i:i+8])[0]; i += 8
            out.append((field, wire, val))
        elif wire == 5:
            val = struct.unpack('<f', data[i:i+4])[0]; i += 4
            out.append((field, wire, val))
        elif wire == 2:
            length, i = read_varint(data, i)
            chunk = data[i:i+length]; i += length
            # try string
            try:
                s = chunk.decode('utf-8')
                if all(c.isprintable() or c in '\n\r\t' for c in s):
                    out.append((field, wire, ('str', s)))
                    continue
            except Exception:
                pass
            # try nested message (recurse if it parses cleanly)
            try:
                nested = parse_message(chunk)
                # heuristic: if consumed fully and at least one field, treat as message
                out.append((field, wire, ('msg', nested, chunk)))
            except Exception:
                out.append((field, wire, ('bytes', chunk)))
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

def _ability_heroes():
    """Map ability id -> hero id from items_raw.json (cached)."""
    global _ABILITY_HERO_CACHE
    if _ABILITY_HERO_CACHE is not None:
        return _ABILITY_HERO_CACHE
    _ABILITY_HERO_CACHE = {}
    try:
        root = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(root, 'items_raw.json'), encoding='utf-8') as f:
            for it in json.load(f):
                if it.get('type') == 'ability':
                    for h in (it.get('heroes') or []):
                        _ABILITY_HERO_CACHE[it['id']] = h
    except Exception:
        pass
    return _ABILITY_HERO_CACHE

_ABILITY_HERO_CACHE = None


def decode_build_code(code):
    code = ''.join(code.split())
    # try standard then url-safe
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
    # zstd?
    if raw[:4] == b'\x28\xb5\x2f\xfd':
        try:
            import zstandard
            raw = zstandard.ZstdDecompressor().decompress(raw)
        except Exception as e:
            # maybe zstandard not installed; try zstd cli? skip
            raise ValueError('zstd decompress failed: %s' % e)
    top = parse_message(raw)
    hero_id = get_int(top, 1)
    # Resolve the real hero id. Three cases:
    #  1. Default Valve builds store 1000 + hero in field 1 (e.g. 1001 = Infernus).
    #  2. Some builds (default copies, kv3-derived) store a non-hero index in
    #     field 1; the hero is recoverable from the ability ids in ability_order.
    #  3. Normal builds store the hero directly in field 1.
    # ability_order is parsed later; do a first pass over the raw details.
    _ah = _ability_heroes()
    _ability_ids = []
    for f, w, v in top:
        if f == 10 and isinstance(v, tuple) and v[0] == 'msg':
            for f2, w2, v2 in v[1]:
                if f2 == 2 and isinstance(v2, tuple) and v2[0] == 'msg':
                    for cc in get_msgs(v2[1], 1):
                        aid = get_int(cc, 1)
                        if aid is not None:
                            _ability_ids.append(aid)
    _hero_from_abilities = None
    if _ability_ids:
        heroes = {_ah.get(aid) for aid in _ability_ids if aid in _ah}
        if len(heroes) == 1:
            _hero_from_abilities = next(iter(heroes))
    is_default_build = bool(hero_id is not None and hero_id >= 1000)
    if is_default_build:
        resolved_hero_id = hero_id - 1000
    elif _hero_from_abilities is not None:
        resolved_hero_id = _hero_from_abilities
    else:
        resolved_hero_id = hero_id
    version = get_int(top, 2)
    hero_build_id = get_int(top, 3)
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
    # details is field 10
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
            # also mods could be direct varints? handle repeated field 1 varints
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
        # ability_order: field 2 of details?
        for f, w, v in details:
            if f == 2 and isinstance(v, tuple) and v[0] == 'msg':
                ability_order = v[1]
    ability_changes = []
    if ability_order is not None:
        # currency_changes repeated field 1
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
    result = {
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
    return result

def main():
    if len(sys.argv) < 2:
        print('usage: decode_build_code.py <base64-code-or-file>', file=sys.stderr)
        sys.exit(1)
    arg = sys.argv[1]
    if arg == "-":
        code = sys.stdin.read()
    else:
        # if arg points to a file, read it
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

def _self_test():
    import base64
    raw = open('build.zst', 'rb').read()
    code = base64.b64encode(raw).decode()
    r = decode_build_code(code)
    assert r['hero_id'] == 6, r['hero_id']
    assert r['name'] == 'Copy of [second RAG build]'
    assert len(r['details']['mod_categories']) == 3
    # raw protobuf path
    raw2 = open('build.bin', 'rb').read()
    r2 = decode_build_code(base64.b64encode(raw2).decode())
    assert r2['hero_id'] == 6
    print('self-test OK')

if __name__ == '__main__':
    if '--self-test' in sys.argv:
        _self_test()
    else:
        main()
