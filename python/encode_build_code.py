import base64, json, struct, sys, zstandard

def encode_varint(value):
    v = int(value)
    if v < 0:
        v += (1 << 64)
    out = bytearray()
    while v > 0x7f:
        out.append((v & 0x7f) | 0x80)
        v >>= 7
    out.append(v & 0x7f)
    return bytes(out)

def encode_field(field, wire, value_bytes):
    return encode_varint((field << 3) | wire) + value_bytes

def encode_string(s):
    b = s.encode('utf-8')
    return encode_varint(len(b)) + b

def encode_mod(mid):
    return encode_field(1, 0, encode_varint(mid))

def encode_category(cat):
    parts = bytearray()
    for mid in (cat.get('mods') or []):
        mod_msg = encode_mod(mid)
        parts += encode_field(1, 2, encode_varint(len(mod_msg)) + mod_msg)
    if cat.get('name') is not None:
        parts += encode_field(2, 2, encode_string(cat['name']))
    if cat.get('description') is not None:
        parts += encode_field(3, 2, encode_string(cat['description']))
    if cat.get('height') is not None:
        parts += encode_field(4, 5, struct.pack('<f', float(cat['height'])))
    if cat.get('width') is not None:
        parts += encode_field(5, 5, struct.pack('<f', float(cat['width'])))
    if cat.get('optional'):
        parts += encode_field(6, 0, encode_varint(1))
    return bytes(parts)

def encode_cc(cc):
    parts = bytearray()
    if cc.get('ability_id') is not None:
        parts += encode_field(1, 0, encode_varint(cc['ability_id']))
    if cc.get('currency_type') is not None:
        parts += encode_field(2, 0, encode_varint(cc['currency_type']))
    if cc.get('delta') is not None:
        parts += encode_field(3, 0, encode_varint(cc['delta']))
    if cc.get('annotation'):
        parts += encode_field(4, 2, encode_string(cc['annotation']))
    return bytes(parts)

def encode_details(details):
    parts = bytearray()
    for cat in (details.get('mod_categories') or []):
        cat_bytes = encode_category(cat)
        parts += encode_field(1, 2, encode_varint(len(cat_bytes)) + cat_bytes)
    ao = details.get('ability_order')
    if ao and ao.get('currency_changes'):
        cc_bytes = bytearray()
        for cc in ao['currency_changes']:
            ccb = encode_cc(cc)
            cc_bytes += encode_field(1, 2, encode_varint(len(ccb)) + ccb)
        parts += encode_field(2, 2, encode_varint(len(cc_bytes)) + bytes(cc_bytes))
    return bytes(parts)

def encode_build(obj):
    parts = bytearray()
    if obj.get('hero_id') is not None:
        parts += encode_field(1, 0, encode_varint(obj['hero_id']))
    if obj.get('version') is not None:
        parts += encode_field(2, 0, encode_varint(obj['version']))
    if obj.get('hero_build_id') is not None:
        parts += encode_field(3, 0, encode_varint(obj['hero_build_id']))
    if obj.get('author_account_id') is not None:
        parts += encode_field(4, 0, encode_varint(obj['author_account_id']))
    if obj.get('name') is not None:
        parts += encode_field(5, 2, encode_string(obj['name']))
    if obj.get('description') is not None:
        parts += encode_field(6, 2, encode_string(obj['description']))
    if obj.get('language') is not None:
        parts += encode_field(7, 0, encode_varint(obj['language']))
    if obj.get('origin_build_id') is not None:
        parts += encode_field(8, 0, encode_varint(obj['origin_build_id']))
    if obj.get('field_9') is not None:
        parts += encode_field(9, 0, encode_varint(obj['field_9']))
    if obj.get('details'):
        db = encode_details(obj['details'])
        parts += encode_field(10, 2, encode_varint(len(db)) + db)
    for t in (obj.get('tags') or []):
        parts += encode_field(11, 0, encode_varint(t))
    if obj.get('field_13') is not None:
        parts += encode_field(13, 0, encode_varint(obj['field_13']))
    comp = zstandard.ZstdCompressor().compress(bytes(parts))
    return base64.b64encode(comp).decode()

def main():
    if len(sys.argv) >= 2:
        with open(sys.argv[1], encoding='utf-8') as f:
            obj = json.load(f)
    else:
        obj = json.load(sys.stdin)
    print(encode_build(obj))

if __name__ == '__main__':
    main()
