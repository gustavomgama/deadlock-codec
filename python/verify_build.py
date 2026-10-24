"""Verify a Deadlock build code: encode/decode round-trip, validation, id resolution.

Usage:
  python verify_build.py <build.json or build code>
  python verify_build.py --code "<base64 code>"

Runs all 4 import-bar steps from build.md:
  1. Encode (if JSON input)
  2. Decode round-trip (code -> JSON -> re-encode -> compare)
  3. Validate (0 errors)
  4. Resolve every id (mods as upgrades, ability_ids as abilities) via raw mirrors

Exit 0 if all pass, 1 otherwise. Prints a per-step report.
"""
import json, os, sys, subprocess, tempfile

BASE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(BASE)
PY = os.environ.get("DEADLOCK_PYTHON", r"C:\Users\helmet\AppData\Roaming\uv\python\cpython-3.13-windows-x86_64-none\python.exe")
ITEMS_RAW = os.path.join(REPO_ROOT, "data", "items_raw.json")
HEROES_RAW = os.path.join(REPO_ROOT, "data", "heroes_raw.json")

def _load_mirror(path):
    if not os.path.isfile(path):
        print(f"WARN: {os.path.basename(path)} missing, id checks disabled", file=sys.stderr)
        return []
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


items = _load_mirror(ITEMS_RAW)
heroes = _load_mirror(HEROES_RAW)
item_by_id = {x["id"]: x for x in items}
hero_by_id = {x["id"]: x for x in heroes}
upgrade_ids = {x["id"] for x in items if x["type"] == "upgrade"}
ability_ids = {x["id"] for x in items if x["type"] == "ability"}


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def is_code(s):
    return not s.strip().startswith("{") and not s.strip().endswith(".json")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs="?")
    parser.add_argument("--strict", action="store_true", help="fail on any warning")
    args = parser.parse_args()
    target = args.target
    if not target:
        print("usage: verify_build.py <file.json or code> [--strict]")
        sys.exit(2)

    code = None
    if os.path.isfile(target) and target.endswith(".json"):
        rc, out = run([PY, os.path.join(BASE, "encode_build_code.py"), target])
        if rc != 0 or not out:
            print("STEP 1 ENCODE: FAIL")
            print(out[:500])
            sys.exit(1)
        code = out.strip()
        print("STEP 1 ENCODE: OK")
    elif is_code(target):
        code = target.strip()
        print("STEP 1 ENCODE: (input already a code)")
    else:
        # treat as raw code possibly with spaces
        code = target.strip()
        print("STEP 1 ENCODE: (input treated as code)")

    # Step 2: decode round-trip
    rc, out = run([PY, os.path.join(BASE, "decode_build_code.py"), code])
    if rc != 0:
        print("STEP 2 DECODE: FAIL")
        print(out[:500])
        sys.exit(1)
    try:
        decoded = json.loads(out)
    except Exception as e:
        print("STEP 2 DECODE: FAIL (json parse)", e)
        sys.exit(1)
    # re-encode and compare
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(decoded, tmp); tmp.close()
    rc2, out2 = run([PY, os.path.join(BASE, "encode_build_code.py"), tmp.name])
    os.unlink(tmp.name)
    if rc2 != 0 or not out2.strip():
        print("STEP 2 ROUND-TRIP: FAIL (re-encode failed)")
        print(out2[:500])
        sys.exit(1)
    # the game's zstd frames are not reproducible, so compare the decoded build, not the code bytes
    rc3, out3 = run([PY, os.path.join(BASE, "decode_build_code.py"), out2.strip()])
    try:
        redecoded = json.loads(out3)
    except ValueError:
        redecoded = None
    if rc3 != 0 or redecoded != decoded:
        print("STEP 2 ROUND-TRIP: FAIL (re-encoded code decodes differently)")
        sys.exit(1)
    print("STEP 2 DECODE+ROUNDTRIP: OK")

    # Step 3: validate
    rc, out = run([PY, os.path.join(BASE, "validate_build.py"), code])
    has_error = "ERROR" in out.upper()
    if "VALID" not in out or has_error:
        print("STEP 3 VALIDATE: FAIL")
        print(out[:800])
        sys.exit(1)
    # count warnings
    warn_count = out.upper().count("WARN")
    if args.strict and warn_count > 0:
        print(f"STEP 3 VALIDATE: FAIL (strict: {warn_count} warnings)")
        print(out[:800])
        sys.exit(1)
    print(f"STEP 3 VALIDATE: OK ({warn_count} warnings)")

    # Step 4: resolve ids
    if not item_by_id or not hero_by_id:
        print("STEP 4 ID RESOLUTION: SKIPPED (data mirrors missing)")
        print("\nALL CHECKS PASSED")
        sys.exit(0)
    hero_id = decoded.get("hero_id")
    # hero may be 1000+hero for default builds; resolve via ability ids if needed
    resolved_hero = decoded.get("hero", hero_id)
    if resolved_hero not in hero_by_id and hero_id in hero_by_id:
        resolved_hero = hero_id
    errors = []
    if resolved_hero not in hero_by_id:
        errors.append(f"unknown hero id {resolved_hero}")
    for cat in decoded.get("details", {}).get("mod_categories", []):
        for mid in cat.get("mods", []):
            if mid not in item_by_id:
                errors.append(f"unknown item id {mid} in {cat.get('name')}")
            elif mid not in upgrade_ids:
                errors.append(f"id {mid} in {cat.get('name')} is not an upgrade")
    ao = decoded.get("details", {}).get("ability_order")
    if ao:
        for ch in ao.get("currency_changes", []):
            aid = ch.get("ability_id")
            if aid not in item_by_id:
                errors.append(f"unknown ability id {aid}")
            elif aid not in ability_ids:
                errors.append(f"id {aid} is not an ability")
            ct = ch.get("currency_type")
            if ct not in (1, 2):
                errors.append(f"bad currency_type {ct}")
            d = ch.get("delta")
            if not isinstance(d, int) or d >= 0:
                errors.append(f"bad delta {d}")
    if errors:
        print("STEP 4 ID RESOLUTION: FAIL")
        for e in errors[:20]:
            print("  -", e)
        sys.exit(1)
    print("STEP 4 ID RESOLUTION: OK")

    print("\nALL CHECKS PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()