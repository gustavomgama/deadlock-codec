import json
import sys
import pathlib

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
DATA_DIR = ROOT / "data"
sys.path.insert(0, str(SCRIPT_DIR))

def _load_mirror(name):
    path = DATA_DIR / name
    if not path.is_file():
        print(f"WARN: data/{name} missing, id checks disabled", file=sys.stderr)
        return {}
    return {row.get("id"): row for row in json.loads(path.read_text(encoding="utf-8"))}


HEROES = _load_mirror("heroes_raw.json")
ITEMS = _load_mirror("items_raw.json")


def resolve_hero(obj):
    """Resolve the real hero id, mirroring decode_build_code.py.

    Raw `hero_id` (field 1) may be a build index (9-16) or `1000 + hero`
    (default builds); the hero is recovered from the ability ids in
    ability_order when field 1 is not the real hero.
    """
    raw = obj.get("hero_id")
    if isinstance(raw, int) and raw >= 1000:
        return raw - 1000
    details = obj.get("details") or {}
    ao = details.get("ability_order") or {}
    changes = ao.get("currency_changes") or []
    heroes = set()
    for e in changes:
        if not isinstance(e, dict):
            continue
        it = ITEMS.get(e.get("ability_id"))
        if it and it.get("type") == "ability":
            for h in (it.get("heroes") or []):
                heroes.add(h)
    if len(heroes) == 1:
        return next(iter(heroes))
    return raw

VALID_CATEGORIES = {
    "early", "early-mid", "mid", "mid-late", "late", "late-late",
    "optional spirit-resist", "optional general-resist-sustain",
}


def _load(path_or_code):
    p = pathlib.Path(path_or_code)
    if p.exists():
        text = p.read_text(encoding="utf-8")
        # try json first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        # maybe build code
        import decode_build_code
        return decode_build_code.decode_build_code(text.strip())
    # treat as build code
    import decode_build_code
    return decode_build_code.decode_build_code(path_or_code)


def validate(obj):
    errors = []
    warnings = []
    if not isinstance(obj, dict):
        return ["input is not an object"], warnings
    hero_id = obj.get("hero_id")
    resolved = resolve_hero(obj)
    if HEROES and resolved not in HEROES:
        errors.append(f"unknown hero (resolved {resolved} from raw hero_id {hero_id})")
    elif isinstance(hero_id, int) and hero_id in HEROES and hero_id != resolved:
        warnings.append(f"hero_id {hero_id} does not match resolved hero {resolved} from ability ids")
    details = obj.get("details") or {}
    cats = details.get("mod_categories") or []
    if not isinstance(cats, list):
        errors.append("mod_categories must be a list")
        cats = []
    seen_items = set()
    for c in cats:
        if not isinstance(c, dict):
            errors.append("category must be object")
            continue
        name = c.get("name")
        if name not in VALID_CATEGORIES:
            warnings.append(f"non-standard category name: {name!r}")
        mods = c.get("mods") or []
        if not isinstance(mods, list):
            errors.append(f"mods not list in {name!r}")
            continue
        if len(mods) > 12:
            warnings.append(f"{name!r} has {len(mods)} items (>12 slots)")
        for m in mods:
            if not isinstance(m, int):
                errors.append(f"non-int mod id {m!r} in {name!r}")
                continue
            if ITEMS and m not in ITEMS:
                errors.append(f"unknown item id {m} in {name!r}")
            if m in seen_items:
                warnings.append(f"duplicate item id {m} across categories")
            seen_items.add(m)
    ao = details.get("ability_order")
    if ao is not None:
        if not isinstance(ao, dict):
            errors.append("ability_order must be object")
        else:
            cc = ao.get("currency_changes")
            if not isinstance(cc, list):
                errors.append("currency_changes must be list")
            else:
                for e in cc:
                    if not isinstance(e, dict):
                        errors.append("currency_change entry not object")
                        continue
                    aid = e.get("ability_id")
                    if ITEMS and (aid not in ITEMS or ITEMS.get(aid, {}).get("type") != "ability"):
                        warnings.append(f"ability_id {aid} not found as ability")
                    if e.get("currency_type") not in (1, 2):
                        errors.append(f"bad currency_type {e.get('currency_type')}")
                    if not isinstance(e.get("delta"), int) or e.get("delta", 0) >= 0:
                        errors.append(f"delta must be negative int, got {e.get('delta')}")
    if not obj.get("name"):
        warnings.append("build has no name")
    return errors, warnings


def main():
    if len(sys.argv) < 2:
        print("usage: validate_build.py <file-or-build-code>", file=sys.stderr)
        sys.exit(1)
    try:
        obj = _load(sys.argv[1])
    except Exception as e:
        print(f"ERROR loading: {e}", file=sys.stderr)
        sys.exit(1)
    errors, warnings = validate(obj)
    for w in warnings:
        print(f"WARN: {w}")
    for e in errors:
        print(f"ERROR: {e}")
    if errors:
        print(f"INVALID: {len(errors)} errors, {len(warnings)} warnings")
        sys.exit(1)
    print(f"VALID: {len(warnings)} warnings")
    sys.exit(0)


if __name__ == "__main__":
    main()
