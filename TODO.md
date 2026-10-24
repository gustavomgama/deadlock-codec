# deadlock-codec improvement TODO

100 grounded improvements for `python/decode_build_code.py`, `python/decode_kv3.py`, `python/encode_build_code.py`, `README.md` and `data/`, ordered correctness-first; nothing below is implemented yet.

Scope of evidence: the three scripts as committed at `11b9c96` (401 / 773 / 106 lines), `README.md` (120 lines), and `data/examplecodefromgame.md`, `data/cached_hero_builds.kv3`, `data/cached_hero_builds.json`.

Effort: **S** under 30 min, **M** 30 min to 2 h, **L** over 2 h.

## Correctness and security bugs (1-23)

1. [x] **`python/decode_build_code.py:84-89`** — Bounds-check wire type 5 and 1 before `struct.unpack`, recording a truncation issue when fewer than 4 (or 8) bytes remain. Today a truncated float/double raises `struct.error`, which is swallowed into a `bytes` node during nested parsing and aborts the whole dump at top level, so a corrupt code is silently misreported instead of flagged. Effort: S. Note: implemented.

2. [x] **`python/decode_build_code.py:11-20`** — Cap `shift` at 63 bits (10 continuation bytes) and return a sentinel when exceeded. A run of `0x80` bytes currently builds an arbitrarily large Python int with a huge shift, so a tiny hostile code costs superlinear memory and time in every caller of `read_varint`. Effort: S. Note: implemented.

3. [x] **`python/decode_build_code.py:14-20`** — Detect an unterminated varint (continuation bit set on the final byte) and report it via `issues`. The loop currently exits on `i >= n` and returns the partial value as if valid, so truncation is indistinguishable from a legitimate value. Effort: S. Note: implemented.

4. [x] **`python/decode_build_code.py:23-94`** — Bound `parse_message` recursion (explicit depth argument, default ~64) and raise/report when exceeded. Recursive descent over attacker-controlled lengths has no depth limit, so a deeply nested payload ends in `RecursionError` after parsing most of the tree. Effort: M. Note: implemented.

5. [x] **`python/decode_build_code.py:154-163`** — Pass a `max_output_size` to `ZstdDecompressor.decompress` (and a bounded read on the stream fallback). A small base64 string can currently expand to an unbounded buffer before any validation runs, which is a memory-exhaustion vector for any service embedding the decoder. Effort: M. Note: implemented.

6. [x] **`python/decode_build_code.py:166-176`** — Reject inputs above a sane character cap (e.g. 1 MiB) before base64 decoding. `''.join(code.split())` materialises an arbitrarily large string and `b64decode` a second buffer, with no guard in the library path. Effort: S. Note: implemented.

7. [x] **`python/decode_build_code.py:168-176`** — Preserve and surface the original base64 exception instead of collapsing two failures into `'invalid base64'`. Callers cannot tell an alphabet problem from padding or invalid characters, which is exactly the distinction users hit when pasting URL-safe codes. Effort: S. Note: implemented.

8. [x] **`python/decode_build_code.py:104-108`** — Restrict `get_int` to wire type 0/1 integers rather than "any non-tuple". A fixed32 field currently returns a `float`, so `hero_id`, `version` and `tags` can silently become `1034.0`, and downstream `_signed` comparisons still succeed. Effort: S. Note: implemented.

9. [x] **`python/decode_build_code.py:126-129`** — Mask to 64 bits before the single sign fold. Values at or above `2**64` (reachable through the over-long varints of item 2) stay positive, producing hero and account ids that are impossible on the wire. Effort: S. Note: implemented.

10. [x] **`python/decode_build_code.py:216-222`** — Tighten layout auto-detection: require a field-1 message whose own field 2 looks like a hero *and* whose field 3 (shared build id) is absent, rather than inferring from `get_int(top, 1) is None`. A shared build that legitimately omits field 1 is currently parsed as a cached wrapper, shifting every field by one. Effort: M. Note: implemented.

11. [x] **`python/decode_build_code.py:205-207`** — Replace the `0 < hero < 1000` heuristic with an explicit validity range (known hero ids, or the `1000 + hero` default-build band) and report when the predicate is inconclusive. Hero id 0 and any future hero above 999 make the cached/shared decision wrong without any diagnostic. Effort: S. Note: implemented.

12. [x] **`python/decode_build_code.py:229-232`** — Remove the dead assignment: `hero_build_id` is read from field 3 on line 230 and immediately overwritten from field 1 when `hero_field == 2`. The current code hides that cached builds store the build id in field 1, so a reader cannot tell which field is authoritative. Effort: S. Note: implemented.

13. [x] **`python/decode_build_code.py:246-247`** — Only null the fields the cached layout genuinely omits; keep `version`, `language`, `origin_build_id` and the unknown fields when the wrapper actually carries them. Blanking six fields unconditionally discards real data from the wrapper message and makes `--raw` and default output disagree. Effort: S. Note: implemented.

14. [x] **`python/decode_build_code.py:249-251`** — Handle repeated field 10 (merge categories across occurrences, or report the extras) instead of `break`-ing at the first. A code with two details messages currently loses every category in the second one with no issue recorded. Effort: S. Note: implemented.

15. [x] **`python/decode_build_code.py:255-263`** — Walk `cat_msg` once so mods keep wire order. Nested mod messages are appended before scalar mods regardless of their position, so decode→encode→decode reorders mods in categories that mix both encodings. Effort: M. Note: implemented.

16. [x] **`python/decode_build_code.py:262-263`** — Apply `_signed` to scalar mod ids, matching the nested path's `get_int` treatment. Without it a mod id encoded as a 64-bit negative decodes as a huge positive number that will not resolve to any item. Effort: S. Note: implemented.

17. [x] **`python/decode_kv3.py:120-153`** — Bounds-check `src[ip]` and `src[ip+1]` in the LZ4 token and offset reads. A truncated block raises `IndexError`, which bypasses the `KV3Error` handler in `main` and dumps a traceback instead of a diagnosable error message. Effort: S. Note: implemented.

18. [x] **`python/decode_kv3.py:182-231`** — Validate `len(self.data)` against the version-dependent header size before `struct.unpack_from`. Any file shorter than 28 bytes currently raises `struct.error` out of `read_header`, which is neither `KV3Error` nor caught, so the CLI crashes on truncated or non-KV3 input. Effort: S. Note: implemented.

19. [x] **`python/decode_kv3.py:279-282`** — Convert `blob.index(b"\x00", pos)` failures into a `KV3Error` naming the string index, and assert that the declared string count consumed the whole b1 blob. An unterminated string table currently raises a bare `ValueError`, and leftover string bytes are silently accepted. Effort: S. Note: implemented.

20. [x] **`python/decode_kv3.py:273`** — Check `count_bytes4 >= 1` before reading the string count from `aux.b4`. A header declaring zero 4-byte lanes makes `struct.unpack_from` fail with `struct.error` instead of a message that the header contradicts itself. Effort: S. Note: implemented.

21. [x] **`python/decode_kv3.py:369-416`** — Bound `read_node` recursion and the per-object/per-array entry count. A crafted object length or a self-referential structure drives `RecursionError`, and a huge declared count allocates until memory runs out before any byte accounting happens. Effort: M. Note: implemented.

22. [x] **`python/decode_kv3.py:325-342`** — Use the byte count returned by `lz4_block_decode` and verify it equals the declared frame size. `off += size` currently trusts the header, so a frame that decodes to fewer bytes silently shifts every later blob and the trailer check, corrupting extracted blobs without an error. Effort: M. Note: implemented.

23. [x] **`python/encode_build_code.py:67-70`** versus **`python/decode_build_code.py:231-232`** — Make the encoder reproduce the layout it consumed: when the input came from a cached build, write the build id to field 1 and the hero to field 2. The encoder always writes `hero_id` to field 1, so decoding a cached build and re-encoding it produces a code that decodes as shared with the id in the wrong slot. Effort: M. Note: implemented.

## Decode edge-case correctness risks (24-46)

24. [x] **`python/decode_build_code.py:57-62`** — Replace the "decodes as printable UTF-8, therefore string" heuristic with structural rules (field-number knowledge or a stricter predicate such as no control bytes *and* valid UTF-8 *and* no embedded NUL). A nested message whose bytes happen to be printable ASCII is currently emitted as text, dropping its children silently. Effort: M. Note: implemented.

25. [x] **`python/decode_build_code.py:60-61`** — Collapse the three-clause predicate into one helper (`_is_text`). The middle clause already handles the empty string and the third recomputes the same check after stripping newlines, so the two branches can drift apart under later edits. Effort: S. Note: implemented.

26. [x] **`python/decode_build_code.py:68`** — Decide and document the empty-chunk case: `(chunk and not nested)` is false for `chunk == b""`, so an empty length-delimited field becomes `('msg', [])` rather than an empty `bytes` node. Whichever is intended, encode it explicitly. Effort: S. Note: implemented.

27. [x] **`python/decode_build_code.py:64-71`** — Narrow the bare `except Exception` around the nested parse to `struct.error`/`IndexError`. It currently absorbs real parser defects, so a bug in `parse_message` degrades silently to opaque bytes instead of surfacing. Effort: S. Note: implemented.

28. [x] **`python/decode_build_code.py:36-39`** — Record the tag's start offset rather than `i - 1`. With a multi-byte tag, `i - 1` points at the last tag byte, so every issue offset after the first is off by the tag length, which defeats the offsets as a debugging aid. Effort: S. Note: implemented.

29. [x] **`python/decode_build_code.py:90-93`** — Treat protobuf wire types 3/4 (deprecated start/end group) as record-and-skip instead of `break`. A single group field currently truncates the remainder of the message with only one issue, losing all following fields. Effort: S. Note: implemented.

30. [x] **`python/decode_build_code.py:40-41`** — Reject field number 0 with an `issues` entry. Field 0 is invalid on the wire; the parser accepts it and emits a field-0 node that every `get_*` helper ignores, hiding the corruption. Effort: S. Note: implemented.

31. [x] **`python/decode_build_code.py:53-55`** — When `i + length > n`, clamp and record a `truncated length-delimited field` issue naming the declared and available bytes. `chunk = data[i:end]` silently returns a short slice and `i` jumps past the buffer, so the truncation never reaches `issues`. Effort: S. Note: implemented.

32. [x] **`python/decode_build_code.py:72-83`** — Distinguish "varint truncated" from "varint value 0" by returning `None`. The truncation branch still appends `0` to the output, so a missing hero id becomes hero 0 and flows on as a real value. Effort: S. Note: implemented.

33. [x] **`python/decode_build_code.py:223-229`** — Apply the `1000 + hero` default-build offset only in the shared layout and only when the value is plausibly a build id. The offset is currently applied to cached-layout field 2 as well, so a real hero id at or above 1000 would be misreported as a default build. Effort: S. Note: implemented.

34. [x] **`python/decode_build_code.py:240-245`** — Keep packed tags out of the text heuristic: test wire 2 + field 11 before the printable-UTF-8 branch. A packed varint blob that happens to be printable ASCII is classified as `str` and dropped from `tags`, so tags vanish exactly for the ids that encode as ASCII-range bytes. Effort: M. Note: implemented.

35. [x] **`python/decode_build_code.py:328-334`** — Add the same truncation and over-long guard to `_packed_varints` that items 2-3 add to `read_varint`, and stop cleanly. Today a malformed packed chunk yields a short or garbage tag list with no signal. Effort: S. Note: implemented.

36. [x] **`python/decode_build_code.py:310-325`** — Make the duplicated payload (`payload_base64`) opt-in and compute the normalised code once. `raw_document` re-runs `''.join(code.split())` three times and then base64-encodes the whole decoded buffer again, doubling output size for a field that is derivable from the input. Effort: S. Note: implemented.

37. [x] **`python/decode_build_code.py:314-322`** — Record which base64 alphabet and padding path succeeded. `input` currently reports only lengths, so a consumer debugging a rejected paste cannot see that the URL-safe fallback was used. Effort: S. Note: implemented.

38. [x] **`python/decode_build_code.py:343-348`** — Catch `UnicodeDecodeError` from the UTF-16 retry and fall back to the argument/`ValueError`. A file that is neither valid UTF-8 nor valid UTF-16 currently escapes the handler (only `OSError` is caught there) and prints a traceback. Effort: S. Note: implemented.

39. [x] **`python/decode_build_code.py:340-350`** — Distinguish "path does not exist" from "path is unreadable" and stop treating every `OSError` as an inline code. A typo'd filename is currently passed to the base64 decoder and reported as `invalid base64`, which sends users looking in the wrong place. Effort: S. Note: implemented.

40. [x] **`python/decode_build_code.py:353-372`** — Replace `assert` with explicit `raise AssertionError`, or refuse to run under `-O`. `python -O` strips every check, so `--self-test` prints `SELF_TEST_OK` without testing anything. Effort: S. Note: implemented.

41. [x] **`python/decode_build_code.py:353-372`** — Add coverage for the cached layout, `--raw` document shape, `tags`, `ability_changes` and a populated `issues` list. The only assertions are on the shared sample's hero, layout and category count, so a regression in any other branch is invisible. Effort: M. Note: implemented.

42. [x] **`python/decode_build_code.py:358-365`** — Pin the full decoded document for the sample (or a digest of it) instead of five loose fields. The current checks would pass while `name`, `description`, `tags` and `ability_order` silently changed. Effort: S. Note: implemented.

43. [x] **`python/decode_kv3.py:289-323`** — Validate every declared lane count and `count_types` against the remaining buffer2 length before slicing, and bound the trailer read. Inflated header counts currently produce short lanes and a later `IndexError` deep in `read_node`, with nothing pointing at the header that lied. Effort: S. Note: implemented.

44. [x] **`python/decode_kv3.py:345-362`** — Bounds-check the optional flags/extra byte reads and record the raw type byte when the high bits are dropped. `b &= 0x3F` discards 0xC0 information, so a type byte using those bits is silently reinterpreted instead of being flagged as unknown. Effort: S. Note: implemented.

45. [x] **`python/decode_kv3.py:389-393`** — Reject negative object/array counts from `take4s` with a `KV3Error`. `range(n)` over a negative count yields an empty container, so a corrupt length is indistinguishable from a legitimately empty object. Effort: S. Note: implemented.

46. [x] **`python/decode_kv3.py:474-495`** — Detect duplicate object keys in `to_plain` and emit a warning or raise under a strict flag. The lossless default preserves duplicates by design, but `--plain` and `--builds` collapse them through a dict comprehension with no indication that data was dropped. Effort: S. Note: implemented.

## Tests and verification (47-63)

47. [x] **`python/tests/` (new)**, target **`python/decode_build_code.py:1-401`**, **`python/decode_kv3.py:1-773`**, **`python/encode_build_code.py:1-106`** — Add a test package plus `python/__init__.py`-free import shim (`sys.path` fixture) so all three modules are importable. There is no `tests/` directory at all today, so `--self-test` inside each script is the entire verification story. Effort: M. Note: implemented.

48. [x] **`python/tests/test_build_code.py` (new)**, calling **`python/encode_build_code.py:67-95`** — Round-trip test: decode `data/examplecodefromgame.md`, encode with `encode_build_code.encode_build`, decode again, assert equal documents. The README claims the encoder consumes the decoder's shape, but nothing verifies the pair, which is how the field-1/field-2 mismatch of item 23 survives. Effort: M. Note: implemented.

49. [x] **`python/tests/test_build_code.py` (new)**, covering **`python/decode_build_code.py:218-247`** — Add a synthetic cached-layout fixture (wrapper field 1, build id field 1, hero field 2) and assert `layout == 'cached'`, `hero_build_id`, `author_account_id is None` and the field nulling rules. No cached-layout sample exists in `data/`, so that branch is untested. Effort: M. Note: implemented.

50. [x] **`python/tests/test_build_code.py` (new)** — URL-safe alphabet case: decode a `-`/`_` code produced by re-encoding the sample with `base64.urlsafe_b64encode` and assert the same document. The fallback path at `decode_build_code.py:171-174` has no test. Effort: S. Note: implemented.

51. [x] **`python/tests/test_build_code.py` (new)**, covering **`python/decode_build_code.py:177-184`** — Uncompressed payload case: decode the sample's `payload_base64` (already exposed by `--raw`) without the zstd magic and assert `compressed is False` in `raw_document`. The non-zstd branch is exercised by nothing in the repo. Effort: S. Note: implemented.

52. [x] **`python/tests/test_build_code.py` (new)** — Invalid-input matrix: `''`, `'   '`, `'!!!'`, `'A'`, standard-alphabet string with a `-`, and over-padded input; assert `ValueError`-class failures and exit code 1 through the CLI. Only `'!!!'` is checked today (`decode_build_code.py:366-371`). Effort: S. Note: implemented.

53. [x] **`python/tests/test_build_code.py` (new)**, covering **`python/decode_build_code.py:84-89`** — Truncation tests: a payload ending mid-fixed32 and mid-fixed64 field must yield an issue (after item 1) rather than `struct.error`. Effort: S. Note: implemented.

54. [x] **`python/tests/test_build_code.py` (new)**, covering **`python/decode_build_code.py:11-20`** — Over-long varint case: 11 continuation bytes must be rejected/flagged, pinning the cap added for item 2. Effort: S. Note: implemented.

55. [x] **`python/tests/test_build_code.py` (new)**, covering **`python/decode_build_code.py:23-94`** — Deep-nesting case: 200 nested length-delimited messages must raise the bounded-depth error added in item 4, not `RecursionError`. Effort: S. Note: implemented.

56. [x] **`python/tests/test_build_code.py` (new)**, covering **`python/decode_build_code.py:240-245`** — Regression for item 34: a build whose packed tag bytes are printable ASCII must still appear in `tags`. Effort: S. Note: implemented.

57. [x] **`python/tests/test_build_code.py` (new)**, covering **`python/decode_build_code.py:310-325`** — Golden `--raw` document for the sample (stored under `python/tests/golden/`) compared on JSON-normalised structure, including `issues == []` and `input.zstd is True`. Effort: S. Note: implemented.

58. [x] **`python/tests/test_kv3.py` (new)** — Assert the README's "`--plain` is byte-identical to the previous decoder" claim by committing a golden `--plain` JSON for `data/cached_hero_builds.kv3` and diffing. The claim in `README.md:96` is currently unverifiable. Effort: M. Note: implemented.

59. [x] **`python/tests/test_kv3.py` (new)**, covering **`python/decode_kv3.py:546-587`** — Blob accounting test: extract all 35 declared blobs and assert their concatenated length equals `size_binary_blobs` (85278) and that `completeness.blob_frames.consumed == declared`. Effort: S. Note: implemented.

60. [x] **`python/tests/test_kv3.py` (new)**, covering **`python/decode_kv3.py:180-254`** — Corrupt-file matrix: 4-byte file, bad magic, wrong version, bad trailer, declared buffer sizes larger than the file; each must raise `KV3Error` (after items 17-22) and the CLI must exit 1 with `KV3_ERROR`, never a traceback. Effort: M. Note: implemented.

61. [x] **`python/tests/test_kv3.py` (new)** — Assert `completeness.trailing_bytes == 0` and every `unconsumed` counters == 0 for the committed cache. The lossless promise in `decode_kv3.py:546-587` is only eyeballed today. Effort: S. Note: implemented.

62. [x] **`python/tests/test_cli.py` (new)**, covering **`python/decode_kv3.py:723-773`** — Exit-code and stream tests for all three scripts: invalid input exits 1, `--out` writes and prints nothing, `-` reads stdin, and `--self-test` exits 0. Effort: M. Note: implemented.

63. [x] **`python/` (new lint config)**, targeting **`python/decode_build_code.py:1`** and **`python/decode_kv3.py:24-29`** — Wire `ruff` into a documented check command (a `.ruff_cache` already exists, proving the tool is used locally) and add `.ouroboros/mechanical.toml` with `ruff check` + the pytest command so automated evaluation runs them. Without it, no mechanical gate exists at all. Effort: S. Note: implemented.

## API and CLI consistency (64-79)

64. [x] **`python/decode_build_code.py:395-397`** versus **`python/decode_kv3.py:768-773`** — Unify the failure contract: both should print one prefix (`ERROR:`) to stderr and exit 1, or share a `fail(prefix, exc)` helper. Two different prefixes (`ERROR` vs `KV3_ERROR`) force every wrapper to parse both. Effort: S. Note: implemented.

65. [x] **`python/decode_build_code.py:390-394`** — Make `--out` and stdout produce byte-identical text. `print(text)` appends a newline while `write_text` does not, so the same command differs by a trailing byte depending on destination. Effort: S. Note: implemented.

66. [x] **`python/decode_build_code.py:377`** versus **`python/decode_kv3.py:725`** — Align `--self-test` with the positional argument: `decode_kv3.py` requires a path even to self-test, `decode_build_code.py` makes the code optional. Adopt one rule (self-test needs no path, or both do) and document it. Effort: S. Note: implemented.

67. [x] **`python/decode_build_code.py:210`** — Expose the `layout` parameter (or make it private). The decoder accepts `layout='auto'|'cached'|'shared'` but the CLI offers no `--layout`, so a user hitting a misdetected code has no override; item 10 makes that override genuinely useful. Effort: S. Note: implemented.

68. [x] **`python/encode_build_code.py:97-103`** — Add `argparse` with `--out`, `--self-test`, `--url-safe` and `--level`. The encoder is the only script with no argument parser, so it has no `--help`, no file output and no test hook, and a JSON typo surfaces as a traceback. Effort: M. Note: implemented.

69. [x] **`python/encode_build_code.py:95`** — Accept a URL-safe output mode (or at least document that only the standard alphabet is emitted). The decoder tolerates both alphabets, so the pair is asymmetric in a way users discover only after a downstream tool rejects the code. Effort: S. Note: implemented.

70. [x] **`python/decode_kv3.py:727-731`** — Reject mutually exclusive flag combinations with `ap.error` (`--strings-only` + `--blobs`, `--plain` + `--builds`, `--blobs` + JSON output). Today the `if` order silently decides which flag wins. Effort: S. Note: implemented.

71. [x] **`python/decode_kv3.py:755-760`** — Use one escaping policy: the lossless document sets `ensure_ascii=True` while `--plain`/`--builds` set `False`. Non-ASCII build names therefore print differently depending on the flag; pick a policy or add `--ascii`. Effort: S. Note: implemented.

72. [x] **`python/decode_kv3.py:737-743`** — Reconfigure stdout before the `--strings-only` and `--blobs` `print` calls, not only in the JSON branch at line 764. On a cp1252 console, a non-ASCII string table currently raises `UnicodeEncodeError` on the one flag whose purpose is to list strings. Effort: S. Note: implemented.

73. [x] **`python/decode_kv3.py:744-752`** — Make `--blobs` composable or explicitly exclusive: it mutates `kv3.blobs` and returns before `read_tree`, so the tree cannot be decoded afterwards, and the flag silently wins over a requested JSON dump. Effort: S. Note: implemented.

74. [x] **`python/encode_build_code.py:98-102`** — Support `-` for stdin like `decode_build_code.read_input`. The encoder reads stdin only when no argument is passed, so a wrapper cannot pass `-` uniformly across the three scripts. Effort: S. Note: implemented.

75. [x] **`python/decode_build_code.py:379`** and **`python/decode_kv3.py:726`** — Add help text to `--out` and create missing parent directories (or fail with a clear message). Both flags are currently bare and fail with `FileNotFoundError` for a nested path. Effort: S. Note: implemented.

76. [x] **`python/decode_build_code.py:287-307`** — Add a `schema_version` key to the decoded build document. Consumers currently have no way to detect a shape change, and the function already returns two aliases (`hero_id`, `hero`) whose contract lives only in prose. Effort: S. Note: implemented.

77. [x] **`python/decode_kv3.py:590-597`** — Add `schema_version` to the lossless document alongside `header`, `payload`, `strings`, `tree` and `completeness`. Same reason as item 76: the document is a public shape with no version marker. Effort: S. Note: implemented.

78. [x] **`python/decode_build_code.py:310-325`** versus **`python/decode_build_code.py:287-307`** — Give `--raw` and default output a shared envelope (`schema_version`, `input`, `issues`, `document`). The two shapes share only `issues`, so a consumer that wants both must branch on which mode produced the file. Effort: M. Note: implemented.

79. [x] **`python/decode_build_code.py:210`**, **`python/decode_kv3.py:600`**, **`python/encode_build_code.py:67`** — Expose a documented library surface (`decode_build_code`, `encode_build`, `decode_kv3`) and keep `main()` thin. Every script's logic is currently reachable only through CLI flags or by importing a module whose name shadows the function, so tests and downstream callers must reimplement glue. Effort: M. Note: implemented.

## Performance (80-89)

80. [x] **`python/decode_kv3.py:80-108`** — Replace `del self.b1[0]` / `del self.b2[:2]` style consumption with a cursor index per lane. Each `del` shifts the remaining bytes, making node decoding quadratic in lane size; the fix is constant-time and touches only `Lanes`. Effort: M. Note: implemented.

81. [x] **`python/decode_kv3.py:151-152`** — Copy LZ4 matches in slices instead of one `append` per byte, handling the overlapping case by doubling the available slice. The 85 KB blob section currently costs one Python-level append per output byte. Effort: M. Note: implemented.

82. [x] **`python/decode_build_code.py:56-63`** — Try the nested-message parse before, or instead of, the UTF-8 decode for fields already known to be messages (`10`, `11` when wire 2). Every length-delimited field currently pays a full UTF-8 decode plus `isprintable` scan even when the field is structurally a message. Effort: M. Note: implemented.

83. [x] **`python/decode_build_code.py:167`**, **`316-317`** — Normalise the input string once in `_payload` and pass the stripped code to `raw_document`. `''.join(code.split())` is currently executed up to four times per invocation on the same string. Effort: S. Note: implemented.

84. [x] **`python/decode_build_code.py:390-394`** — Stream with `json.dump(doc, fh, indent=2)` instead of `json.dumps` into a temporary string. `--raw` on a large code builds the entire JSON twice (dict plus string) before writing. Effort: S. Note: implemented.

85. [x] **`python/decode_kv3.py:753-765`** — Stream the document with `json.dump` to `--out`/stdout rather than materialising one string. The lossless document embeds base64 blobs, so peak memory is roughly three times the file size today. Effort: S. Note: implemented.

86. [x] **`python/decode_kv3.py:277-283`** — Build the string table in a single pass (`blob.split(b'\x00')` with a count bound) instead of `blob.index` per string. The index-based loop rescans from `pos` each iteration, which is quadratic on a large table. Effort: S. Note: implemented.

87. [x] **`python/encode_build_code.py:94`** — Reuse a module-level `zstandard.ZstdCompressor` (and expose the level) as `decode_build_code.py:154-158` already does for the decompressor. Every call currently constructs a new compressor with default settings, adding avoidable setup cost and no way to trade ratio for speed. Effort: S. Note: implemented.

88. [x] **`python/decode_kv3.py:747-750`** — Slice the blob buffer once into a memoryview and write the declared ranges, instead of `bytes(...)` plus `del` per blob. Each extraction currently copies the remaining buffer and shifts it. Effort: S. Note: implemented.

89. [x] **`python/decode_build_code.py:211-213`** and **`310-313`** — Cache the parsed message on the payload so `raw_document` and `decode_build_code` can share one parse. Any consumer that wants both shapes currently pays the full parse twice, including the nested recursion. Effort: M. Note: implemented.

## Docs and cleanup (90-100)

90. [x] **`README.md:9-11`**, **`README.md:109`** — State the `zstandard` requirement once and add a `requirements.txt` (or `pyproject.toml`) with the pinned minimum. The dependency is currently declared twice in prose and nowhere machine-readable, so a fresh clone cannot install it. Effort: S. Note: implemented.

91. [x] **`README.md:63`** — Correct the claim that cached `.kv3` blobs "decode in the same mode". `--raw` takes a base64 build code; the kv3 file is decoded by `decode_kv3.py`, so the sentence sends readers to the wrong tool. Effort: S. Note: implemented.

92. [x] **`README.md:83-91`** — Complete the flag table: note that `--blobs DIR` writes files rather than printing, that `--self-test` still requires the positional path, and that flags are not mutually exclusive (until item 70). Effort: S. Note: implemented.

93. [x] **`README.md:115-119`** — Split the `sh` block that contains a PowerShell `Get-Content ... |` line into separate `sh` and `powershell` blocks. Copy-pasting the block as-is fails on one of the two shells. Effort: S. Note: implemented.

94. [x] **`README.md:71-74`** — Fix the steam path: `%LOCALAPPDATA%/../Steam/...` resolves to `AppData/Steam`, not `Program Files (x86)/Steam`. Give the real path (`%ProgramFiles(x86)%\Steam\userdata\<id>\1422450\remote\cfg\cached_hero_builds.kv3`) and note the alternate library case. Effort: S. Note: implemented.

95. [x] **`python/decode_kv3.py:608-612`** — Resolve the missing `data/items_raw.json`: commit the item table, read ids from an existing source, or make `--builds` report that names are unavailable. `load_items()` returns `{}` today, so every `mod_names` entry is `None` with no warning. Effort: M. Note: implemented.

96. [x] **`data/cached_hero_builds.json:1`** — Stop committing the 138 KB generated dump next to its source; gitignore it and document the one-liner that regenerates it (`decode_kv3.py ... --out`, `README.md:76-81`). It is derived data with no provenance header, so it drifts silently from the `.kv3` beside it. Effort: S. Note: implemented.

97. [x] **`data/examplecodefromgame.md:1`**, **`data/cached_hero_builds.kv3`** — Add small fixtures for the cases the tests need: a cached-layout code, a truncated payload, a URL-safe code, and a corrupt kv3. The directory currently holds only one happy-path example plus one real cache, so every edge case must be synthesised ad hoc. Effort: S. Note: implemented.

98. [x] **`LICENSE` (new, repo root)** — Add a license and the upstream attribution `README.md:5` refers to. The README credits codec-site but the repo grants no terms, which blocks reuse. Effort: S. Note: implemented.

99. [x] **`python/decode_build_code.py:8`**, **`238-239`**, **`298-300`** — Document the protocol constants once: the `1000 + hero` default-build offset and the still-unknown `field_9`/`field_13`. They are exposed in the output with no explanation, so consumers cannot tell whether they are meaningful or placeholders. Effort: S. Note: implemented.

100. [x] **`python/decode_build_code.py:1`** and **`python/encode_build_code.py:1`** — Split the single-line imports to match `decode_kv3.py:24-29` and run `ruff check`/`ruff format` (the repo already carries `.ruff_cache`). One-line imports plus mixed statement style are the main source of lint noise and make diffs harder to read. Effort: S. Note: implemented.
