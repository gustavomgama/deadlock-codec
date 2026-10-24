import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
PY = sys.executable


def run(script, *args, input_text=None):
    cmd = [PY, str(ROOT / "python" / script), *args]
    return subprocess.run(cmd, capture_output=True, text=True, input=input_text)


def test_build_code_invalid_exit():
    r = run("decode_build_code.py", "!!!")
    assert r.returncode == 1
    assert "ERROR" in r.stderr


def test_kv3_invalid_exit():
    r = run(
        "decode_kv3.py", str(ROOT / "python" / "tests" / "fixtures" / "corrupt.kv3")
    )
    assert r.returncode == 1
    assert "KV3_ERROR" in r.stderr


def test_out_writes_file(tmp_path):
    out = tmp_path / "out.json"
    r = run(
        "decode_build_code.py",
        str(ROOT / "data" / "examplecodefromgame.md"),
        "--out",
        str(out),
    )
    assert r.returncode == 0
    assert out.exists()
    assert r.stdout == ""
    # stdout vs file byte-identical when re-run to stdout
    r2 = run("decode_build_code.py", str(ROOT / "data" / "examplecodefromgame.md"))
    assert r2.stdout == out.read_text()


def test_stdin_dash():
    code = (ROOT / "data" / "examplecodefromgame.md").read_text()
    r = run("decode_build_code.py", "-", input_text=code)
    assert r.returncode == 0
    assert "hero_id" in r.stdout


def test_self_test_no_path():
    r = run("decode_build_code.py", "--self-test")
    assert r.returncode == 0
    assert "SELF_TEST_OK" in r.stdout
    r2 = run("decode_kv3.py", "--self-test")
    assert r2.returncode == 0
    assert "SELF_TEST_OK" in r2.stdout


def test_encoder_cli():
    # use sample decode
    r = run("decode_build_code.py", str(ROOT / "data" / "examplecodefromgame.md"))
    # encode from a temp json
    import json as J

    d = J.loads(r.stdout)
    p = ROOT / "python" / "tests" / "fixtures" / "tmp_build.json"
    p.write_text(J.dumps(d))
    r2 = run("encode_build_code.py", str(p))
    assert r2.returncode == 0
    assert r2.stdout.strip() != ""
