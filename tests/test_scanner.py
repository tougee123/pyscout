import hashlib

from pyscout.scanner import MAX_CHARS, collect


def test_collects_py_and_skips_noise(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "notes.txt").write_text("not python")
    (tmp_path / "empty.py").write_text("   \n")
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "lib.py").write_text("y = 2\n")

    files, _ = collect(tmp_path)
    names = {f.path.name for f in files}
    assert names == {"a.py"}  # .txt, empty, and .venv/ all excluded


def test_hash_matches_content(tmp_path):
    p = tmp_path / "a.py"
    body = "z = 3\n"
    p.write_text(body)
    files, _ = collect(tmp_path)
    assert files[0].sha256 == hashlib.sha256(body.encode()).hexdigest()


def test_oversized_file_skipped_with_warning(tmp_path):
    (tmp_path / "big.py").write_text("a = 1\n" + "# pad\n" * MAX_CHARS)
    files, warnings = collect(tmp_path)
    assert files == []
    assert any("too large" in w for w in warnings)


def test_single_file_target(tmp_path):
    p = tmp_path / "one.py"
    p.write_text("q = 1\n")
    files, _ = collect(p)
    assert len(files) == 1 and files[0].path == p
