import json

from pyscout.models import Finding
from pyscout.report import fingerprint, has_findings, render_json, render_markdown

META = {
    "tool": "pyscout", "version": "0.1.0", "generated_at": "2026-01-01T00:00:00+00:00",
    "target": "x.py", "explained": False, "model": None, "record": None,
}


def _finding(**kw):
    base = dict(
        rule_id="PY-SQL", title="SQL", severity="high", category="sql-injection",
        cwe="CWE-89", line=5, code="cur.execute(q + x)", why="w", fix="f",
    )
    base.update(kw)
    return Finding(**base)


def test_fingerprint_is_stable_and_location_sensitive():
    f = _finding()
    assert fingerprint("x.py", f) == fingerprint("x.py", _finding())
    assert fingerprint("x.py", f) != fingerprint("x.py", _finding(line=6))


def test_json_structure_has_meta_hash_and_id():
    results = {"x.py": [_finding()]}
    out = json.loads(render_json(results, META, {"x.py": "deadbeef"}))
    assert out["meta"]["tool"] == "pyscout"
    assert out["files"]["x.py"]["sha256"] == "deadbeef"
    assert out["files"]["x.py"]["findings"][0]["cwe"] == "CWE-89"
    assert out["files"]["x.py"]["findings"][0]["id"] == fingerprint("x.py", _finding())


def test_markdown_header_cwe_and_record():
    meta = {**META, "record": {"operator": "Jane", "scope": "own repo"}}
    md = render_markdown({"x.py": [_finding()]}, meta, {"x.py": "abc123"})
    assert "# pyscout security report" in md
    assert "sha256: `abc123`" in md
    assert "CWE-89" in md
    assert "## Engagement record" in md
    assert "Jane" in md


def test_has_findings_ignores_false_positives():
    assert has_findings({"x.py": [_finding()]})
    assert not has_findings({"x.py": [_finding(likely_false_positive=True)]})
    assert not has_findings({"x.py": []})
