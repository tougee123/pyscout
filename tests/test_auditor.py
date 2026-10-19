import json
from types import SimpleNamespace

import pytest

from pyscout.auditor import _extract_json_array, enrich
from pyscout.cli import run_enrichment
from pyscout.models import Finding


def _finding():
    return Finding(
        rule_id="PY-SQL", title="SQL", severity="high", category="sql-injection",
        cwe="CWE-89", line=1, code="cur.execute(q + x)", why="old", fix="old",
    )


class FakeClient:
    """Stub Anthropic client: returns a canned response, or raises."""

    def __init__(self, text=None, stop_reason="end_turn", raises=None):
        self._text, self._stop, self._raises = text, stop_reason, raises
        self.messages = self

    def create(self, **kwargs):
        if self._raises:
            raise self._raises
        block = SimpleNamespace(type="text", text=self._text)
        return SimpleNamespace(stop_reason=self._stop, content=[block])


@pytest.mark.parametrize("raw", [
    '[{"index": 0}]',
    '```json\n[{"index": 0}]\n```',
    'Here you go:\n[{"index": 0}]\nThanks!',
])
def test_extract_json_array_tolerates_wrapping(raw):
    assert json.loads(_extract_json_array(raw)) == [{"index": 0}]


def test_extract_json_array_raises_without_array():
    with pytest.raises(ValueError):
        _extract_json_array("no array here")


def test_enrich_applies_fields_in_place():
    f = _finding()
    resp = json.dumps([{"index": 0, "why": "W2", "fix": "F2", "likely_false_positive": True}])
    err = enrich(FakeClient(text=resp), "cur.execute(q + x)", [f], "model")
    assert err is None
    assert (f.why, f.fix, f.likely_false_positive, f.enriched) == ("W2", "F2", True, True)


def test_enrich_reports_refusal():
    f = _finding()
    err = enrich(FakeClient(text="", stop_reason="refusal"), "code", [f], "model")
    assert "refused" in err
    assert f.enriched is False


def test_run_enrichment_parallel_success_and_failure():
    good = {"ok.py": [_finding()]}
    good_src = {"ok.py": SimpleNamespace(text="cur.execute(q + x)")}
    resp = json.dumps([{"index": 0, "why": "W", "fix": "F", "likely_false_positive": False}])
    failures = list(run_enrichment(FakeClient(text=resp), good, good_src, "m", jobs=4))
    assert failures == []
    assert good["ok.py"][0].why == "W"

    bad = {"bad.py": [_finding()]}
    bad_src = {"bad.py": SimpleNamespace(text="code")}
    client = FakeClient(raises=RuntimeError("boom"))
    failures = list(run_enrichment(client, bad, bad_src, "m", jobs=2))
    assert failures and failures[0][0] == "bad.py" and "boom" in failures[0][1]
