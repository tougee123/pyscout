from pyscout.rules import scan_text


def _ids(text):
    return {f.rule_id for f in scan_text(text)}


def test_detects_core_patterns():
    src = (
        "import os, pickle, subprocess, hashlib\n"
        "API_KEY = 'sk-live-abcdef123456'\n"
        "os.system('ping ' + h)\n"
        "subprocess.call(c, shell=True)\n"
        "pickle.loads(b)\n"
        "hashlib.md5(x)\n"
        "eval(s)\n"
    )
    ids = _ids(src)
    assert {"PY-SECRET", "PY-OS-SYSTEM", "PY-SHELL-TRUE", "PY-PICKLE", "PY-WEAK-HASH", "PY-EVAL"} <= ids


def test_sql_dynamic_vs_parameterized():
    dynamic = "cur.execute('SELECT * FROM t WHERE n = ' + name)\n"
    assert "PY-SQL" in _ids(dynamic)
    safe = "cur.execute('SELECT * FROM t WHERE n = ?', (name,))\n"
    assert "PY-SQL" not in _ids(safe)


def test_yaml_safe_loader_not_flagged():
    assert "PY-YAML" in _ids("yaml.load(s)\n")
    assert "PY-YAML" not in _ids("yaml.load(s, Loader=yaml.SafeLoader)\n")


def test_secret_skips_placeholder_and_short():
    assert "PY-SECRET" not in _ids("password = 'your_password_here'\n")
    assert "PY-SECRET" not in _ids("token = 'x'\n")


def test_finding_has_cwe_and_line():
    f = scan_text("import os\nos.system(cmd)\n")[0]
    assert f.cwe == "CWE-78"
    assert f.line == 2
    assert f.severity == "high"


def test_syntax_error_returns_empty():
    assert scan_text("def (:\n") == []
