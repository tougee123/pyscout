"""Deterministic AST-based security rules.

Each rule flags a well-known dangerous pattern and ships with a static
why/fix, so the base scan is useful offline with no API key. The optional
LLM layer (see auditor.py) rewrites why/fix in context.
"""

from __future__ import annotations

import ast
import re

from pyscout.models import Finding

_SECRET_NAME = re.compile(r"(secret|password|passwd|pwd|token|api[_-]?key|access[_-]?key)", re.I)
# Values that are obviously placeholders, not real secrets.
_PLACEHOLDER = re.compile(r"^(your[_-]?|xxx|changeme|<|\{|\$|example|placeholder|todo)", re.I)


def _dotted_name(node: ast.AST) -> str:
    """Best-effort dotted name for a call target, e.g. 'os.system'."""
    if isinstance(node, ast.Attribute):
        return f"{_dotted_name(node.value)}.{node.attr}".lstrip(".")
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _has_kw_true(call: ast.Call, name: str) -> bool:
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _has_kw_false(call: ast.Call, name: str) -> bool:
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            return True
    return False


def _kw(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_dynamic_string(node: ast.expr | None) -> bool:
    """True if the expression builds a string at runtime (concat / f-string / % / .format)."""
    if isinstance(node, ast.JoinedStr):                      # f"... {x} ..."
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


class _Visitor(ast.NodeVisitor):
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.findings: list[Finding] = []

    def _add(self, node: ast.AST, rule_id, title, severity, category, cwe, why, fix) -> None:
        line = getattr(node, "lineno", 0)
        code = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.findings.append(
            Finding(rule_id, title, severity, category, cwe, line, code, why, fix)
        )

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted_name(node.func)

        if name in ("eval", "exec"):
            self._add(node, "PY-EVAL", f"Use of {name}()", "high", "code-injection", "CWE-95",
                      f"{name}() runs arbitrary code; attacker-controlled input leads to RCE.",
                      "Avoid dynamic code execution; use ast.literal_eval or an explicit dispatch.")

        if name in ("os.system", "os.popen"):
            self._add(node, "PY-OS-SYSTEM", f"Use of {name}()", "high", "command-injection", "CWE-78",
                      "The command runs through a shell; unsanitized input enables command injection.",
                      "Use subprocess with an argument list and shell=False.")

        if name.startswith("subprocess.") and _has_kw_true(node, "shell"):
            self._add(node, "PY-SHELL-TRUE", "subprocess called with shell=True", "high", "command-injection", "CWE-78",
                      "shell=True runs the command through a shell; input can inject extra commands.",
                      "Pass the command as a list and drop shell=True.")

        if name in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load"):
            self._add(node, "PY-PICKLE", f"Use of {name}()", "high", "unsafe-deserialization", "CWE-502",
                      "pickle executes arbitrary objects while loading; untrusted data leads to RCE.",
                      "Use json for untrusted data, or verify/sign the payload before unpickling.")

        if name in ("yaml.load",) and not isinstance(_kw(node, "Loader"), (ast.Attribute, ast.Name)):
            self._add(node, "PY-YAML", "yaml.load without a safe Loader", "high", "unsafe-deserialization", "CWE-502",
                      "yaml.load without SafeLoader can construct arbitrary Python objects.",
                      "Use yaml.safe_load(), or pass Loader=yaml.SafeLoader.")

        if _has_kw_false(node, "verify"):
            self._add(node, "PY-TLS-VERIFY", "TLS certificate verification disabled", "medium", "insecure-transport", "CWE-295",
                      "verify=False disables certificate checks, allowing man-in-the-middle attacks.",
                      "Remove verify=False, or pin a trusted CA bundle.")

        if name in ("hashlib.md5", "hashlib.sha1"):
            algo = name.split(".")[-1]
            self._add(node, "PY-WEAK-HASH", f"Weak hash: {algo}", "low", "weak-crypto", "CWE-327",
                      f"{algo} is cryptographically broken and unsafe for security use.",
                      "Use hashlib.sha256 or better; for passwords use bcrypt/argon2.")

        if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany"):
            first = node.args[0] if node.args else None
            if _is_dynamic_string(first):
                self._add(node, "PY-SQL", "SQL query built from a dynamic string", "high", "sql-injection", "CWE-89",
                          "Building SQL by concatenation/formatting allows SQL injection.",
                          "Use parameterized queries: execute(sql, params) with placeholders.")

        self.generic_visit(node)

    def _check_secret(self, target: ast.expr, value: ast.expr, node: ast.AST) -> None:
        if not (isinstance(target, ast.Name) and _SECRET_NAME.search(target.id)):
            return
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            return
        v = value.value
        if len(v) < 6 or _PLACEHOLDER.match(v):
            return
        self._add(node, "PY-SECRET", f"Hardcoded secret in '{target.id}'", "high", "hardcoded-secret", "CWE-798",
                  "A secret committed in source is exposed to anyone with repo access.",
                  "Load it from an environment variable or a secrets manager.")

    def visit_Assign(self, node: ast.Assign) -> None:
        for t in node.targets:
            self._check_secret(t, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_secret(node.target, node.value, node)
        self.generic_visit(node)


def scan_text(text: str) -> list[Finding]:
    """Run all rules over one file's source. Returns [] on a syntax error."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    visitor = _Visitor(text.splitlines())
    visitor.visit(tree)
    visitor.findings.sort(key=lambda f: (f.line, f.rule_id))
    return visitor.findings
