"""Render audit results as a terminal report, JSON, or a Markdown evidence report."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from pyscout.models import SEVERITIES, Finding

_COLORS = {
    "critical": "\033[1;91m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
}
_RESET = "\033[0m"

Results = "dict[str, list[Finding]]"


def fingerprint(path: str, f: Finding) -> str:
    """Stable short ID for a finding, usable to track it across reports."""
    raw = f"{path}:{f.rule_id}:{f.line}:{f.code}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:12]


def _counts(results) -> tuple[int, dict[str, int]]:
    counts = {s: 0 for s in SEVERITIES}
    total = 0
    for findings in results.values():
        for f in findings:
            counts[f.severity] += 1
            total += 1
    return total, counts


def _summary_line(total: int, counts: dict[str, int]) -> str:
    if total == 0:
        return "No findings."
    parts = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s])
    return f"{total} finding(s): {parts}"


def render_text(results, color: bool = True) -> str:
    out: list[str] = []

    def sev(s: str) -> str:
        return f"{_COLORS.get(s, '')}{s.upper()}{_RESET}" if color else s.upper()

    for path, findings in results.items():
        if not findings:
            continue
        out.append(f"\n{path}")
        for f in sorted(findings, key=lambda x: SEVERITIES.index(x.severity)):
            fp = "  ~likely false positive" if f.likely_false_positive else ""
            cwe = f" {f.cwe}" if f.cwe else ""
            out.append(f"  [{sev(f.severity)}] {f.title}  ({f.rule_id}{cwe}:{f.line}){fp}")
            out.append(f"      code: {f.code}")
            out.append(f"      why:  {f.why}")
            out.append(f"      fix:  {f.fix}")

    total, counts = _counts(results)
    out.append("\n" + "-" * 60)
    out.append(_summary_line(total, counts))
    return "\n".join(out)


def render_json(results, meta: dict, file_hashes: dict[str, str]) -> str:
    out = {
        "meta": meta,
        "files": {
            path: {
                "sha256": file_hashes.get(path),
                "findings": [
                    {"id": fingerprint(path, f), **asdict(f)} for f in findings
                ],
            }
            for path, findings in results.items()
        },
    }
    return json.dumps(out, indent=2, ensure_ascii=False)


def render_markdown(results, meta: dict, file_hashes: dict[str, str]) -> str:
    total, counts = _counts(results)
    lines: list[str] = []
    lines.append("# pyscout security report")
    lines.append("")
    lines.append(f"- **Target:** `{meta['target']}`")
    lines.append(f"- **Generated:** {meta['generated_at']}")
    lines.append(f"- **Tool:** {meta['tool']} {meta['version']}")
    if meta.get("explained"):
        lines.append(f"- **LLM review:** {meta['model']}")
    else:
        lines.append("- **LLM review:** not run (rule layer only)")
    lines.append(f"- **Summary:** {_summary_line(total, counts)}")
    lines.append("")

    record = meta.get("record") or {}
    if record:
        lines.append("## Engagement record")
        lines.append("")
        for key, label in (
            ("operator", "Operator (approved user)"),
            ("organization_id", "Organization / workspace ID"),
            ("engagement_id", "Engagement ID"),
            ("scope", "Authorized scope"),
            ("security_contact", "Security contact"),
            ("data_retention", "Data retention"),
            ("notes", "Notes"),
        ):
            if record.get(key):
                lines.append(f"- **{label}:** {record[key]}")
        lines.append("")

    any_findings = False
    for path, findings in results.items():
        if not findings:
            continue
        any_findings = True
        lines.append(f"## `{path}`")
        lines.append(f"<sub>sha256: `{file_hashes.get(path, '?')}`</sub>")
        lines.append("")
        for f in sorted(findings, key=lambda x: SEVERITIES.index(x.severity)):
            fp = fingerprint(path, f)
            flag = " — _likely false positive_" if f.likely_false_positive else ""
            lines.append(f"### [{f.severity.upper()}] {f.title}{flag}")
            lines.append("")
            lines.append(f"- **ID:** `{fp}`")
            lines.append(f"- **Rule:** `{f.rule_id}` ({f.category})")
            if f.cwe:
                lines.append(f"- **CWE:** {f.cwe}")
            lines.append(f"- **Location:** `{path}:{f.line}`")
            lines.append("")
            lines.append("```python")
            lines.append(f.code)
            lines.append("```")
            lines.append("")
            lines.append(f"**Impact.** {f.why}")
            lines.append("")
            lines.append(f"**Remediation.** {f.fix}")
            lines.append("")

    if not any_findings:
        lines.append("_No findings._")
        lines.append("")

    return "\n".join(lines)


def has_findings(results) -> bool:
    return any(
        f for findings in results.values() for f in findings if not f.likely_false_positive
    )
