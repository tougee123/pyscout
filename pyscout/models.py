"""Shared data model for findings."""

from __future__ import annotations

from dataclasses import dataclass

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    cwe: str           # e.g. "CWE-89", or "" if not mapped
    line: int
    code: str          # the offending source line, stripped
    why: str           # why it matters / how it could be exploited
    fix: str           # suggested fix
    enriched: bool = False   # True once the LLM has rewritten why/fix in context
    likely_false_positive: bool = False
