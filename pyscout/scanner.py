"""Collect Python source files to audit."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

# Directories we never want to walk into.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".venv", "venv", "env", "node_modules", ".tox", "build", "dist",
    ".eggs", "site-packages",
}

# Files larger than this (in characters) are skipped rather than silently
# truncated. Small tools rarely hit this; a huge generated file would just
# waste tokens and blur the audit.
MAX_CHARS = 60_000


@dataclass
class SourceFile:
    path: Path
    text: str
    sha256: str


def collect(target: Path) -> tuple[list[SourceFile], list[str]]:
    """Return (files_to_audit, warnings) for a file or directory target."""
    paths: list[Path]
    if target.is_file():
        paths = [target]
    elif target.is_dir():
        paths = sorted(
            p for p in target.rglob("*.py")
            if not any(part in SKIP_DIRS for part in p.parts)
        )
    else:
        raise FileNotFoundError(f"No such file or directory: {target}")

    files: list[SourceFile] = []
    warnings: list[str] = []
    for p in paths:
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as e:
            warnings.append(f"skipped (unreadable): {p} ({e})")
            continue
        if len(text) > MAX_CHARS:
            warnings.append(
                f"skipped (too large: {len(text)} chars > {MAX_CHARS}): {p}"
            )
            continue
        if not text.strip():
            continue
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        files.append(SourceFile(path=p, text=text, sha256=digest))

    return files, warnings
