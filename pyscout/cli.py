"""Command-line entry point for pyscout."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from pyscout import __version__
from pyscout.report import has_findings, render_json, render_markdown, render_text
from pyscout.rules import scan_text
from pyscout.scanner import collect

DEFAULT_MODEL = "claude-opus-5-5"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pyscout",
        description="Hybrid security auditor for small Python projects "
        "(deterministic AST rules + optional LLM explanations).",
    )
    parser.add_argument("path", help="Python file or directory to audit")
    parser.add_argument(
        "--explain", action="store_true",
        help="Use Claude to rewrite why/fix in context and flag false positives",
    )
    parser.add_argument(
        "--model", default=DEFAULT_MODEL,
        help=f"Claude model for --explain (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--jobs", type=int, default=4, metavar="N",
        help="Concurrent files during --explain (default: 4)",
    )
    parser.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text",
        help="Report format (default: text)",
    )
    parser.add_argument(
        "-o", "--output", metavar="PATH",
        help="Write the report to a file instead of stdout",
    )
    parser.add_argument(
        "--record", metavar="PATH",
        help="JSON file with engagement/record fields (operator, scope, ...) "
        "to embed in the report header; see record.example.json",
    )
    parser.add_argument("--version", action="version", version=f"pyscout {__version__}")
    args = parser.parse_args(argv)

    try:
        files, warnings = collect(Path(args.path))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)

    if not files:
        print("No Python files to audit.", file=sys.stderr)
        return 0

    # Detection: always runs, offline, no key needed.
    results = {str(src.path): scan_text(src.text) for src in files}
    file_hashes = {str(src.path): src.sha256 for src in files}

    # Enrichment: optional LLM pass over the findings.
    if args.explain:
        client, err = _make_client()
        if err:
            print(f"error: {err}", file=sys.stderr)
            return 2
        by_path = {str(src.path): src for src in files}
        for path, msg in run_enrichment(
            client, results, by_path, args.model, max(1, args.jobs)
        ):
            print(f"warning: enrichment failed for {path}: {msg}", file=sys.stderr)

    record = None
    if args.record:
        try:
            record = json.loads(Path(args.record).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"error: could not read --record file: {e}", file=sys.stderr)
            return 2

    meta = {
        "tool": "pyscout",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": args.path,
        "explained": args.explain,
        "model": args.model if args.explain else None,
        "record": record,
    }

    if args.format == "json":
        text = render_json(results, meta, file_hashes)
    elif args.format == "markdown":
        text = render_markdown(results, meta, file_hashes)
    else:
        text = render_text(results, color=args.output is None and sys.stdout.isatty())

    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(text)

    return 1 if has_findings(results) else 0


def run_enrichment(client, results, by_path, model, jobs):
    """Enrich findings in parallel. Yields (path, error_message) for failures."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from pyscout.auditor import enrich

    targets = {p: f for p, f in results.items() if f}
    if not targets:
        return

    with ThreadPoolExecutor(max_workers=min(jobs, len(targets))) as pool:
        futures = {
            pool.submit(enrich, client, by_path[p].text, f, model): p
            for p, f in targets.items()
        }
        for future in as_completed(futures):
            path = futures[future]
            try:
                msg = future.result()
            except Exception as e:  # noqa: BLE001 - surface any worker failure, don't crash
                msg = str(e)
            if msg:
                yield path, msg


def _make_client():
    """Return (client, error). error is a message string if setup failed."""
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        return None, (
            "--explain needs Anthropic credentials. Set ANTHROPIC_API_KEY "
            "(or ANTHROPIC_AUTH_TOKEN), or copy .env.example."
        )
    try:
        from pyscout.auditor import make_client
        return make_client(), None
    except RuntimeError as e:
        return None, str(e)


if __name__ == "__main__":
    raise SystemExit(main())
