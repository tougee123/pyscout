# pyscout

**Hybrid security auditor for small Python projects.**

pyscout scans your Python code for common security issues with deterministic
AST rules — fast, offline, and free — then, optionally, uses Claude to explain
each finding in context and flag likely false positives.

The two layers are independent: the rule scan always runs with no API key, and
the LLM layer only kicks in with `--explain`.

## What it finds (rule layer)

- Code injection: `eval` / `exec`
- Command injection: `os.system`, `subprocess(..., shell=True)`
- SQL injection: queries built by concatenation / f-strings / `.format`
- Unsafe deserialization: `pickle`, `yaml.load` without a safe loader
- Hardcoded secrets (keys, tokens, passwords)
- Disabled TLS verification (`verify=False`)
- Weak hashes (`md5`, `sha1`)

Each rule ships with a plain-language **why** and **fix**, so the offline
report is already actionable.

## What `--explain` adds (LLM layer)

- Rewrites **why** / **fix** using the actual surrounding code
- Flags findings that are **likely false positives** in context

It never invents new findings — detection stays deterministic.

## Why

Built to audit my own small tools, and to help harden other small open-source
projects in the community. Issues found in third-party projects are reported
through **responsible disclosure** — privately to maintainers first, never
dropped publicly before a fix.

## Install

```bash
pip install -e .                 # rule layer only, zero dependencies
pip install -e '.[explain]'      # also install the Anthropic SDK for --explain
```

## Usage

```bash
pyscout path/to/file.py                      # offline rule scan (text)
pyscout path/to/project/                     # scan every .py under a directory
pyscout src/ --explain                       # add LLM explanations (needs ANTHROPIC_API_KEY)
pyscout src/ --explain --model claude-sonnet-5-5   # cheaper model for --explain
pyscout src/ --format json                   # machine-readable output
pyscout src/ --format markdown -o report.md  # write a Markdown evidence report
```

Exit code is `1` when real findings exist and `0` when clean, so it drops into
CI as a gate. (Findings the LLM marks as likely false positives don't fail the
build.)

## Reports & evidence

`--format markdown` (or `json`) produces a traceable report suited to a
defensive engagement's records:

- A metadata header: target, UTC timestamp, tool version, and which model (if
  any) reviewed the findings.
- A **SHA-256** of each scanned file, so the report is pinned to the exact code
  that was audited.
- A stable **finding ID** per issue, so the same finding can be tracked across
  re-scans.
- A **CWE** reference per finding, mapping it to the standard weakness class.

Use `-o PATH` to write the report to a file; stdout stays human-readable text.

### Engagement record

`--record record.json` embeds an engagement header in the report — operator,
organization/workspace ID, authorized scope, security contact, data-retention
note. Copy `record.example.json` and fill it in:

```bash
pyscout src/ --explain --format markdown --record record.json -o report.md
```

> **Note on scope.** Anthropic's Cyber Verification Program covers *your own*
> code, products, and infrastructure. This record header is a convenience for
> documenting defensive audits of in-scope assets — it is **not** an official
> CVP template, and auditing third-party projects is governed by the general
> Usage Policy and responsible disclosure, not a CVP grant.

Try it against the bundled insecure sample:

```bash
pyscout examples/vulnerable_sample.py
```

## Notes

- For broader coverage, run [`bandit`](https://bandit.readthedocs.io) and
  [`pip-audit`](https://pypi.org/project/pip-audit/) alongside pyscout —
  pyscout keeps a small, high-signal rule set rather than reimplementing them.
- Files larger than ~60k characters are skipped (not silently truncated).
- `--explain` default model is `claude-opus-5-5`; override with `--model`.

## Status

Early / experimental. Treat findings as a second opinion, not a guarantee.
