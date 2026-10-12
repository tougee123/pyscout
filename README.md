# pyscout

**Python security review with offline AST checks and optional Claude analysis.**

pyscout helps maintainers find common security weaknesses in small Python
projects, understand their impact, and produce actionable remediation reports.
It combines a dependency-free static scanner with Claude's ability to interpret
findings in the context of the surrounding code.

Built to review my own Python tools and support security improvements in small
open-source projects.

## How it works

1. **Detect locally.** Parse Python source with deterministic AST rules. Every
   finding includes a source location, severity, CWE, explanation, and suggested
   fix. No API key is required.
2. **Review with Claude.** Add `--explain` to get contextual impact explanations,
   concrete remediation advice, and likely-false-positive assessments.
3. **Keep the evidence.** Export text, JSON, or Markdown reports, apply fixes, and
   re-scan the code.

The scanner parses source without executing the target program. Claude reviews
existing rule findings; rule IDs, locations, and severities stay rule-defined.
Findings marked as likely false positives remain visible in the report.

## Rule coverage

| Category | Patterns checked | CWE |
| --- | --- | --- |
| Code injection | `eval`, `exec` | CWE-95 |
| Command injection | `os.system`, `os.popen`, `subprocess.*` with literal `shell=True` | CWE-78 |
| SQL injection | Dynamic strings passed directly to `execute` / `executemany`: concatenation, f-strings, `%`, `.format` | CWE-89 |
| Unsafe deserialization | `pickle.load` / `loads`, and selected `yaml.load` calls without an explicit loader | CWE-502 |
| Hardcoded secrets | String assignments to names resembling keys, tokens, or passwords, excluding common placeholders | CWE-798 |
| Disabled TLS verification | Calls with literal `verify=False` | CWE-295 |
| Weak cryptography | `hashlib.md5`, `hashlib.sha1` | CWE-327 |

## Quick start

Requires **Python 3.9+**. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .

pyscout examples/vulnerable_sample.py
```

The bundled sample produces **five high-severity findings**: a hardcoded key,
two shell command patterns, a dynamically constructed SQL query, and unsafe
pickle loading. The command exits with `1` because findings exist.

## Claude review

Install the Anthropic SDK and set your credentials:

```bash
python -m pip install -e '.[explain]'
export ANTHROPIC_API_KEY='your-api-key'

pyscout examples/vulnerable_sample.py --explain
```

For each file with findings, `--explain` sends the full source file and finding
list to the Anthropic API. Claude refines the impact explanation and suggested
fix, and assesses whether each finding is likely a false positive. Source is
processed locally when `--explain` is omitted.

The CLI also accepts `ANTHROPIC_AUTH_TOKEN` through the Anthropic SDK. Credentials
must be set in the environment; `.env` files are not loaded automatically.

To select a model available to your account:

```bash
pyscout src/ --explain --model claude-sonnet-5-5
```

## Usage

```bash
pyscout path/to/file.py                      # scan one file
pyscout path/to/project/                     # scan a directory
pyscout src/ --explain                       # add Claude review
pyscout src/ --format json                   # machine-readable output
pyscout src/ --format markdown -o report.md  # save a Markdown report
```

Directory scans collect `.py` files and exclude common environment, dependency,
build, and cache directories. Without `-o`, the report goes to stdout.

## Audit reports

JSON and Markdown reports include:

- Target, UTC timestamp, tool version, and the model selected when review is requested.
- SHA-256 source hashes: every collected file in JSON, files with findings in Markdown.
- Finding IDs, source locations, severity, rule IDs, and CWE references.
- Impact explanations, remediation advice, and likely-false-positive labels.

Finding IDs are repeatable for the same path, rule, line number, and source line.

Attach review metadata with `--record`:

```bash
cp record.example.json record.json
# Replace the example values with your actual review details.
pyscout src/ --format markdown --record record.json -o report.md
```

The record supports operator, organization/workspace ID, engagement ID, scope,
security contact, and retention notes.

## CI integration

| Exit code | Meaning |
| --- | --- |
| `0` | No findings remain after excluding likely false positives, or no files were collected |
| `1` | At least one finding is not marked as a likely false positive |
| `2` | A handled setup or input error |

Run without `--explain` for a deterministic CI gate. With `--explain`, Claude's
likely-false-positive assessments affect the exit code. If review fails with an
API error, refusal, or unparseable response, the CLI warns and retains the
affected file's original rule findings.
