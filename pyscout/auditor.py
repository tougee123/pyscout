"""Optional LLM layer: explain rule findings in context and flag false positives.

This is enrichment only. Detection is done deterministically in rules.py; the
model never invents findings here, it just improves why/fix for the ones the
AST rules already flagged and judges whether each is a true positive.
"""

from __future__ import annotations

import json

from pyscout.models import Finding

# Import the SDK's error class if available, so enrich() can be imported and
# tested without the optional `anthropic` package installed.
try:
    from anthropic import APIError as _APIError
except ImportError:  # pragma: no cover - exercised only without the extra
    _APIError = Exception

ENRICH_SYSTEM = """\
You are a security reviewer refining findings from a static Python scanner.
You are given a source file and a list of findings (each with an index and a
line number). For each finding, decide whether it is a real issue in THIS code
and rewrite its explanation in plain language.

Respond with ONLY a JSON array (no prose, no markdown fences). One object per
input finding, with exactly these keys:
  "index": the finding's index (integer, echo it back)
  "why":   one sentence on why it matters here / how it could be exploited
  "fix":   one sentence with a concrete fix for this code
  "likely_false_positive": true if this pattern is safe as used here, else false
"""


def make_client():
    """Construct an Anthropic client, raising a clear error if the SDK is missing."""
    try:
        import anthropic
    except ImportError as e:
        raise RuntimeError(
            "--explain needs the anthropic SDK. Install with: pip install 'pyscout[explain]'"
        ) from e
    return anthropic.Anthropic()


def _number_lines(text: str) -> str:
    return "\n".join(f"{i:>4}  {line}" for i, line in enumerate(text.splitlines(), 1))


def enrich(client, source_text: str, findings: list[Finding], model: str) -> str | None:
    """Rewrite why/fix on `findings` in place. Returns an error string on failure."""
    if not findings:
        return None

    listing = "\n".join(
        f"[{i}] line {f.line}: {f.title} ({f.category}) -- {f.code}"
        for i, f in enumerate(findings)
    )
    user = (
        f"Source file:\n{_number_lines(source_text)}\n\n"
        f"Findings to review:\n{listing}"
    )

    try:
        response = client.messages.create(
            model=model,
            max_tokens=4000,
            output_config={"effort": "medium"},
            system=[{"type": "text", "text": ENRICH_SYSTEM, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}],
        )
    except _APIError as e:
        return str(e)

    if response.stop_reason == "refusal":
        return "model refused to enrich findings"

    text = next((b.text for b in response.content if b.type == "text"), "")
    try:
        data = json.loads(_extract_json_array(text))
    except (ValueError, json.JSONDecodeError) as e:
        return f"could not parse enrichment: {e}"

    for item in data:
        idx = item.get("index")
        if not isinstance(idx, int) or not (0 <= idx < len(findings)):
            continue
        f = findings[idx]
        if item.get("why"):
            f.why = str(item["why"])
        if item.get("fix"):
            f.fix = str(item["fix"])
        f.likely_false_positive = bool(item.get("likely_false_positive", False))
        f.enriched = True
    return None


def _extract_json_array(raw: str) -> str:
    s = raw.strip()
    if s.startswith("```"):
        s = s.split("```", 2)[1] if s.count("```") >= 2 else s.strip("`")
        if s.lstrip().startswith("json"):
            s = s.lstrip()[4:]
    start, end = s.find("["), s.rfind("]")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON array found in model response")
    return s[start : end + 1]
