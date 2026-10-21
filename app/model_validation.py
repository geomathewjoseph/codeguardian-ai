"""Strict post-generation validation for optional local-model review output."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import ValidationError

from app.schemas import ReviewReport
from app.security_engine import parse_unified_diff


class ModelOutputValidationError(ValueError):
    """The model produced malformed or ungrounded review data."""


def _json_payload(raw: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    candidate = raw.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", candidate, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        candidate = fenced.group(1)
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise ModelOutputValidationError(f"Model response is not valid JSON: {exc.msg}") from exc
    if not isinstance(parsed, dict):
        raise ModelOutputValidationError("Model response must be a JSON object")
    return parsed


def validate_model_report(raw: str | dict[str, Any], diff: str) -> ReviewReport:
    """Validate output schema and ensure every finding refers to a changed new-file line."""
    try:
        report = ReviewReport.model_validate(_json_payload(raw))
    except (ValidationError, ModelOutputValidationError) as exc:
        if isinstance(exc, ModelOutputValidationError):
            raise
        raise ModelOutputValidationError(f"Model response does not match review schema: {exc}") from exc

    locations = {
        changed_file.new_path: {line.new_line for line in changed_file.lines if line.new_line is not None}
        for changed_file in parse_unified_diff(diff)
        if changed_file.new_path
    }
    for finding in report.findings:
        allowed_lines = locations.get(finding.file)
        if not allowed_lines:
            raise ModelOutputValidationError(f"Finding {finding.id} refers to a file outside the changed diff")
        if any(line not in allowed_lines for line in range(finding.line_start, finding.line_end + 1)):
            raise ModelOutputValidationError(
                f"Finding {finding.id} refers to a line outside the changed diff: "
                f"{finding.file}:{finding.line_range}"
            )
    return report
