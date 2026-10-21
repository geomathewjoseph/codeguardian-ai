"""
CodeGuardian AI — Local Review History & Report Exporter
Stores audit sessions in local JSON storage and generates compliance Markdown/JSON reports.
"""

import os
import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
from app.schemas import ReviewReport

HISTORY_FILE = os.environ.get(
    "CODEGUARDIAN_HISTORY_FILE",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "review_history.json"),
)


def _history_safe_report(report: ReviewReport) -> Dict[str, Any]:
    """Persist review metadata without saving source snippets, patches, or test code."""
    data = report.model_dump()
    for finding in data.get("findings", []):
        finding["evidence"] = []
        finding["suggested_fix"] = None
        for test in finding.get("related_tests", []):
            test["code"] = ""
            test["execution_output"] = None
    for test in data.get("unit_tests", []):
        test["code"] = ""
        test["execution_output"] = None
    return data

def save_review_history(report: ReviewReport, repo_name: str = "llm-fine-tuning", commit_hash: str = "HEAD") -> str:
    """Appends completed review to local history store."""
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception:
            history = []

    session_id = f"REV-{int(time.time())}"
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    entry = {
        "id": session_id,
        "timestamp": timestamp_str,
        "repo_name": repo_name,
        "commit_hash": commit_hash,
        "verdict": report.verdict,
        "risk_level": report.risk_level,
        "counts": report.counts.model_dump(),
        "finding_count": len(report.findings),
        "duration_ms": report.execution_time_ms,
        "summary": report.summary,
        "report": _history_safe_report(report),
    }

    # Prepend newest review first
    history.insert(0, entry)
    # Cap history at 50 sessions
    history = history[:50]

    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

    return session_id

def get_review_history() -> List[Dict[str, Any]]:
    """Retrieves list of past review sessions."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def export_report_markdown(report: ReviewReport, repo_name: str = "llm-fine-tuning", commit_hash: str = "HEAD") -> str:
    """Formats ReviewReport into an engineering-grade Markdown audit document."""
    timestamp = report.timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    md = [
        f"# CodeGuardian Security Audit Report",
        f"**Repository:** `{repo_name}` | **Commit:** `{commit_hash}` | **Generated:** `{timestamp}`",
        f"**Engine:** `{report.engine}` | **Execution Latency:** `{report.execution_time_ms} ms`\n",
        f"## Executive Summary",
        f"- **Merge Verdict:** `{report.verdict}`",
        f"- **Overall Risk Level:** `{report.risk_level}`",
        f"- **Finding Breakdown:** {report.counts.critical} Critical, {report.counts.high} High, {report.counts.medium} Medium, {report.counts.low} Low",
        f"- **CVSS Risk:** Max Score: **{report.max_cvss or 'N/A'}**, Average: **{report.average_cvss or 'N/A'}**",
        f"- **Summary:** {report.summary}\n",
        f"## Analyzed Files",
    ]

    for f in report.analyzed_files:
        md.append(f"- `{f}`")
    md.append("")

    if report.compliance_matrix:
        md.append("## 🛡️ OWASP Top 10 Compliance Mapping\n")
        md.append("| Category | Standard & Description | Finding Count | Finding IDs |")
        md.append("| :--- | :--- | :---: | :--- |")
        for item in report.compliance_matrix:
            md.append(f"| `{item.category_id}` | {item.title} | **{item.count}** | {', '.join(item.finding_ids)} |")
        md.append("")

    if report.findings:
        md.append("## Vulnerability Findings\n")
        for f in report.findings:
            cvss_tag = f" | CVSS {f.cvss_score}" if f.cvss_score else ""
            vector_line = f"**CVSS v3.1 Vector:** `{f.cvss_vector}`  \n" if f.cvss_vector else ""
            md.extend([
                f"### [{f.severity}{cvss_tag}] {f.rule_id} — `{f.file}:{f.line_range}`",
                f"**Confidence:** `{f.confidence}` | **Status:** `{f.patch_status}`\n",
                vector_line + f"**Description:**  \n{f.description}\n",
                f"**Exploit Conditions:**  \n{f.exploit_conditions or 'N/A'}\n",
                f"**Remediation Recommendation:**  \n{f.remediation}\n",
            ])
            if f.suggested_fix:
                md.extend([
                    "**Proposed Grounded Patch:**",
                    "```diff",
                    f.suggested_fix,
                    "```\n"
                ])
    else:
        md.append("## Vulnerability Findings\n*No critical security findings detected in this review.*\n")

    if report.unit_tests:
        md.extend([
            "## Candidate Regression Tests"
        ])
        for test in report.unit_tests:
            md.extend([
                f"### `{test.name}`",
                f"**Framework:** `{test.framework}` | **Execution State:** `{test.status}`\n",
                test.description,
                "",
                "```python",
                test.code,
                "```\n"
            ])

    md.extend([
        "---",
        "*Report generated locally by CodeGuardian AI Workstation (Zero telemetry egress).*"
    ])

    return "\n".join(md)


def export_pr_summary_markdown(report: ReviewReport) -> str:
    """Format ReviewReport into a clean, GitHub/GitLab-ready pull request review comment."""
    verdict_emoji = "🔴" if report.verdict == "REQUEST_CHANGES" else ("🟡" if report.verdict == "COMMENT" else "🟢")
    lines = [
        f"## {verdict_emoji} CodeGuardian AI Security Review — `{report.verdict}`",
        f"**Risk Level:** `{report.risk_level}` | **Files Audited:** {len(report.analyzed_files)} | **Scan Time:** `{report.execution_time_ms}ms`\n",
        f"> {report.summary}\n",
        "| Severity | Count |",
        "| :--- | :---: |",
        f"| 🔴 Critical | **{report.counts.critical}** |",
        f"| 🟠 High | **{report.counts.high}** |",
        f"| 🟡 Medium | **{report.counts.medium}** |",
        f"| 🔵 Low | **{report.counts.low}** |\n",
    ]

    if report.findings:
        lines.append("### Detected Vulnerabilities\n")
        for finding in report.findings:
            sev_icon = "🔴" if finding.severity in ("CRITICAL", "HIGH") else "🟡"
            lines.extend([
                f"<details open>",
                f"<summary>{sev_icon} <b>[{finding.severity}] {finding.rule_id}</b> in <code>{finding.file}:{finding.line_range}</code></summary>\n",
                f"- **Title:** {finding.title}",
                f"- **Description:** {finding.description}",
                f"- **Confidence:** `{finding.confidence}`",
            ])
            if finding.evidence:
                lines.extend([
                    "- **Evidence:**",
                    "```" + (finding.file.split('.')[-1] if '.' in finding.file else ""),
                    *finding.evidence,
                    "```",
                ])
            lines.extend([
                f"- **Remediation:** {finding.remediation}\n",
                "</details>\n",
            ])
    else:
        lines.append("✅ **No deterministic security vulnerabilities detected in changed lines.**\n")

    lines.append("*Reviewed by CodeGuardian AI (Local-first, deterministic AST security engine).*")
    return "\n".join(lines)


def export_report_sarif(report: ReviewReport, repo_name: str = "llm-fine-tuning") -> Dict[str, Any]:
    """Generates OASIS SARIF v2.1.0 JSON for GitHub Code Scanning / GitLab SAST integration."""
    severity_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }

    rules_dict: Dict[str, Dict[str, Any]] = {}
    results = []

    for finding in report.findings:
        rule_id = finding.rule_id
        if rule_id not in rules_dict:
            tags = ["security", finding.category.lower(), finding.severity.lower()]
            if finding.owasp_category:
                tags.append(finding.owasp_category)
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "help": {"text": finding.remediation},
                "properties": {
                    "tags": tags,
                    "problem.severity": finding.severity.lower(),
                },
            }

        results.append({
            "ruleId": rule_id,
            "level": severity_map.get(finding.severity, "warning"),
            "message": {
                "text": f"{finding.title}: {finding.description}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(1, finding.line_start),
                            "endLine": max(1, finding.line_end),
                        },
                    }
                }
            ],
            "properties": {
                "confidence": finding.confidence,
                "provenance": finding.provenance,
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeGuardian AI",
                        "semanticVersion": report.version,
                        "informationUri": "https://github.com/codeguardian/codeguardian-ai",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }
