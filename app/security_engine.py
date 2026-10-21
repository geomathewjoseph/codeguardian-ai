"""Deterministic, source-located review of unified Git diffs.

The engine deliberately scans only added lines. It is a bounded first stage in the
review pipeline, not a claim of comprehensive security coverage or a substitute for
an independently loaded local model.
"""

from __future__ import annotations

import fnmatch
import json
import math
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None

from app.schemas import ComplianceItem, Finding, ReviewReport, SecurityPolicyConfig, SeverityCounts, UnitTestFixture


HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
SQL_KEYWORD_RE = re.compile(r"\b(select|insert\s+into|update\s+\w+\s+set|delete\s+from)\b", re.IGNORECASE)
DYNAMIC_INTERPOLATION_RE = re.compile(r"""(?:\bf["']|\.format\(|%\s*\(?\s*\w+|\+\s*\w+|\$\{[^}]+\})""", re.IGNORECASE)
SECRET_RE = re.compile(
    r"^\s*(?:(?:const|let|var|final)\s+)?(?:(?:api|jwt|private|secret)[_-]?\w+|password)\s*=\s*[\"'][^\"'\n]{8,}[\"']\s*(?:#.*)?$",
    re.IGNORECASE,
)
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")
GITHUB_PAT_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
OPENAI_KEY_RE = re.compile(r"\bsk-(?:proj-|live-)?[A-Za-z0-9_-]{32,}\b")
ANTHROPIC_KEY_RE = re.compile(r"\bsk-ant-(?:api\d+-)[A-Za-z0-9_-]{32,}\b")
HUGGINGFACE_KEY_RE = re.compile(r"\bhf_[A-Za-z0-9]{32,}\b")
STRIPE_KEY_RE = re.compile(r"\b[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}\b")
DB_URI_SECRET_RE = re.compile(r"""\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|amqp|mssql):\/\/[^\s"'`]+:[^\s"'`]+@[^\s"'`]+\b""", re.IGNORECASE)
ASSIGNMENT_TOKEN_RE = re.compile(
    r"""(?:token|key|secret|password|api[_-]?key|auth)\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{20,})["']""",
    re.IGNORECASE,
)
PATH_INPUT_RE = re.compile(r"(?:pathlib?\.Path|os\.path\.join|path\.join|open)\([^\n]*(?:filename|user_path|destination|req\.(?:body|query)|request\.)", re.IGNORECASE)
ZIP_SLIP_RE = re.compile(r"\b(?:tar|tarfile|zip|zipfile|ArchiveFile|archive)\b[^\n]*\.(?:extractall|extract)\s*\(", re.IGNORECASE)
COMMAND_RE = re.compile(
    r"(?:os\.(?:system|popen)|subprocess\.(?:run|Popen|call|check_output|check_call)|child_process\.(?:exec|execSync|spawn)|execSync|execFile|exec)\([^\n]*",
    re.IGNORECASE,
)
DESERIALIZATION_RE = re.compile(
    r"\b(?:pickle|_pickle|yaml|jsonpickle|dill|shelve)\.(?:loads?|decode|open)\s*\(|\btorch\.load\s*\(",
    re.IGNORECASE,
)
SHELL_TRUE_RE = re.compile(r"\bshell\s*=\s*True\b")
XSS_RE = re.compile(r"(?:dangerouslySetInnerHTML\s*=|innerHTML\s*=|document\.write\s*\(|v-html\s*=)", re.IGNORECASE)
MARKUP_XSS_RE = re.compile(r"""(?:Markup|markupsafe\.Markup)\s*\([^\n]*(?:f["']|\+|\.format|%)""", re.IGNORECASE)
BROKEN_CRYPTO_RE = re.compile(
    r"\b(?:hashlib\.(?:md5|sha1)|crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"]\)|DES\.new|ARC4\.new|AES\.MODE_ECB|modes\.ECB\(\)|Blowfish\.new)\b",
    re.IGNORECASE,
)
DISABLED_TLS_RE = re.compile(r"\b(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|check_hostname\s*=\s*False)\b")
SSRF_RE = re.compile(
    r"(?:requests\.(?:get|post|put|delete|request)|httpx\.(?:get|post|put|delete|request|Client|AsyncClient)|urllib\.request\.urlopen|axios\.(?:get|post)|fetch|client\.(?:get|post|put|delete)|session\.(?:get|post))\([^\n]*(?:req\.(?:query|params|body)|request\.(?:args|form|GET|POST)|user_url|target_url|webhook_url|callback_url|dest_url|destination_url|remote_url)",
    re.IGNORECASE,
)
REDOS_RE = re.compile(
    r"(?:re\.compile|new RegExp)\s*\([^\n]*(?:[\+\*]\s*[\)\}]{1,4}\s*[\+\*]|(?:\([^\)]*\|[^\)]*\)[\+\*]))",
    re.IGNORECASE,
)
CORS_WILDCARD_RE = re.compile(
    r"""(?:Access-Control-Allow-Origin["']?\s*[:=,]\s*["']\*|cors\s*\(\s*\{\s*origin\s*:\s*["']?\*|allow_origins\s*=\s*\[\s*["']\*["']\s*\])""",
    re.IGNORECASE,
)
JWT_NONE_ALG_RE = re.compile(r"""(?:algorithms?\s*=\s*\[?["']none["']|verify_signature\s*=\s*False|algorithms?\s*:\s*\[?["']none["'])""", re.IGNORECASE)
PROTOTYPE_POLLUTION_RE = re.compile(r"""(?:__proto__|constructor\s*\[\s*["']prototype["']\])""", re.IGNORECASE)
XXE_RE = re.compile(r"""(?:xml\.etree\.ElementTree\.(?:parse|fromstring)|xml\.sax\.parse|minidom\.parse|lxml\.etree\.(?:parse|fromstring))\s*\(""", re.IGNORECASE)
OPEN_REDIRECT_RE = re.compile(r"""(?:redirect|res\.redirect)\s*\([^\n]*(?:req\.(?:query|params|body)|request\.(?:args|form|GET)|url_param|next_url)""", re.IGNORECASE)
INSECURE_TEMPFILE_RE = re.compile(r"""\btempfile\.mktemp\s*\(""", re.IGNORECASE)
SECURITY_ASSERT_RE = re.compile(r"""^\s*assert\s+(?:user\.|token|role|is_admin|authenticated|authorized|permission)""", re.IGNORECASE)
PERMISSIVE_CHMOD_RE = re.compile(r"""(?:os\.chmod|fs\.chmod)\s*\([^\n]*(?:0o?777|0777|0o?666)""", re.IGNORECASE)
SSTI_RE = re.compile(
    r"""(?:render_template_string\s*\(|jinja2\.Template\s*\(|Environment\([^\)]*\)\.from_string\s*\()[^\n]*(?:f["']|\+|\.format|%|\b(?:req|request|params|user_input|template|html|content)\b)""",
    re.IGNORECASE,
)
INSECURE_RANDOM_RE = re.compile(
    r"""(?:token|secret|key|salt|password|session_?id|nonce|auth|verification_?code)\s*[:=]\s*[^\n]*(?:random\.(?:random|randint|choice|randrange)|Math\.random)\s*\(""",
    re.IGNORECASE,
)
MASS_ASSIGNMENT_RE = re.compile(
    r"""\b(?:create|update|update_or_create)\s*\(\s*\*\*(?:request\.(?:POST|GET|data|json)|req\.(?:body|query|params))\b""",
    re.IGNORECASE,
)

VULN_DEP_PATTERNS = [
    (re.compile(r"""^\s*requests\s*([<]=?|==)\s*2\.(?:[0-9]|1[0-9]|2[0-9]|30)\b""", re.IGNORECASE), "requests < 2.31.0 (CVE-2023-32681 session leak)"),
    (re.compile(r"""^\s*urllib3\s*([<]=?|==)\s*(?:1\.26\.(?:[0-9]|1[0-7])|2\.0\.[0-6])\b""", re.IGNORECASE), "urllib3 < 1.26.18 / 2.0.7 (CVE-2023-45803 cookie injection)"),
    (re.compile(r"""^\s*flask\s*([<]=?|==)\s*(?:[01]\.|2\.[01]\.|2\.2\.[0-4]\b)""", re.IGNORECASE), "flask < 2.2.5 (CVE-2023-30861 cookie disclosure)"),
    (re.compile(r"""^\s*pyyaml\s*([<]=?|==)\s*[0-5]\.[0-3]\b""", re.IGNORECASE), "pyyaml < 5.4 (CVE-2020-14343 arbitrary code execution)"),
    (re.compile(r"""["']lodash["']\s*:\s*["']~?(?:[0-3]\.|4\.(?:[0-9]|1[0-6])\.|4\.17\.(?:[0-9]|1[0-9]|20)\b)""", re.IGNORECASE), "lodash < 4.17.21 (CVE-2021-23337 command injection)"),
    (re.compile(r"""["']jsonwebtoken["']\s*:\s*["']~?(?:[0-8]\.|9\.0\.0\b)""", re.IGNORECASE), "jsonwebtoken < 9.0.0 (CVE-2022-23529 RCE)"),
]

RULE_OWASP_MAP: dict[str, str] = {
    "SEC-SQLI": "A03:2021-Injection",
    "SEC-CMD-INJECTION": "A03:2021-Injection",
    "SEC-PATH-TRAVERSAL": "A01:2021-Broken Access Control",
    "SEC-HARDCODED-SECRET": "A07:2021-Identification and Authentication Failures",
    "SEC-HIGH-ENTROPY-SECRET": "A07:2021-Identification and Authentication Failures",
    "SEC-INSECURE-DESERIALIZATION": "A08:2021-Software and Data Integrity Failures",
    "SEC-XSS": "A03:2021-Injection",
    "SEC-BROKEN-CRYPTO": "A02:2021-Cryptographic Failures",
    "SEC-DISABLED-TLS": "A02:2021-Cryptographic Failures",
    "SEC-SSRF": "A10:2021-Server-Side Request Forgery",
    "SEC-REDOS": "A03:2021-Injection",
    "SEC-CORS-WILDCARD": "A01:2021-Broken Access Control",
    "SEC-JWT-NONE-ALG": "A02:2021-Cryptographic Failures",
    "SEC-PROTOTYPE-POLLUTION": "A08:2021-Software and Data Integrity Failures",
    "SEC-VULN-DEPENDENCY": "A06:2021-Vulnerable and Outdated Components",
    "SEC-XXE": "A05:2021-Security Misconfiguration",
    "SEC-OPEN-REDIRECT": "A01:2021-Broken Access Control",
    "SEC-INSECURE-TEMPFILE": "A08:2021-Software and Data Integrity Failures",
    "SEC-SECURITY-ASSERT": "A04:2021-Insecure Design",
    "SEC-PERMISSIVE-CHMOD": "A01:2021-Broken Access Control",
    "SEC-SSTI": "A03:2021-Injection",
    "SEC-INSECURE-RANDOM": "A02:2021-Cryptographic Failures",
    "SEC-MASS-ASSIGNMENT": "A01:2021-Broken Access Control",
}

RULE_CVSS_MAP: dict[str, tuple[float, str]] = {
    "SEC-SQLI": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SEC-CMD-INJECTION": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SEC-INSECURE-DESERIALIZATION": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SEC-SSRF": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "SEC-JWT-NONE-ALG": (8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SEC-PATH-TRAVERSAL": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "SEC-HARDCODED-SECRET": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "SEC-HIGH-ENTROPY-SECRET": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "SEC-REDOS": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
    "SEC-PROTOTYPE-POLLUTION": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"),
    "SEC-VULN-DEPENDENCY": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"),
    "SEC-XXE": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "SEC-SECURITY-ASSERT": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SEC-DISABLED-TLS": (7.4, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "SEC-PERMISSIVE-CHMOD": (7.3, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "SEC-XSS": (7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "SEC-CORS-WILDCARD": (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"),
    "SEC-OPEN-REDIRECT": (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "SEC-INSECURE-TEMPFILE": (5.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    "SEC-BROKEN-CRYPTO": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "SEC-SSTI": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SEC-MASS-ASSIGNMENT": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "SEC-INSECURE-RANDOM": (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
}


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for a string to detect high-entropy secrets."""
    if not data or len(data) < 12:
        return 0.0
    length = len(data)
    counts: dict[str, int] = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy



@dataclass(frozen=True)
class DiffLine:
    kind: str
    text: str
    old_line: Optional[int] = None
    new_line: Optional[int] = None


@dataclass
class ChangedFile:
    old_path: Optional[str]
    new_path: Optional[str]
    status: str = "modified"
    lines: list[DiffLine] = field(default_factory=list)

    @property
    def display_path(self) -> str:
        return self.new_path or self.old_path or "unknown"

    @property
    def added_lines(self) -> list[DiffLine]:
        return [line for line in self.lines if line.kind == "add"]


def _strip_git_prefix(path: str) -> Optional[str]:
    value = path.strip().strip('"')
    if value == "/dev/null":
        return None
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    return value or None


def _header_paths(line: str) -> tuple[Optional[str], Optional[str]]:
    # Git quotes paths with spaces; this lightweight parser keeps normal Git paths
    # exact while gracefully falling back for unusual quoted headers.
    raw = line[len("diff --git "):].strip()
    if raw.startswith('"'):
        parts = re.findall(r'"(?:\\.|[^"\\])*"|\S+', raw)
    else:
        parts = raw.split(" ", 1)
    if len(parts) != 2:
        return None, None
    return _strip_git_prefix(parts[0]), _strip_git_prefix(parts[1])


def parse_unified_diff(diff_text: str) -> list[ChangedFile]:
    """Parse Git file boundaries and old/new hunk coordinates without guessing."""
    files: list[ChangedFile] = []
    current: Optional[ChangedFile] = None
    old_number = new_number = None

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("diff --git "):
            if current is not None:
                files.append(current)
            old_path, new_path = _header_paths(raw_line)
            current = ChangedFile(old_path=old_path, new_path=new_path)
            old_number = new_number = None
            continue

        if current is None:
            # A hunk-only snippet has no trustworthy file path. It can be displayed
            # but no source-located finding should be created from it.
            continue

        if raw_line.startswith("rename from "):
            current.old_path = raw_line[len("rename from "):].strip()
            current.status = "renamed"
            continue
        if raw_line.startswith("rename to "):
            current.new_path = raw_line[len("rename to "):].strip()
            current.status = "renamed"
            continue
        if raw_line.startswith("new file mode "):
            current.status = "added"
            continue
        if raw_line.startswith("deleted file mode "):
            current.status = "deleted"
            continue
        if raw_line.startswith("--- "):
            current.old_path = _strip_git_prefix(raw_line[4:])
            continue
        if raw_line.startswith("+++ "):
            current.new_path = _strip_git_prefix(raw_line[4:])
            continue

        hunk = HUNK_RE.match(raw_line)
        if hunk:
            old_number, new_number = int(hunk.group(1)), int(hunk.group(3))
            current.lines.append(DiffLine("hunk", raw_line))
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            current.lines.append(DiffLine("add", raw_line[1:], new_line=new_number))
            if new_number is not None:
                new_number += 1
            continue
        if raw_line.startswith("-") and not raw_line.startswith("---"):
            current.lines.append(DiffLine("delete", raw_line[1:], old_line=old_number))
            if old_number is not None:
                old_number += 1
            continue
        if raw_line.startswith(" "):
            current.lines.append(DiffLine("context", raw_line[1:], old_number, new_number))
            if old_number is not None:
                old_number += 1
            if new_number is not None:
                new_number += 1
            continue
        current.lines.append(DiffLine("meta", raw_line))

    if current is not None:
        files.append(current)
    return files


def parse_diff_files(diff_text: str) -> list[dict[str, object]]:
    """Compatibility view for callers that need a serialisable parsed diff."""
    return [
        {
            "file": item.display_path,
            "old_path": item.old_path,
            "new_path": item.new_path,
            "status": item.status,
            "added_lines": [line.text for line in item.added_lines],
            "deleted_lines": [line.text for line in item.lines if line.kind == "delete"],
            "hunk_headers": [line.text for line in item.lines if line.kind == "hunk"],
        }
        for item in parse_unified_diff(diff_text)
    ]


def _test_for(rule: str, path: str) -> list[UnitTestFixture]:
    """Generate an explicitly unexecuted candidate only when the target is clear."""
    if not path.endswith(".py"):
        return []
    module = path[:-3].replace("/", ".")

    if rule == "SEC-SQLI":
        return [
            UnitTestFixture(
                name="test_sql_injection_payload_is_rejected",
                framework="pytest",
                description=(
                    "Candidate regression test. Wire the repository's database fixture and "
                    "authentication entry point before executing it."
                ),
                code=(
                    f"# Requires the project's database fixture and authentication API.\n"
                    f"from {module} import authenticate_user\n\n"
                    f"def test_sql_injection_payload_is_rejected(db):\n"
                    f"    result = authenticate_user(db, \"admin' OR '1'='1' --\", \"wrong-password\")\n"
                    f"    assert result is None\n"
                ),
                status="GENERATED",
            )
        ]
    if rule == "SEC-PATH-TRAVERSAL":
        return [
            UnitTestFixture(
                name="test_path_traversal_payload_is_rejected",
                framework="pytest",
                description="Candidate regression test verifying directory traversal payloads ('../') are rejected.",
                code=(
                    f"# Verify directory traversal attempts raise an error or stay in sandbox.\n"
                    f"import pytest\n"
                    f"from {module} import handle_file\n\n"
                    f"def test_path_traversal_payload_is_rejected():\n"
                    f"    with pytest.raises((ValueError, PermissionError)):\n"
                    f"        handle_file('../../etc/passwd')\n"
                ),
                status="GENERATED",
            )
        ]
    if rule == "SEC-CMD-INJECTION":
        return [
            UnitTestFixture(
                name="test_command_injection_payload_is_rejected",
                framework="pytest",
                description="Candidate regression test verifying shell metacharacters are safely quoted or rejected.",
                code=(
                    f"# Verify shell injection payloads are rejected.\n"
                    f"import pytest\n"
                    f"from {module} import execute_task\n\n"
                    f"def test_command_injection_payload_is_rejected():\n"
                    f"    with pytest.raises((ValueError, PermissionError)):\n"
                    f"        execute_task('test; rm -rf /')\n"
                ),
                status="GENERATED",
            )
        ]
    if rule == "SEC-SSTI":
        return [
            UnitTestFixture(
                name="test_ssti_payload_is_escaped",
                framework="pytest",
                description="Candidate regression test verifying template expressions ('{{7*7}}') are treated as literal text.",
                code=(
                    f"# Verify template injection payload does not execute.\n"
                    f"from {module} import render_custom_template\n\n"
                    f"def test_ssti_payload_is_escaped():\n"
                    f"    output = render_custom_template('{{{{ 7 * 7 }}}}')\n"
                    f"    assert '49' not in output\n"
                ),
                status="GENERATED",
            )
        ]
    return []


def _rule_matches(line: str, filename: str = "") -> Iterable[tuple[str, str, str, str, str, Optional[str]]]:
    """Yield rule metadata for a single *added* source line."""
    if SQL_KEYWORD_RE.search(line) and DYNAMIC_INTERPOLATION_RE.search(line):
        yield (
            "SEC-SQLI",
            "CWE-89",
            "Dynamic SQL query uses string interpolation",
            "CRITICAL",
            "HIGH",
            "Added SQL text appears to interpolate runtime values rather than bind parameters.",
        )
    if COMMAND_RE.search(line) and (SHELL_TRUE_RE.search(line) or DYNAMIC_INTERPOLATION_RE.search(line) or any(k in line for k in ["os.system", "os.popen", "execSync", "child_process.exec"])):
        yield (
            "SEC-CMD-INJECTION",
            "CWE-78",
            "Dynamic command execution may permit command injection",
            "CRITICAL",
            "HIGH",
            "A dynamic command is executed through a shell-sensitive API.",
        )
    if PATH_INPUT_RE.search(line):
        yield (
            "SEC-PATH-TRAVERSAL",
            "CWE-22",
            "User-controlled path reaches a filesystem operation",
            "HIGH",
            "MEDIUM",
            "The added path operation includes a user-controlled filename or destination.",
        )
    if ZIP_SLIP_RE.search(line) and not any(safe in line.lower() for safe in ["filter='data'", "filter=\"data\"", "safe_extract"]):
        yield (
            "SEC-PATH-TRAVERSAL",
            "CWE-22",
            "Archive extraction without path traversal protection (Zip/Tar Slip)",
            "HIGH",
            "HIGH",
            "extractall() on unvalidated archives allows filenames with '../' to overwrite arbitrary files on disk (CVE-2007-4559).",
        )
    if SECRET_RE.search(line):
        yield (
            "SEC-HARDCODED-SECRET",
            "CWE-798",
            "Potential hardcoded credential committed in source",
            "HIGH",
            "HIGH",
            "A credential-like variable is assigned a literal value in an added line.",
        )
    if AWS_KEY_RE.search(line):
        yield (
            "SEC-HARDCODED-SECRET",
            "CWE-798",
            "Potential hardcoded AWS Access Key committed in source",
            "CRITICAL",
            "HIGH",
            "An AWS access key pattern was introduced in an added line.",
        )
    if GITHUB_PAT_RE.search(line):
        yield (
            "SEC-HARDCODED-SECRET",
            "CWE-798",
            "Potential hardcoded GitHub Personal Access Token committed in source",
            "CRITICAL",
            "HIGH",
            "A GitHub personal access token prefix was identified in an added line.",
        )
    if SLACK_TOKEN_RE.search(line):
        yield (
            "SEC-HARDCODED-SECRET",
            "CWE-798",
            "Potential hardcoded Slack API token committed in source",
            "HIGH",
            "HIGH",
            "A Slack API bearer token pattern was committed in an added line.",
        )
    if OPENAI_KEY_RE.search(line):
        yield (
            "SEC-HARDCODED-SECRET",
            "CWE-798",
            "Potential hardcoded OpenAI API key committed in source",
            "CRITICAL",
            "HIGH",
            "An OpenAI API key pattern was committed directly in source control.",
        )
    if ANTHROPIC_KEY_RE.search(line):
        yield (
            "SEC-HARDCODED-SECRET",
            "CWE-798",
            "Potential hardcoded Anthropic API key committed in source",
            "CRITICAL",
            "HIGH",
            "An Anthropic API key pattern was committed directly in source control.",
        )
    if HUGGINGFACE_KEY_RE.search(line):
        yield (
            "SEC-HARDCODED-SECRET",
            "CWE-798",
            "Potential hardcoded HuggingFace token committed in source",
            "HIGH",
            "HIGH",
            "A HuggingFace access token pattern was committed directly in source control.",
        )
    if STRIPE_KEY_RE.search(line):
        yield (
            "SEC-HARDCODED-SECRET",
            "CWE-798",
            "Potential hardcoded Stripe secret API key committed in source",
            "CRITICAL",
            "HIGH",
            "A Stripe API secret key pattern was committed directly in source control.",
        )
    if DB_URI_SECRET_RE.search(line):
        yield (
            "SEC-HARDCODED-SECRET",
            "CWE-798",
            "Plaintext database credentials exposed in connection URI",
            "CRITICAL",
            "HIGH",
            "A database connection URI with embedded plaintext username and password was committed to source control.",
        )
    if PRIVATE_KEY_RE.search(line):
        yield (
            "SEC-HARDCODED-SECRET",
            "CWE-798",
            "Unencrypted private key committed in source",
            "CRITICAL",
            "HIGH",
            "A private cryptographic key header was introduced directly into source control.",
        )
    assign_match = ASSIGNMENT_TOKEN_RE.search(line)
    if assign_match and not any(ign in line.lower() for ign in ["dummy", "example", "placeholder", "test", "todo"]):
        token_candidate = assign_match.group(1)
        if shannon_entropy(token_candidate) >= 4.2:
            yield (
                "SEC-HIGH-ENTROPY-SECRET",
                "CWE-798",
                "Potential high-entropy secret committed in source",
                "HIGH",
                "HIGH",
                f"A high-entropy literal ({len(token_candidate)} chars) was assigned to a credential-like identifier.",
            )
    if DESERIALIZATION_RE.search(line):
        if "torch.load" in line:
            if "weights_only=True" not in line or "weights_only=False" in line:
                yield (
                    "SEC-INSECURE-DESERIALIZATION",
                    "CWE-502",
                    "Unsafe PyTorch checkpoint loading via torch.load without weights_only lock",
                    "CRITICAL",
                    "HIGH",
                    "torch.load() executes arbitrary pickle bytecodes unless weights_only=True is explicitly enforced.",
                )
        elif "yaml.safe_load" not in line:
            yield (
                "SEC-INSECURE-DESERIALIZATION",
                "CWE-502",
                "Unsafe deserialization of potentially untrusted data",
                "HIGH",
                "MEDIUM",
                "The added line invokes a deserializer that can construct attacker-controlled objects.",
            )
    if XSS_RE.search(line):
        yield (
            "SEC-XSS",
            "CWE-79",
            "Potential Cross-Site Scripting (XSS) via raw HTML injection",
            "HIGH",
            "HIGH",
            "Raw unescaped HTML or markup is directly assigned to the DOM, potentially allowing script injection.",
        )
    if MARKUP_XSS_RE.search(line):
        yield (
            "SEC-XSS",
            "CWE-79",
            "Unescaped HTML markup constructed dynamically via Markup()",
            "HIGH",
            "HIGH",
            "Markup() disables template auto-escaping. Dynamic string formatting within Markup can lead to Cross-Site Scripting (XSS).",
        )
    if BROKEN_CRYPTO_RE.search(line):
        yield (
            "SEC-BROKEN-CRYPTO",
            "CWE-327",
            "Use of broken or obsolete cryptographic algorithm",
            "MEDIUM",
            "HIGH",
            "A collision-vulnerable hash (MD5/SHA-1) or deprecated cipher was introduced in an added line.",
        )
    if DISABLED_TLS_RE.search(line):
        yield (
            "SEC-DISABLED-TLS",
            "CWE-295",
            "Disabled TLS/SSL certificate verification",
            "HIGH",
            "HIGH",
            "Certificate verification is disabled in added code, leaving network communication vulnerable to MITM attacks.",
        )
    if SSRF_RE.search(line):
        yield (
            "SEC-SSRF",
            "CWE-918",
            "Potential Server-Side Request Forgery (SSRF)",
            "HIGH",
            "MEDIUM",
            "An outbound network request uses request-supplied parameters without verified destination boundaries.",
        )
    if REDOS_RE.search(line):
        yield (
            "SEC-REDOS",
            "CWE-1333",
            "Potential Regular Expression Denial of Service (ReDoS)",
            "MEDIUM",
            "HIGH",
            "The added regular expression uses nested quantifiers or overlapping repetition that can trigger catastrophic backtracking.",
        )
    if CORS_WILDCARD_RE.search(line):
        yield (
            "SEC-CORS-WILDCARD",
            "CWE-942",
            "Overly permissive CORS wildcard policy",
            "MEDIUM",
            "MEDIUM",
            "Wildcard '*' Access-Control-Allow-Origin was configured in added code, allowing arbitrary external domains to interact with this resource.",
        )
    if JWT_NONE_ALG_RE.search(line):
        yield (
            "SEC-JWT-NONE-ALG",
            "CWE-347",
            "Insecure JWT algorithm or signature verification disabled",
            "CRITICAL",
            "HIGH",
            "The added line permits the 'none' algorithm or disables signature verification for JSON Web Tokens.",
        )
    if PROTOTYPE_POLLUTION_RE.search(line):
        yield (
            "SEC-PROTOTYPE-POLLUTION",
            "CWE-1321",
            "Potential Prototype Pollution via unsafe property access",
            "HIGH",
            "MEDIUM",
            "The added code manipulates __proto__ or constructor.prototype, which can allow an attacker to modify object prototypes globally.",
        )
    if XXE_RE.search(line):
        yield (
            "SEC-XXE",
            "CWE-611",
            "Potential XML External Entity (XXE) Injection",
            "HIGH",
            "MEDIUM",
            "The added code parses XML without explicitly disabling external entity or DTD resolution.",
        )
    if OPEN_REDIRECT_RE.search(line):
        yield (
            "SEC-OPEN-REDIRECT",
            "CWE-601",
            "Untrusted URL redirection (Open Redirect)",
            "MEDIUM",
            "MEDIUM",
            "An HTTP redirect operation consumes user-controlled input without URL domain allowlisting.",
        )
    if INSECURE_TEMPFILE_RE.search(line):
        yield (
            "SEC-INSECURE-TEMPFILE",
            "CWE-377",
            "Insecure temporary file creation via mktemp",
            "MEDIUM",
            "HIGH",
            "tempfile.mktemp() is prone to symlink races and TOCTOU vulnerabilities; use NamedTemporaryFile().",
        )
    if SECURITY_ASSERT_RE.search(line):
        yield (
            "SEC-SECURITY-ASSERT",
            "CWE-617",
            "Assert statement used for security authorization check",
            "HIGH",
            "HIGH",
            "Assert statements are removed when Python runs with optimization (-O), entirely bypassing this check.",
        )
    if PERMISSIVE_CHMOD_RE.search(line):
        yield (
            "SEC-PERMISSIVE-CHMOD",
            "CWE-732",
            "Overly permissive file permissions assigned",
            "HIGH",
            "HIGH",
            "File permissions are set to world-readable/writable (0o777 or 0o666), violating least privilege.",
        )
    if SSTI_RE.search(line):
        yield (
            "SEC-SSTI",
            "CWE-1336",
            "Server-Side Template Injection (SSTI)",
            "CRITICAL",
            "HIGH",
            "A template is dynamically constructed from user input or unvalidated strings, which can allow remote code execution.",
        )
    if INSECURE_RANDOM_RE.search(line):
        yield (
            "SEC-INSECURE-RANDOM",
            "CWE-330",
            "Use of cryptographically weak pseudo-random number generator for security credentials",
            "MEDIUM",
            "HIGH",
            "A security credential (token, key, or session secret) is generated using pseudo-random functions (random / Math.random) instead of cryptographically secure randomness.",
        )
    if MASS_ASSIGNMENT_RE.search(line):
        yield (
            "SEC-MASS-ASSIGNMENT",
            "CWE-915",
            "Mass assignment vulnerability via raw request dictionary unpacking",
            "HIGH",
            "MEDIUM",
            "Model creation or update dynamically unpacks raw HTTP request data without an attribute allowlist or schema boundary.",
        )
    if filename.endswith(("requirements.txt", "package.json", "Pipfile")):
        for pattern, dep_desc in VULN_DEP_PATTERNS:
            if pattern.search(line):
                yield (
                    "SEC-VULN-DEPENDENCY",
                    "CWE-1104",
                    f"Known vulnerable dependency: {dep_desc}",
                    "HIGH",
                    "HIGH",
                    f"The project manifest pins a package version subject to high-severity public vulnerability advisories: {dep_desc}.",
                )


def _remediation(rule: str) -> tuple[str, Optional[str]]:
    guidance = {
        "SEC-SQLI": (
            "Use the parameter-binding API documented by the active database driver. Preserve password-hash verification, reject missing users, and add tests for valid, invalid, unknown-user, and injection credentials.",
            "An automatic patch is withheld because the diff does not establish the database driver's placeholder style or row interface.",
        ),
        "SEC-CMD-INJECTION": (
            "Pass a validated argument list to the process API with shell execution disabled. Apply a strict allowlist to any user-controlled value.",
            "An automatic patch is withheld until the command's expected arguments and platform behavior are known.",
        ),
        "SEC-PATH-TRAVERSAL": (
            "Resolve the candidate path against a fixed root and reject it unless the resolved result remains below that root. Avoid using request-supplied destination directories.",
            "An automatic patch is withheld because the permitted storage root is not present in this diff.",
        ),
        "SEC-HARDCODED-SECRET": (
            "Remove the literal from version control, rotate it, and load the replacement from the deployment secret mechanism or environment at runtime.",
            "A patch substituting environment variable extraction is proposed.",
        ),
        "SEC-HIGH-ENTROPY-SECRET": (
            "Remove the high-entropy credential from code, rotate the affected API key or secret token immediately, and configure it via environment variables or a vault manager.",
            "No patch is generated because a secure secret identifier and deployment mechanism cannot be inferred safely.",
        ),
        "SEC-INSECURE-DESERIALIZATION": (
            "Use a safe data format or a safe loader and validate the decoded structure before use. Never deserialize untrusted objects with pickle.",
            "No patch is generated because the required data schema is not represented in the diff.",
        ),
        "SEC-XSS": (
            "Sanitize all dynamically inserted HTML using a trusted sanitizer library (such as DOMPurify) or assign text via textContent instead of innerHTML / dangerouslySetInnerHTML.",
            "An automatic patch is withheld because safe context encoding requires knowing the target DOM structure.",
        ),
        "SEC-BROKEN-CRYPTO": (
            "Migrate from MD5 or SHA-1 to modern algorithms: SHA-256 / SHA-512 for cryptographic integrity, bcrypt / argon2id for passwords, and AES-256-GCM for encryption.",
            "A grounded patch upgrading collision-vulnerable algorithms to SHA-256 is proposed.",
        ),
        "SEC-DISABLED-TLS": (
            "Enable TLS certificate verification. If internal self-signed certificates must be trusted, provide a pinned custom CA certificate path instead of disabling verification.",
            "A grounded patch restoring certificate verification is proposed.",
        ),
        "SEC-SSRF": (
            "Validate candidate outbound URLs against a strict allowlist of known safe hostnames and schemes. Explicitly block requests to internal or link-local IP addresses (127.0.0.1, 10.0.0.0/8, 169.254.169.254).",
            "An automatic patch is withheld because outbound network architecture boundaries are not defined in the diff.",
        ),
        "SEC-REDOS": (
            "Simplify regex syntax and avoid nested quantifiers (such as (a+)+ or (a|aa)+). Use atomic groups or pre-validate input string lengths before evaluating regexes.",
            "An automatic patch is withheld because regex semantics depend on application input grammar.",
        ),
        "SEC-CORS-WILDCARD": (
            "Replace wildcard '*' with an explicit allowlist of trusted application origins, especially if cookies, authorization headers, or sensitive user sessions are involved.",
            "A grounded patch restricting the CORS origin header is proposed.",
        ),
        "SEC-JWT-NONE-ALG": (
            "Explicitly configure accepted signing algorithms (such as RS256 or HS256) and ensure JWT signature verification is enabled in all environments.",
            "A grounded patch configuring explicit secure algorithms is proposed.",
        ),
        "SEC-PROTOTYPE-POLLUTION": (
            "Validate object keys against '__proto__', 'constructor', and 'prototype', or use Object.create(null) for unpolluted key-value dictionaries.",
            "An automatic patch is withheld because safe object structure depends on application context.",
        ),
        "SEC-VULN-DEPENDENCY": (
            "Upgrade the pinned dependency version to a patched release without known CVE vulnerabilities, and review changelogs for breaking changes.",
            "An automatic patch is withheld because updating dependency versions requires full regression testing.",
        ),
        "SEC-XXE": (
            "Disable external entity resolution (DTD processing) in XML parsers before loading untrusted XML data.",
            "An automatic patch is withheld because parser-specific secure configuration flags require context.",
        ),
        "SEC-OPEN-REDIRECT": (
            "Validate redirect targets against an explicit allowlist of relative paths or known trusted hosts.",
            "An automatic patch is withheld because the destination allowlist is not defined in the diff.",
        ),
        "SEC-INSECURE-TEMPFILE": (
            "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() which securely create files with restrictive permissions.",
            "A grounded patch replacing mktemp with NamedTemporaryFile is proposed.",
        ),
        "SEC-SECURITY-ASSERT": (
            "Replace assert statements with explicit conditional checks that raise standard exceptions (e.g. PermissionError). Python skips assert statements when running with optimizations (-O).",
            "A grounded patch converting the assertion to an explicit exception raise is proposed.",
        ),
        "SEC-PERMISSIVE-CHMOD": (
            "Restrict file permissions to the least privilege needed (e.g., 0o600 for user-only read/write, 0o700 for directories). Avoid 0o777 permissions.",
            "A grounded patch restricting permissions to 0o600 is proposed.",
        ),
        "SEC-SSTI": (
            "Avoid rendering raw user input inside template strings. Use parameterized template context dictionaries with auto-escaping enabled (e.g. render_template('template.html', variable=user_input)).",
            "An automatic patch is withheld because safe template separation requires isolating presentation templates from backend logic.",
        ),
        "SEC-INSECURE-RANDOM": (
            "Use cryptographically secure randomness via Python's 'secrets' module (e.g. secrets.token_urlsafe, secrets.choice) or Node.js 'crypto.randomBytes' for tokens, keys, passwords, or session IDs.",
            "A grounded patch substituting cryptographically secure 'secrets' methods is proposed.",
        ),
        "SEC-MASS-ASSIGNMENT": (
            "Validate and filter input dictionaries against an explicit field allowlist or strongly typed schema before updating or creating model records.",
            "An automatic patch is withheld because allowed model attributes cannot be inferred safely from the diff.",
        ),
    }
    return guidance.get(rule, ("Review this finding and apply security best practices.", "Automatic patch withheld."))


def generate_grounded_patch(file_path: str, line_no: int, rule_id: str, line_content: str) -> Optional[str]:
    """Generate a high-confidence, contextually grounded unified diff patch where deterministic remediation is unambiguous."""
    clean_line = line_content.rstrip("\r\n")
    replacement_line = None

    if rule_id == "SEC-DISABLED-TLS":
        if "verify=False" in clean_line:
            replacement_line = clean_line.replace("verify=False", "verify=True")
        elif "verify = False" in clean_line:
            replacement_line = clean_line.replace("verify = False", "verify = True")
        elif "rejectUnauthorized: false" in clean_line:
            replacement_line = clean_line.replace("rejectUnauthorized: false", "rejectUnauthorized: true")
        elif "rejectUnauthorized:false" in clean_line:
            replacement_line = clean_line.replace("rejectUnauthorized:false", "rejectUnauthorized:true")
        elif "InsecureSkipVerify: true" in clean_line:
            replacement_line = clean_line.replace("InsecureSkipVerify: true", "InsecureSkipVerify: false")
        elif "check_hostname=False" in clean_line:
            replacement_line = clean_line.replace("check_hostname=False", "check_hostname=True")

    elif rule_id == "SEC-BROKEN-CRYPTO":
        if "hashlib.md5" in clean_line:
            replacement_line = clean_line.replace("hashlib.md5", "hashlib.sha256")
        elif "hashlib.sha1" in clean_line:
            replacement_line = clean_line.replace("hashlib.sha1", "hashlib.sha256")
        elif 'crypto.createHash("md5")' in clean_line or "crypto.createHash('md5')" in clean_line:
            replacement_line = clean_line.replace("'md5'", "'sha256'").replace('"md5"', '"sha256"')

    elif rule_id == "SEC-INSECURE-TEMPFILE":
        if "tempfile.mktemp()" in clean_line:
            replacement_line = clean_line.replace("tempfile.mktemp()", "tempfile.NamedTemporaryFile().name")

    elif rule_id == "SEC-PERMISSIVE-CHMOD":
        for perm in ["0o777", "0777", "0o666", "0666"]:
            if perm in clean_line:
                replacement_line = clean_line.replace(perm, "0o600")
                break

    elif rule_id == "SEC-JWT-NONE-ALG":
        if "verify_signature=False" in clean_line:
            replacement_line = clean_line.replace("verify_signature=False", "verify_signature=True")
        elif '["none"]' in clean_line:
            replacement_line = clean_line.replace('["none"]', '["HS256", "RS256"]')
        elif "['none']" in clean_line:
            replacement_line = clean_line.replace("['none']", "['HS256', 'RS256']")

    elif rule_id == "SEC-SECURITY-ASSERT":
        stripped = clean_line.strip()
        indent = clean_line[:len(clean_line) - len(stripped)]
        if stripped.startswith("assert "):
            condition = stripped[7:].strip()
            replacement_line = f'{indent}if not ({condition}):\n{indent}    raise PermissionError("Access denied: security check failed")'

    elif rule_id == "SEC-CORS-WILDCARD":
        if '"*"' in clean_line:
            replacement_line = clean_line.replace('"*"', '"https://trusted-domain.com"')
        elif "'*'" in clean_line:
            replacement_line = clean_line.replace("'*'", "'https://trusted-domain.com'")

    elif rule_id == "SEC-HARDCODED-SECRET":
        # Check for simple assignment e.g. api_key = "..."
        sec_m = re.search(r"""^(\s*(?:const\s+|let\s+|var\s+)?([A-Za-z0-9_]+)\s*=\s*)["'][^"']+["']""", clean_line)
        if sec_m:
            prefix = sec_m.group(1)
            var_name = sec_m.group(2).upper()
            if file_path.endswith((".js", ".ts", ".jsx", ".tsx")):
                replacement_line = f"{prefix}process.env.{var_name} || ''"
            else:
                replacement_line = f"{prefix}os.environ.get('{var_name}', '')"

    elif rule_id == "SEC-INSECURE-RANDOM":
        if "random.choice(" in clean_line:
            replacement_line = clean_line.replace("random.choice(", "secrets.choice(")
        elif "random.randint(" in clean_line:
            replacement_line = clean_line.replace("random.randint(", "secrets.randbelow(")
        elif "random.random()" in clean_line:
            replacement_line = clean_line.replace("random.random()", "secrets.token_hex(16)")

    if replacement_line and replacement_line != clean_line:
        rep_lines = replacement_line.split("\n")
        patch_lines = [
            f"--- a/{file_path}",
            f"+++ b/{file_path}",
            f"@@ -{line_no},1 +{line_no},{len(rep_lines)} @@",
            f"-{clean_line}",
        ]
        for rl in rep_lines:
            patch_lines.append(f"+{rl}")
        return "\n".join(patch_lines) + "\n"

    return None


def load_security_policy(repo_path: Optional[Path] = None) -> SecurityPolicyConfig:
    """Load security policy from .codeguardian.yaml, .codeguardian.json, or default policy."""
    if repo_path is None:
        repo_path = Path.cwd()
    for name in [".codeguardian.yaml", "codeguardian.yaml", ".codeguardian.json"]:
        cfg_file = repo_path / name
        if cfg_file.is_file():
            try:
                content = cfg_file.read_text(encoding="utf-8")
                if name.endswith((".yaml", ".yml")) and yaml is not None:
                    data = yaml.safe_load(content)
                else:
                    data = json.loads(content)
                if isinstance(data, dict):
                    return SecurityPolicyConfig.model_validate(data)
            except Exception:
                pass
    return SecurityPolicyConfig()


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int]] = set()
    output: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line_start)
        if key not in seen:
            seen.add(key)
            output.append(finding)
    return output


def analyze_diff(diff_text: str, focus: str = "ALL", policy: Optional[SecurityPolicyConfig] = None) -> ReviewReport:
    """Create a schema-validated deterministic review report for a Git diff."""
    started = time.perf_counter()
    if policy is None:
        policy = load_security_policy()

    files = parse_unified_diff(diff_text)
    if not files:
        raise ValueError("No Git file headers were found; provide a unified diff beginning with 'diff --git'.")
    findings: list[Finding] = []

    for file in files:
        if not file.new_path or file.status == "deleted":
            continue

        # Check policy file exclusion
        if any(fnmatch.fnmatch(file.new_path, pat) for pat in policy.exclude_files):
            continue

        for line in file.added_lines:
            if line.new_line is None:
                # Do not invent a line location for malformed/no-hunk snippets.
                continue

            for rule, cwe, title, severity, confidence, description in _rule_matches(line.text, file.new_path or ""):
                if focus == "PERFORMANCE":
                    continue
                if rule in policy.ignore_rules or cwe in policy.ignore_rules:
                    continue

                cvss_score, cvss_vector = RULE_CVSS_MAP.get(rule, (5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"))
                remediation, withheld_reason = _remediation(rule)
                finding_id = f"{rule}-{len(findings) + 1:03d}"
                owasp_cat = RULE_OWASP_MAP.get(rule, "A00:2021-Security-Misc")
                suggested_patch = generate_grounded_patch(file.new_path, line.new_line, rule, line.text)

                findings.append(
                    Finding(
                        id=finding_id,
                        rule_id=cwe,
                        cwe_id=cwe,
                        owasp_category=owasp_cat,
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        title=title,
                        category="SECURITY",
                        severity=severity,
                        confidence=confidence,
                        file=file.new_path,
                        line_start=line.new_line,
                        line_end=line.new_line,
                        evidence=[line.text],
                        description=description,
                        exploit_conditions=(
                            "Exploitability depends on this value being reachable from an untrusted input. "
                            "That data-flow condition has not been executed or reproduced by this review."
                        ),
                        remediation=f"{remediation} {withheld_reason}",
                        suggested_fix=suggested_patch,
                        patch_status="SUGGESTION_ONLY",
                        provenance="DETERMINISTIC_SCANNER",
                        related_tests=_test_for(rule, file.new_path),
                    )
                )

            # Evaluate custom rules defined in security policy
            for custom_rule in policy.custom_rules:
                if custom_rule.rule_id in policy.ignore_rules:
                    continue
                try:
                    c_pattern = re.compile(custom_rule.pattern, re.IGNORECASE)
                    if c_pattern.search(line.text):
                        c_id = f"{custom_rule.rule_id}-{len(findings) + 1:03d}"
                        c_cvss = custom_rule.cvss_score or (7.5 if custom_rule.severity in {"CRITICAL", "HIGH"} else 5.0)
                        findings.append(
                            Finding(
                                id=c_id,
                                rule_id=custom_rule.cwe_id or custom_rule.rule_id,
                                cwe_id=custom_rule.cwe_id,
                                owasp_category="A00:2021-Custom-Policy",
                                cvss_score=c_cvss,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                                title=custom_rule.title,
                                category=custom_rule.category,
                                severity=custom_rule.severity,
                                confidence="HIGH",
                                file=file.new_path,
                                line_start=line.new_line,
                                line_end=line.new_line,
                                evidence=[line.text],
                                description=custom_rule.description,
                                remediation=custom_rule.remediation,
                                suggested_fix=None,
                                patch_status="SUGGESTION_ONLY",
                                provenance="DETERMINISTIC_SCANNER",
                                related_tests=[],
                            )
                        )
                except re.error:
                    pass

    findings = _deduplicate(findings)
    counts = SeverityCounts(
        critical=sum(item.severity == "CRITICAL" for item in findings),
        high=sum(item.severity == "HIGH" for item in findings),
        medium=sum(item.severity == "MEDIUM" for item in findings),
        low=sum(item.severity == "LOW" for item in findings),
    )
    all_tests = [test for finding in findings for test in finding.related_tests]

    # Calculate CVSS metrics
    scores = [f.cvss_score for f in findings if f.cvss_score is not None]
    avg_cvss = round(sum(scores) / len(scores), 1) if scores else None
    max_cvss = max(scores, default=None) if scores else None

    # Group findings into OWASP Top 10 compliance items
    compliance_counts: dict[str, list[str]] = {}
    for finding in findings:
        if finding.owasp_category:
            compliance_counts.setdefault(finding.owasp_category, []).append(finding.id)

    compliance_matrix = [
        ComplianceItem(
            standard="OWASP_TOP_10",
            category_id=cat.split("-")[0].strip(),
            title=cat.split("-", 1)[1].strip() if "-" in cat else cat,
            finding_ids=ids,
            count=len(ids),
        )
        for cat, ids in sorted(compliance_counts.items())
    ]

    if counts.critical or counts.high:
        verdict, risk = "REQUEST_CHANGES", "CRITICAL" if counts.critical else "HIGH"
        summary = (
            f"{len(findings)} deterministic finding(s) require review before merge. "
            "Locations and source evidence are limited to added diff lines."
        )
    elif findings:
        verdict, risk = "COMMENT", "MEDIUM" if counts.medium else "LOW"
        summary = f"{len(findings)} non-blocking finding(s) were identified from added diff lines."
    else:
        verdict, risk = "APPROVE", "LOW"
        summary = (
            "No deterministic findings were detected in the added, source-located diff lines. "
            "This result is not a guarantee of security or correctness."
        )

    return ReviewReport(
        summary=summary,
        risk_level=risk,
        verdict=verdict,
        counts=counts,
        findings=findings,
        compliance_matrix=compliance_matrix,
        average_cvss=avg_cvss,
        max_cvss=max_cvss,
        unit_tests=all_tests,
        execution_time_ms=int((time.perf_counter() - started) * 1000),
        analyzed_files=[item.display_path for item in files if item.display_path != "unknown"],
        engine="CodeGuardian deterministic diff scanner",
        analyzers=["CodeGuardian built-in rules (added diff lines only)"],
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


