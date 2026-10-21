"""Versioned contracts shared by the CodeGuardian API and review pipeline."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
Confidence = Literal["HIGH", "MEDIUM", "LOW"]
FindingCategory = Literal[
    "SECURITY", "BUG", "PERFORMANCE", "STYLE", "MAINTAINABILITY", "CONFIGURATION"
]
PatchStatus = Literal[
    "SUGGESTION_ONLY", "PROPOSED", "APPLIED_ISOLATED", "TESTED", "VERIFIED", "FAILED", "UNAVAILABLE"
]
TestStatus = Literal[
    "GENERATED", "NOT_EXECUTED", "EXECUTED_PASSED", "EXECUTED_FAILED", "SKIPPED", "UNAVAILABLE"
]


def _safe_repo_path(value: str) -> str:
    """Reject absolute and parent-traversal paths in external review data."""
    normalized = value.replace("\\", "/").strip()
    if not normalized or normalized.startswith("/") or ":" in normalized.split("/")[0]:
        raise ValueError("file must be a relative repository path")
    if any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise ValueError("file must not contain empty, current, or parent path components")
    return normalized


class UnitTestFixture(BaseModel):
    """A candidate regression test. Generated never implies it has been run."""

    name: str = Field(min_length=1, max_length=160)
    framework: str = Field(default="pytest", max_length=80)
    description: str = Field(default="", max_length=1000)
    code: str = Field(default="", max_length=30000)
    status: TestStatus = "GENERATED"
    execution_output: Optional[str] = Field(default=None, max_length=12000)


class Finding(BaseModel):
    """A validated, source-located review finding."""

    id: str = Field(min_length=3, max_length=120)
    rule_id: str = Field(min_length=1, max_length=160)
    title: str = Field(min_length=1, max_length=240)
    category: FindingCategory = "SECURITY"
    severity: Severity = "MEDIUM"
    confidence: Confidence = "MEDIUM"
    file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    evidence: list[str] = Field(default_factory=list, max_length=12)
    description: str = Field(min_length=1, max_length=6000)
    exploit_conditions: Optional[str] = Field(default=None, max_length=4000)
    remediation: str = Field(min_length=1, max_length=4000)
    suggested_fix: Optional[str] = Field(default=None, max_length=30000)
    cwe_id: Optional[str] = Field(default=None, max_length=80)
    owasp_category: Optional[str] = Field(default=None, max_length=160)
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = Field(default=None, max_length=120)
    patch_status: PatchStatus = "SUGGESTION_ONLY"
    provenance: Literal["DETERMINISTIC_SCANNER", "LOCAL_LLM", "HYBRID_RECONCILED"] = "DETERMINISTIC_SCANNER"
    related_tests: list[UnitTestFixture] = Field(default_factory=list)

    @field_validator("file")
    @classmethod
    def validate_file(cls, value: str) -> str:
        return _safe_repo_path(value)

    @model_validator(mode="after")
    def validate_location_and_patch_state(self) -> "Finding":
        if self.line_end < self.line_start:
            raise ValueError("line_end must be greater than or equal to line_start")
        if self.suggested_fix and self.patch_status == "SUGGESTION_ONLY":
            # A candidate patch is still only a suggestion until a separate verifier reports otherwise.
            return self
        if not self.suggested_fix and self.patch_status in {"PROPOSED", "APPLIED_ISOLATED", "TESTED", "VERIFIED"}:
            raise ValueError("a non-terminal patch status requires suggested_fix")
        return self

    @property
    def line_range(self) -> str:
        return str(self.line_start) if self.line_start == self.line_end else f"{self.line_start}-{self.line_end}"


class SeverityCounts(BaseModel):
    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)


class ReviewRequest(BaseModel):
    diff: str = Field(min_length=1, max_length=2_000_000, description="Unified Git diff to audit")
    focus: Literal["ALL", "SECURITY", "PERFORMANCE", "TESTS"] = "ALL"
    repo_name: Optional[str] = Field(default=None, max_length=240)
    branch: Optional[str] = Field(default=None, max_length=240)
    commit_hash: Optional[str] = Field(default=None, max_length=240)


class ComplianceItem(BaseModel):
    """Compliance framework standard mapping."""
    standard: str = "OWASP_TOP_10"
    category_id: str
    title: str
    finding_ids: list[str] = Field(default_factory=list)
    count: int = 0


class ReviewReport(BaseModel):
    version: str = "2.0.0"
    summary: str = Field(min_length=1, max_length=6000)
    risk_level: Severity = "LOW"
    verdict: Literal["APPROVE", "REQUEST_CHANGES", "COMMENT"] = "APPROVE"
    counts: SeverityCounts = Field(default_factory=SeverityCounts)
    findings: list[Finding] = Field(default_factory=list)
    compliance_matrix: list[ComplianceItem] = Field(default_factory=list)
    average_cvss: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    max_cvss: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    unit_tests: list[UnitTestFixture] = Field(default_factory=list)
    execution_time_ms: int = Field(default=0, ge=0)
    analyzed_files: list[str] = Field(default_factory=list)
    engine: str = Field(default="CodeGuardian deterministic review engine")
    analyzers: list[str] = Field(default_factory=list)
    timestamp: str

    @model_validator(mode="after")
    def validate_counts(self) -> "ReviewReport":
        actual = SeverityCounts(
            critical=sum(f.severity == "CRITICAL" for f in self.findings),
            high=sum(f.severity == "HIGH" for f in self.findings),
            medium=sum(f.severity == "MEDIUM" for f in self.findings),
            low=sum(f.severity == "LOW" for f in self.findings),
        )
        if self.counts != actual:
            raise ValueError("severity counts must be derived from findings")
        finding_ids = [f.id for f in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("finding IDs must be unique")
        finding_paths = {f.file for f in self.findings}
        if not finding_paths.issubset(set(self.analyzed_files)):
            raise ValueError("all finding paths must be included in analyzed_files")
        return self


class HardwareTelemetry(BaseModel):
    device: Optional[str] = None
    allocated_mb: Optional[float] = Field(default=None, ge=0)
    reserved_mb: Optional[float] = Field(default=None, ge=0)
    total_mb: Optional[float] = Field(default=None, gt=0)
    available_mb: Optional[float] = Field(default=None, ge=0)
    cuda_available: bool
    measurement_note: str

    # Extended real-time hardware & resource allocation metrics:
    gpu_used_mb: Optional[float] = Field(default=None, ge=0)
    gpu_free_mb: Optional[float] = Field(default=None, ge=0)
    gpu_util_pct: Optional[float] = Field(default=None, ge=0)
    system_ram_total_gb: Optional[float] = Field(default=None, ge=0)
    system_ram_used_gb: Optional[float] = Field(default=None, ge=0)
    system_ram_pct: Optional[float] = Field(default=None, ge=0)
    cpu_util_pct: Optional[float] = Field(default=None, ge=0)
    cpu_cores: Optional[int] = Field(default=None, ge=1)
    process_rss_mb: Optional[float] = Field(default=None, ge=0)


class GitContextInfo(BaseModel):
    is_git_repo: bool
    repo_name: str
    branch: Optional[str] = None
    target_branch: Optional[str] = None
    commit_hash: Optional[str] = None
    modified_files: int = Field(ge=0)
    uncommitted_changes: bool = False
    working_tree_state: Literal["clean", "uncommitted", "not_git_repository", "unknown"]
    remote_name: Optional[str] = None


class SandboxVerificationRequest(BaseModel):
    file_path: str
    original_code: str = Field(min_length=0, max_length=2_000_000)
    patch: str = Field(min_length=1, max_length=2_000_000)
    test_code: str = Field(min_length=1, max_length=300_000)
    framework: str = Field(default="pytest", max_length=80)

    @field_validator("file_path")
    @classmethod
    def validate_file_path(cls, value: str) -> str:
        return _safe_repo_path(value)


class SandboxVerificationResponse(BaseModel):
    success: bool
    patch_applied: bool
    test_passed: bool
    status: Literal["VERIFIED", "FAILED", "TEST_FAILED", "PATCH_REJECTED", "UNAVAILABLE", "ERROR"]
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = Field(ge=0)


class ApplyPatchRequest(BaseModel):
    patch: str = Field(min_length=1, max_length=2_000_000)
    commit_message: Optional[str] = Field(default=None, max_length=240)
    create_backup_stash: bool = True


class ApplyPatchResponse(BaseModel):
    success: bool
    backup_ref: Optional[str] = None
    files_modified: list[str] = Field(default_factory=list)
    message: str


class RevertPatchRequest(BaseModel):
    patch: Optional[str] = Field(default=None, max_length=2_000_000)
    backup_ref: Optional[str] = Field(default=None, max_length=120)


class RevertPatchResponse(BaseModel):
    success: bool
    files_reverted: list[str] = Field(default_factory=list)
    message: str


class LocalProviderInfo(BaseModel):
    provider: str
    status: str
    url: Optional[str] = None
    active_model: Optional[str] = None


class CustomRuleConfig(BaseModel):
    rule_id: str = Field(min_length=3, max_length=120)
    title: str = Field(min_length=1, max_length=240)
    severity: Severity = "MEDIUM"
    category: FindingCategory = "SECURITY"
    pattern: str = Field(min_length=1, max_length=1000)
    description: str = Field(min_length=1, max_length=2000)
    remediation: str = Field(min_length=1, max_length=2000)
    cwe_id: Optional[str] = Field(default=None, max_length=80)
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)


class SecurityPolicyConfig(BaseModel):
    version: str = "1.0.0"
    ignore_rules: list[str] = Field(default_factory=list)
    exclude_files: list[str] = Field(default_factory=list)
    min_shannon_entropy: float = Field(default=4.5, ge=2.0, le=8.0)
    fail_on_critical: bool = True
    custom_rules: list[CustomRuleConfig] = Field(default_factory=list)


class FindingExplainRequest(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    remediation: str
    file: str
    line_start: int = 1
    prompt: Optional[str] = None


class FindingExplainResponse(BaseModel):
    finding_id: str
    exploit_scenario: str
    attack_vector: str
    impact_analysis: str
    step_by_step_remediation: str
    defensive_best_practices: list[str] = Field(default_factory=list)
    model_used: str = "Deterministic Security Advisor"

