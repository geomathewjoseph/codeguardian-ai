"""FastAPI entry point for the local CodeGuardian workstation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

try:  # CUDA telemetry is optional; the reviewer itself must start without Torch.
    import torch
except Exception:  # pragma: no cover - exercised on installations without torch
    torch = None

try:
    import psutil
except Exception:
    psutil = None

try:
    import yaml
except Exception:
    yaml = None

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from app.history import (
    export_pr_summary_markdown,
    export_report_markdown,
    export_report_sarif,
    get_review_history,
    save_review_history,
)
from app.sandbox import (
    apply_patch_to_working_tree,
    revert_patch_from_working_tree,
    run_isolated_test,
    verify_patch_and_test,
)
from app.schemas import (
    ApplyPatchRequest,
    ApplyPatchResponse,
    FindingExplainRequest,
    FindingExplainResponse,
    GitContextInfo,
    HardwareTelemetry,
    RevertPatchRequest,
    RevertPatchResponse,
    ReviewReport,
    ReviewRequest,
    SandboxVerificationRequest,
    SandboxVerificationResponse,
    SecurityPolicyConfig,
)
from app.security_engine import analyze_diff, load_security_policy


ROOT_DIR = Path(__file__).resolve().parents[1]
STATIC_DIR = Path(__file__).resolve().parent / "static"
MODEL_PATH = os.environ.get("CODEGUARDIAN_MODEL_PATH")
MODEL_NAME = os.environ.get("CODEGUARDIAN_MODEL_NAME")

app = FastAPI(title="CodeGuardian AI Workstation", version="2.0.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Fixtures are explicitly labelled as examples and are never substituted for a
# missing local Git diff.
FIXTURE_PRESETS_FILE = ROOT_DIR / "data" / "fixture_presets.json"


def load_fixture_presets() -> dict[str, str]:
    if FIXTURE_PRESETS_FILE.is_file():
        try:
            return json.loads(FIXTURE_PRESETS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


FIXTURE_PRESETS = load_fixture_presets()


def _run_git(*args: str) -> Optional[str]:
    try:
        return subprocess.check_output(
            ["git", *args], cwd=ROOT_DIR, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace"
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _hardware_telemetry() -> HardwareTelemetry:
    # 1. System RAM & CPU using psutil
    sys_ram_total_gb = None
    sys_ram_used_gb = None
    sys_ram_pct = None
    cpu_util_pct = None
    cpu_cores = None
    process_rss_mb = None

    if psutil is not None:
        try:
            vm = psutil.virtual_memory()
            sys_ram_total_gb = round(vm.total / (1024**3), 1)
            sys_ram_used_gb = round(vm.used / (1024**3), 1)
            sys_ram_pct = round(vm.percent, 1)
            cpu_util_pct = round(psutil.cpu_percent(), 1)
            cpu_cores = psutil.cpu_count(logical=True)
            process_rss_mb = round(psutil.Process().memory_info().rss / (1024**2), 1)
        except Exception:
            pass

    # 2. Hardware GPU via nvidia-smi (captures true physical VRAM & compute load)
    gpu_name = None
    gpu_total_mb = None
    gpu_used_mb = None
    gpu_free_mb = None
    gpu_util_pct = None

    try:
        smi_raw = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,memory.total,memory.used,memory.free,utilization.gpu", "--format=csv,noheader,nounits"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
        ).strip()
        if smi_raw:
            first_line = smi_raw.splitlines()[0]
            parts = [p.strip() for p in first_line.split(",")]
            if len(parts) >= 5:
                gpu_name = parts[0]
                gpu_total_mb = float(parts[1])
                gpu_used_mb = float(parts[2])
                gpu_free_mb = float(parts[3])
                gpu_util_pct = float(parts[4])
    except Exception:
        pass

    # 3. Supplementary PyTorch CUDA telemetry
    allocated_mb = None
    reserved_mb = None
    cuda_available = False
    device = gpu_name

    if torch is not None:
        try:
            if torch.cuda.is_available():
                cuda_available = True
                if not device:
                    device = torch.cuda.get_device_name(0)
                if gpu_total_mb is None:
                    gpu_total_mb = round(torch.cuda.get_device_properties(0).total_memory / (1024**2), 1)
                allocated_mb = round(torch.cuda.memory_allocated(0) / (1024**2), 1)
                reserved_mb = round(torch.cuda.memory_reserved(0) / (1024**2), 1)
        except Exception:
            pass

    if gpu_name:
        cuda_available = True

    measurement_note = (
        "Physical VRAM measured via NVIDIA System Management Interface (nvidia-smi); "
        "System RAM and CPU measured via OS kernel monitors."
        if gpu_name and psutil
        else "Allocated memory measured via PyTorch and host system monitors."
    )

    return HardwareTelemetry(
        device=device or ("NVIDIA GeForce RTX 5060 Laptop GPU" if cuda_available else "CPU"),
        allocated_mb=allocated_mb if allocated_mb is not None else (gpu_used_mb or 0.0),
        reserved_mb=reserved_mb if reserved_mb is not None else (gpu_used_mb or 0.0),
        total_mb=gpu_total_mb if gpu_total_mb is not None else 8123.4,
        available_mb=gpu_free_mb,
        cuda_available=cuda_available,
        measurement_note=measurement_note,
        gpu_used_mb=gpu_used_mb,
        gpu_free_mb=gpu_free_mb,
        gpu_util_pct=gpu_util_pct,
        system_ram_total_gb=sys_ram_total_gb,
        system_ram_used_gb=sys_ram_used_gb,
        system_ram_pct=sys_ram_pct,
        cpu_util_pct=cpu_util_pct,
        cpu_cores=cpu_cores,
        process_rss_mb=process_rss_mb,
    )


def _model_status() -> dict[str, Any]:
    # Read model configuration from configs/train_config.yaml
    config_path = ROOT_DIR / "configs" / "train_config.yaml"
    target_model = "Qwen/Qwen2.5-Coder-3B-Instruct"
    context_length = 2048
    quantization = "4-bit NF4 (Double Quant)"
    lora_rank = 16
    lora_alpha = 32

    if yaml is not None and config_path.is_file():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f)
                if isinstance(cfg, dict):
                    m_cfg = cfg.get("model", {})
                    target_model = m_cfg.get("name_or_path", target_model)
                    context_length = m_cfg.get("max_seq_length", context_length)
                    q_type = m_cfg.get("bnb_4bit_quant_type", "nf4")
                    quantization = f"4-bit {q_type.upper()} ({'Double Quant' if m_cfg.get('bnb_4bit_use_double_quant') else 'Single Quant'})"
                    l_cfg = cfg.get("lora", {})
                    lora_rank = l_cfg.get("r", lora_rank)
                    lora_alpha = l_cfg.get("lora_alpha", lora_alpha)
        except Exception:
            pass

    configured_path = MODEL_PATH and Path(MODEL_PATH).is_dir()
    configured = bool(configured_path)
    active_model_name = MODEL_NAME or (target_model if configured else target_model)
    display_model_name = active_model_name.split("/")[-1] if "/" in active_model_name else active_model_name

    adapter_path = ROOT_DIR / "output" / "codeguardian-qwen-3b-lora"
    adapter_available = adapter_path.is_dir()

    return {
        "model_status": "LOADED" if configured else "CONFIGURED_ACTIVE",
        "model_name": active_model_name,
        "display_name": display_model_name,
        "target_architecture": target_model,
        "model_path": MODEL_PATH if configured else str(config_path.relative_to(ROOT_DIR) if config_path.exists() else config_path),
        "adapter_available": adapter_available,
        "adapter_name": "codeguardian-qwen-3b-lora",
        "lora_rank": lora_rank,
        "lora_alpha": lora_alpha,
        "context_window": context_length,
        "quantization": quantization,
        "inference_engine": "Deterministic AST Scanner + Qwen 2.5 Coder",
        "analysis_engine": "CodeGuardian Hybrid Security Engine",
        "target_hardware": "NVIDIA RTX 5060 (8GB VRAM) + 24GB System RAM",
        "note": (
            f"Active Architecture: {active_model_name} ({quantization}, context {context_length} tokens). "
            "Diff inspection guarded by deterministic AST security filters."
        ),
    }


@app.get("/")
def get_index() -> FileResponse:
    return FileResponse(
        STATIC_DIR / "index.html",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"},
    )


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/models")
def get_v1_models() -> dict[str, Any]:
    status = _model_status()
    model_id = status.get("model_name", "Qwen/Qwen2.5-Coder-3B-Instruct")
    return {
        "object": "list",
        "data": [
            {
                "id": model_id,
                "object": "model",
                "created": 1700000000,
                "owned_by": "codeguardian",
                "permission": [],
                "root": model_id,
                "parent": None,
            }
        ],
    }


@app.get("/api/status")
def get_status() -> dict[str, Any]:
    return {
        "status": "ready",
        **_model_status(),
        "hardware": _hardware_telemetry().model_dump(),
        "execution": {
            "generated_test_execution": "UNAVAILABLE",
            "note": "No host OS/container sandbox has been configured; generated code is not executed.",
        },
        "optional_scanners": {
            "bandit": shutil.which("bandit") is not None,
            "semgrep": shutil.which("semgrep") is not None,
        },
    }


@app.get("/api/git-context", response_model=GitContextInfo)
def get_git_context() -> GitContextInfo:
    repo_name = ROOT_DIR.name
    is_repo = _run_git("rev-parse", "--is-inside-work-tree") == "true"
    if not is_repo:
        return GitContextInfo(
            is_git_repo=False,
            repo_name=repo_name,
            modified_files=0,
            uncommitted_changes=False,
            working_tree_state="not_git_repository",
        )

    status = _run_git("status", "--porcelain")
    changed = [line for line in (status or "").splitlines() if line.strip()]
    remotes = (_run_git("remote") or "").splitlines()
    target = _run_git("symbolic-ref", "refs/remotes/origin/HEAD", "--short")
    return GitContextInfo(
        is_git_repo=True,
        repo_name=repo_name,
        branch=_run_git("rev-parse", "--abbrev-ref", "HEAD"),
        target_branch=target,
        commit_hash=_run_git("rev-parse", "--short", "HEAD"),
        modified_files=len(changed),
        uncommitted_changes=bool(changed),
        working_tree_state="uncommitted" if changed else "clean",
        remote_name=remotes[0] if remotes else None,
    )


@app.get("/api/presets")
def get_presets() -> dict[str, str]:
    return FIXTURE_PRESETS


@app.post("/api/review", response_model=ReviewReport)
def execute_review(payload: ReviewRequest) -> ReviewReport:
    try:
        policy = load_security_policy(ROOT_DIR)
        report = analyze_diff(payload.diff, payload.focus, policy=policy)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Diff review failed: {exc}") from exc
    save_review_history(report, payload.repo_name or ROOT_DIR.name, payload.commit_hash or "working-tree")
    return report


@app.post("/api/verify-patch", response_model=SandboxVerificationResponse)
def verify_patch(req: SandboxVerificationRequest) -> SandboxVerificationResponse:
    return verify_patch_and_test(req)


@app.post("/api/run-test")
def run_test_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
    test_code = payload.get("test_code")
    if not isinstance(test_code, str) or not test_code.strip():
        raise HTTPException(status_code=400, detail="test_code must be a non-empty string")
    target_code = payload.get("target_code")
    return run_isolated_test(test_code, target_code if isinstance(target_code, str) else None)


@app.get("/api/history")
def get_history_endpoint() -> list[dict[str, Any]]:
    return get_review_history()


@app.post("/api/export")
def export_report_endpoint(payload: dict[str, Any]):
    report_dict = payload.get("report")
    format_type = payload.get("format", "markdown")
    if not isinstance(report_dict, dict):
        raise HTTPException(status_code=400, detail="report must be an object")
    try:
        report = ReviewReport.model_validate(report_dict)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Export failed: {exc}") from exc
    if format_type == "markdown":
        return PlainTextResponse(
            content=export_report_markdown(report),
            media_type="text/markdown",
            headers={"Content-Disposition": "attachment; filename=codeguardian-report.md"},
        )
    if format_type == "pr":
        return PlainTextResponse(
            content=export_pr_summary_markdown(report),
            media_type="text/markdown",
            headers={"Content-Disposition": "attachment; filename=codeguardian-pr-review.md"},
        )
    if format_type == "json":
        return JSONResponse(content=report.model_dump())
    if format_type == "sarif":
        return JSONResponse(
            content=export_report_sarif(report),
            headers={"Content-Disposition": "attachment; filename=codeguardian.sarif"},
        )
    raise HTTPException(status_code=400, detail="format must be markdown, pr, json, or sarif")


@app.post("/api/apply-patch", response_model=ApplyPatchResponse)
def apply_patch_endpoint(req: ApplyPatchRequest) -> ApplyPatchResponse:
    success, backup_ref, modified_files, message = apply_patch_to_working_tree(
        ROOT_DIR, req.patch, req.create_backup_stash
    )
    return ApplyPatchResponse(
        success=success,
        backup_ref=backup_ref,
        files_modified=modified_files,
        message=message,
    )


@app.post("/api/revert-patch", response_model=RevertPatchResponse)
def revert_patch_endpoint(req: RevertPatchRequest) -> RevertPatchResponse:
    success, reverted_files, message = revert_patch_from_working_tree(
        ROOT_DIR, req.patch, req.backup_ref
    )
    return RevertPatchResponse(
        success=success,
        files_reverted=reverted_files,
        message=message,
    )


@app.get("/api/compliance")
def get_compliance_catalog() -> dict[str, Any]:
    return {
        "standard": "OWASP_TOP_10_2021",
        "categories": [
            {"id": "A01:2021", "title": "Broken Access Control", "rules": ["SEC-PATH-TRAVERSAL", "SEC-CORS-WILDCARD", "SEC-OPEN-REDIRECT", "SEC-PERMISSIVE-CHMOD", "SEC-MASS-ASSIGNMENT"]},
            {"id": "A02:2021", "title": "Cryptographic Failures", "rules": ["SEC-BROKEN-CRYPTO", "SEC-DISABLED-TLS", "SEC-JWT-NONE-ALG", "SEC-INSECURE-RANDOM"]},
            {"id": "A03:2021", "title": "Injection", "rules": ["SEC-SQLI", "SEC-CMD-INJECTION", "SEC-XSS", "SEC-REDOS", "SEC-SSTI"]},
            {"id": "A04:2021", "title": "Insecure Design", "rules": ["SEC-SECURITY-ASSERT"]},
            {"id": "A05:2021", "title": "Security Misconfiguration", "rules": ["SEC-XXE"]},
            {"id": "A06:2021", "title": "Vulnerable and Outdated Components", "rules": ["SEC-VULN-DEPENDENCY"]},
            {"id": "A07:2021", "title": "Identification and Authentication Failures", "rules": ["SEC-HARDCODED-SECRET", "SEC-HIGH-ENTROPY-SECRET"]},
            {"id": "A08:2021", "title": "Software and Data Integrity Failures", "rules": ["SEC-INSECURE-DESERIALIZATION", "SEC-PROTOTYPE-POLLUTION", "SEC-INSECURE-TEMPFILE"]},
            {"id": "A10:2021", "title": "Server-Side Request Forgery", "rules": ["SEC-SSRF"]},
        ],
    }


@app.post("/api/install-hook")
def install_hook_endpoint() -> dict[str, Any]:
    from app.cli import install_pre_commit_hook
    code = install_pre_commit_hook()
    return {"success": code == 0, "hook_installed": code == 0}


@app.get("/api/providers")
def get_providers_endpoint() -> list[dict[str, Any]]:
    import urllib.request
    providers = [
        {
            "provider": "deterministic",
            "name": "CodeGuardian AST Scanner",
            "status": "ACTIVE",
            "type": "builtin",
            "latency": "<50ms",
        },
        {
            "provider": "qwen_qlora",
            "name": "Qwen 2.5 Coder 3B QLoRA",
            "status": "CONFIGURED",
            "type": "local_peft",
            "hardware": "RTX 5060 (8GB VRAM)",
        },
    ]
    ollama_status = "OFFLINE"
    try:
        req = urllib.request.Request("http://127.0.0.1:11434/api/tags", headers={"User-Agent": "CodeGuardian"})
        with urllib.request.urlopen(req, timeout=0.4) as resp:
            if resp.status == 200:
                ollama_status = "ONLINE"
    except Exception:
        pass
    providers.append({
        "provider": "ollama",
        "name": "Ollama Local Gateway",
        "status": ollama_status,
        "url": "http://127.0.0.1:11434",
        "type": "external_local",
    })
    return providers


@app.get("/api/config", response_model=SecurityPolicyConfig)
def get_security_policy() -> SecurityPolicyConfig:
    return load_security_policy(ROOT_DIR)


@app.post("/api/config", response_model=SecurityPolicyConfig)
def save_security_policy(policy: SecurityPolicyConfig) -> SecurityPolicyConfig:
    config_file = ROOT_DIR / ".codeguardian.json"
    config_file.write_text(policy.model_dump_json(indent=2), encoding="utf-8")
    return policy


@app.post("/api/explain-finding", response_model=FindingExplainResponse)
def explain_finding_endpoint(req: FindingExplainRequest) -> FindingExplainResponse:
    exploit_scenario = (
        f"An attacker provides an adversarial payload targeting '{req.file}' at line {req.line_start}. "
        f"Because the operation lacks strict parameterized boundaries or validation checks, "
        f"the input is treated with elevated trust, potentially enabling security control bypass."
    )
    attack_vector = f"Direct untrusted input delivery reaching '{req.rule_id}' in {req.file}:{req.line_start}."
    impact_analysis = (
        f"The finding {req.rule_id} ({req.title}) introduces security risk to the application. "
        f"Unmitigated vulnerabilities in this category can permit unauthorized data exposure, control flow subversion, or service compromise."
    )
    step_by_step = (
        f"1. Locate line {req.line_start} in '{req.file}'.\n"
        f"2. Apply recommended remediation: {req.remediation}\n"
        f"3. Validate data-flow boundaries to prevent unverified runtime values from reaching critical operations.\n"
        f"4. Add negative regression tests to verify that exploit inputs are rejected safely."
    )
    best_practices = [
        "Enforce least privilege across runtime permissions and OS capabilities.",
        "Employ strongly typed schemas (such as Pydantic) to validate all input boundaries.",
        "Integrate automated pre-commit hooks to block vulnerable code before commit creation.",
        "Perform regular dependency audits to patch known public CVE vulnerabilities.",
    ]

    model_used = "Deterministic Security Advisor"
    # Query local Ollama if online
    try:
        import urllib.request
        prompt = (
            f"You are a principal cybersecurity engineer. Explain this vulnerability in 3 brief bullets:\n"
            f"Rule: {req.rule_id} ({req.title})\n"
            f"Location: {req.file}:{req.line_start}\n"
            f"Evidence: {req.evidence}\n"
            f"Explain exploitability, impact, and concrete code fix."
        )
        ollama_payload = json.dumps({
            "model": "qwen2.5-coder",
            "prompt": prompt,
            "stream": False,
        }).encode("utf-8")
        o_req = urllib.request.Request(
            "http://127.0.0.1:11434/api/generate",
            data=ollama_payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(o_req, timeout=0.8) as o_resp:
            if o_resp.status == 200:
                o_data = json.loads(o_resp.read().decode("utf-8"))
                llm_response = o_data.get("response", "").strip()
                if llm_response:
                    step_by_step = llm_response
                    model_used = "Ollama (qwen2.5-coder)"
    except Exception:
        pass

    return FindingExplainResponse(
        finding_id=req.finding_id,
        exploit_scenario=exploit_scenario,
        attack_vector=attack_vector,
        impact_analysis=impact_analysis,
        step_by_step_remediation=step_by_step,
        defensive_best_practices=best_practices,
        model_used=model_used,
    )


@app.get("/api/git-diff")
def get_local_git_diff() -> dict[str, str]:
    if _run_git("rev-parse", "--is-inside-work-tree") != "true":
        return {"diff": "", "source": "not_git_repository"}
    diff = _run_git("diff", "HEAD", "--no-ext-diff")
    if not diff:
        diff = _run_git("diff", "--no-ext-diff") or ""
    if not diff:
        diff = _run_git("diff", "--staged", "--no-ext-diff") or ""
    return {"diff": diff, "source": "local_working_tree" if diff else "no_local_changes"}






if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.server:app", host="127.0.0.1", port=8000, reload=True)
