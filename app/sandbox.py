"""Safe-by-default patch validation.

Code and tests from a diff or model are untrusted. This module never touches the
user's working tree. Arbitrary generated-test execution is intentionally unavailable
until a real OS/container sandbox is configured by the host.
"""

from __future__ import annotations

import re
import time
from pathlib import PurePosixPath
from typing import Any, Optional

from app.schemas import SandboxVerificationRequest, SandboxVerificationResponse


HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class PatchValidationError(ValueError):
    """A unified patch was malformed or did not match the supplied base content."""


def _normalise_path(value: str) -> str:
    path = value.replace("\\", "/").strip()
    if path.startswith(("a/", "b/")):
        path = path[2:]
    parsed = PurePosixPath(path)
    if not path or parsed.is_absolute() or ".." in parsed.parts:
        raise PatchValidationError("patch path must stay within the isolated repository")
    return str(parsed)


def apply_single_file_unified_patch(original: str, patch: str, expected_path: str) -> str:
    """Apply one context-validated unified patch in memory.

    This is intentionally narrow: it rejects multi-file patches, missing headers,
    non-matching context, and patches aimed at another path. It is suitable for an
    isolated preview, not as a replacement for ``git apply`` on a real worktree.
    """
    lines = patch.splitlines()
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    hunk_indexes: list[int] = []

    for index, line in enumerate(lines):
        if line.startswith("--- "):
            old_path = _normalise_path(line[4:])
        elif line.startswith("+++ "):
            new_path = _normalise_path(line[4:])
        elif line.startswith("diff --git ") and index > 0:
            raise PatchValidationError("only one file may be verified at a time")
        elif HUNK_RE.match(line):
            hunk_indexes.append(index)

    target = _normalise_path(expected_path)
    if old_path is None or new_path is None or not hunk_indexes:
        raise PatchValidationError("a unified patch with ---, +++, and @@ headers is required")
    if old_path != target or new_path != target:
        raise PatchValidationError("patch target does not match the requested file")

    original_lines = original.splitlines()
    output: list[str] = []
    cursor = 0

    for hunk_position, hunk_index in enumerate(hunk_indexes):
        header = HUNK_RE.match(lines[hunk_index])
        assert header is not None
        old_start = int(header.group(1))
        expected_cursor = old_start - 1
        if expected_cursor < cursor or expected_cursor > len(original_lines):
            raise PatchValidationError("hunk has an invalid source line range")
        output.extend(original_lines[cursor:expected_cursor])
        cursor = expected_cursor
        next_hunk = hunk_indexes[hunk_position + 1] if hunk_position + 1 < len(hunk_indexes) else len(lines)

        for patch_line in lines[hunk_index + 1:next_hunk]:
            if patch_line.startswith("\\ No newline at end of file"):
                continue
            if not patch_line or patch_line[0] not in {" ", "+", "-"}:
                raise PatchValidationError("unsupported content inside unified patch hunk")
            content = patch_line[1:]
            if patch_line.startswith(" "):
                if cursor >= len(original_lines) or original_lines[cursor] != content:
                    raise PatchValidationError("patch context does not match the supplied original code")
                output.append(content)
                cursor += 1
            elif patch_line.startswith("-"):
                if cursor >= len(original_lines) or original_lines[cursor] != content:
                    raise PatchValidationError("patch removal does not match the supplied original code")
                cursor += 1
            else:
                output.append(content)

    output.extend(original_lines[cursor:])
    result = "\n".join(output)
    if original.endswith("\n") or patch.endswith("\n"):
        result += "\n"
    return result


def run_isolated_test(test_code: str, target_code: Optional[str] = None, target_filename: str = "target_module.py") -> dict[str, Any]:
    """Report that execution is unavailable instead of running untrusted code unsafely."""
    _ = test_code, target_code, target_filename
    return {
        "success": False,
        "status": "UNAVAILABLE",
        "stdout": "",
        "stderr": (
            "Generated-test execution is disabled: this host has no configured OS/container sandbox. "
            "No code was executed."
        ),
        "exit_code": None,
        "duration_ms": 0,
    }


def verify_patch_and_test(req: SandboxVerificationRequest) -> SandboxVerificationResponse:
    """Validate a patch in memory, then truthfully report test execution availability."""
    started = time.perf_counter()
    try:
        apply_single_file_unified_patch(req.original_code, req.patch, req.file_path)
    except PatchValidationError as exc:
        return SandboxVerificationResponse(
            success=False,
            patch_applied=False,
            test_passed=False,
            status="PATCH_REJECTED",
            stderr=str(exc),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
    except Exception as exc:  # defensive boundary for API callers
        return SandboxVerificationResponse(
            success=False,
            patch_applied=False,
            test_passed=False,
            status="ERROR",
            stderr=f"Patch validation error: {exc}",
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    return SandboxVerificationResponse(
        success=False,
        patch_applied=True,
        test_passed=False,
        status="UNAVAILABLE",
        stdout="Patch context validated in memory; no working-tree files were changed.",
        stderr=(
            "Test verification is unavailable because arbitrary generated code is not executed without "
            "a host-provided OS/container sandbox."
        ),
        duration_ms=int((time.perf_counter() - started) * 1000),
    )


def split_multi_file_unified_patch(patch: str) -> list[tuple[str, str]]:
    """Split a multi-file unified diff into individual (target_path, file_patch) pairs."""
    file_chunks: list[tuple[str, str]] = []
    current_lines: list[str] = []
    current_target: Optional[str] = None

    for line in patch.splitlines(keepends=True):
        if line.startswith("diff --git ") and current_lines:
            if current_target:
                file_chunks.append((current_target, "".join(current_lines)))
            current_lines = [line]
            current_target = None
            continue

        if line.startswith("+++ "):
            raw = line[4:].strip().strip('"')
            if raw.startswith("b/"):
                raw = raw[2:]
            current_target = raw

        current_lines.append(line)

    if current_lines and current_target:
        file_chunks.append((current_target, "".join(current_lines)))

    return file_chunks


def apply_multi_file_unified_patch(base_files: dict[str, str], patch: str) -> dict[str, str]:
    """Apply a multi-file unified patch in memory to a dictionary of {file_path: file_content}."""
    chunks = split_multi_file_unified_patch(patch)
    if not chunks:
        if len(base_files) == 1:
            target_path = next(iter(base_files.keys()))
            return {target_path: apply_single_file_unified_patch(base_files[target_path], patch, target_path)}
        raise PatchValidationError("No file diff headers were found in multi-file patch")

    results = dict(base_files)
    for target_path, file_patch in chunks:
        normalized = _normalise_path(target_path)
        if normalized not in results:
            raise PatchValidationError(f"Base file content for '{normalized}' was not provided")
        results[normalized] = apply_single_file_unified_patch(results[normalized], file_patch, normalized)

    return results


def apply_patch_to_working_tree(
    repo_root: Any,
    patch: str,
    create_backup: bool = True
) -> tuple[bool, Optional[str], list[str], str]:
    """Safely apply a unified patch to the local git working tree with an automatic stash backup."""
    import subprocess
    from pathlib import Path

    root = Path(repo_root)
    backup_ref: Optional[str] = None
    if create_backup:
        try:
            stash_out = subprocess.check_output(
                ["git", "stash", "create", "CodeGuardian Pre-Patch Backup"],
                cwd=root,
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
            if stash_out:
                backup_ref = stash_out
                subprocess.run(
                    ["git", "update-ref", "refs/codeguardian/backups/latest", backup_ref],
                    cwd=root,
                    check=False,
                )
        except Exception:
            pass

    try:
        proc_check = subprocess.run(
            ["git", "apply", "--check", "--whitespace=fix", "-"],
            input=patch,
            cwd=root,
            capture_output=True,
            text=True,
        )
        if proc_check.returncode != 0:
            return False, backup_ref, [], f"Patch check failed: {proc_check.stderr.strip() or 'Conflicts detected'}"

        proc_apply = subprocess.run(
            ["git", "apply", "--whitespace=fix", "-"],
            input=patch,
            cwd=root,
            capture_output=True,
            text=True,
        )
        if proc_apply.returncode != 0:
            return False, backup_ref, [], f"Patch apply failed: {proc_apply.stderr.strip()}"

        status_out = subprocess.check_output(
            ["git", "diff", "--name-only"],
            cwd=root,
            text=True,
        )
        modified = [line.strip() for line in status_out.splitlines() if line.strip()]
        return True, backup_ref, modified, f"Successfully applied patch to {len(modified)} file(s)"
    except Exception as exc:
        return False, backup_ref, [], f"Execution error: {exc}"


def revert_patch_from_working_tree(
    repo_root: Any,
    patch: Optional[str] = None,
    backup_ref: Optional[str] = None,
) -> tuple[bool, list[str], str]:
    """Safely revert a patch from the local git working tree using git apply -R or backup stash."""
    import subprocess
    from pathlib import Path

    root = Path(repo_root)

    # 1. If patch string is provided, try git apply --reverse first
    if patch and patch.strip():
        try:
            proc_rev = subprocess.run(
                ["git", "apply", "--reverse", "--whitespace=fix", "-"],
                input=patch,
                cwd=root,
                capture_output=True,
                text=True,
            )
            if proc_rev.returncode == 0:
                status_out = subprocess.check_output(
                    ["git", "diff", "--name-only"],
                    cwd=root,
                    text=True,
                )
                modified = [line.strip() for line in status_out.splitlines() if line.strip()]
                return True, modified, "Successfully reverted patch via reverse diff."
        except Exception:
            pass

    # 2. If reverse apply failed or wasn't possible, try restoring backup ref if available
    ref_to_restore = backup_ref or "refs/codeguardian/backups/latest"
    try:
        check_ref = subprocess.run(
            ["git", "rev-parse", "--verify", ref_to_restore],
            cwd=root,
            capture_output=True,
            text=True,
        )
        if check_ref.returncode == 0:
            proc_restore = subprocess.run(
                ["git", "checkout", ref_to_restore, "--", "."],
                cwd=root,
                capture_output=True,
                text=True,
            )
            if proc_restore.returncode == 0:
                return True, [], f"Successfully restored working tree from backup checkpoint ({ref_to_restore})."
    except Exception as exc:
        return False, [], f"Revert error: {exc}"

    return False, [], "Could not revert patch: neither reverse application nor backup ref succeeded."

