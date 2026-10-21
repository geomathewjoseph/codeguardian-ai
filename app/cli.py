"""Command-line entry point for local, deterministic diff review."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from app.history import export_pr_summary_markdown, export_report_markdown, export_report_sarif
from app.security_engine import analyze_diff


console = Console()
ROOT_DIR = Path(__file__).resolve().parents[1]


def get_git_diff(staged_only: bool = False, repo_dir: Optional[Path] = None) -> str:
    target_dir = repo_dir or Path.cwd()
    args = ["git", "diff", "--no-ext-diff"]
    if staged_only:
        args.append("--staged")
    try:
        out = subprocess.check_output(args, cwd=target_dir, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace").strip()
        if not out and not staged_only:
            out = subprocess.check_output(["git", "diff", "--no-ext-diff", "--staged"], cwd=target_dir, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace").strip()
        return out
    except (OSError, subprocess.CalledProcessError):
        return ""


def install_pre_commit_hook(repo_dir: Optional[Path] = None) -> int:
    """Install a local Git pre-commit security gate."""
    target_root = repo_dir or ROOT_DIR
    hooks_dir = target_root / ".git" / "hooks"
    if not (target_root / ".git").exists():
        console.print("[bold red]Error:[/bold red] Workspace root is not a Git repository.")
        return 1

    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_script = hooks_dir / "pre-commit"

    python_exec = sys.executable.replace("\\", "/")
    root_str = str(ROOT_DIR).replace("\\", "/")

    script_content = (
        "#!/usr/bin/env bash\n"
        "# CodeGuardian Local Git Pre-Commit Security Gate\n"
        "echo \"[CodeGuardian] Running deterministic diff security scan...\"\n"
        f"\"{python_exec}\" -c \"import sys; sys.path.insert(0, '{root_str}'); from app.cli import main; sys.exit(main())\" --staged --fail-on-critical\n"
        "EXIT_CODE=$?\n"
        "if [ $EXIT_CODE -ne 0 ]; then\n"
        "    echo \"[CodeGuardian] Commit blocked: Critical/High vulnerabilities detected.\"\n"
        "    exit 1\n"
        "fi\n"
        "exit 0\n"
    )

    try:
        hook_script.write_text(script_content, encoding="utf-8")
        if os.name != "nt":
            hook_script.chmod(0o755)
        console.print(Panel(
            f"[bold green]Successfully installed CodeGuardian Git pre-commit hook![/bold green]\n"
            f"[dim]Hook path: {hook_script}[/dim]\n"
            "Every staged commit will now be audited for critical vulnerabilities before creation.",
            border_style="green",
        ))
        return 0
    except OSError as exc:
        console.print(f"[bold red]Failed to install hook:[/bold red] {exc}")
        return 1


def uninstall_pre_commit_hook(repo_dir: Optional[Path] = None) -> int:
    """Remove the CodeGuardian pre-commit hook."""
    target_root = repo_dir or ROOT_DIR
    hook_script = target_root / ".git" / "hooks" / "pre-commit"
    if hook_script.exists():
        try:
            hook_script.unlink()
            console.print("[bold green]Successfully uninstalled CodeGuardian pre-commit hook.[/bold green]")
            return 0
        except OSError as exc:
            console.print(f"[bold red]Failed to delete hook:[/bold red] {exc}")
            return 1
    console.print("[yellow]No pre-commit hook found to uninstall.[/yellow]")
    return 0



def review_cli(
    diff_content: str,
    fail_on_critical: bool = False,
    show_compliance: bool = False,
    export_format: Optional[str] = None,
) -> int:
    if not diff_content.strip():
        console.print("[dim]No changes or empty Git diff detected. Repository is clean.[/dim]")
        return 0
    try:
        report = analyze_diff(diff_content)
    except ValueError as exc:
        console.print(f"[bold red]Review failed:[/bold red] {exc}")
        return 2

    if export_format:
        if export_format == "json":
            print(report.model_dump_json(indent=2))
            return 0
        elif export_format == "markdown":
            print(export_report_markdown(report))
            return 0
        elif export_format == "pr":
            print(export_pr_summary_markdown(report))
            return 0
        elif export_format == "sarif":
            import json
            print(json.dumps(export_report_sarif(report), indent=2))
            return 0

    console.print(Panel.fit(
        "[bold cyan]CodeGuardian local diff review[/bold cyan]\n"
        "[dim]Deterministic scanner; zero telemetry egress; source-located coordinates.[/dim]",
        border_style="cyan",
    ))
    console.print(Syntax(diff_content, "diff", theme="monokai", line_numbers=True, word_wrap=True))
    console.print(
        Panel(
            report.summary,
            title=f"{report.verdict} | {report.risk_level}",
            border_style="red" if report.verdict == "REQUEST_CHANGES" else "green",
        )
    )

    if show_compliance and report.compliance_matrix:
        c_table = Table(title="OWASP Top 10 Compliance Mapping", show_lines=True)
        c_table.add_column("Category", style="cyan")
        c_table.add_column("Title", style="bold")
        c_table.add_column("Count", justify="center")
        c_table.add_column("Finding IDs", style="dim")
        for item in report.compliance_matrix:
            c_table.add_row(item.category_id, item.title, str(item.count), ", ".join(item.finding_ids))
        console.print(c_table)

    if not report.findings:
        return 0

    table = Table(title="Source-located findings", show_lines=True)
    table.add_column("Severity / CVSS", style="bold")
    table.add_column("Rule / location")
    table.add_column("Evidence and remediation")
    for finding in report.findings:
        sev_display = finding.severity
        if finding.cvss_score:
            sev_display += f"\n[yellow]CVSS {finding.cvss_score}[/yellow]"
        remediation_text = f"{finding.description}\n\nEvidence: {finding.evidence[0]}\n\n{finding.remediation}"
        if finding.suggested_fix:
            remediation_text += "\n\n[bold green][+] Grounded patch available (use UI or --export to view)[/bold green]"
        table.add_row(
            sev_display,
            f"{finding.rule_id}\n{finding.file}:{finding.line_range}\n[dim]{finding.owasp_category or ''}[/dim]",
            remediation_text,
        )
    console.print(table)

    if fail_on_critical:
        return 1 if (report.counts.critical > 0 or report.counts.high > 0) else 0
    return 1 if report.verdict == "REQUEST_CHANGES" else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="CodeGuardian local unified-diff reviewer")
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("--git", action="store_true", help="review the current working-tree diff")
    source.add_argument("--staged", action="store_true", help="review staged Git changes only")
    source.add_argument("--file", type=Path, help="review a unified .diff or .patch file")
    source.add_argument("--diff", type=str, help="review a unified diff string directly")
    source.add_argument("--install-hook", action="store_true", help="install Git pre-commit security hook")
    source.add_argument("--uninstall-hook", action="store_true", help="remove Git pre-commit security hook")

    parser.add_argument("--fail-on-critical", action="store_true", help="exit with status 1 if CRITICAL/HIGH findings exist")
    parser.add_argument("--compliance", action="store_true", help="display OWASP Top 10 compliance matrix")
    parser.add_argument("--export", choices=["markdown", "json", "sarif", "pr"], help="export report in specified format")
    args = parser.parse_args()

    if args.install_hook:
        return install_pre_commit_hook()
    if args.uninstall_hook:
        return uninstall_pre_commit_hook()

    if args.diff:
        diff_text = args.diff
    elif args.staged:
        diff_text = get_git_diff(staged_only=True)
    elif args.git:
        diff_text = get_git_diff()
    elif args.file:
        try:
            diff_text = args.file.read_text(encoding="utf-8")
        except OSError as exc:
            console.print(f"[bold red]Cannot read {args.file}:[/bold red] {exc}")
            return 2
    else:
        # Default to git diff if inside worktree, else show help
        diff_text = get_git_diff()
        if not diff_text:
            parser.print_help()
            return 0

    return review_cli(
        diff_text,
        fail_on_critical=args.fail_on_critical,
        show_compliance=args.compliance,
        export_format=args.export,
    )


if __name__ == "__main__":
    sys.exit(main())
