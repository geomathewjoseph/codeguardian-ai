/* ============================================================
   CodeGuardian AI Workstation — Client Controller
   High-density developer workstation logic.
   Zero AI clichés: precise contracts, keyboard-first, deterministic.
   ============================================================ */

document.addEventListener("DOMContentLoaded", () => {
  const $ = (id) => document.getElementById(id);

  const elements = {
    // Header & Telemetry
    engineButton: $("engineButton"), enginePanel: $("enginePanel"), engineDot: $("engineDot"),
    engineLabel: $("engineLabel"), hardwareLabel: $("hardwareLabel"), modelValue: $("modelValue"),
    inferenceValue: $("inferenceValue"), deviceValue: $("deviceValue"), vramValue: $("vramValue"),
    executionValue: $("executionValue"), scannersValue: $("scannersValue"), vramBarFill: $("vramBarFill"),
    vramBarLabel: $("vramBarLabel"), vramMeterBox: $("vramMeterBox"),
    topModelName: $("topModelName"), topModelQuant: $("topModelQuant"), modelPill: $("modelPill"),
    quantValue: $("quantValue"), contextValue: $("contextValue"), adapterValue: $("adapterValue"),
    vramSubLabel: $("vramSubLabel"), ramMeterBox: $("ramMeterBox"), ramBarLabel: $("ramBarLabel"),
    ramBarFill: $("ramBarFill"), ramSubLabel: $("ramSubLabel"), cpuMeterBox: $("cpuMeterBox"),
    cpuBarLabel: $("cpuBarLabel"), cpuBarFill: $("cpuBarFill"),
    exportBtn: $("exportBtn"), exportMenu: $("exportMenu"), exportWrapper: $("exportWrapper"),
    exportMdBtn: $("exportMdBtn"), exportPrBtn: $("exportPrBtn"), exportSarifBtn: $("exportSarifBtn"), exportJsonBtn: $("exportJsonBtn"),
    copyPrCommentBtn: $("copyPrCommentBtn"),
    repoName: $("repoName"), branchName: $("branchName"), targetBranch: $("targetBranch"),
    commitHash: $("commitHash"), workingTree: $("workingTree"), workingTreeBadge: $("workingTreeBadge"),
    reviewState: $("reviewState"),

    // Sidebar & File Explorer
    toggleFilesBtn: $("toggleFilesBtn"), filesSidebar: $("filesSidebar"),
    filesList: $("filesList"), filesBadge: $("filesBadge"),

    // Diff Bar & Canvas
    fileSelect: $("fileSelect"), fixtureSelect: $("fixtureSelect"),
    fetchGitButton: $("fetchGitButton"), copyFileButton: $("copyFileButton"), copyDiffButton: $("copyDiffButton"),
    formattedButton: $("formattedButton"), rawButton: $("rawButton"), wrapToggleBtn: $("wrapToggleBtn"),
    diffSearch: $("diffSearch"), searchCount: $("searchCount"), diffStats: $("diffStats"),
    diffScroll: $("diffScroll"), formattedDiff: $("formattedDiff"), rawDiff: $("rawDiff"), diffEmpty: $("diffEmpty"),
    emptySqlExampleBtn: $("emptySqlExampleBtn"), emptyGitFetchBtn: $("emptyGitFetchBtn"),
    diffHeading: $("diffHeading"), diffHunkInfo: $("diffHunkInfo"),

    // Audit Panel
    reviewButton: $("reviewButton"), reviewTiming: $("reviewTiming"), verdict: $("verdict"),
    findingCount: $("findingCount"), reviewSummary: $("reviewSummary"), analysisMeta: $("analysisMeta"),
    criticalCount: $("criticalCount"), highCount: $("highCount"), mediumCount: $("mediumCount"),
    lowCount: $("lowCount"), clearFilter: $("clearFilter"), findingsList: $("findingsList"),

    // Inspector
    findingDetail: $("findingDetail"), detailSeverity: $("detailSeverity"), detailCvss: $("detailCvss"), detailRule: $("detailRule"),
    detailConfidence: $("detailConfidence"), detailTitle: $("detailTitle"), detailLocation: $("detailLocation"),
    detailProvenance: $("detailProvenance"), detailEvidence: $("detailEvidence"), detailDescription: $("detailDescription"),
    detailExploit: $("detailExploit"), detailRemediation: $("detailRemediation"), copyEvidenceBtn: $("copyEvidenceBtn"),
    patchStatus: $("patchStatus"), patchMessage: $("patchMessage"), patchCode: $("patchCode"),
    copyPatchButton: $("copyPatchButton"), verifyPatchButton: $("verifyPatchButton"),
    applyPatchWorktreeButton: $("applyPatchWorktreeButton"), revertPatchWorktreeButton: $("revertPatchWorktreeButton"),
    patchVerifyOutput: $("patchVerifyOutput"),
    testStatus: $("testStatus"), testDescription: $("testDescription"), testMeta: $("testMeta"),
    testCode: $("testCode"), testActions: $("testActions"), copyTestButton: $("copyTestButton"),
    runTestButton: $("runTestButton"), testOutput: $("testOutput"),

    // History, Compliance & Shortcuts
    installHookBtn: $("installHookBtn"), complianceBtn: $("complianceBtn"), complianceDrawer: $("complianceDrawer"),
    closeComplianceBtn: $("closeComplianceBtn"), complianceContent: $("complianceContent"),
    historyBtn: $("historyBtn"), historyDrawer: $("historyDrawer"), closeHistoryBtn: $("closeHistoryBtn"), historyList: $("historyList"),
    shortcutsBtn: $("shortcutsBtn"), shortcutsModal: $("shortcutsModal"), closeShortcutsBtn: $("closeShortcutsBtn"),

    // Policy & AI Explainer
    policyBtn: $("policyBtn"), policyDrawer: $("policyDrawer"), closePolicyBtn: $("closePolicyBtn"),
    savePolicyBtn: $("savePolicyBtn"), policyEntropyInput: $("policyEntropyInput"),
    policyEntropyVal: $("policyEntropyVal"), policyExcludeInput: $("policyExcludeInput"),
    policyIgnoreInput: $("policyIgnoreInput"), policyGateCheckbox: $("policyGateCheckbox"),
    explainFindingBtn: $("explainFindingBtn"), explainModal: $("explainModal"), closeExplainBtn: $("closeExplainBtn"),
    explainModalFindingRule: $("explainModalFindingRule"), explainModalModelBadge: $("explainModalModelBadge"),
    explainExploitText: $("explainExploitText"), explainImpactText: $("explainImpactText"),
    explainRemediationSteps: $("explainRemediationSteps"), explainBestPractices: $("explainBestPractices"),

    toast: $("toast")
  };

  const state = {
    diff: "",
    files: [],
    fileIndex: 0,
    mode: "formatted",
    isWrapped: false,
    presets: {},
    report: null,
    severity: null,
    selectedId: null,
    selectedTest: null,
    searchMatchIndex: -1,
    searchMatches: [],
    appliedPatches: new Map()
  };

  let toastTimer = null;

  const statusText = {
    GENERATED: "GENERATED · CANDIDATE",
    NOT_EXECUTED: "NOT EXECUTED",
    EXECUTED_PASSED: "EXECUTED · PASSED",
    EXECUTED_FAILED: "EXECUTED · FAILED",
    SKIPPED: "SKIPPED",
    UNAVAILABLE: "EXECUTION UNAVAILABLE (HOST SAFETY LOCK)"
  };

  function showToast(message) {
    if (!elements.toast) return;
    elements.toast.textContent = message;
    elements.toast.classList.add("visible");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => elements.toast.classList.remove("visible"), 3200);
  }

  async function getJson(url, options) {
    const response = await fetch(url, options);
    let data;
    try { data = await response.json(); } catch { data = {}; }
    if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
    return data;
  }

  function splitHeaderPaths(line) {
    const raw = line.slice("diff --git ".length).trim();
    const parts = raw.match(/"(?:\\.|[^"\\])*"|\S+/g) || [];
    if (parts.length < 2) return [null, null];
    return [stripGitPrefix(parts[0]), stripGitPrefix(parts[1])];
  }

  function stripGitPrefix(value) {
    const path = value.replace(/^"|"$/g, "");
    if (path === "/dev/null") return null;
    return path.replace(/^[ab]\//, "");
  }

  function parseDiff(text) {
    const files = [];
    let current = null, oldNumber = null, newNumber = null;
    for (const raw of text.replace(/\r\n/g, "\n").split("\n")) {
      if (raw.startsWith("diff --git ")) {
        const [oldPath, newPath] = splitHeaderPaths(raw);
        current = {
          oldPath,
          newPath,
          path: newPath || oldPath || "unknown",
          hunkCount: 0,
          additions: 0,
          deletions: 0,
          lines: [{ kind: "meta", text: raw }]
        };
        files.push(current);
        oldNumber = null;
        newNumber = null;
        continue;
      }
      if (!current && raw.startsWith("@@")) {
        current = { oldPath: null, newPath: null, path: "unlabelled diff", hunkCount: 0, additions: 0, deletions: 0, lines: [] };
        files.push(current);
      }
      if (!current) continue;
      if (raw.startsWith("--- ")) {
        current.oldPath = stripGitPrefix(raw.slice(4));
        current.path = current.newPath || current.oldPath || "unknown";
        current.lines.push({ kind: "meta", text: raw });
        continue;
      }
      if (raw.startsWith("+++ ")) {
        current.newPath = stripGitPrefix(raw.slice(4));
        current.path = current.newPath || current.oldPath || "unknown";
        current.lines.push({ kind: "meta", text: raw });
        continue;
      }
      if (raw.startsWith("rename from ")) {
        current.oldPath = raw.slice(12);
        current.lines.push({ kind: "meta", text: raw });
        continue;
      }
      if (raw.startsWith("rename to ")) {
        current.newPath = raw.slice(10);
        current.path = current.newPath;
        current.lines.push({ kind: "meta", text: raw });
        continue;
      }
      const hunk = raw.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (hunk) {
        current.hunkCount += 1;
        oldNumber = Number(hunk[1]);
        newNumber = Number(hunk[2]);
        current.lines.push({ kind: "hunk", text: raw });
        continue;
      }
      if (raw.startsWith("+") && !raw.startsWith("+++")) {
        current.additions += 1;
        current.lines.push({ kind: "add", text: raw.slice(1), old: null, new: newNumber });
        if (newNumber !== null) newNumber += 1;
        continue;
      }
      if (raw.startsWith("-") && !raw.startsWith("---")) {
        current.deletions += 1;
        current.lines.push({ kind: "delete", text: raw.slice(1), old: oldNumber, new: null });
        if (oldNumber !== null) oldNumber += 1;
        continue;
      }
      if (raw.startsWith(" ")) {
        current.lines.push({ kind: "context", text: raw.slice(1), old: oldNumber, new: newNumber });
        if (oldNumber !== null) oldNumber += 1;
        if (newNumber !== null) newNumber += 1;
        continue;
      }
      current.lines.push({ kind: "meta", text: raw });
    }
    return files.filter((file) => file.lines.length > 0);
  }

  function currentFile() { return state.files[state.fileIndex] || null; }
  function selectedFinding() { return state.report?.findings?.find((f) => f.id === state.selectedId) || null; }
  function findingForLine(file, line) {
    return state.report?.findings?.find((f) => f.file === file.path && line.new >= f.line_start && line.new <= f.line_end) || null;
  }
  function findingsForFile(filePath) {
    return (state.report?.findings || []).filter((f) => f.file === filePath);
  }
  function selectedScope() { return document.querySelector("input[name=scope]:checked")?.value || "ALL"; }

  function setDiff(text, source) {
    state.diff = text.replace(/\r\n/g, "\n");
    state.files = parseDiff(state.diff);
    state.fileIndex = 0;
    elements.rawDiff.value = state.diff;
    populateFiles();
    renderDiff();
    clearReview(source || "Diff loaded — ready to review");
    elements.copyDiffButton.disabled = !state.diff.trim();
    elements.reviewButton.disabled = !state.diff.trim();
    elements.diffSearch.disabled = !state.files.length;
  }

  function populateFiles() {
    elements.fileSelect.replaceChildren();
    elements.filesList.replaceChildren();

    const count = state.files.length;
    elements.filesBadge.textContent = String(count);

    if (!count) {
      elements.fileSelect.append(new Option("No changed file", ""));
      elements.fileSelect.disabled = true;
      elements.copyFileButton.disabled = true;
      const empty = document.createElement("div");
      empty.className = "files-empty";
      empty.textContent = "No changed files";
      elements.filesList.append(empty);
      return;
    }

    state.files.forEach((file, index) => {
      // Option in dropdown
      elements.fileSelect.append(new Option(file.path, String(index)));

      // Item in files tree sidebar
      const item = document.createElement("button");
      item.type = "button";
      item.className = `file-item${index === state.fileIndex ? " is-selected" : ""}`;
      item.setAttribute("role", "tab");
      item.setAttribute("aria-selected", String(index === state.fileIndex));

      const left = document.createElement("span");
      left.className = "file-item-left";

      // File icon
      const icon = document.createElement("span");
      icon.innerHTML = `<svg class="icon-xs text-muted" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>`;

      const name = document.createElement("span");
      name.className = "file-name";
      name.textContent = file.path.split("/").pop() || file.path;
      name.title = file.path;

      left.append(icon, name);

      const right = document.createElement("span");
      right.className = "file-item-right";

      const fileFindings = findingsForFile(file.path);
      if (fileFindings.length > 0) {
        const pip = document.createElement("span");
        pip.className = "file-finding-pip";
        pip.title = `${fileFindings.length} security finding(s)`;
        right.append(pip);
      }

      const stats = document.createElement("span");
      stats.className = "diff-counts";
      stats.innerHTML = `<span class="stat-pill-add">+${file.additions}</span><span class="stat-pill-del">-${file.deletions}</span>`;
      right.append(stats);

      item.append(left, right);
      item.addEventListener("click", () => {
        state.fileIndex = index;
        elements.fileSelect.value = String(index);
        populateFiles();
        renderDiff();
      });

      elements.filesList.append(item);
    });

    elements.fileSelect.value = String(state.fileIndex);
    elements.fileSelect.disabled = false;
    elements.copyFileButton.disabled = false;
  }

  function makeCell(className, text) {
    const cell = document.createElement("span");
    cell.className = className;
    cell.textContent = text ?? "";
    return cell;
  }

  function renderDiff() {
    const file = currentFile();
    elements.formattedDiff.replaceChildren();
    state.searchMatches = [];
    state.searchMatchIndex = -1;

    elements.diffEmpty.classList.toggle("is-hidden", Boolean(file) || state.mode === "raw");
    if (!file) {
      elements.diffStats.innerHTML = `<span class="stat-pill-add">+0</span> <span class="stat-pill-del">-0</span>`;
      elements.searchCount.textContent = "";
      elements.diffHunkInfo.textContent = "No hunks loaded";
      return;
    }

    elements.diffHunkInfo.textContent = `${file.hunkCount} hunk${file.hunkCount === 1 ? "" : "s"} · +${file.additions} / -${file.deletions}`;

    const query = elements.diffSearch.value.trim().toLocaleLowerCase();
    let additions = 0, deletions = 0;

    for (const line of file.lines) {
      if (line.kind === "meta") {
        const metaRow = document.createElement("div");
        metaRow.className = "line-meta-row";
        const cell = document.createElement("div");
        cell.className = "line-meta-cell";
        cell.textContent = line.text;
        metaRow.append(cell);
        elements.formattedDiff.append(metaRow);
        continue;
      }

      if (line.kind === "hunk") {
        const hunkRow = document.createElement("div");
        hunkRow.className = "line-hunk-row";
        const cell = document.createElement("div");
        cell.className = "line-hunk-cell";
        cell.textContent = line.text;
        hunkRow.append(cell);
        elements.formattedDiff.append(hunkRow);
        continue;
      }

      const row = document.createElement("div");
      row.className = `diff-line line-${line.kind}`;
      row.dataset.newLine = line.new ?? "";

      const sign = line.kind === "add" ? "+" : line.kind === "delete" ? "-" : " ";
      row.append(
        makeCell("line-old", line.old ? String(line.old) : ""),
        makeCell("line-new", line.new ? String(line.new) : ""),
        makeCell("line-sign", sign),
        makeCell("line-content", line.text)
      );

      if (line.kind === "add") additions += 1;
      if (line.kind === "delete") deletions += 1;

      const finding = line.new ? findingForLine(file, line) : null;
      if (finding) {
        row.classList.add("line-finding");
        row.dataset.findingId = finding.id;
      }

      if (query && line.text.toLocaleLowerCase().includes(query)) {
        row.classList.add("line-search");
        state.searchMatches.push(row);
      }

      elements.formattedDiff.append(row);

      // Clean inline finding callout card positioned neatly beneath the line
      if (finding) {
        const card = document.createElement("div");
        card.className = "inline-finding-card";
        card.setAttribute("role", "alert");
        card.title = "Click to inspect this security finding in the audit panel";

        const left = document.createElement("div");
        left.className = "inline-finding-left";

        const chip = document.createElement("span");
        chip.className = "inline-sev-chip";
        chip.textContent = finding.severity;

        const rule = document.createElement("span");
        rule.className = "inline-rule-id";
        rule.textContent = finding.rule_id;

        const title = document.createElement("span");
        title.textContent = finding.title;

        left.append(chip, rule, title);

        const right = document.createElement("div");
        right.className = "inline-finding-right";
        right.innerHTML = `<span>Inspect</span> <svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>`;

        card.append(left, right);
        card.addEventListener("click", () => selectFinding(finding.id, false));
        elements.formattedDiff.append(card);
      }
    }

    elements.diffStats.innerHTML = `
      <span class="stat-pill-add">+${additions}</span>
      <span class="stat-pill-del">-${deletions}</span>
    `;

    if (query) {
      elements.searchCount.textContent = `${state.searchMatches.length} match${state.searchMatches.length === 1 ? "" : "es"}`;
    } else {
      elements.searchCount.textContent = "";
    }
  }

  function clearReview(message) {
    state.report = null;
    state.severity = null;
    state.selectedId = null;
    state.selectedTest = null;
    renderReviewEmpty(message);
    renderDiff();
    populateFiles();
  }

  function renderReviewEmpty(message) {
    elements.verdict.textContent = "NOT REVIEWED";
    elements.verdict.className = "verdict-tag verdict-neutral";
    elements.findingCount.textContent = "Load a diff to begin";
    elements.reviewSummary.textContent = "Deterministic AST & regex analysis with CWE categorization and test fixtures.";
    elements.analysisMeta.textContent = "Ready";
    elements.reviewState.textContent = message || "Ready";
    elements.reviewState.className = "review-status-pill";
    updateCounts({ critical: 0, high: 0, medium: 0, low: 0 });
    elements.findingsList.replaceChildren();
    const placeholder = document.createElement("p");
    placeholder.className = "placeholder";
    placeholder.textContent = "No findings to display. Run review to detect vulnerabilities.";
    elements.findingsList.append(placeholder);
    elements.findingDetail.classList.add("is-hidden");
    elements.copyPrCommentBtn?.classList.add("is-hidden");
  }

  function updateCounts(counts) {
    elements.criticalCount.textContent = counts.critical || 0;
    elements.highCount.textContent = counts.high || 0;
    elements.mediumCount.textContent = counts.medium || 0;
    elements.lowCount.textContent = counts.low || 0;
    document.querySelectorAll(".severity, .filter-btn[data-severity]").forEach((button) => {
      button.classList.toggle("is-active", button.dataset.severity === state.severity);
    });
    if (elements.clearFilter) {
      elements.clearFilter.classList.toggle("is-active", state.severity === null);
    }
  }

  function verdictClass(verdict) {
    return verdict === "APPROVE" ? "verdict-approve" : verdict === "REQUEST_CHANGES" ? "verdict-changes" : "verdict-comment";
  }

  function severityClass(severity) {
    return String(severity || "medium").toLocaleLowerCase();
  }

  function renderReport(report) {
    state.report = report;
    state.severity = null;
    state.selectedId = report.findings[0]?.id || null;
    state.selectedTest = null;

    const formattedVerdict = report.verdict.replace("_", " ");
    elements.verdict.textContent = formattedVerdict;
    elements.verdict.className = `verdict-tag ${verdictClass(report.verdict)}`;
    elements.findingCount.textContent = `${report.findings.length} finding${report.findings.length === 1 ? "" : "s"}`;
    elements.reviewSummary.textContent = report.summary;
    elements.analysisMeta.textContent = `${report.engine} · ${report.execution_time_ms} ms`;

    elements.reviewState.textContent = `${formattedVerdict} (${report.findings.length})`;
    elements.reviewState.className = `review-status-pill ${report.verdict === "REQUEST_CHANGES" ? "changes" : report.verdict === "APPROVE" ? "clean" : ""}`;
    elements.copyPrCommentBtn?.classList.remove("is-hidden");

    updateCounts(report.counts);
    populateFiles();
    renderFindings();
    renderDetail();
    renderDiff();
  }

  function visibleFindings() {
    return (state.report?.findings || []).filter((f) => !state.severity || f.severity === state.severity);
  }

  function renderFindings() {
    elements.findingsList.replaceChildren();
    const findings = visibleFindings();
    if (!findings.length) {
      const placeholder = document.createElement("p");
      placeholder.className = "placeholder";
      placeholder.textContent = state.report?.findings?.length
        ? "No findings match this severity filter."
        : "No deterministic security findings were identified.";
      elements.findingsList.append(placeholder);
      return;
    }
    if (!findings.some((f) => f.id === state.selectedId)) {
      state.selectedId = findings[0].id;
    }
    findings.forEach((finding, index) => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = `finding-row${finding.id === state.selectedId ? " is-selected" : ""}`;
      row.setAttribute("role", "option");
      row.setAttribute("aria-selected", String(finding.id === state.selectedId));
      row.dataset.findingId = finding.id;

      const headerDiv = document.createElement("div");
      headerDiv.className = "finding-row-header";

      const badgesDiv = document.createElement("div");
      badgesDiv.className = "finding-row-badges";

      const severity = document.createElement("span");
      severity.className = `severity-label ${severityClass(finding.severity)}`;
      severity.textContent = finding.severity;
      badgesDiv.append(severity);

      if (finding.cvss_score !== undefined && finding.cvss_score !== null) {
        const cvssPill = document.createElement("span");
        cvssPill.className = `badge-cvss ${finding.cvss_score >= 9.0 ? "crit" : finding.cvss_score >= 7.0 ? "high" : ""}`;
        cvssPill.textContent = `CVSS ${Number(finding.cvss_score).toFixed(1)}`;
        cvssPill.title = finding.cvss_vector || `CVSS:3.1 Base Score ${finding.cvss_score}`;
        badgesDiv.append(cvssPill);
      }

      if (finding.suggested_fix) {
        const patchPill = document.createElement("span");
        patchPill.className = "patch-badge";
        patchPill.textContent = "⚡ Auto-Fix";
        badgesDiv.append(patchPill);
      }

      const locSpan = document.createElement("span");
      locSpan.className = "finding-row-loc";
      locSpan.textContent = `${finding.file}:${finding.line_start}`;

      headerDiv.append(badgesDiv, locSpan);

      const title = document.createElement("div");
      title.className = "finding-title";
      title.textContent = finding.title;

      const meta = document.createElement("div");
      meta.className = "finding-meta";
      const ruleSpan = document.createElement("span");
      ruleSpan.className = "finding-rule-tag";
      ruleSpan.textContent = finding.rule_id;
      meta.append(ruleSpan);

      if (finding.confidence) {
        const confSpan = document.createElement("span");
        confSpan.className = "finding-conf-hint";
        confSpan.textContent = `· Conf: ${finding.confidence}`;
        meta.append(confSpan);
      }

      row.append(headerDiv, title, meta);
      row.addEventListener("click", () => selectFinding(finding.id, true));
      row.addEventListener("keydown", (event) => {
        if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        const target = event.key === "ArrowDown" ? Math.min(index + 1, findings.length - 1)
          : event.key === "ArrowUp" ? Math.max(index - 1, 0)
          : event.key === "Home" ? 0 : findings.length - 1;
        selectFinding(findings[target].id, true);
        document.querySelector(`[data-finding-id="${CSS.escape(findings[target].id)}"]`)?.focus();
      });
      elements.findingsList.append(row);
    });
  }

  function selectFinding(id, navigate) {
    state.selectedId = id;
    state.selectedTest = null;
    const finding = selectedFinding();
    const fileIndex = state.files.findIndex((file) => file.path === finding?.file);
    if (fileIndex >= 0) {
      state.fileIndex = fileIndex;
      elements.fileSelect.value = String(fileIndex);
      populateFiles();
    }
    renderFindings();
    renderDetail();
    renderDiff();
    if (navigate && finding) {
      window.requestAnimationFrame(() => {
        const line = document.querySelector(`.diff-line[data-new-line="${finding.line_start}"]`);
        if (line) line.scrollIntoView({ block: "center", behavior: "smooth" });
      });
    }
  }

  function renderDetail() {
    const finding = selectedFinding();
    if (!finding) {
      elements.findingDetail.classList.add("is-hidden");
      return;
    }
    elements.findingDetail.classList.remove("is-hidden");
    switchDetailTab("overview");
    elements.detailSeverity.textContent = finding.severity;
    elements.detailSeverity.className = `cg-severity-${severityClass(finding.severity)} badge-sev`;
    if (elements.detailCvss) {
      if (finding.cvss_score !== undefined && finding.cvss_score !== null) {
        elements.detailCvss.textContent = `CVSS ${Number(finding.cvss_score).toFixed(1)}`;
        elements.detailCvss.className = `badge-cvss ${finding.cvss_score >= 9.0 ? "crit" : finding.cvss_score >= 7.0 ? "high" : ""}`;
        elements.detailCvss.title = finding.cvss_vector || `CVSS:3.1 Base Score ${finding.cvss_score}`;
        elements.detailCvss.classList.remove("is-hidden");
      } else {
        elements.detailCvss.classList.add("is-hidden");
      }
    }
    elements.detailRule.textContent = finding.rule_id;
    elements.detailConfidence.textContent = `Confidence: ${finding.confidence}`;
    if (elements.detailTitle) elements.detailTitle.textContent = finding.title;
    const fileLocEl = $("detailFileLocation");
    const lineLocEl = $("detailLineLocation");
    if (fileLocEl) fileLocEl.textContent = finding.file;
    if (lineLocEl) lineLocEl.textContent = `Line ${finding.line_start}`;
    if (elements.detailLocation) elements.detailLocation.textContent = `${finding.file}:${finding.line_start}${finding.line_end !== finding.line_start ? `-${finding.line_end}` : ""}`;
    if (elements.detailProvenance) elements.detailProvenance.textContent = finding.provenance.replaceAll("_", " ");
    elements.detailEvidence.textContent = (finding.evidence || []).join("\n") || "No source evidence was supplied.";
    elements.detailDescription.textContent = finding.description;
    elements.detailExploit.textContent = finding.exploit_conditions || "No exploit conditions were provided.";
    elements.detailRemediation.textContent = finding.remediation;

    const hasPatch = Boolean(finding.suggested_fix);
    elements.patchStatus.textContent = finding.patch_status.replaceAll("_", " ");
    elements.patchMessage.textContent = hasPatch ? "Candidate unified patch. Validated in-memory against source." : "No automatic patch is available for this finding.";
    elements.patchCode.classList.toggle("is-hidden", !hasPatch);
    elements.copyPatchButton.classList.toggle("is-hidden", !hasPatch);
    if (elements.verifyPatchButton) elements.verifyPatchButton.classList.toggle("is-hidden", !hasPatch);
    if (elements.applyPatchWorktreeButton) elements.applyPatchWorktreeButton.classList.toggle("is-hidden", !hasPatch);
    if (elements.revertPatchWorktreeButton) {
      elements.revertPatchWorktreeButton.classList.toggle("is-hidden", !state.appliedPatches.has(finding.id));
    }
    if (elements.patchVerifyOutput) elements.patchVerifyOutput.classList.add("is-hidden");
    if (hasPatch) elements.patchCode.firstElementChild.textContent = finding.suggested_fix;

    const test = finding.related_tests?.[0] || null;
    state.selectedTest = test;
    elements.testCode.classList.toggle("is-hidden", !test);
    elements.testActions.classList.toggle("is-hidden", !test);
    elements.testOutput.classList.add("is-hidden");

    if (!test) {
      elements.testStatus.textContent = "NOT GENERATED";
      elements.testDescription.textContent = "No regression test candidate is available for this finding.";
      elements.testMeta.textContent = "";
      elements.testCode.firstElementChild.textContent = "";
      return;
    }
    elements.testStatus.textContent = statusText[test.status] || test.status;
    elements.testDescription.textContent = test.description || "Generated candidate fixture.";
    elements.testMeta.textContent = `Framework: ${test.framework}`;
    elements.testCode.firstElementChild.textContent = test.code;
  }

  const detailTabs = { overview: $("tabOverview"), patch: $("tabPatch"), test: $("tabTest") };
  const detailPanels = { overview: $("panelOverview"), patch: $("panelPatch"), test: $("panelTest") };

  function switchDetailTab(activeTab) {
    Object.keys(detailTabs).forEach((key) => {
      const btn = detailTabs[key];
      const panel = detailPanels[key];
      if (!btn || !panel) return;
      const isActive = key === activeTab;
      btn.classList.toggle("is-active", isActive);
      btn.setAttribute("aria-selected", String(isActive));
      panel.classList.toggle("is-hidden", !isActive);
    });
  }
  if (detailTabs.overview) detailTabs.overview.addEventListener("click", () => switchDetailTab("overview"));
  if (detailTabs.patch) detailTabs.patch.addEventListener("click", () => switchDetailTab("patch"));
  if (detailTabs.test) detailTabs.test.addEventListener("click", () => switchDetailTab("test"));

  async function copyText(value, label) {
    try {
      await navigator.clipboard.writeText(value);
      showToast(`${label} copied to clipboard`);
    } catch {
      showToast(`Unable to copy ${label.toLocaleLowerCase()}`);
    }
  }

  async function runReview() {
    const diff = state.mode === "raw" ? elements.rawDiff.value : state.diff;
    if (!diff.trim()) {
      showToast("Provide a unified Git diff first");
      return;
    }
    elements.reviewButton.disabled = true;
    elements.reviewTiming.textContent = "Scanning diff…";
    const started = performance.now();
    try {
      const report = await getJson("/api/review", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ diff, focus: selectedScope() })
      });
      renderReport(report);
      elements.reviewTiming.textContent = `${Math.round(performance.now() - started)} ms total`;
      showToast("Review complete · " + report.verdict.replace("_", " "));
    } catch (error) {
      elements.reviewTiming.textContent = "Review failed";
      elements.reviewSummary.textContent = `Review failed: ${error.message}`;
      showToast("Review could not complete: " + error.message);
    } finally {
      elements.reviewButton.disabled = !state.diff.trim();
    }
  }

  async function loadGitDiff() {
    elements.fetchGitButton.disabled = true;
    try {
      const data = await getJson("/api/git-diff");
      if (data.source === "not_git_repository") {
        showToast("Workspace is not a Git repository. Paste a patch or pick an example.");
        elements.workingTree.textContent = "not a git repo";
        elements.workingTreeBadge.className = "worktree-tag";
      } else if (data.source === "local_working_tree") {
        setDiff(data.diff || "", "Local working-tree diff loaded");
        showToast("Loaded local working-tree diff");
      } else {
        setDiff("", "No local Git changes available");
        showToast("No uncommitted changes in this repository");
      }
    } catch (error) {
      showToast(`Could not fetch Git diff: ${error.message}`);
    } finally {
      elements.fetchGitButton.disabled = false;
    }
  }

  async function runCandidateTest() {
    if (!state.selectedTest) return;
    elements.runTestButton.disabled = true;
    elements.testOutput.classList.remove("is-hidden");
    elements.testOutput.textContent = "Requesting isolated execution in safety sandbox…";
    try {
      const result = await getJson("/api/run-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test_code: state.selectedTest.code })
      });
      elements.testStatus.textContent = statusText[result.status] || result.status;
      elements.testOutput.textContent = [result.stdout, result.stderr].filter(Boolean).join("\n") || "No output returned.";
      showToast(result.status === "UNAVAILABLE" ? "Isolated execution disabled (host safety lock)" : "Test execution complete");
    } catch (error) {
      elements.testOutput.textContent = error.message;
      showToast("Test request failed: " + error.message);
    } finally {
      elements.runTestButton.disabled = false;
    }
  }

  async function verifyCandidatePatch() {
    const finding = selectedFinding();
    if (!finding?.suggested_fix) return;
    if (!elements.verifyPatchButton || !elements.patchVerifyOutput) return;

    elements.verifyPatchButton.disabled = true;
    elements.patchVerifyOutput.classList.remove("is-hidden");
    elements.patchVerifyOutput.textContent = "Validating unified patch in memory…";

    try {
      const result = await getJson("/api/verify-patch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          file_path: finding.file,
          original_code: (finding.evidence || []).join("\n"),
          patch: finding.suggested_fix,
          test_code: finding.related_tests?.[0]?.code || "def test_noop(): pass",
          framework: finding.related_tests?.[0]?.framework || "pytest"
        })
      });

      elements.patchVerifyOutput.textContent = [
        result.stdout,
        result.stderr,
        `Status: ${result.status} (Duration: ${result.duration_ms} ms)`
      ].filter(Boolean).join("\n");

      showToast(`Patch verification: ${result.status}`);
    } catch (err) {
      elements.patchVerifyOutput.textContent = "Verification request failed: " + err.message;
      showToast("Verification error: " + err.message);
    } finally {
      elements.verifyPatchButton.disabled = false;
    }
  }

  async function applyPatchToWorktree() {
    const finding = selectedFinding();
    if (!finding?.suggested_fix) return;
    if (!elements.applyPatchWorktreeButton || !elements.patchVerifyOutput) return;

    elements.applyPatchWorktreeButton.disabled = true;
    elements.patchVerifyOutput.classList.remove("is-hidden");
    elements.patchVerifyOutput.textContent = "Creating Git stash backup & applying unified patch to working tree…";

    try {
      const result = await getJson("/api/apply-patch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          patch: finding.suggested_fix,
          create_backup_stash: true
        })
      });

      if (result.success) {
        state.appliedPatches.set(finding.id, {
          patch: finding.suggested_fix,
          backup_ref: result.backup_ref
        });
        if (elements.revertPatchWorktreeButton) {
          elements.revertPatchWorktreeButton.classList.remove("is-hidden");
        }
        elements.patchVerifyOutput.textContent = `Applied Cleanly!\n${result.message}\nBackup Ref: ${result.backup_ref || "None"}\nModified: ${(result.files_modified || []).join(", ") || "Files updated"}`;
        showToast("Patch applied! Re-scanning working tree diff...");
        await loadGitDiff();
        await runReview();
      } else {
        elements.patchVerifyOutput.textContent = `Patch Apply Failed:\n${result.message}\nBackup Stash: ${result.backup_ref || "None"}`;
        showToast("Apply failed: " + result.message);
      }
    } catch (err) {
      elements.patchVerifyOutput.textContent = "Apply request error: " + err.message;
      showToast("Apply error: " + err.message);
    } finally {
      elements.applyPatchWorktreeButton.disabled = false;
    }
  }

  async function revertPatchFromWorktree() {
    const finding = selectedFinding();
    if (!finding) return;
    const applied = state.appliedPatches.get(finding.id) || { patch: finding.suggested_fix };
    if (!elements.revertPatchWorktreeButton || !elements.patchVerifyOutput) return;

    elements.revertPatchWorktreeButton.disabled = true;
    elements.patchVerifyOutput.classList.remove("is-hidden");
    elements.patchVerifyOutput.textContent = "Reverting patch and restoring working tree files…";

    try {
      const result = await getJson("/api/revert-patch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          patch: applied.patch,
          backup_ref: applied.backup_ref
        })
      });

      if (result.success) {
        state.appliedPatches.delete(finding.id);
        elements.revertPatchWorktreeButton.classList.add("is-hidden");
        elements.patchVerifyOutput.textContent = `Reverted Successfully!\n${result.message}`;
        showToast("Patch reverted! Re-scanning working tree diff...");
        await loadGitDiff();
        await runReview();
      } else {
        elements.patchVerifyOutput.textContent = `Revert Failed:\n${result.message}`;
        showToast("Revert failed: " + result.message);
      }
    } catch (err) {
      elements.patchVerifyOutput.textContent = "Revert request error: " + err.message;
      showToast("Revert error: " + err.message);
    } finally {
      elements.revertPatchWorktreeButton.disabled = false;
    }
  }

  function renderComplianceMatrix() {
    if (!elements.complianceContent) return;
    elements.complianceContent.replaceChildren();

    if (!state.report || !state.report.compliance_matrix || !state.report.compliance_matrix.length) {
      const p = document.createElement("p");
      p.className = "placeholder";
      p.textContent = state.report ? "No compliance-tracked vulnerabilities detected in this review." : "Review a diff to see OWASP Top 10 breakdown.";
      elements.complianceContent.append(p);
      return;
    }

    const title = document.createElement("h4");
    title.className = "compliance-matrix-title";
    title.textContent = `OWASP Top 10 (2021) — ${state.report.compliance_matrix.length} Categories Triggered`;
    elements.complianceContent.append(title);

    state.report.compliance_matrix.forEach((item) => {
      const card = document.createElement("div");
      card.className = "compliance-card";

      const header = document.createElement("div");
      header.className = "compliance-card-header";

      const catPill = document.createElement("span");
      catPill.className = "compliance-cat-pill";
      catPill.textContent = item.category_id;

      const countBadge = document.createElement("span");
      countBadge.className = `compliance-badge-count ${item.count > 0 ? "has-findings" : "clean"}`;
      countBadge.textContent = `${item.count} Finding${item.count === 1 ? "" : "s"}`;

      header.append(catPill, countBadge);

      const desc = document.createElement("div");
      desc.className = "compliance-card-desc";
      desc.textContent = item.title;

      const ids = document.createElement("div");
      ids.className = "compliance-findings-list";
      ids.textContent = `Associated Findings: ${(item.finding_ids || []).join(", ") || "None"}`;

      card.append(header, desc, ids);
      elements.complianceContent.append(card);
    });
  }

  async function exportReport(format) {
    if (!state.report) {
      showToast("Run a review before exporting");
      return;
    }
    try {
      const res = await fetch("/api/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report: state.report, format })
      });
      if (!res.ok) throw new Error(`Export failed (${res.status})`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const ext = format === "json" ? "json" : format === "sarif" ? "sarif" : "md";
      const filename = format === "pr" ? "codeguardian-pr-review.md" : format === "sarif" ? "codeguardian.sarif" : `codeguardian-report.${ext}`;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast(`Exported ${format.toUpperCase()} successfully`);
    } catch (err) {
      showToast("Export failed: " + err.message);
    }
  }

  async function copyPrComment() {
    if (!state.report) {
      showToast("Run a review before copying PR comment");
      return;
    }
    try {
      const res = await fetch("/api/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report: state.report, format: "pr" })
      });
      if (!res.ok) throw new Error(`Fetch failed (${res.status})`);
      const text = await res.text();
      await navigator.clipboard.writeText(text);
      showToast("Copied GitHub PR Review comment to clipboard!");
    } catch (err) {
      showToast("Copy failed: " + err.message);
    }
  }

  async function loadContext() {
    try {
      const data = await getJson("/api/git-context");
      elements.repoName.textContent = data.repo_name;
      elements.repoName.title = `Workspace: ${data.repo_name}`;
      elements.branchName.textContent = data.branch || "HEAD";
      elements.targetBranch.textContent = data.target_branch || "N/A";
      elements.commitHash.textContent = data.commit_hash || "N/A";

      const rawState = (data.working_tree_state || "").toLowerCase();
      let stateDisplay = "Local";
      if (rawState === "not_git_repository") {
        stateDisplay = "Local";
      } else if (rawState === "clean") {
        stateDisplay = "Clean";
      } else if (rawState === "uncommitted") {
        stateDisplay = "Uncommitted";
      } else {
        stateDisplay = rawState ? rawState.replaceAll("_", " ") : "Local";
      }
      elements.workingTree.textContent = stateDisplay;
      if (elements.workingTreeBadge) {
        elements.workingTreeBadge.className = `worktree-tag ${rawState || "local"}`;
      }
    } catch {
      elements.repoName.textContent = "Workspace";
      elements.workingTree.textContent = "Local";
    }
  }

  async function loadStatus() {
    try {
      const data = await getJson("/api/status");
      const hardware = data.hardware || {};

      // 1. Top bar Model Pill & Engine Trigger
      if (elements.topModelName) {
        elements.topModelName.textContent = data.display_name || data.model_name || "Qwen 2.5 Coder 3B";
      }
      if (elements.topModelQuant) {
        elements.topModelQuant.textContent = data.quantization ? data.quantization.split(" ")[0] + " " + (data.quantization.split(" ")[1] || "NF4") : "4-bit NF4";
      }
      if (elements.modelPill) {
        elements.modelPill.title = `Model: ${data.model_name || 'N/A'}\nArchitecture: ${data.target_architecture || 'Qwen 2.5 Coder'}\nHardware: ${data.target_hardware || 'RTX 5060'}`;
      }

      elements.engineLabel.textContent = data.display_name ? "Qwen 2.5 · AST Guard" : "Deterministic AST";
      elements.engineDot.className = `status-indicator ${hardware.cuda_available ? "ready" : "unavailable"}`;
      elements.hardwareLabel.textContent = hardware.cuda_available
        ? `${(hardware.device || "RTX 5060").replace("NVIDIA GeForce ", "").replace(" Laptop GPU", "")} · ${((hardware.total_mb || 8151) / 1024).toFixed(1)} GB`
        : "CUDA N/A";

      // 2. Telemetry Grid Details
      if (elements.modelValue) elements.modelValue.textContent = data.model_name || "Qwen/Qwen2.5-Coder-3B-Instruct";
      if (elements.quantValue) elements.quantValue.textContent = data.quantization || "4-bit NF4 (Double Quant)";
      if (elements.contextValue) elements.contextValue.textContent = `${(data.context_window || 2048).toLocaleString()} tokens`;
      if (elements.adapterValue) elements.adapterValue.textContent = data.adapter_available ? `${data.adapter_name} (Loaded)` : `${data.adapter_name} (Ready to train)`;
      if (elements.inferenceValue) elements.inferenceValue.textContent = data.inference_engine || "Deterministic AST + Qwen 2.5";
      if (elements.deviceValue) elements.deviceValue.textContent = hardware.device || "NVIDIA RTX 5060 (8GB)";

      // 3. GPU VRAM Utilization Meter
      if (hardware.cuda_available && hardware.total_mb) {
        const used = hardware.gpu_used_mb !== undefined && hardware.gpu_used_mb !== null ? hardware.gpu_used_mb : (hardware.allocated_mb || 0);
        const total = hardware.total_mb;
        const pct = Math.min(100, Math.round((used / total) * 100));
        const free = hardware.gpu_free_mb !== undefined && hardware.gpu_free_mb !== null ? hardware.gpu_free_mb : Math.max(0, total - used);
        const gpuLoad = hardware.gpu_util_pct !== undefined && hardware.gpu_util_pct !== null ? `${hardware.gpu_util_pct}%` : "Idle";

        if (elements.vramBarLabel) elements.vramBarLabel.textContent = `${Math.round(used).toLocaleString()} MB / ${Math.round(total).toLocaleString()} MB (${pct}%)`;
        if (elements.vramBarFill) {
          elements.vramBarFill.style.width = `${Math.max(4, pct)}%`;
          elements.vramBarFill.className = `meter-fill vram-fill ${pct > 90 ? "alert" : pct > 80 ? "warn" : ""}`;
        }
        if (elements.vramSubLabel) elements.vramSubLabel.textContent = `Free: ${Math.round(free).toLocaleString()} MB · GPU Load: ${gpuLoad}`;
        if (elements.vramValue) elements.vramValue.textContent = `${used.toFixed(0)} MB / ${total.toFixed(0)} MB (${pct}%)`;
      } else {
        if (elements.vramBarLabel) elements.vramBarLabel.textContent = "N/A (No CUDA)";
        if (elements.vramValue) elements.vramValue.textContent = "N/A";
      }

      // 4. System RAM Allocation Meter
      if (hardware.system_ram_total_gb && elements.ramMeterBox) {
        const ramUsed = hardware.system_ram_used_gb || 0;
        const ramTotal = hardware.system_ram_total_gb || 0;
        const ramPct = hardware.system_ram_pct || Math.round((ramUsed / ramTotal) * 100);
        const ramFree = Math.max(0, ramTotal - ramUsed).toFixed(1);
        const procRss = hardware.process_rss_mb ? `${hardware.process_rss_mb} MB` : "N/A";

        if (elements.ramBarLabel) elements.ramBarLabel.textContent = `${ramUsed} GB / ${ramTotal} GB (${ramPct}%)`;
        if (elements.ramBarFill) {
          elements.ramBarFill.style.width = `${Math.max(4, ramPct)}%`;
          elements.ramBarFill.className = `meter-fill ram-fill ${ramPct > 90 ? "alert" : ramPct > 80 ? "warn" : ""}`;
        }
        if (elements.ramSubLabel) elements.ramSubLabel.textContent = `Host Available: ${ramFree} GB · Process RSS: ${procRss}`;
      }

      // 5. CPU Utilization Meter
      if (elements.cpuMeterBox && hardware.cpu_cores) {
        const cpuPct = hardware.cpu_util_pct || 0;
        const cores = hardware.cpu_cores || 1;
        if (elements.cpuBarLabel) elements.cpuBarLabel.textContent = `${cpuPct.toFixed(1)}% (${cores} Cores)`;
        if (elements.cpuBarFill) {
          elements.cpuBarFill.style.width = `${Math.max(3, cpuPct)}%`;
          elements.cpuBarFill.className = `meter-fill cpu-fill ${cpuPct > 90 ? "alert" : cpuPct > 75 ? "warn" : ""}`;
        }
      }
    } catch {
      elements.engineLabel.textContent = "Status unavailable";
      elements.engineDot.className = "status-indicator unavailable";
    }
  }

  async function loadPresets() {
    try {
      state.presets = await getJson("/api/presets");
    } catch {
      state.presets = {};
    }
  }

  async function loadHistory() {
    if (!elements.historyList) return;
    elements.historyList.replaceChildren();
    try {
      const history = await getJson("/api/history");
      if (!Array.isArray(history) || !history.length) {
        const p = document.createElement("p");
        p.className = "placeholder";
        p.textContent = "No audit history found in local storage.";
        elements.historyList.append(p);
        return;
      }
      history.forEach((entry) => {
        const card = document.createElement("div");
        card.className = "history-card";
        card.setAttribute("role", "button");

        const header = document.createElement("div");
        header.className = "history-card-header";

        const verdict = document.createElement("span");
        verdict.className = `verdict-tag ${verdictClass(entry.verdict)}`;
        verdict.textContent = entry.verdict.replace("_", " ");

        const time = document.createElement("span");
        time.className = "history-card-time";
        time.textContent = entry.timestamp;

        header.append(verdict, time);

        const summary = document.createElement("div");
        summary.className = "history-card-summary";
        summary.textContent = `${entry.finding_count} finding(s) · ${entry.repo_name || "repo"} (${entry.commit_hash || "HEAD"})`;

        card.append(header, summary);
        elements.historyList.append(card);
      });
    } catch (err) {
      const p = document.createElement("p");
      p.className = "placeholder";
      p.textContent = "Could not load history: " + err.message;
      elements.historyList.append(p);
    }
  }

  function closeAllPopovers() {
    elements.enginePanel?.classList.add("is-hidden");
    elements.engineButton?.setAttribute("aria-expanded", "false");
    elements.exportMenu?.classList.add("is-hidden");
    elements.exportBtn?.setAttribute("aria-expanded", "false");
    elements.historyDrawer?.classList.add("is-hidden");
    elements.historyBtn?.setAttribute("aria-expanded", "false");
    elements.complianceDrawer?.classList.add("is-hidden");
    elements.complianceBtn?.setAttribute("aria-expanded", "false");
    elements.policyDrawer?.classList.add("is-hidden");
    elements.policyBtn?.setAttribute("aria-expanded", "false");
    elements.shortcutsModal?.classList.add("is-hidden");
    elements.explainModal?.classList.add("is-hidden");
  }

  // Event Listeners: Popovers & Drawers
  elements.engineButton.addEventListener("click", (event) => {
    event.stopPropagation();
    const isClosed = elements.enginePanel.classList.contains("is-hidden");
    closeAllPopovers();
    if (isClosed) {
      elements.enginePanel.classList.remove("is-hidden");
      elements.engineButton.setAttribute("aria-expanded", "true");
      loadStatus();
    }
  });

  if (elements.exportBtn) {
    elements.exportBtn.addEventListener("click", (event) => {
      event.stopPropagation();
      const isClosed = elements.exportMenu.classList.contains("is-hidden");
      closeAllPopovers();
      if (isClosed) {
        elements.exportMenu.classList.remove("is-hidden");
        elements.exportBtn.setAttribute("aria-expanded", "true");
      }
    });
    elements.exportMdBtn.addEventListener("click", () => {
      closeAllPopovers();
      exportReport("markdown");
    });
    elements.exportPrBtn?.addEventListener("click", () => {
      closeAllPopovers();
      exportReport("pr");
    });
    elements.exportSarifBtn?.addEventListener("click", () => {
      closeAllPopovers();
      exportReport("sarif");
    });
    elements.exportJsonBtn.addEventListener("click", () => {
      closeAllPopovers();
      exportReport("json");
    });
  }

  if (elements.copyPrCommentBtn) {
    elements.copyPrCommentBtn.addEventListener("click", () => {
      copyPrComment();
    });
  }

  if (elements.historyBtn) {
    elements.historyBtn.addEventListener("click", (event) => {
      event.stopPropagation();
      const isClosed = elements.historyDrawer.classList.contains("is-hidden");
      closeAllPopovers();
      if (isClosed) {
        elements.historyDrawer.classList.remove("is-hidden");
        elements.historyBtn.setAttribute("aria-expanded", "true");
        loadHistory();
      }
    });
  }

  if (elements.closeHistoryBtn) {
    elements.closeHistoryBtn.addEventListener("click", () => {
      elements.historyDrawer.classList.add("is-hidden");
      elements.historyBtn?.setAttribute("aria-expanded", "false");
    });
  }

  if (elements.complianceBtn) {
    elements.complianceBtn.addEventListener("click", (event) => {
      event.stopPropagation();
      const isClosed = elements.complianceDrawer.classList.contains("is-hidden");
      closeAllPopovers();
      if (isClosed) {
        elements.complianceDrawer.classList.remove("is-hidden");
        elements.complianceBtn.setAttribute("aria-expanded", "true");
        renderComplianceMatrix();
      }
    });
  }

  if (elements.closeComplianceBtn) {
    elements.closeComplianceBtn.addEventListener("click", () => {
      elements.complianceDrawer.classList.add("is-hidden");
      elements.complianceBtn?.setAttribute("aria-expanded", "false");
    });
  }

  if (elements.installHookBtn) {
    elements.installHookBtn.addEventListener("click", async () => {
      elements.installHookBtn.disabled = true;
      try {
        const res = await getJson("/api/install-hook", { method: "POST" });
        if (res.success) {
          showToast("Git pre-commit security hook installed successfully!");
        } else {
          showToast("Failed to install hook (workspace not a Git repository)");
        }
      } catch (err) {
        showToast("Failed to install hook: " + err.message);
      } finally {
        elements.installHookBtn.disabled = false;
      }
    });
  }

  if (elements.shortcutsBtn) {
    elements.shortcutsBtn.addEventListener("click", () => {
      closeAllPopovers();
      elements.shortcutsModal.classList.remove("is-hidden");
    });
  }

  if (elements.closeShortcutsBtn) {
    elements.closeShortcutsBtn.addEventListener("click", () => {
      elements.shortcutsModal.classList.add("is-hidden");
    });
  }

  // Security Policy Drawer Management
  async function loadPolicyConfig() {
    try {
      const config = await getJson("/api/config");
      if (elements.policyEntropyInput) {
        elements.policyEntropyInput.value = config.min_shannon_entropy ?? 4.5;
        if (elements.policyEntropyVal) {
          elements.policyEntropyVal.textContent = elements.policyEntropyInput.value;
        }
      }
      if (elements.policyExcludeInput) {
        elements.policyExcludeInput.value = (config.exclude_files || []).join(", ");
      }
      if (elements.policyIgnoreInput) {
        elements.policyIgnoreInput.value = (config.ignore_rules || []).join(", ");
      }
      if (elements.policyGateCheckbox) {
        elements.policyGateCheckbox.checked = config.fail_on_critical !== false;
      }
    } catch (err) {
      showToast("Could not load policy: " + err.message);
    }
  }

  if (elements.policyBtn) {
    elements.policyBtn.addEventListener("click", (event) => {
      event.stopPropagation();
      const isClosed = elements.policyDrawer.classList.contains("is-hidden");
      closeAllPopovers();
      if (isClosed) {
        elements.policyDrawer.classList.remove("is-hidden");
        elements.policyBtn.setAttribute("aria-expanded", "true");
        loadPolicyConfig();
      }
    });
  }

  if (elements.closePolicyBtn) {
    elements.closePolicyBtn.addEventListener("click", () => {
      elements.policyDrawer.classList.add("is-hidden");
      elements.policyBtn?.setAttribute("aria-expanded", "false");
    });
  }

  if (elements.policyEntropyInput) {
    elements.policyEntropyInput.addEventListener("input", () => {
      if (elements.policyEntropyVal) {
        elements.policyEntropyVal.textContent = elements.policyEntropyInput.value;
      }
    });
  }

  if (elements.savePolicyBtn) {
    elements.savePolicyBtn.addEventListener("click", async () => {
      elements.savePolicyBtn.disabled = true;
      elements.savePolicyBtn.textContent = "Saving…";
      try {
        const payload = {
          min_shannon_entropy: parseFloat(elements.policyEntropyInput?.value || 4.5),
          exclude_files: (elements.policyExcludeInput?.value || "")
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          ignore_rules: (elements.policyIgnoreInput?.value || "")
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          fail_on_critical: Boolean(elements.policyGateCheckbox?.checked)
        };
        await getJson("/api/config", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        showToast("Security policy saved to .codeguardian.json");
        elements.policyDrawer.classList.add("is-hidden");
        elements.policyBtn?.setAttribute("aria-expanded", "false");
      } catch (err) {
        showToast("Failed to save policy: " + err.message);
      } finally {
        elements.savePolicyBtn.disabled = false;
        elements.savePolicyBtn.textContent = "Save Policy Configuration";
      }
    });
  }

  // Local AI Explainer Modal Management
  async function triggerExplainer() {
    const finding = selectedFinding();
    if (!finding) return;

    closeAllPopovers();
    elements.explainModal.classList.remove("is-hidden");
    if (elements.explainModalFindingRule) {
      elements.explainModalFindingRule.textContent = `${finding.rule_id} · ${finding.title}`;
    }
    if (elements.explainModalModelBadge) {
      elements.explainModalModelBadge.textContent = "Probing Security Advisor…";
    }
    elements.explainExploitText.textContent = "Synthesizing real-world exploit scenario and reachability analysis…";
    elements.explainImpactText.textContent = "Assessing system, data, and blast-radius impact…";
    elements.explainRemediationSteps.textContent = "Generating deterministic step-by-step remediation guide…";
    elements.explainBestPractices.replaceChildren();

    try {
      const res = await getJson("/api/explain-finding", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding_id: finding.id,
          rule_id: finding.rule_id,
          title: finding.title,
          description: finding.description,
          evidence: finding.evidence || [],
          remediation: finding.remediation || "",
          file: finding.file,
          line_start: finding.line_start
        })
      });
      elements.explainExploitText.textContent = res.exploit_scenario;
      elements.explainImpactText.textContent = res.impact_analysis || res.attack_vector || "";
      elements.explainRemediationSteps.textContent = res.step_by_step_remediation;
      if (elements.explainModalModelBadge) {
        elements.explainModalModelBadge.textContent = res.model_name || "Deterministic Security Advisor";
      }
      elements.explainBestPractices.replaceChildren();
      (res.defensive_best_practices || []).forEach((bp) => {
        const li = document.createElement("li");
        li.textContent = bp;
        elements.explainBestPractices.append(li);
      });
    } catch (err) {
      elements.explainExploitText.textContent = "Unable to generate advisory: " + err.message;
      elements.explainImpactText.textContent = "Advisory generation encountered an error.";
      elements.explainRemediationSteps.textContent = "Please consult standard OWASP guidance for " + finding.rule_id;
    }
  }

  if (elements.explainFindingBtn) {
    elements.explainFindingBtn.addEventListener("click", triggerExplainer);
  }

  const secondaryExplainBtn = $("explainFindingSecondaryBtn");
  if (secondaryExplainBtn) {
    secondaryExplainBtn.addEventListener("click", triggerExplainer);
  }

  if (elements.closeExplainBtn) {
    elements.closeExplainBtn.addEventListener("click", () => {
      elements.explainModal.classList.add("is-hidden");
    });
  }

  // Click outside closes popovers
  document.addEventListener("click", (event) => {
    if (!elements.enginePanel?.contains(event.target) && !elements.engineButton?.contains(event.target)) {
      elements.enginePanel?.classList.add("is-hidden");
      elements.engineButton?.setAttribute("aria-expanded", "false");
    }
    if (!elements.exportWrapper?.contains(event.target)) {
      elements.exportMenu?.classList.add("is-hidden");
      elements.exportBtn?.setAttribute("aria-expanded", "false");
    }
    if (elements.shortcutsModal && event.target === elements.shortcutsModal) {
      elements.shortcutsModal.classList.add("is-hidden");
    }
    if (elements.explainModal && event.target === elements.explainModal) {
      elements.explainModal.classList.add("is-hidden");
    }
  });

  // Sidebar toggle
  if (elements.toggleFilesBtn) {
    elements.toggleFilesBtn.addEventListener("click", () => {
      elements.filesSidebar.classList.toggle("is-collapsed");
    });
  }

  // Line Wrap toggle
  if (elements.wrapToggleBtn) {
    elements.wrapToggleBtn.addEventListener("click", () => {
      state.isWrapped = !state.isWrapped;
      elements.formattedDiff.classList.toggle("diff-wrap", state.isWrapped);
      elements.wrapToggleBtn.classList.toggle("is-active", state.isWrapped);
      showToast(state.isWrapped ? "Line wrap enabled" : "Line wrap disabled");
    });
  }

  // Empty state buttons
  if (elements.emptySqlExampleBtn) {
    elements.emptySqlExampleBtn.addEventListener("click", () => {
      elements.fixtureSelect.value = "sql_injection";
      elements.fixtureSelect.dispatchEvent(new Event("change"));
    });
  }
  if (elements.emptyGitFetchBtn) {
    elements.emptyGitFetchBtn.addEventListener("click", loadGitDiff);
  }

  // Fixture dropdown
  elements.fixtureSelect.addEventListener("change", () => {
    const key = elements.fixtureSelect.value;
    if (key && state.presets[key]) {
      setDiff(state.presets[key], "Example fixture loaded — not repository data");
      showToast(`Loaded "${elements.fixtureSelect.selectedOptions[0].text}" example`);
    }
  });

  elements.fetchGitButton.addEventListener("click", loadGitDiff);
  elements.copyDiffButton.addEventListener("click", () => copyText(state.diff, "Diff"));
  elements.copyFileButton.addEventListener("click", () => currentFile() && copyText(currentFile().path, "File path"));

  elements.fileSelect.addEventListener("change", () => {
    state.fileIndex = Number(elements.fileSelect.value);
    populateFiles();
    renderDiff();
  });

  elements.formattedButton.addEventListener("click", () => {
    state.mode = "formatted";
    elements.formattedButton.classList.add("is-active");
    elements.rawButton.classList.remove("is-active");
    elements.rawDiff.classList.add("is-hidden");
    elements.formattedDiff.classList.remove("is-hidden");
    state.diff = elements.rawDiff.value;
    state.files = parseDiff(state.diff);
    populateFiles();
    renderDiff();
  });

  elements.rawButton.addEventListener("click", () => {
    state.mode = "raw";
    elements.rawButton.classList.add("is-active");
    elements.formattedButton.classList.remove("is-active");
    elements.formattedDiff.classList.add("is-hidden");
    elements.diffEmpty.classList.add("is-hidden");
    elements.rawDiff.classList.remove("is-hidden");
    elements.rawDiff.value = state.diff;
    elements.rawDiff.focus();
  });

  elements.rawDiff.addEventListener("input", () => {
    state.diff = elements.rawDiff.value;
    state.files = parseDiff(state.diff);
    state.fileIndex = 0;
    populateFiles();
    elements.reviewButton.disabled = !state.diff.trim();
    elements.copyDiffButton.disabled = !state.diff.trim();
    clearReview("Raw patch modified; run review");
  });

  // Diff search with Enter navigation
  elements.diffSearch.addEventListener("input", renderDiff);
  elements.diffSearch.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && state.searchMatches.length > 0) {
      event.preventDefault();
      if (event.shiftKey) {
        state.searchMatchIndex = (state.searchMatchIndex - 1 + state.searchMatches.length) % state.searchMatches.length;
      } else {
        state.searchMatchIndex = (state.searchMatchIndex + 1) % state.searchMatches.length;
      }
      const match = state.searchMatches[state.searchMatchIndex];
      if (match) {
        match.scrollIntoView({ block: "center", behavior: "smooth" });
        elements.searchCount.textContent = `${state.searchMatchIndex + 1} of ${state.searchMatches.length}`;
      }
    }
  });

  elements.reviewButton.addEventListener("click", runReview);

  document.querySelectorAll(".severity").forEach((button) => {
    button.addEventListener("click", () => {
      if (!state.report) return;
      state.severity = state.severity === button.dataset.severity ? null : button.dataset.severity;
      renderFindings();
      renderDetail();
      updateCounts(state.report.counts);
    });
  });

  elements.clearFilter.addEventListener("click", () => {
    if (!state.report) return;
    state.severity = null;
    renderFindings();
    renderDetail();
    updateCounts(state.report.counts);
  });

  elements.copyPatchButton.addEventListener("click", () => {
    const finding = selectedFinding();
    if (finding?.suggested_fix) copyText(finding.suggested_fix, "Suggested patch");
  });

  if (elements.copyEvidenceBtn) {
    elements.copyEvidenceBtn.addEventListener("click", () => {
      const finding = selectedFinding();
      if (finding?.evidence?.length) copyText(finding.evidence.join("\n"), "Evidence");
    });
  }

  elements.copyTestButton.addEventListener("click", () => {
    if (state.selectedTest) copyText(state.selectedTest.code, "Test code");
  });

  elements.runTestButton.addEventListener("click", runCandidateTest);

  if (elements.verifyPatchButton) {
    elements.verifyPatchButton.addEventListener("click", verifyCandidatePatch);
  }

  if (elements.applyPatchWorktreeButton) {
    elements.applyPatchWorktreeButton.addEventListener("click", applyPatchToWorktree);
  }

  if (elements.revertPatchWorktreeButton) {
    elements.revertPatchWorktreeButton.addEventListener("click", revertPatchFromWorktree);
  }

  // Keyboard navigation & Shortcuts
  document.addEventListener("keydown", (event) => {
    const isInput = ["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName);

    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      event.preventDefault();
      runReview();
      return;
    }

    if (event.key === "Escape") {
      closeAllPopovers();
      if (elements.diffSearch === document.activeElement) {
        elements.diffSearch.value = "";
        renderDiff();
        elements.diffSearch.blur();
      }
      return;
    }

    if (!isInput) {
      if (event.key === "?" || (event.shiftKey && event.key === "/")) {
        event.preventDefault();
        elements.shortcutsModal.classList.toggle("is-hidden");
        return;
      }
      if (event.key === "b" || event.key === "B") {
        event.preventDefault();
        elements.filesSidebar.classList.toggle("is-collapsed");
        return;
      }
      if (event.key === "w" || event.key === "W") {
        event.preventDefault();
        elements.wrapToggleBtn?.click();
        return;
      }
      if (event.key === "g" || event.key === "G") {
        event.preventDefault();
        loadGitDiff();
        return;
      }
      if (event.key === "/" || event.key === "f") {
        if (!elements.diffSearch.disabled) {
          event.preventDefault();
          elements.diffSearch.focus();
          elements.diffSearch.select();
        }
        return;
      }
      if (["1", "2", "3"].includes(event.key)) {
        event.preventDefault();
        const tabKeys = ["overview", "patch", "test"];
        switchDetailTab(tabKeys[Number(event.key) - 1]);
        return;
      }
      if (event.key === "j" || event.key === "ArrowDown") {
        const findings = visibleFindings();
        if (findings.length > 0) {
          event.preventDefault();
          const currIdx = findings.findIndex((f) => f.id === state.selectedId);
          const nextIdx = Math.min(currIdx + 1, findings.length - 1);
          selectFinding(findings[nextIdx].id, true);
        }
        return;
      }
      if (event.key === "k" || event.key === "ArrowUp") {
        const findings = visibleFindings();
        if (findings.length > 0) {
          event.preventDefault();
          const currIdx = findings.findIndex((f) => f.id === state.selectedId);
          const prevIdx = Math.max(currIdx - 1, 0);
          selectFinding(findings[prevIdx].id, true);
        }
        return;
      }
    }
  });

  async function initialize() {
    renderReviewEmpty("Ready");
    await Promise.all([loadContext(), loadStatus(), loadPresets()]);
    // Start periodic background telemetry update (every 5 seconds)
    setInterval(loadStatus, 5000);
    const params = new URLSearchParams(window.location.search);
    const fixture = params.get("fixture");
    if (fixture && state.presets[fixture]) {
      elements.fixtureSelect.value = fixture;
      setDiff(state.presets[fixture], "Example fixture loaded — not repository data");
      if (params.get("review") === "1") {
        await runReview();
        const tab = params.get("tab");
        if (tab && ["overview", "patch", "test"].includes(tab)) {
          switchDetailTab(tab);
        }
      }
    }
  }

  initialize();
});
