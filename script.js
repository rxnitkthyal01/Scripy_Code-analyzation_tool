const codeInput = document.getElementById("code-input");
const languageSelect = document.getElementById("language-select");
const fileInput = document.getElementById("file-input");
const folderInput = document.getElementById("folder-input");
const sampleButton = document.getElementById("sample-btn");
const scanButton = document.getElementById("scan-btn");
const clearButton = document.getElementById("clear-btn");
const inputMessage = document.getElementById("input-message");
const selectionLabel = document.getElementById("selection-label");
const fileCount = document.getElementById("file-count");
const sourceMetrics = document.getElementById("source-metrics");
const engineStatus = document.getElementById("engine-status");
const scanStatus = document.getElementById("scan-status");
const durationLabel = document.getElementById("duration-label");
const scanActivity = document.getElementById("scan-activity");
const scanActivityLabel = document.getElementById("scan-activity-label");
const scanElapsed = document.getElementById("scan-elapsed");
const summaryFilters = document.querySelectorAll(".summary-filter");
const severityFilter = document.getElementById("severity-filter");
const searchInput = document.getElementById("search-input");
const resultsList = document.getElementById("results-list");
const issueCount = document.getElementById("issue-count");
const criticalCount = document.getElementById("critical-count");
const highCount = document.getElementById("high-count");
const scannedCount = document.getElementById("scanned-count");
const jsonButton = document.getElementById("json-btn");
const sarifButton = document.getElementById("sarif-btn");
const copyButton = document.getElementById("copy-btn");
const historySelect = document.getElementById("history-select");
const clearHistoryButton = document.getElementById("clear-history-btn");
const avatarButton = document.getElementById("avatar-button");
const avatarMessage = document.getElementById("avatar-message");

const HISTORY_KEY = "scripy.scan-history.v2";
const MAX_HISTORY = 8;
const MAX_FILES = 500;
const MAX_TOTAL_BYTES = 5 * 1024 * 1024;
const languageExtensions = {
  javascript: "js",
  typescript: "ts",
  python: "py",
  java: "java",
  c: "c",
  cpp: "cpp",
  csharp: "cs",
  go: "go",
  php: "php",
  ruby: "rb",
  rust: "rs",
  kotlin: "kt",
  swift: "swift",
  scala: "scala",
  bash: "sh",
  html: "html",
  yaml: "yaml",
  json: "json",
  toml: "toml",
  sql: "sql"
};
const supportedExtensions = new Set([
  "py", "js", "jsx", "mjs", "cjs", "ts", "tsx", "java", "c", "h", "cc",
  "cpp", "hpp", "cs", "go", "php", "rb", "rs", "kt", "kts", "swift",
  "scala", "html", "htm", "vue", "sh", "sql", "yaml", "yml", "json", "toml"
]);
const ignoredDirectories = new Set([
  ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "coverage",
  ".venv", "venv", "__pycache__", "target", "bin", "obj"
]);

let selectedProjectFiles = [];
let currentReport = null;
let savedHistory = [];
let avatarReactionIndex = 0;
let avatarMessageTimeout = null;
let scanInProgress = false;
let scanTimer = null;
let scanStartedAt = 0;

const avatarReactions = [
  { message: "Hey, coder!", mood: "bounce" },
  { message: "Let's squash bugs!", mood: "wiggle" },
  { message: "Scan mode: ON!", mood: "bounce" },
  { message: "You got this!", mood: "wiggle" }
];

function showInputMessage(message) {
  inputMessage.textContent = message;
}

function showAvatarReaction(message, mood) {
  avatarButton.dataset.mood = mood;
  avatarButton.classList.remove("is-reacting");
  requestAnimationFrame(() => avatarButton.classList.add("is-reacting"));
  avatarMessage.textContent = message;
  avatarMessage.hidden = false;
  clearTimeout(avatarMessageTimeout);
  avatarMessageTimeout = setTimeout(() => {
    avatarMessage.hidden = true;
  }, 2800);
}

avatarButton.addEventListener("click", () => {
  const reaction = avatarReactions[avatarReactionIndex];
  avatarReactionIndex = (avatarReactionIndex + 1) % avatarReactions.length;
  showAvatarReaction(reaction.message, reaction.mood);
});

function setEngineStatus(message, state) {
  engineStatus.textContent = message;
  engineStatus.dataset.state = state;
}

function setScanStatus(message) {
  scanStatus.textContent = message;
}

function updateSourceMetrics() {
  const source = codeInput.value;
  const line = source.slice(0, codeInput.selectionStart).split("\n").length;
  const characterLabel = source.length === 1 ? "character" : "characters";
  sourceMetrics.textContent = `Line ${line} · ${source.length} ${characterLabel}`;
}

function updateSummaryFilters() {
  for (const button of summaryFilters) {
    const active = Boolean(currentReport) && severityFilter.value === button.dataset.severity;
    button.setAttribute("aria-pressed", String(active));
    button.classList.toggle("is-active", active);
    button.disabled = !currentReport ||
      !currentReport.findings.some((finding) => finding.severity === button.dataset.severity);
  }
}

function updateScanElapsed() {
  const elapsedSeconds = Math.floor((performance.now() - scanStartedAt) / 1000);
  const minutes = String(Math.floor(elapsedSeconds / 60)).padStart(2, "0");
  const seconds = String(elapsedSeconds % 60).padStart(2, "0");
  scanElapsed.textContent = `${minutes}:${seconds}`;
  scanActivity.querySelector(".scan-meter").setAttribute(
    "aria-valuetext",
    `Scanning locally for ${minutes} minutes and ${seconds} seconds; no percentage estimate`
  );
}

function startScanActivity(files) {
  scanStartedAt = performance.now();
  scanActivityLabel.textContent = `Checking ${files} source file${files === 1 ? "" : "s"} locally…`;
  scanActivity.hidden = false;
  updateScanElapsed();
  scanTimer = window.setInterval(updateScanElapsed, 1000);
}

function stopScanActivity() {
  if (scanTimer !== null) {
    window.clearInterval(scanTimer);
    scanTimer = null;
  }
  scanActivity.hidden = true;
}

function invalidateCurrentReport() {
  if (!currentReport) return;
  setReport(null);
  setScanStatus("Source changed · Run a new scan");
}

function setBusy(isBusy) {
  scanButton.disabled = isBusy || engineStatus.dataset.state !== "ready";
  codeInput.disabled = isBusy;
  languageSelect.disabled = isBusy;
  fileInput.disabled = isBusy;
  folderInput.disabled = isBusy;
  sampleButton.disabled = isBusy;
  clearButton.disabled = isBusy;
  scanButton.innerHTML = isBusy
    ? '<span aria-hidden="true">…</span> Scanning'
    : '<span aria-hidden="true">✦</span> Scan code';
}

function updateInputLabels() {
  if (selectedProjectFiles.length) {
    selectionLabel.textContent = "Project folder mode";
    const count = getCandidateFiles(selectedProjectFiles).length;
    fileCount.textContent = `${count} source file${count === 1 ? "" : "s"} selected`;
    return;
  }
  selectionLabel.textContent = `Snippet mode · ${languageSelect.options[languageSelect.selectedIndex].text}`;
  fileCount.textContent = "0 project files selected";
}

function getExtension(fileName) {
  const dot = fileName.lastIndexOf(".");
  return dot < 0 ? "" : fileName.slice(dot + 1).toLowerCase();
}

function getCandidateFiles(fileList) {
  return Array.from(fileList).filter((file) => {
    const folders = (file.webkitRelativePath || file.name).split(/[\\/]/).slice(0, -1);
    return supportedExtensions.has(getExtension(file.name)) &&
      !folders.some((folder) => ignoredDirectories.has(folder.toLowerCase()));
  });
}

function setReport(report) {
  currentReport = report;
  const findings = report?.findings || [];
  issueCount.textContent = String(findings.length);
  criticalCount.textContent = String(findings.filter((item) => item.severity === "CRITICAL").length);
  highCount.textContent = String(findings.filter((item) => item.severity === "HIGH").length);
  scannedCount.textContent = report ? String(report.scannedFiles) : "—";
  durationLabel.textContent = report ? `${report.durationMs} ms` : "";
  const canExport = Boolean(report);
  jsonButton.disabled = !canExport;
  sarifButton.disabled = !canExport;
  copyButton.disabled = !canExport;
  updateSummaryFilters();
  renderFindings();
}

function addText(parent, tagName, className, value) {
  const element = document.createElement(tagName);
  if (className) element.className = className;
  element.textContent = value;
  parent.appendChild(element);
  return element;
}

function renderFindings() {
  resultsList.replaceChildren();
  if (!currentReport) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    addText(empty, "span", "empty-icon", "?");
    addText(empty, "strong", "", "No scan yet");
    addText(empty, "p", "", "Choose code and hit Scan code to start.");
    resultsList.appendChild(empty);
    return;
  }

  const search = searchInput.value.trim().toLowerCase();
  const severity = severityFilter.value;
  const findings = currentReport.findings.filter((finding) => {
    if (severity !== "ALL" && finding.severity !== severity) return false;
    const text = [
      finding.ruleId,
      finding.file,
      finding.message,
      finding.fix,
      finding.snippet,
      finding.category,
      finding.cwe
    ].join(" ").toLowerCase();
    return !search || text.includes(search);
  });

  if (!findings.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    addText(empty, "strong", "", currentReport.findings.length
      ? "No findings match these filters"
      : "No issues matched the bundled rules");
    addText(empty, "p", "", currentReport.findings.length
      ? "Try another severity or search term."
      : "This is not a guarantee that the code is secure.");
    resultsList.appendChild(empty);
    return;
  }

  for (const finding of findings) {
    const card = document.createElement("article");
    card.className = "finding-card";
    card.style.setProperty("--finding-index", String(resultsList.children.length));
    const topLine = document.createElement("div");
    topLine.className = "finding-topline";
    const severity = addText(topLine, "span", `severity severity-${finding.severity.toLowerCase()}`, finding.severity);
    severity.setAttribute("aria-label", `Severity ${finding.severity}`);
    addText(topLine, "span", "finding-rule", finding.ruleId);
    addText(topLine, "span", "finding-location", `${finding.file}:${finding.line}`);
    card.appendChild(topLine);
    addText(card, "p", "finding-message", finding.message);
    if (finding.fix) addText(card, "p", "finding-fix", `Suggested fix: ${finding.fix}`);
    addText(card, "p", "finding-confidence", `Category: ${finding.category} · Confidence: ${finding.confidence}${finding.cwe ? ` · ${finding.cwe}` : ""}`);
    if (finding.snippet) addText(card, "code", "finding-snippet", finding.snippet.trim());
    resultsList.appendChild(card);
  }
}

async function checkScanner() {
  try {
    const response = await fetch("/api/health");
    const status = await response.json();
    if (!response.ok) throw new Error(status.error || "Could not check the local scanner.");
    if (status.available) {
      setEngineStatus(`Scripy Scanner ${status.scannerVersion} · Python ${status.pythonVersion} · Ready`, "ready");
      setScanStatus("Ready when you are");
    } else {
      setEngineStatus("Scanner setup needed · Install Python 3.15 (see README)", "error");
      setScanStatus(status.message);
      showInputMessage(`${status.message} Install Python 3.15.2, then restart Scripy.`);
    }
  } catch (error) {
    setEngineStatus("Cannot reach the local scanner", "error");
    setScanStatus(error.message);
    showInputMessage(`${error.message} Start Scripy with npm start.`);
  }
  setBusy(false);
}

async function readSelectedFiles(fileList) {
  const accepted = getCandidateFiles(fileList);
  if (accepted.length === 0) {
    throw new Error("No supported source files were selected.");
  }
  if (accepted.length > MAX_FILES) {
    throw new Error(`Select no more than ${MAX_FILES} supported files at a time.`);
  }
  const totalSize = accepted.reduce((total, file) => total + file.size, 0);
  if (totalSize > MAX_TOTAL_BYTES) {
    throw new Error("The selected source files exceed the 5 MB total scan limit.");
  }
  const files = await Promise.all(accepted.map(async (file) => ({
    path: file.webkitRelativePath || file.name,
    content: await file.text()
  })));
  return files;
}

async function scan() {
  if (scanInProgress) return;
  scanInProgress = true;
  showInputMessage("");
  const snippet = codeInput.value;
  let files;
  try {
    if (selectedProjectFiles.length) {
      files = await readSelectedFiles(selectedProjectFiles);
    } else if (snippet.trim()) {
      const extension = languageExtensions[languageSelect.value] || "js";
      files = [{ path: `snippet.${extension}`, content: snippet }];
    } else {
      showInputMessage("Paste a snippet, upload a file, or choose a project folder first.");
      return;
    }

    setBusy(true);
    setReport(null);
    setScanStatus(`Scanning ${files.length} file${files.length === 1 ? "" : "s"} with the local Python scanner…`);
    startScanActivity(files.length);
    showAvatarReaction("On patrol! Checking your code…", "scan");
    resultsList.replaceChildren();
    const activityState = addText(resultsList, "div", "empty-state scan-pending", "Your local scanner is checking the selected files…");
    activityState.setAttribute("aria-hidden", "true");
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ files })
    });
    const payload = await response.json();
    if (!response.ok) {
      const error = new Error(payload.error || `Scan failed with status ${response.status}.`);
      error.code = payload.code;
      throw error;
    }

    setReport(payload);
    const scanSummary = payload.findings.length
      ? `${payload.findings.length} finding${payload.findings.length === 1 ? "" : "s"}`
      : "No matches in local rules";
    setScanStatus(`${scanSummary} · Python ${payload.pythonVersion}`);
    if (payload.analysisWarnings?.length) {
      showInputMessage(`Some files could not be fully analyzed: ${payload.analysisWarnings.join("; ")}`);
    }
    if (payload.findings.length) {
      showAvatarReaction(`${payload.findings.length} clue${payload.findings.length === 1 ? "" : "s"} found! Check the severity and review each one.`, "alert");
    } else {
      showAvatarReaction("No bundled-rule matches. That is not a security guarantee!", "success");
    }
    saveHistory(payload, selectedProjectFiles.length ? "Project folder" : "Code snippet");
  } catch (error) {
    setScanStatus("Scan failed");
    showInputMessage(error.message);
    showAvatarReaction("The scan stopped. Check the message by your code and try again.", "alert");
    resultsList.replaceChildren();
    const failure = document.createElement("div");
    failure.className = "empty-state";
    addText(failure, "strong", "", "Scanner couldn't complete");
    addText(failure, "p", "", error.message);
    resultsList.appendChild(failure);
  } finally {
    stopScanActivity();
    scanInProgress = false;
    setBusy(false);
  }
}

function getReportDocument() {
  return {
    scanner: "Scripy local Python AST and source-rule scanner",
    generatedAt: currentReport.scannedAt,
    scannerVersion: currentReport.scannerVersion,
    pythonVersion: currentReport.pythonVersion,
    summary: currentReport.summary,
    scannedFiles: currentReport.scannedFiles,
    durationMs: currentReport.durationMs,
    analysisWarnings: currentReport.analysisWarnings,
    findings: currentReport.findings
  };
}

function downloadFile(fileName, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
}

function downloadJson() {
  if (!currentReport) return;
  downloadFile(
    "scripy-scan-report.json",
    JSON.stringify(getReportDocument(), null, 2),
    "application/json"
  );
}

function downloadSarif() {
  if (!currentReport) return;
  const rules = new Map();
  const results = currentReport.findings.map((finding) => {
    if (!rules.has(finding.ruleId)) {
      rules.set(finding.ruleId, {
        id: finding.ruleId,
        shortDescription: { text: finding.ruleId },
        help: { text: finding.fix || finding.message },
        properties: { category: finding.category, confidence: finding.confidence }
      });
    }
    return {
      ruleId: finding.ruleId,
      level: finding.severity === "CRITICAL" || finding.severity === "HIGH"
        ? "error"
        : finding.severity === "MEDIUM" ? "warning" : "note",
      message: { text: finding.message },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: finding.file },
          region: {
            startLine: finding.line,
            endLine: finding.endLine,
            ...(finding.snippet ? { snippet: { text: finding.snippet } } : {})
          }
        }
      }]
    };
  });
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "Scripy",
          informationUri: "https://www.python.org/",
          version: `${currentReport.scannerVersion} (Python ${currentReport.pythonVersion})`,
          rules: Array.from(rules.values())
        }
      },
      results
    }]
  };
  downloadFile("scripy-scan-report.sarif", JSON.stringify(sarif, null, 2), "application/sarif+json");
}

async function copyReport() {
  if (!currentReport) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(getReportDocument(), null, 2));
    setScanStatus("Report copied to clipboard");
  } catch (error) {
    setScanStatus(`Clipboard unavailable: ${error.message}`);
  }
}

function isValidHistoryRecord(record) {
  if (
    !record ||
    typeof record !== "object" ||
    typeof record.id !== "string" ||
    typeof record.sourceName !== "string" ||
    typeof record.scannedAt !== "string" ||
    !Number.isFinite(Date.parse(record.scannedAt))
  ) {
    return false;
  }

  const report = record.report;
  if (
    !report ||
    typeof report !== "object" ||
    typeof report.scannerVersion !== "string" ||
    typeof report.pythonVersion !== "string" ||
    typeof report.scannedAt !== "string" ||
    !Number.isFinite(Date.parse(report.scannedAt)) ||
    !Number.isFinite(report.scannedFiles) ||
    !Number.isFinite(report.durationMs) ||
    !report.summary ||
    typeof report.summary !== "object" ||
    Array.isArray(report.summary) ||
    !Array.isArray(report.findings)
  ) {
    return false;
  }

  return report.findings.every((finding) =>
    finding &&
    typeof finding === "object" &&
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(finding.severity) &&
    typeof finding.ruleId === "string" &&
    typeof finding.file === "string" &&
    Number.isFinite(finding.line) &&
    Number.isFinite(finding.endLine) &&
    typeof finding.message === "string" &&
    typeof finding.category === "string" &&
    typeof finding.confidence === "string" &&
    (finding.fix === undefined || typeof finding.fix === "string") &&
    (finding.snippet === undefined || typeof finding.snippet === "string")
  );
}

function readHistory() {
  try {
    const value = localStorage.getItem(HISTORY_KEY);
    if (!value) return [];
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) {
      setScanStatus("Saved scan history was invalid and has been ignored.");
      return [];
    }

    const validRecords = parsed.filter(isValidHistoryRecord);
    if (validRecords.length !== parsed.length) {
      setScanStatus("Some saved scan history entries were invalid and were ignored.");
    }
    return validRecords.slice(0, MAX_HISTORY);
  } catch (error) {
    setScanStatus(`Could not read local scan history: ${error.message}`);
    return [];
  }
}

function saveHistory(report, sourceName) {
  const historyReport = {
    ...report,
    findings: report.findings.map((finding) => {
      const savedFinding = { ...finding };
      delete savedFinding.snippet;
      return savedFinding;
    })
  };
  const record = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    sourceName,
    scannedAt: report.scannedAt,
    report: historyReport
  };
  savedHistory = [record, ...savedHistory].slice(0, MAX_HISTORY);
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(savedHistory));
    renderHistory();
  } catch (error) {
    setScanStatus(`Scan complete, but history could not be saved: ${error.message}`);
  }
}

function renderHistory() {
  historySelect.replaceChildren();
  if (!savedHistory.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No saved scans";
    historySelect.appendChild(option);
    historySelect.disabled = true;
    return;
  }
  historySelect.disabled = false;
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Open a previous scan…";
  historySelect.appendChild(placeholder);
  for (const record of savedHistory) {
    const option = document.createElement("option");
    option.value = record.id;
    const date = new Date(record.scannedAt).toLocaleString();
    option.textContent = `${date} · ${record.sourceName} · ${record.report.findings.length} finding(s)`;
    historySelect.appendChild(option);
  }
}

function openHistory() {
  const record = savedHistory.find((item) => item.id === historySelect.value);
  if (!record) return;
  setReport(record.report);
  setScanStatus(`Previous scan · ${new Date(record.scannedAt).toLocaleString()}`);
  showInputMessage("Showing a saved report. Re-scan to analyze current code.");
}

function clearInputs() {
  codeInput.value = "";
  fileInput.value = "";
  folderInput.value = "";
  selectedProjectFiles = [];
  currentReport = null;
  severityFilter.value = "ALL";
  searchInput.value = "";
  durationLabel.textContent = "";
  showInputMessage("");
  setReport(null);
  setScanStatus("Ready when you are");
  updateInputLabels();
  updateSourceMetrics();
}

sampleButton.addEventListener("click", () => {
  invalidateCurrentReport();
  selectedProjectFiles = [];
  folderInput.value = "";
  fileInput.value = "";
  languageSelect.value = "javascript";
  codeInput.value = [
    'const query = "SELECT * FROM users WHERE id = " + request.query.id;',
    "db.query(query);",
    "document.body.innerHTML = request.query.name;",
    "eval(request.query.debug);"
  ].join("\n");
  updateInputLabels();
  updateSourceMetrics();
  showInputMessage("Sample vulnerable code loaded. Scan it to see findings from the local Python scanner.");
});

fileInput.addEventListener("change", async () => {
  const [file] = fileInput.files || [];
  if (!file) return;
  try {
    const extension = getExtension(file.name);
    if (!supportedExtensions.has(extension)) {
      throw new Error(`Unsupported source file type: .${extension || "(none)"}`);
    }
    if (file.size > 1024 * 1024) throw new Error("A single file cannot exceed 1 MB.");
    codeInput.value = await file.text();
    invalidateCurrentReport();
    selectedProjectFiles = [];
    const languageForExtension = {
      js: "javascript", jsx: "javascript", mjs: "javascript", cjs: "javascript",
      ts: "typescript", tsx: "typescript", py: "python", java: "java", c: "c",
      h: "c", cc: "cpp", cpp: "cpp", hpp: "cpp", cs: "csharp", go: "go",
      php: "php", rb: "ruby", rs: "rust", kt: "kotlin", kts: "kotlin",
      swift: "swift", scala: "scala", sh: "bash", html: "html", htm: "html",
      yaml: "yaml", yml: "yaml", json: "json", toml: "toml", sql: "sql"
    };
    if (languageForExtension[extension]) languageSelect.value = languageForExtension[extension];
    updateInputLabels();
    updateSourceMetrics();
    selectionLabel.textContent = `File mode · ${file.name}`;
    showInputMessage("");
    showInputMessage("");
  } catch (error) {
    showInputMessage(error.message);
  }
});

folderInput.addEventListener("change", () => {
  invalidateCurrentReport();
  selectedProjectFiles = Array.from(folderInput.files || []);
  codeInput.value = "";
  fileInput.value = "";
  showInputMessage("");
  updateInputLabels();
  updateSourceMetrics();
  if (selectedProjectFiles.length > MAX_FILES) {
    showInputMessage(`The selection has more than ${MAX_FILES} files. Choose a smaller project folder.`);
  }
});

languageSelect.addEventListener("change", () => {
  if (!selectedProjectFiles.length && !fileInput.files.length) {
    invalidateCurrentReport();
    updateInputLabels();
    showInputMessage("");
  }
});

languageSelect.addEventListener("change", updateSourceMetrics);

codeInput.addEventListener("input", () => {
  invalidateCurrentReport();
  showInputMessage("");
  updateSourceMetrics();
  if (codeInput.value) {
    selectedProjectFiles = [];
    folderInput.value = "";
    fileInput.value = "";
    updateInputLabels();
  }
});

codeInput.addEventListener("click", updateSourceMetrics);
codeInput.addEventListener("keyup", updateSourceMetrics);
codeInput.addEventListener("select", updateSourceMetrics);
codeInput.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    event.preventDefault();
    scan();
  }
});

scanButton.addEventListener("click", scan);
clearButton.addEventListener("click", clearInputs);
severityFilter.addEventListener("change", () => {
  updateSummaryFilters();
  renderFindings();
});
for (const button of summaryFilters) {
  button.addEventListener("click", () => {
    severityFilter.value = severityFilter.value === button.dataset.severity
      ? "ALL"
      : button.dataset.severity;
    updateSummaryFilters();
    renderFindings();
  });
}
searchInput.addEventListener("input", renderFindings);
jsonButton.addEventListener("click", downloadJson);
sarifButton.addEventListener("click", downloadSarif);
copyButton.addEventListener("click", copyReport);
historySelect.addEventListener("change", openHistory);
clearHistoryButton.addEventListener("click", () => {
  try {
    localStorage.removeItem(HISTORY_KEY);
    savedHistory = [];
    renderHistory();
    setScanStatus("Local scan history cleared");
  } catch (error) {
    setScanStatus(`Could not clear local scan history: ${error.message}`);
  }
});

savedHistory = readHistory();
renderHistory();
updateInputLabels();
updateSourceMetrics();
updateSummaryFilters();
setBusy(true);
checkScanner();
