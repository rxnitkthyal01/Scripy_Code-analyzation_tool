const http = require("node:http");
const { spawn } = require("node:child_process");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");

const ROOT = __dirname;
const SCANNER_FILE = path.join(ROOT, "scanner.py");
const PORT = Number.parseInt(process.env.PORT || "4173", 10);
const HOST = "127.0.0.1";
const PYTHON_COMMAND = process.env.PYTHON_315_EXECUTABLE || (process.platform === "win32" ? "py" : "python3.15");
const PYTHON_PREFIX_ARGS = process.env.PYTHON_315_EXECUTABLE
  ? []
  : process.platform === "win32" ? ["-3.15"] : [];
const MAX_BODY_BYTES = 32 * 1024 * 1024;
const MAX_FILES = 500;
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_PATH_BYTES = 1024;
const MAX_SCAN_MS = 120_000;
const SUPPORTED_EXTENSIONS = new Set([
  ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".c", ".h",
  ".cc", ".cpp", ".hpp", ".cs", ".go", ".php", ".rb", ".rs", ".kt", ".kts",
  ".swift", ".scala", ".html", ".htm", ".vue", ".sh", ".sql", ".yaml", ".yml",
  ".json", ".toml"
]);

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8"
};

function sendJson(response, status, payload) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  response.end(JSON.stringify(payload));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    let size = 0;
    let tooLarge = false;
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      size += Buffer.byteLength(chunk);
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
        return;
      }
      if (!tooLarge) body += chunk;
    });
    request.on("end", () => {
      if (tooLarge) {
        reject(Object.assign(new Error("Request exceeds the 5 MB scan limit."), { status: 413 }));
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(Object.assign(new Error("Request body must be valid JSON."), { status: 400 }));
      }
    });
    request.on("error", reject);
  });
}

function validateFiles(payload) {
  if (!payload || !Array.isArray(payload.files) || payload.files.length === 0) {
    throw Object.assign(new Error("Provide at least one source file to scan."), { status: 400 });
  }
  if (payload.files.length > MAX_FILES) {
    throw Object.assign(new Error(`A scan can contain at most ${MAX_FILES} files.`), { status: 413 });
  }

  let totalBytes = 0;
  const seenPaths = new Set();
  const files = payload.files.map((file) => {
    if (!file || typeof file.path !== "string" || typeof file.content !== "string") {
      throw Object.assign(new Error("Each file must include a relative path and text content."), { status: 400 });
    }

    const relativePath = file.path.replaceAll("\\", "/");
    const segments = relativePath.split("/");
    if (
      !relativePath ||
      relativePath.startsWith("/") ||
      /^[a-zA-Z]:/.test(relativePath) ||
      relativePath.includes("\0") ||
      Buffer.byteLength(relativePath, "utf8") > MAX_PATH_BYTES ||
      segments.some((segment) => segment === "." || segment === ".." || segment === "")
    ) {
      throw Object.assign(new Error(`Unsafe file path: ${file.path}`), { status: 400 });
    }
    const duplicateKey = process.platform === "win32" ? relativePath.toLowerCase() : relativePath;
    if (seenPaths.has(duplicateKey)) {
      throw Object.assign(new Error(`Duplicate source path: ${relativePath}`), { status: 400 });
    }
    seenPaths.add(duplicateKey);

    const extension = path.posix.extname(relativePath).toLowerCase();
    if (!SUPPORTED_EXTENSIONS.has(extension)) {
      throw Object.assign(new Error(`Unsupported source file type: ${relativePath}`), { status: 400 });
    }

    const bytes = Buffer.byteLength(file.content, "utf8");
    if (bytes > MAX_FILE_BYTES) {
      throw Object.assign(new Error(`${relativePath} exceeds the 1 MB per-file limit.`), { status: 413 });
    }
    totalBytes += bytes;
    if (totalBytes > MAX_BODY_BYTES) {
      throw Object.assign(new Error("The selected source exceeds the 5 MB total scan limit."), { status: 413 });
    }

    return { path: relativePath, content: file.content };
  });

  return files;
}

function runPythonScanner(scanDirectory, healthCheck = false) {
  return new Promise((resolve, reject) => {
    const args = [...PYTHON_PREFIX_ARGS, SCANNER_FILE];
    if (healthCheck) {
      args.push("--health");
    } else {
      args.push("--root", scanDirectory);
    }
    const child = spawn(PYTHON_COMMAND, args, {
      cwd: ROOT,
      windowsHide: true,
      env: process.env,
      shell: false
    });
    let stdout = "";
    let stderr = "";
    let outputBytes = 0;
    const outputLimit = healthCheck ? 16_384 : 12 * 1024 * 1024;
    const timer = setTimeout(() => {
      child.kill();
      reject(Object.assign(
        new Error(healthCheck
          ? "Python scanner health check timed out."
          : "The local scanner did not finish within two minutes."),
        { status: 504 }
      ));
    }, healthCheck ? 10_000 : MAX_SCAN_MS);

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      outputBytes += Buffer.byteLength(chunk);
      if (outputBytes > outputLimit) {
        child.kill();
        return;
      }
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      if (stderr.length < 20_000) stderr += chunk;
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      if (error.code === "ENOENT") {
        reject(Object.assign(
          new Error("Python 3.15 was not found. Install Python 3.15 and ensure `py -3.15 --version` works."),
          { status: 503, code: "PYTHON_315_NOT_INSTALLED" }
        ));
        return;
      }
      reject(Object.assign(new Error(`Could not start the Python scanner: ${error.message}`), { status: 500 }));
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (outputBytes > outputLimit) {
        reject(Object.assign(new Error("Python scanner output exceeded the safety limit."), { status: 413 }));
        return;
      }
      try {
        const report = JSON.parse(stdout);
        if (code !== 0 || report.error) {
          reject(Object.assign(
            new Error(report.error || stderr.trim() || `Python scanner exited with code ${code}${signal ? ` (${signal})` : ""}.`),
            { status: 422 }
          ));
          return;
        }
        resolve(report);
      } catch {
        const reason = stderr.trim() || `Python scanner exited with code ${code}${signal ? ` (${signal})` : ""} without a valid JSON report.`;
        reject(Object.assign(new Error(reason.slice(0, 1200)), { status: healthCheck ? 503 : 422 }));
      }
    });
  });
}

async function scanFiles(files) {
  const scanDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "scripy-scan-"));
  const startedAt = performance.now();
  try {
    for (const file of files) {
      const destination = path.resolve(scanDirectory, ...file.path.split("/"));
      if (!destination.startsWith(`${scanDirectory}${path.sep}`)) {
        throw Object.assign(new Error(`Unsafe file path: ${file.path}`), { status: 400 });
      }
      await fs.mkdir(path.dirname(destination), { recursive: true });
      await fs.writeFile(destination, file.content, { encoding: "utf8", flag: "wx" });
    }

    const report = await runPythonScanner(scanDirectory);
    return {
      ...report,
      durationMs: Math.round(performance.now() - startedAt),
      scannedFiles: files.length
    };
  } finally {
    await fs.rm(scanDirectory, { recursive: true, force: true });
  }
}

async function checkPythonScanner() {
  try {
    return await runPythonScanner("", true);
  } catch (error) {
    return {
      available: false,
      scannerVersion: "",
      pythonVersion: "",
      message: error.message
    };
  }
}

async function serveStatic(request, response, pathname) {
  const fileName = pathname === "/" ? "index.html" : pathname.slice(1);
  if (!["index.html", "style.css", "script.js"].includes(fileName)) {
    sendJson(response, 404, { error: "Not found." });
    return;
  }
  try {
    const content = await fs.readFile(path.join(ROOT, fileName));
    response.writeHead(200, {
      "Content-Type": MIME_TYPES[path.extname(fileName)] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
      "Cache-Control": "no-cache"
    });
    response.end(content);
  } catch (error) {
    sendJson(response, 500, { error: `Could not read the app file: ${error.message}` });
  }
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${HOST}`);
  const origin = request.headers.origin;
  if (
    origin &&
    origin !== `http://${HOST}:${PORT}` &&
    origin !== `http://localhost:${PORT}`
  ) {
    sendJson(response, 403, { error: "Requests from other origins are not allowed." });
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/health") {
    const health = await checkPythonScanner();
    sendJson(response, 200, {
      ...health,
      message: health.available
        ? `Python AST and local source rules ready · Python ${health.pythonVersion}`
        : health.message
    });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/scan") {
    try {
      if (!request.headers["content-type"]?.toLowerCase().startsWith("application/json")) {
        throw Object.assign(new Error("Scan requests must use application/json."), { status: 415 });
      }
      const files = validateFiles(await readJson(request));
      sendJson(response, 200, await scanFiles(files));
    } catch (error) {
      sendJson(response, error.status || 500, {
        error: error.message || "The scan failed unexpectedly.",
        code: error.code || "SCAN_FAILED"
      });
    }
    return;
  }
  if (request.method === "GET" && !url.pathname.startsWith("/api/")) {
    await serveStatic(request, response, url.pathname);
    return;
  }
  sendJson(response, 404, { error: "Not found." });
});

if (require.main === module) {
 server.listen(PORT, HOST, () => {
   console.log(`Scripy is running at http://${HOST}:${PORT}`);
 });
}

module.exports = { checkPythonScanner, readJson, runPythonScanner, scanFiles, server, validateFiles };
