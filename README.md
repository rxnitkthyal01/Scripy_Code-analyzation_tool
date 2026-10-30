# Scripy Local Code Scanner

Scripy is a local-first tool for checking source code for selected security risks and common code-quality problems. Use the web interface to scan a code snippet, an individual source file, or a project folder. Scans run on your computer; source code is not uploaded to a hosted analysis service.

**Workspace:** r9sys Workspace

## What Scripy checks

Python files are parsed with Python's built-in abstract syntax tree (AST). Supported non-Python files are checked against bundled, language-specific source patterns.

The bundled rules cover selected examples of:

- Dynamic code execution
- Dynamically constructed SQL queries
- Shell command execution and command-injection risks
- Unsafe HTML insertion and related cross-site scripting risks
- Hardcoded-looking credentials
- Disabled TLS certificate verification
- Unsafe deserialization
- Weak random-number and hash functions
- Unsafe C and C++ buffer functions
- Debug-mode configuration
- Loose JavaScript equality
- Bare Python exception handlers
- Python temporary-file handling
- Other selected security and code-quality patterns

The rules are a first-pass review aid. They are not a complete security audit. Apart from Python's syntax-aware AST checks, the bundled analysis is pattern-based rather than full parsing or cross-function data-flow analysis. It can miss vulnerabilities and report safe code, particularly when patterns appear in comments or strings. Findings include severity, confidence, file and line information, an explanation, and a suggested fix where available. Review every finding in context.

Scripy does not execute submitted code, perform full cross-function taint analysis, or audit third-party dependencies.

## Supported file types

The scanner accepts these source extensions:

`.py`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.java`, `.c`, `.h`, `.cc`, `.cpp`, `.hpp`, `.cs`, `.go`, `.php`, `.rb`, `.rs`, `.kt`, `.kts`, `.swift`, `.scala`, `.html`, `.htm`, `.vue`, `.sh`, `.sql`, `.yaml`, `.yml`, `.json`, and `.toml`.

Python is analyzed with the built-in AST. Other listed languages and formats use local source-pattern rules; their coverage and confidence vary.

## Requirements

- Node.js 18 or newer
- Python 3.15 or newer

The scanner uses Python's standard library and does not require pip packages or an external scanning engine.

## Install Python on Windows

1. Install Python 3.15.2 or a later Python 3.15 patch release from the [official Python downloads page](https://www.python.org/downloads/).
2. Ensure the Python launcher is installed.
3. Open PowerShell and verify the installation:

   ```powershell
   py -3.15 --version
   ```

If Scripy cannot find the launcher-installed interpreter, set the path to your Python executable before starting the server:

```powershell
$env:PYTHON_315_EXECUTABLE = "C:\Path\To\Python315\python.exe"
```

## Install Python on macOS or Linux

Install Python 3.15 and ensure `python3.15` is available on `PATH`. Scripy uses that command by default. To use a different interpreter path, set `PYTHON_315_EXECUTABLE` before starting the app.

## Run Scripy

Open a terminal in the project directory and start the local server:

```powershell
npm start
```

On macOS or Linux, use the same `npm start` command in a terminal.

Open [http://127.0.0.1:4173](http://127.0.0.1:4173) in your browser. The server binds to the loopback interface and is intended for local use. If the port is already in use, stop the other Scripy server or set a different port before starting:

```powershell
$env:PORT = "4174"
npm start
```

The app's status indicator checks whether the Python scanner is available.

## Use the scanner

1. Paste code into the editor, load the built-in sample, upload one source file, or choose a project folder.
2. Select the language for a pasted snippet. Uploaded files select a language from their extension.
3. Select **Scan code** or press **Ctrl+Enter** (Windows/Linux) or **Command+Enter** (macOS).
4. Review the findings, severity counts, locations, explanations, confidence, and suggested fixes.
5. Filter by severity or search finding details.
6. Export a JSON or SARIF 2.1.0 report, or copy the JSON report.
7. Reopen a recent scan summary from the browser's scan history.

The editor and scan feedback report the current source metrics and elapsed scan time. The scan indicator does not estimate a percentage. A report with no matches only means that the bundled rules did not identify a pattern; it does not prove that the code is secure.

## Limits and local data

- A scan can contain up to 500 supported files.
- Each file is limited to 1 MB.
- Total source content is limited to 5 MB.
- The HTTP request limit allows additional room for JSON encoding overhead.
- Only supported source extensions are scanned.
- Python syntax errors are reported as analysis warnings rather than clean scan results.
- Unsupported or unsafe relative paths are rejected by the backend.

The local server writes submitted source to a temporary directory while scanning and removes that directory when the scan finishes. The scanner is launched without a shell. Browser history stores up to eight report summaries and does not save source snippets. Clearing history removes those saved summaries from the browser.

## Change or add scanner rules

Python AST checks and non-Python source-pattern rules are in `scanner.py`. The scanner API and local server are implemented in `server.js`. The browser interface is in `index.html`, `style.css`, and `script.js`. Regression tests are in `server.test.js`.

Non-Python rules use source patterns and may match comments or strings. Test rule changes against both positive examples and similar safe code to check for missed cases and false positives.

## Run tests

Run the automated tests from the project directory:

```powershell
npm test
```

The tests cover file and path validation, source-size limits, Python 3.15 AST scanning, non-Python source rules, and invalid Python syntax warnings. Python integration tests require the configured Python 3.15 interpreter.

## Project

Scripy is maintained in the `r9sys Workspace`.
