const assert = require("node:assert/strict");
const { Readable } = require("node:stream");
const test = require("node:test");
const { readJson, scanFiles, validateFiles } = require("./server");

test("validates supported relative source files", () => {
  const files = validateFiles({
    files: [{ path: "src/app.ts", content: "const ready: boolean = true;" }]
  });
  assert.equal(files.length, 1);
  assert.equal(files[0].path, "src/app.ts");
});

test("rejects paths that escape the temporary scan directory", () => {
  assert.throws(
    () => validateFiles({ files: [{ path: "../outside.py", content: "print('x')" }] }),
    /Unsafe file path/
  );
  assert.throws(
    () => validateFiles({ files: [{ path: "src\\..\\outside.py", content: "print('x')" }] }),
    /Unsafe file path/
  );
});

test("rejects unsupported, duplicate, and oversized input", () => {
  assert.throws(
    () => validateFiles({ files: [{ path: "notes.txt", content: "not source" }] }),
    /Unsupported source file type/
  );
  assert.throws(
    () => validateFiles({
      files: [
        { path: "src/app.js", content: "first" },
        { path: "SRC/APP.JS", content: "second" }
      ]
    }),
    /Duplicate source path/
  );
  assert.throws(
    () => validateFiles({ files: [{ path: "large.js", content: "x".repeat(1024 * 1024 + 1) }] }),
    /1 MB per-file limit/
  );
  assert.throws(
    () => validateFiles({ files: [{ path: `${"a".repeat(1024)}.js`, content: "" }] }),
    /Unsafe file path/
  );
});

test("accepts allowed source when JSON escaping expands the request beyond 5 MB", async () => {
  const source = "\u0001".repeat(1024 * 1024);
  const body = JSON.stringify({ files: [{ path: "src/escaped.js", content: source }] });
  assert.ok(Buffer.byteLength(body) > 5 * 1024 * 1024);

  const payload = await readJson(Readable.from([body]));
  const files = validateFiles(payload);
  assert.equal(files[0].content.length, 1024 * 1024);
});

test("runs Python 3.15 AST analysis and source rules on submitted code", async () => {
  const report = await scanFiles([
    {
      path: "src/app.py",
      content: [
        "import subprocess",
        "user_input = input()",
        'query = "SELECT * FROM users WHERE id = " + user_input',
        "cursor.execute(query)",
        "eval(user_input)",
        "subprocess.run(user_input, shell=True)",
        "try:",
        "    work()",
        "except:",
        "    pass"
      ].join("\n")
    },
    {
      path: "src/page.js",
      content: [
        'const example = "eval(userInput)";',
        'const message = "Select no more than ${total} files";',
        'const query = "SELECT * FROM users WHERE id = " + request.query.id;',
        "document.body.innerHTML = request.query.name;"
      ].join("\n")
    }
  ]);
  assert.match(report.pythonVersion, /^3\.15\./);
  assert.equal(report.scannedFiles, 2);
  assert.equal(report.analysisWarnings.length, 0);
  assert.deepEqual(
    new Set(report.findings.map((item) => item.ruleId)),
    new Set([
      "scripy.dynamic-code",
      "scripy.sql-dynamic-query",
      "scripy.subprocess-shell-true",
      "scripy.python-bare-except",
      "scripy.dom-xss"
    ])
  );
  assert.equal(report.findings.find((item) => item.ruleId === "scripy.sql-dynamic-query").line, 4);
  assert.equal(
    report.findings.filter((item) => item.file === "src/page.js").length,
    2
  );
});

test("detects SQL query construction with common interpolation and formatting styles", async () => {
  const report = await scanFiles([
    {
      path: "src/template.js",
      content: 'const query = `SELECT * FROM users WHERE id = ${userId}`;'
    },
    {
      path: "src/query.go",
      content: 'query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)'
    },
    {
      path: "src/query.java",
      content: 'String query = String.format("SELECT * FROM users WHERE id = %s", userId);'
    }
  ]);
  assert.deepEqual(
    report.findings.map((item) => item.file).sort(),
    ["src/query.go", "src/query.java", "src/template.js"]
  );
  assert.ok(report.findings.every((item) => item.ruleId === "scripy.sql-dynamic-query"));
});

test("reports invalid Python syntax instead of returning a clean scan", async () => {
  const report = await scanFiles([
    { path: "broken.py", content: "def broken(:\n    pass\n" }
  ]);
  assert.equal(report.findings.length, 0);
  assert.equal(report.analysisWarnings.length, 1);
  assert.match(report.analysisWarnings[0], /AST analysis skipped/);
});

test("enforces 5 MB total source size limit", () => {
  const hugeSource = "x".repeat(6 * 1024 * 1024);
  assert.throws(
    () => validateFiles({ files: [{ path: "huge.js", content: hugeSource }] }),
    /5 MB total scan limit/
  );
});

test("detects future-threat patterns in code", async () => {
  const report = await scanFiles([
    {
      path: "threats.js",
      content: [
        'app.use(cors());', // scripy.ai-insecure-default
        'atob("Y29kZSA9IG1hbGljaW91cw==");', // scripy.obfuscated-payload
        'const key = crypto.createCipher("des", "password");' // scripy.weak-crypto-future
      ].join("\n")
    }
  ]);
  const ruleIds = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ruleIds.has("scripy.ai-insecure-default"));
  assert.ok(ruleIds.has("scripy.obfuscated-payload"));
  assert.ok(ruleIds.has("scripy.weak-crypto-future"));
});

test("detects insecure infrastructure patterns", async () => {
  const report = await scanFiles([
    {
      path: "deploy.yaml",
      content: [
        "securityContext:",
        "  privileged: true",
        "  runAsUser: 0"
      ].join("\n")
    },
    {
      path: "config.json",
      content: '{"cidr": "0.0.0.0/0"}'
    }
  ]);
  const ruleIds = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ruleIds.has("scripy.k8s-privileged-container"));
  assert.ok(ruleIds.has("scripy.k8s-root-user"));
  assert.ok(ruleIds.has("scripy.iac-public-access"));
});

test("detects privacy and side-channel patterns", async () => {
  const report = await scanFiles([
    {
      path: "privacy.json",
      content: '{"user": {"dob": "1990-01-01", "ssn": "000-00-0000"}}'
    },
    {
      path: "auth.js",
      content: 'if (inputToken === internalSecretToken) { login(); }'
    },
    {
      path: "keys.json",
      content: '{"aws": "AKIAIOSFODNN7EXAMPLE", "gcp": "AIzaSyA1234567890abcdefghijklmnopqrstuvwxyz"}'
    }
  ]);
  const ruleIds = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ruleIds.has("scripy.privacy-pii-handling"));
  assert.ok(ruleIds.has("scripy.side-channel-timing"));
  assert.ok(ruleIds.has("scripy.aws-access-key"));
  assert.ok(ruleIds.has("scripy.gcp-api-key"));
});

test("respects .scripy.json rule overrides", async () => {
  const report = await scanFiles([
    {
      path: ".scripy.json",
      content: JSON.stringify({
        overrides: {
          "scripy.dom-xss": { enabled: false },
          "scripy.dynamic-code": { severity: "LOW" }
        }
      })
    },
    {
      path: "test.js",
      content: 'eval("alert(1)"); document.body.innerHTML = location.search;'
    }
  ]);
  const domXss = report.findings.find(f => f.ruleId === "scripy.dom-xss");
  const dynamicCode = report.findings.find(f => f.ruleId === "scripy.dynamic-code");

  assert.equal(domXss, undefined, "scripy.dom-xss should be disabled");
  assert.ok(dynamicCode, "scripy.dynamic-code should be present");
  assert.equal(dynamicCode.severity, "LOW", "scripy.dynamic-code severity should be overridden to LOW");
});
