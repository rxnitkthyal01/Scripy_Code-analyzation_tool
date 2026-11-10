# Comprehensive Security Hardening Plan - Scripy

## 1. Vulnerability Assessment Summary

The analysis has identified critical and high-severity vulnerabilities:

1.  **ReDoS (Regular Expression Denial of Service):** `mask_non_code` and several scan rules utilize regex patterns vulnerable to exponential backtracking on large, maliciously crafted inputs, allowing for resource exhaustion.
2.  **Environment Variable Exposure:** `server.js` passes the entire parent `process.env` to the Python child process, potentially leaking secrets to the scanner.
3.  **Lack of Rate Limiting:** The `/api/scan` endpoint lacks request throttling, exposing the system to resource-exhaustion attacks.
4.  **Information Leakage:** Error responses in `server.js` return raw error messages, which may inadvertently leak internal file paths or system information.
5.  **Inconsistent Python Environment Logic:** The logic in `server.js` for handling `PYTHON_315_EXECUTABLE` can lead to the execution of incorrect Python versions.
6.  **Unbounded I/O:** File system operations (e.g., `fs.rm`) are performed without timeouts, potentially leading to hung processes under high load.

## 2. Proposed Security Enhancements

1.  **Regex Hardening:** Rewrite regex patterns in `scanner.py` to use non-backtracking patterns (e.g., possessive quantifiers or alternative grouping techniques).
2.  **Environment Sanitization:** Modify `server.js` to whitelist only necessary environment variables when spawning the scanner.
3.  **Endpoint Throttling:** Implement rate limiting on `/api/scan` (e.g., using `express-rate-limit` logic or a basic map-based counter).
4.  **Standardized Error Handling:** Sanitize all errors before sending them to the client.
5.  **Robust Path/Process Handling:** Centralize Python path discovery and ensure consistent usage of environment flags.
6.  **I/O Timeouts:** Add timeouts to all asynchronous filesystem operations in `server.js` to prevent I/O blocking.

## 3. Implementation Steps

- [ ] **Phase 1: Regex Remediation**
    - Audit all regex patterns in `scanner.py` for backtracking vulnerabilities.
    - Implement a test suite covering ReDoS-prone strings.
- [ ] **Phase 2: Environment & Process Hardening**
    - Refactor `runPythonScanner` in `server.js` to sanitize the `env` object.
    - Standardize Python command/flag logic.
- [ ] **Phase 3: API Security**
    - Implement a simple rate limiter for the `/api/scan` endpoint.
    - Sanitize error outputs.
- [ ] **Phase 4: Resource & I/O Protection**
    - Enforce process-level memory limits (using `ulimit` or `node:child_process` spawn constraints).
    - Wrap filesystem cleanup operations in a timeout mechanism.

## 4. Open Questions/Decisions

- **Decision Required:** Should I implement custom middleware for rate limiting, or use a dependency like `rate-limiter-flexible`?
    - *Recommendation:* Keep it dependency-free to maintain the project's "local-first, no external dependencies" philosophy (if applicable).
- **Decision Required:** Do you want to prioritize reducing false positives over performance, or vice versa?
    - *Recommendation:* Prioritize security and false-positive reduction, as this is a code analysis tool.

## 5. Future Threat Modeling & extensibility

### 5.1 Emerging Threat Categories to Monitor
- **AI-Generated Code Vulnerabilities:** Patterns specific to code produced by LLMs (Copilot, ChatGPT), including insecure defaults, over-permissive IAM patterns, and hallucinated API usage.
- **Supply Chain Attacks:** Detection of dependency confusion, ghost writing, and patterns that indicate attempt to inject malicious code via package name similarities or environment variable manipulation.
- **Obfuscated Code Detection:** Identification of base64/hex/gzip encoding, binary data embedding, and eval/Function constructors with dynamically constructed strings that attempt to hide malicious intent.
- **Side-Channel Patterns:** Code structures that may indicate timing attack vectors, cache-based side channels, or speculative execution patterns (e.g., unusual cryptographic key handling).
- **Quantum-Resistant Cryptography Audit:** Flagging symmetric keys, hashes, and key exchange mechanisms that will be vulnerable to future cryptanalysis (e.g., RSA, ECDSA with small key sizes, MD5/SHA1 usage).
- **Privacy Compliance Patterns:** Detection of GDPR/CCPA-relevant data handling (personal identifiers, consent tracking, data retention, cross-border transfer patterns).
- **Multi-Language Taint Tracking:** Beyond single-file analysis, tracking how untrusted data flows across language boundaries (Python → JavaScript → HTML → SQL, etc.) in full-stack applications.

### 5.2 Plugin / Rule Extension Architecture
- Design `scanner.py` rules as independently loadable modules so new detection categories can be added without modifying core logic.
- Expose a simple JSON schema for rule definitions so community-contributed rules can be validated and imported.
- Add a `--rule-dir` CLI flag to `main()` that scans additional directories for user-defined rule files.

### 5.3 Optional Advanced Analyzers (Future Integration)
- **ML-Assisted Detection:** Optional integration with lightweight scikit-learn or ONNX models for classifying code patterns beyond regex capabilities.
- **Cross-Function Data Flow:** Abstract syntax tree (AST) based taint analysis that tracks variable provenance across function boundaries (requires more extensive parser changes).
- **Container/Kubernetes Manifest Scanning:** Extended support for YAML/Helm template analysis to detect insecure run-as-user, hostPath mounts, and privileged container patterns.
- **Infrastructure-as-Code Scanning:** Terraform, CloudFormation, and Bicep template analysis for cloud misconfiguration patterns.

### 5.4 Long-Term Roadmap Priorities
1. **Rule accuracy over breadth:** Focus on reducing false positives in existing rules before adding new categories.
2. **Configurable severity/confidence:** Allow users to tune rule strictness via a `.scripyrc` config file.
3. **Graph-based inter-file analysis:** For project folder mode, build a minimal data-flow graph between files to reduce cross-function false negatives.
4. **WASM sandboxing:** Run the Python scanner in a WebAssembly sandbox for enhanced isolation and resource control.
5. **Real-time threat intelligence feeds:** Periodic download of CVE pattern signatures to auto-update detection rules.
