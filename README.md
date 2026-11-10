# Scripy — Advanced Local Code Security Scanner

Scripy is a high-performance, local-first security analysis tool designed to identify vulnerabilities, privacy risks, and supply chain threats directly on your machine. No code is ever uploaded to the cloud.

## Key Features

- **AST-Powered Analysis**: Deep Python source analysis using built-in Abstract Syntax Trees.
- **Enterprise-Grade Protection**: Defense against ReDoS, command injection, and SQLi.
- **AI & Future Threat Detection**: Scans for insecure AI-generated defaults and legacy cryptographic patterns.
- **Infrastructure-as-Code (IaC)**: Security auditing for Kubernetes manifests and cloud configurations.
- **Supply Chain Security**: Audits for wildcard dependencies and suspicious package registries.
- **Privacy Compliance**: Automatic detection of PII (SSN, credit cards, etc.) for GDPR/CCPA readiness.
- **Extensible Architecture**: Load custom JSON-based rules via the `--rule-dir` flag.
- **Standardized Reporting**: Export findings in JSON, SARIF 2.1.0, or CycloneDX 1.5 SBOM formats.

## Quick Start

### Installation
Ensure you have **Node.js 18+** and **Python 3.15+** installed.

```bash
npm install
npm start
```

### Usage
Open `http://127.0.0.1:4173` in your browser to start scanning snippets, files, or entire project folders.

## Advanced Usage

### Custom Rules
Pass a directory of JSON rule files to extend detection capabilities:
```bash
python3 scanner.py --root ./my-project --rule-dir ./custom-rules
```

### Configuration
Customize rule severity and status via a `.scripy.json` file in your project root:
```json
{
  "overrides": {
    "scripy.dom-xss": { "enabled": false },
    "scripy.hardcoded-secret": { "severity": "CRITICAL" }
  }
}
```

## Security & Privacy
- **Local Scanning**: All processing happens on your local hardware.
- **Resource Isolated**: Configurable process limits (CPU/RAM) for safe analysis of untrusted code.
- **Zero Dependencies**: Core scanner uses only the Python standard library.

---
*Security is a superpower. Use it wisely.*
