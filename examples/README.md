# DepGuard Examples

This directory contains example projects to demonstrate DepGuard's capabilities.

## Vulnerable App Example

The `vulnerable-app` directory contains a simple Express.js application with intentional security vulnerabilities. It's designed to showcase DepGuard's reachability analysis.

### Vulnerabilities Present

1. **lodash@4.17.20** - CVE-2021-23337 (Prototype Pollution)
   - **REACHABLE** via `/render` endpoint
   - **NOT REACHABLE** in `unusedVulnerableFunction()`

2. **axios@0.21.1** - CVE-2023-45857 (SSRF)
   - **REACHABLE** via `/fetch` endpoint

3. **jsonwebtoken@8.5.1** - CVE-2022-23529 (Signature Verification Bypass)
   - **REACHABLE** via `/verify` endpoint

4. **express@4.17.1** - CVE-2022-24999 (Open Redirect)
   - **NOT REACHABLE** (not using vulnerable redirect function)

### Running the Demo

1. Navigate to the vulnerable app:
```bash
cd examples/vulnerable-app
```

2. Scan with DepGuard:
```bash
depguard scan
```

3. Expected output should show:
   - 4 vulnerabilities found
   - 3 marked as REACHABLE
   - 1 marked as NOT REACHABLE
   - Call paths showing how vulnerable code is reached

### Example Scan Output

```
╔════════════════════════════════════════════════════════════════╗
║ DepGuard Security Report                                       ║
╠════════════════════════════════════════════════════════════════╣
║ Total Dependencies: 4                                          ║
║ Vulnerabilities Found: 4                                       ║
║ Reachable Vulnerabilities: 3                                   ║
║ Critical: 2                                                    ║
╚════════════════════════════════════════════════════════════════╝

[CRITICAL] 🔴 ⚠️  REACHABLE (95% confidence)
Package: lodash@4.17.20
Vulnerability: CVE-2021-23337
CVSS: 9.8 (Critical)
Description: Prototype Pollution in lodash

Reachable Path:
  app.js::app.post
  → express-middleware
  → app.js::/render
  → node_modules/lodash/template.js::template [VULNERABLE]

Recommendation: Update to lodash@4.17.21 or higher
```

## Testing Different Scenarios

### Show only reachable vulnerabilities
```bash
depguard scan --reachable-only
```

### Deep analysis mode
```bash
depguard scan --deep-analysis
```

### Generate HTML report
```bash
depguard scan --output html --file report.html
```

### CI/CD integration (SARIF format)
```bash
depguard scan --output sarif --file report.sarif
```

## Creating Your Own Test Cases

1. Create a new directory under `examples/`
2. Add a `package.json` with dependencies
3. Write code that uses (or doesn't use) vulnerable functions
4. Run DepGuard and verify the results

## Learning Objectives

This example demonstrates:
- How reachability analysis reduces false positives
- The difference between having a vulnerability and it being exploitable
- How call graph analysis traces code paths
- Why traditional dependency scanners report too many false positives
