# DepGuard Quick Start Guide

Get up and running with DepGuard in 5 minutes!

## Installation

```bash
npm install -g depguard
```

Or for local project usage:

```bash
npm install --save-dev depguard
```

## Basic Usage

### 1. Scan Your Project

Navigate to your project directory and run:

```bash
depguard scan
```

This will:
- Auto-detect your project type (JavaScript, Python, or Java)
- Find all dependencies
- Check for vulnerabilities
- Analyze reachability
- Display results in a table

### 2. Understanding the Output

```
╔════════════════════════════════════════════════════════════════╗
║ DepGuard Security Report                                       ║
╠════════════════════════════════════════════════════════════════╣
║ Total Dependencies: 150                                        ║
║ Vulnerabilities Found: 23                                      ║
║ Reachable Vulnerabilities: 8                                   ║
╚════════════════════════════════════════════════════════════════╝

[CRITICAL] 🔴 ⚠️  REACHABLE (95% confidence)
Package: lodash@4.17.20
Vulnerability: CVE-2021-23337
CVSS: 9.8 (Critical)

Reachable Path:
  src/app.js:15 → express-middleware
  → node_modules/lodash/template.js:254 [VULNERABLE]

Recommendation: Update to lodash@4.17.21 or higher
```

**Key Information:**
- **Severity**: CRITICAL, HIGH, MEDIUM, LOW
- **Reachability**: REACHABLE or NOT REACHABLE
- **Confidence**: How certain we are (0-100%)
- **Path**: Shows how vulnerable code is reached
- **Recommendation**: How to fix it

### 3. Focus on What Matters

Show only reachable vulnerabilities:

```bash
depguard scan --reachable-only
```

Filter by severity:

```bash
depguard scan --severity critical
```

Combine filters:

```bash
depguard scan --reachable-only --severity high
```

### 4. Generate Reports

#### JSON for automation:
```bash
depguard scan --output json --file report.json
```

#### HTML for sharing:
```bash
depguard scan --output html --file report.html
```

#### SARIF for GitHub:
```bash
depguard scan --output sarif --file report.sarif
```

## Common Workflows

### Daily Development

```bash
# Quick scan
depguard scan --reachable-only
```

### Pre-Commit

```bash
# Fail on critical reachable vulnerabilities
depguard scan --reachable-only --severity critical
```

### CI/CD Pipeline

```bash
# Generate SARIF report
depguard scan --output sarif --file report.sarif

# Upload to GitHub Code Scanning
# (GitHub Actions will handle this automatically)
```

### Security Review

```bash
# Deep analysis with detailed report
depguard scan --deep-analysis --verbosity detailed --output html --file security-report.html
```

## Configuration

Create a `.depguard.yml` file in your project root:

```yaml
scan:
  depth: 10
  excludePaths:
    - test/**
    - dist/**

reachability:
  minConfidence: 0.7
  trackDynamicCalls: true

reporting:
  onlyReachable: true
  minSeverity: medium
```

Generate default config:

```bash
depguard config
```

## Interpreting Confidence Scores

- **90-100%**: Definitely reachable - prioritize immediately
- **70-89%**: Likely reachable - investigate soon
- **50-69%**: Possibly reachable - review when possible
- **<50%**: Unlikely reachable - low priority

## Common Scenarios

### Scenario 1: No Vulnerabilities Found
```
✓ No vulnerabilities found!
```
Great! Your dependencies are clean.

### Scenario 2: Vulnerabilities Found, None Reachable
```
Vulnerabilities Found: 15
Reachable Vulnerabilities: 0
```
Your project has vulnerable dependencies, but none of the vulnerable code is actually used. Still consider updating when convenient.

### Scenario 3: Reachable Critical Vulnerability
```
[CRITICAL] ⚠️  REACHABLE (95% confidence)
```
**Action Required**: Update the package immediately or implement a workaround.

## Tips & Best Practices

### 1. Run Regularly
```bash
# Add to package.json
"scripts": {
  "security": "depguard scan --reachable-only"
}
```

### 2. Integrate with CI/CD
```yaml
# .github/workflows/security.yml
- name: Security Scan
  run: depguard scan --output sarif --file report.sarif
```

### 3. Use Configuration Files
Keep settings consistent across team with `.depguard.yml`

### 4. Start with Reachable Only
Reduce noise by focusing on exploitable vulnerabilities first

### 5. Understand Your Paths
Review the call paths to understand how vulnerabilities are reached

## Troubleshooting

### Issue: Scan is slow
**Solution**: Exclude unnecessary directories
```bash
depguard scan --exclude "test/**,dist/**,build/**"
```

### Issue: Too many results
**Solution**: Filter by reachability and severity
```bash
depguard scan --reachable-only --severity high
```

### Issue: False positives
**Solution**: Use deep analysis mode
```bash
depguard scan --deep-analysis
```

### Issue: Cannot detect project type
**Solution**: Specify language explicitly
```bash
depguard scan --language javascript
```

## Next Steps

1. **Review the full documentation**: `README.md`
2. **Check examples**: `examples/vulnerable-app/`
3. **Learn the architecture**: `ARCHITECTURE.md`
4. **Contribute**: `CONTRIBUTING.md`

## Getting Help

- Documentation: [README.md](README.md)
- Issues: https://github.com/owasp/depguard/issues
- Discussions: https://github.com/owasp/depguard/discussions

## Example Session

```bash
$ cd my-project

$ depguard scan --reachable-only
🔍 Starting DepGuard security scan...

📦 Detected project type: javascript
📋 Analyzing dependencies...
Found 247 dependencies

🔎 Checking for vulnerabilities...
🕸️  Building call graph...
Built call graph: 1,234 nodes, 3,456 edges

🔬 Performing reachability analysis...
✓ Analysis complete: Found 3 reachable vulnerabilities

╔════════════════════════════════════════════════════════════════╗
║ DepGuard Security Report                                       ║
╠════════════════════════════════════════════════════════════════╣
║ Total Dependencies: 247                                        ║
║ Vulnerabilities Found: 12                                      ║
║ Reachable Vulnerabilities: 3                                   ║
╚════════════════════════════════════════════════════════════════╝

[CRITICAL] 🔴 ⚠️  REACHABLE (92% confidence)
Package: lodash@4.17.20
Vulnerability: CVE-2021-23337
...

$ npm install lodash@latest
$ depguard scan --reachable-only
✓ No reachable vulnerabilities found!
```

---

Happy scanning! 🛡️
