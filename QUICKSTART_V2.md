# DepGuard v2.0 - Quick Start Guide

Get started with DepGuard in less than 5 minutes!

## 📦 Installation

```bash
# Install globally
npm install -g depguard

# Or use with npx (no installation)
npx depguard scan
```

## 🚀 First Scan

### 1. Basic Scan

```bash
# Scan current directory
depguard scan

# Scan a specific project
depguard scan /path/to/your/project
```

**Output:**
```
🔍 DepGuard v2.0 - Generic Vulnerability Scanner

📦 Phase 1: Discovering project structure...
  ✓ Found 3 manifest(s): npm, pypi, maven

📋 Phase 2: Analyzing dependencies...
  ✓ Total dependencies: 42

🔎 Phase 3: Checking for vulnerabilities...
  ✓ Found 18 known vulnerabilities

🕸️  Phase 4: Building call graph...
  ✓ Built call graph: 156 nodes, 423 edges

🚪 Phase 5: Detecting entry points...
  ✓ Detected 5 entry points

🔬 Phase 6: Performing reachability analysis...
  ✓ Analyzed 18 potential vulnerabilities

✅ 2 REACHABLE vulnerabilities found!
ℹ️  16 unreachable vulnerabilities
```

### 2. Understanding the Results

DepGuard distinguishes between:

- **Reachable Vulnerabilities** 🔴 : Actually exploitable in your code
- **Unreachable Vulnerabilities** 🟡 : Present but not callable from entry points

Focus on fixing the **reachable** ones first!

## 📊 Output Formats

### JSON (Machine-Readable)

```bash
depguard scan --format json --output results.json
```

Perfect for CI/CD pipelines and automated processing.

### HTML (Interactive Report)

```bash
depguard scan --format html --output report.html
```

Beautiful, shareable reports for stakeholders.

### SARIF (GitHub Integration)

```bash
depguard scan --format sarif --output depguard.sarif
```

Upload to GitHub Security tab for seamless integration.

## 🎯 Common Use Cases

### Scenario 1: "Is this vulnerability actually exploitable?"

```bash
depguard scan --verbose
```

Get detailed call paths showing exactly HOW the vulnerability is reached.

### Scenario 2: "Too many false positives!"

```bash
depguard scan --min-confidence 0.7
```

Increase the confidence threshold to see only high-confidence findings.

### Scenario 3: "Scanning a monorepo"

```bash
depguard scan /path/to/monorepo
```

DepGuard automatically detects and scans all services!

### Scenario 4: "Need quick project overview"

```bash
depguard stats
```

See project statistics without running a full scan.

## ⚙️ Configuration

### No Configuration Needed!

DepGuard works out-of-the-box with zero configuration.

### Optional: Customize via `.depguard.yml`

```yaml
# In your project root
minConfidence: 0.5
entryPointConfidence: 0.6
maxDepth: 10

excludeDirs:
  - node_modules
  - dist
  - test
```

## 🔍 Example: Real Vulnerability Detection

**Scenario**: Your project uses `lodash@4.17.11` which has a prototype pollution vulnerability.

### Traditional Scanner:
```
❌ Found lodash vulnerability CVE-2019-10744
   → Is this exploitable? Unknown!
   → Manual investigation required
   → Wastes developer time
```

### DepGuard v2:
```
✅ Found lodash CVE-2019-10744
   → Reachable: YES (95% confidence)
   → Path: api/users/route.js → utils/merge.js → lodash.defaultsDeep
   → Evidence: Uses vulnerable function with user input
   → Action: Fix immediately!
```

## 🚨 What to Do with Results

### Priority 1: Reachable Vulnerabilities

```
⚠️  CRITICAL: Fix immediately!

1. Review the call path
2. Upgrade the package: npm update <package>
3. Or apply a workaround if upgrade not possible
4. Re-scan to verify fix
```

### Priority 2: Unreachable Vulnerabilities

```
ℹ️  Lower priority (not currently exploitable)

1. Track for future code changes
2. Upgrade when convenient
3. Consider removing unused dependencies
```

## 📈 Improving Accuracy

### Increase Entry Point Detection

```bash
depguard scan --entry-confidence 0.5
```

Lower threshold = more entry points detected = more thorough analysis

### Deep Analysis Mode

```bash
depguard scan --deep --max-depth 15
```

Slower but more thorough (recommended for critical projects).

## 🤖 CI/CD Integration

### GitHub Actions (1 minute setup)

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm install -g depguard
      - run: depguard scan --format sarif --output depguard.sarif
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: depguard.sarif
```

### GitLab CI

```yaml
security_scan:
  script:
    - npm install -g depguard
    - depguard scan --format json --output depguard.json
  artifacts:
    reports:
      dependency_scanning: depguard.json
```

## 💡 Pro Tips

### Tip 1: Start with Stats

```bash
depguard stats
```

Quick overview before full scan.

### Tip 2: Save Results for Comparison

```bash
depguard scan --format json --output scan-$(date +%Y%m%d).json
```

Track improvements over time.

### Tip 3: Focus on New Vulnerabilities

```bash
# Scan and save baseline
depguard scan --format json --output baseline.json

# Later, compare with current
depguard scan --format json --output current.json
diff baseline.json current.json
```

### Tip 4: Use Verbose Mode for Debugging

```bash
depguard scan --verbose
```

See exactly what DepGuard is doing at each phase.

## 🆘 Troubleshooting

### "No manifests found"

```
Problem: DepGuard couldn't find dependency manifests
Solution: Ensure you're in the project root or specify the correct path
```

### "No entry points detected"

```
Problem: DepGuard couldn't identify entry points
Solution:
  1. Lower the confidence threshold: --entry-confidence 0.4
  2. Or manually specify entry points in .depguard.yml
```

### "Too many false positives"

```
Problem: Getting unreachable vulnerabilities marked as reachable
Solution:
  1. Increase confidence threshold: --min-confidence 0.7
  2. Use --deep for more accurate analysis
```

## 🎓 Next Steps

1. **Read the full documentation**: [README_V2.md](README_V2.md)
2. **Understand the architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
3. **Learn about the redesign**: [V2_TRANSFORMATION.md](V2_TRANSFORMATION.md)
4. **Contribute**: [CONTRIBUTING.md](CONTRIBUTING.md)

## 📧 Getting Help

- **Documentation**: See README_V2.md
- **Examples**: Run `depguard examples`
- **Issues**: GitHub Issues
- **Questions**: GitHub Discussions

---

**Ready to scan?**

```bash
depguard scan
```

*Happy scanning! 🔍*
