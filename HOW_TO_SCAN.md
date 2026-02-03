# How to Use DepGuard to Scan Your Projects

## Quick Start - Scanning C:\Users\cczin\dependency-bad

### Method 1: Scan Individual Services (Recommended)

You have a multi-service project. Scan each service separately for best results:

#### 1. Scan Next.js Frontend
```bash
cd C:\Users\cczin\appservice-scan
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend"
```

#### 2. Scan Python Service
```bash
cd C:\Users\cczin\appservice-scan
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\python-service"
```

#### 3. Scan Java Backend
```bash
cd C:\Users\cczin\appservice-scan
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\java-backend"
```

#### 4. Scan Go Service
```bash
cd C:\Users\cczin\appservice-scan
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\go-service"
```
*Note: Go is not currently supported, but you can add support by creating a GoAnalyzer*

### Method 2: Show Only Reachable Vulnerabilities

Focus on what matters - only vulnerabilities that can actually be exploited:

```bash
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --reachable-only
```

### Method 3: Filter by Severity

Only show critical vulnerabilities:

```bash
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --severity critical
```

Only show high and critical:

```bash
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\python-service" --severity high
```

### Method 4: Generate Reports

#### JSON Report (for automation/CI/CD)
```bash
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --output json --file nextjs-report.json
```

#### HTML Report (for sharing with team)
```bash
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --output html --file nextjs-report.html
```

#### SARIF Report (for GitHub Code Scanning)
```bash
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --output sarif --file nextjs-report.sarif
```

#### Markdown Report (for documentation)
```bash
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --output markdown --file nextjs-report.md
```

### Method 5: Deep Analysis Mode

For more thorough analysis (slower but more accurate):

```bash
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --deep-analysis
```

### Method 6: Detailed Verbose Output

```bash
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --verbose
```

## Advanced Usage

### Scan with Multiple Options Combined

```bash
# Show only critical reachable vulnerabilities with detailed output
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --reachable-only --severity critical --verbose

# Deep analysis with HTML report
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\python-service" --deep-analysis --output html --file python-detailed.html
```

### Scan All Services and Generate Reports

Create a batch file `scan-all.bat`:

```batch
@echo off
cd C:\Users\cczin\appservice-scan

echo Scanning Next.js Frontend...
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --output html --file reports\nextjs.html

echo Scanning Python Service...
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\python-service" --output html --file reports\python.html

echo Scanning Java Backend...
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\java-backend" --output html --file reports\java.html

echo All scans complete! Check the reports folder.
```

Run it:
```bash
scan-all.bat
```

## Configuration File Approach

### 1. Create Configuration for Each Service

For Next.js:
```bash
cd C:\Users\cczin\dependency-bad\nextjs-frontend
C:\Users\cczin\appservice-scan\bin\depguard.js config
```

### 2. Edit .depguard.yml

Edit the generated `.depguard.yml` file:

```yaml
scan:
  depth: 10
  excludePaths:
    - node_modules/**
    - .next/**
    - out/**

reachability:
  minConfidence: 0.7
  trackDynamicCalls: true

reporting:
  onlyReachable: true
  minSeverity: medium
```

### 3. Run Scan (it will use the config)

```bash
cd C:\Users\cczin\dependency-bad\nextjs-frontend
C:\Users\cczin\appservice-scan\bin\depguard.js scan
```

## Understanding the Output

### Example Output Explained

```
╔════════════════════════════════════════════════════════════════╗
║ DepGuard Security Report                                       ║
╠════════════════════════════════════════════════════════════════╣
║ Total Dependencies: 150        ← Total packages found          ║
║ Vulnerabilities Found: 23      ← All CVEs in dependencies      ║
║ Reachable Vulnerabilities: 8   ← Actually exploitable!         ║
║ Critical: 2                    ← Need immediate action         ║
╚════════════════════════════════════════════════════════════════╝

[CRITICAL] 🔴 ⚠️  REACHABLE (95% confidence)  ← This is exploitable!
Package: lodash@4.17.20
Vulnerability: CVE-2021-23337
CVSS: 9.8 (Critical)
Description: Prototype Pollution in lodash

Reachable Path:  ← Shows HOW it's reached
  src/app.js:15 → express-middleware
  → node_modules/lodash/template.js:254 [VULNERABLE]

Recommendation: Update to lodash@4.17.21 or higher  ← Fix it!
```

### Interpreting Confidence Scores

- **90-100%**: Definitely reachable - **Fix immediately!**
- **70-89%**: Likely reachable - **Fix soon**
- **50-69%**: Possibly reachable - **Review and fix**
- **<50%**: Unlikely reachable - **Low priority**

## Common Workflows

### Daily Development
```bash
# Quick check before commit
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --reachable-only
```

### Pre-Release Check
```bash
# Comprehensive scan
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --deep-analysis --severity high
```

### Security Audit
```bash
# Full report with all details
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --deep-analysis --verbose --output html --file security-audit.html
```

### CI/CD Integration
```bash
# Generate SARIF for GitHub
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --output sarif --file report.sarif

# Exit with error if critical vulnerabilities found
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --reachable-only --severity critical
```

## Troubleshooting

### Issue: No files found

**Problem**: "Found 0 JavaScript files to analyze"

**Cause**: The scanner excludes `node_modules` and certain directories by default

**Solution**: Make sure there are actual source files (.js, .ts, .jsx, .tsx, .py, .java) in the project directory outside of node_modules

### Issue: No vulnerabilities found but expected some

**Problem**: Scan shows 0 vulnerabilities but you know there are vulnerable packages

**Cause**:
1. The sample vulnerability database only has data for specific packages (lodash, axios, express, jsonwebtoken)
2. The database needs to be connected to real vulnerability sources

**Solution**:
- For production use, implement real API calls to OSV, GitHub Advisory, etc.
- For now, test with packages that are in the sample data

### Issue: Scan is too slow

**Solution**: Exclude unnecessary directories
```bash
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend" --exclude "test/**,dist/**,build/**"
```

## Tips for Best Results

1. **Install Dependencies First**
   ```bash
   cd C:\Users\cczin\dependency-bad\nextjs-frontend
   npm install
   cd C:\Users\cczin\dependency-bad\python-service
   pip install -r requirements.txt
   ```

2. **Scan After Code Changes**
   ```bash
   # After adding new dependencies or updating code
   node bin\depguard.js scan --path "." --reachable-only
   ```

3. **Focus on Reachable**
   ```bash
   # Always use --reachable-only to reduce noise
   node bin\depguard.js scan --path "." --reachable-only
   ```

4. **Generate Reports Regularly**
   ```bash
   # Weekly security report
   node bin\depguard.js scan --path "." --output html --file weekly-$(date +%Y%m%d).html
   ```

## Quick Reference Commands

```bash
# Basic scan
node bin\depguard.js scan --path "C:\Users\cczin\dependency-bad\nextjs-frontend"

# Reachable only
node bin\depguard.js scan --path "." --reachable-only

# Critical only
node bin\depguard.js scan --path "." --severity critical

# HTML report
node bin\depguard.js scan --path "." --output html --file report.html

# JSON report
node bin\depguard.js scan --path "." --output json --file report.json

# SARIF report
node bin\depguard.js scan --path "." --output sarif --file report.sarif

# Deep analysis
node bin\depguard.js scan --path "." --deep-analysis

# Verbose output
node bin\depguard.js scan --path "." --verbose

# Combined
node bin\depguard.js scan --path "." --reachable-only --severity critical --output html --file critical.html
```

## Next Steps

1. **Review the scan results** for each service
2. **Update vulnerable packages** based on recommendations
3. **Set up regular scanning** in your development workflow
4. **Integrate with CI/CD** for automated security checks

For more information:
- Full documentation: `README.md`
- Quick start: `QUICKSTART.md`
- Architecture: `ARCHITECTURE.md`
