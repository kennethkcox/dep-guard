# DepGuard Examples

This directory contains examples and demos for DepGuard v2.0, showcasing advanced features including **Data Flow Analysis** and **Machine Learning Risk Prediction**.

## 📂 Contents

### 🎯 Interactive Demo (NEW!)
**Files:**
- `DEMO.md` - Complete walkthrough guide with data flow & ML features
- `run-demo.sh` - Automated demo script (Linux/Mac)
- `run-demo.bat` - Automated demo script (Windows)

The interactive demo walks you through:
1. Initial scan with data flow and ML analysis
2. Providing feedback on vulnerabilities
3. Training a personalized ML model
4. Re-scanning with trained model
5. Exporting feedback data

### 📦 Example Projects

| Example | Ecosystem | Language | Vulnerabilities | Features |
|---------|-----------|----------|-----------------|----------|
| [vulnerable-test-app](./vulnerable-test-app) | npm | JavaScript | 10 CVEs | Hard-to-detect patterns, data flow testing |
| [vulnerable-app](./vulnerable-app) | npm | JavaScript | 4 CVEs | Basic reachability examples |
| [vulnerable-dotnet-app](./vulnerable-dotnet-app) | NuGet | C# | 8 CVEs | Multi-ecosystem support |

---

## 🚀 Quick Start

### Option 1: Run the Interactive Demo (Recommended)

**Linux/Mac:**
```bash
cd examples
chmod +x run-demo.sh
./run-demo.sh
```

**Windows:**
```cmd
cd examples
run-demo.bat
```

The demo script will guide you through all features step by step.

### Option 2: Manual Exploration

Follow the detailed guide in `DEMO.md` or read it online.

---

## 📊 What's New in v2.0

### Data Flow Analysis
Track user input from sources to vulnerabilities:
```
🌊 Data Flow: TAINTED (95%)
   User input reaches this vulnerability!
   Sources: req.body (HTTP Request Body)
   Sanitizers: None detected
```

### Machine Learning Risk Prediction
Personalized risk scoring based on your feedback:
```
🎯 ML Risk Score: 92/100 (CRITICAL) [ML Model: trained ✓]

💡 Top Risk Factors:
   1. Known Exploitation (KEV) (+35 points)
   2. User Input Reaches Vulnerability (+20 points)
   3. Exploit Probability (EPSS: 0.92) (+23 points)
```

### Multi-Source Threat Intelligence
- OSV, NVD, GitHub Advisory databases
- EPSS (Exploit Prediction Scoring)
- CISA KEV (Known Exploited Vulnerabilities)

---

## 🧪 Vulnerable Test Application

The `vulnerable-test-app` directory contains:
- 10 vulnerable dependencies with known CVEs
- 10 hard-to-detect vulnerability patterns
- Realistic code structures (deep call chains, dynamic requires)
- Comprehensive documentation

**Scan it:**
```bash
cd examples/vulnerable-test-app
depguard scan --deep-analysis -v
```

---

## JavaScript/Node.js Example

The `vulnerable-app` directory contains a simple Express.js application with intentional security vulnerabilities.

### Vulnerabilities Present

1. **lodash@4.17.20** - CVE-2021-23337 (Prototype Pollution)
   - **REACHABLE** via `/render` endpoint

2. **axios@0.21.1** - CVE-2023-45857 (SSRF)
   - **REACHABLE** via `/fetch` endpoint

3. **jsonwebtoken@8.5.1** - CVE-2022-23529 (Signature Verification Bypass)
   - **REACHABLE** via `/verify` endpoint

4. **express@4.17.1** - CVE-2022-24999 (Open Redirect)
   - **NOT REACHABLE** (vulnerable function not used)

### Running the Demo

```bash
cd examples/vulnerable-app
depguard scan
```

---

## .NET/NuGet Example

The `vulnerable-dotnet-app` directory contains a .NET 6 web application with intentional security vulnerabilities.

### Vulnerabilities Present

1. **System.Text.Encodings.Web@4.5.0** - CVE-2021-26701 (RCE)
   - **REACHABLE** via `/encode` endpoint

2. **System.Text.Encodings.Web@4.7.1** - CVE-2022-29117 (DoS)
   - **REACHABLE** via `/encode` endpoint

3. **System.Security.Cryptography.Xml@4.7.0** - CVE-2022-34716 (Info Disclosure)
   - **NOT REACHABLE** (unused function)

4. **Microsoft.AspNetCore.Authentication.JwtBearer@3.1.0** - CVE-2021-34485
   - **NOT REACHABLE** (not configured)

5. **NuGet.Commands@5.9.0** - CVE-2022-41032 (Privilege Escalation)
   - **NOT REACHABLE** (not used)

6. **Newtonsoft.Json@11.0.2** - Deserialization vulnerabilities
   - **REACHABLE** via `/deserialize` endpoint

7. **log4net@2.0.8** - CVE-2018-1285 (XXE)
   - **REACHABLE** via `/log` endpoint

8. **SixLabors.ImageSharp@1.0.3** - CVE-2022-24741 (DoS)
   - **NOT REACHABLE** (not used)

### Running the Demo

```bash
cd examples/vulnerable-dotnet-app
depguard scan
```

---

## Testing Commands

### Scan both examples
```bash
# JavaScript
depguard scan -p examples/vulnerable-app

# .NET
depguard scan -p examples/vulnerable-dotnet-app
```

### Show only reachable vulnerabilities
```bash
depguard scan --reachable-only
```

### Generate reports
```bash
# HTML report
depguard scan -o html -f report.html

# JSON report
depguard scan -o json -f results.json

# SARIF for GitHub
depguard scan -o sarif -f depguard.sarif
```

---

## Learning Objectives

These examples demonstrate:

1. **Reachability Analysis** - Not all vulnerabilities are exploitable
2. **Multi-Ecosystem Support** - Same tool works for npm, NuGet, Maven, PyPI, etc.
3. **False Positive Reduction** - Focus on what actually matters
4. **Call Graph Analysis** - See exactly how vulnerable code is reached
