# DepGuard Examples

This directory contains example projects to demonstrate DepGuard's capabilities across multiple ecosystems.

## Available Examples

| Example | Ecosystem | Language | Vulnerabilities |
|---------|-----------|----------|-----------------|
| [vulnerable-app](./vulnerable-app) | npm | JavaScript | 4 CVEs |
| [vulnerable-dotnet-app](./vulnerable-dotnet-app) | NuGet | C# | 8 CVEs |

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
