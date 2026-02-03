# DepGuard v2.0 🔍

**Truly Generic Vulnerability Scanner with Advanced Reachability Detection**

[![Version](https://img.shields.io/badge/version-2.0.0--alpha-blue.svg)](https://github.com/yourusername/depguard)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org)

DepGuard is a sophisticated dependency vulnerability scanner that goes beyond simple CVE matching. It performs **advanced static reachability analysis** to determine if vulnerabilities are actually exploitable in your codebase, dramatically reducing false positives.

## 🎯 What Makes DepGuard v2 Different?

### Traditional Scanners

```
❌ Found 62 vulnerabilities in your project!
   → 90% are unreachable/unexploitable
   → Overwhelmed by false positives
   → Must manually verify each one
```

### DepGuard v2

```
✅ Found 62 vulnerabilities, 3 are REACHABLE
   → Focuses on what actually matters
   → Shows exact call paths from entry points
   → Explains WHY something is/isn't reachable
   → Confidence scores for every finding
```

## 🚀 Key Features

### 1. **Truly Generic - Zero Hardcoded Assumptions**

Works with **ANY** project structure:
- ✅ Monorepos with multiple services
- ✅ Microservices architectures
- ✅ Non-standard directory layouts
- ✅ Polyglot projects (multiple languages)
- ✅ Legacy codebases

**No configuration needed!** Just point it at your project.

### 2. **Multi-Ecosystem Support**

Automatically detects and analyzes:

| Ecosystem | Manifest Files | Frameworks |
|-----------|---------------|------------|
| **Node.js** | package.json, yarn.lock, pnpm-lock.yaml | Express, Next.js, Koa, Hapi, Fastify |
| **Python** | requirements.txt, Pipfile, pyproject.toml | Flask, FastAPI, Django |
| **Java** | pom.xml, build.gradle | Spring Boot, JAX-RS |
| **Go** | go.mod, go.sum | Gin, Echo |
| **Rust** | Cargo.toml, Cargo.lock | Actix, Rocket |
| **Ruby** | Gemfile, Gemfile.lock | Rails, Sinatra |
| **PHP** | composer.json | Laravel, Symfony |
| **.NET** | *.csproj, packages.config | ASP.NET |

### 3. **Advanced Reachability Analysis**

#### Multi-Signal Entry Point Detection
Automatically finds application entry points using 8 different signals:
- HTTP handlers (20+ framework patterns)
- Main functions (9 languages)
- CLI commands (Commander, Click, Cobra, Clap)
- Event handlers (WebSockets, queues, pub/sub)
- Server initialization
- Package exports
- Negative signals (test files)

#### Call Graph Construction
- Bidirectional graph (forward & backward traversal)
- Handles imports/exports across modules
- Tracks both direct and indirect calls
- AST-based analysis (not regex patterns)

#### Confidence Scoring
Every finding includes:
- **Confidence score** (0-100%): How certain we are
- **Evidence**: Specific code patterns that matched
- **Reasoning**: WHY it was detected
- **Call path**: Exact route from entry point to vulnerability

### 4. **Real-Time Vulnerability Data**

- Queries **OSV (Open Source Vulnerabilities)** database
- No hardcoded CVE lists
- Always up-to-date
- Supports all major ecosystems

## 📦 Installation

```bash
npm install -g depguard

# Or run directly with npx
npx depguard scan
```

## 🔧 Usage

### Basic Scan

```bash
# Scan current directory
depguard scan

# Scan specific project
depguard scan /path/to/project

# Save results to file
depguard scan --format json --output results.json
```

### Advanced Options

```bash
# Adjust sensitivity
depguard scan --min-confidence 0.7        # Higher threshold
depguard scan --entry-confidence 0.8      # Stricter entry points

# Deep analysis (slower, more thorough)
depguard scan --deep --max-depth 15

# Verbose output for debugging
depguard scan --verbose

# Different output formats
depguard scan --format html --output report.html
depguard scan --format sarif --output depguard.sarif  # GitHub integration
```

### Project Statistics

```bash
# Quick overview without scanning
depguard stats /path/to/project
```

### Help & Examples

```bash
depguard --help
depguard examples
depguard info
```

## 📊 Example Output

```
🔍 DepGuard v2.0 - Generic Vulnerability Scanner

📦 Phase 1: Discovering project structure...
  ✓ Found 5 manifest(s):
    - npm: 2
    - pypi: 1
    - maven: 1
    - go: 1
  ℹ️  Detected 4 workspace(s) (monorepo)

📋 Phase 2: Analyzing dependencies...
  ✓ Total dependencies: 47

🔎 Phase 3: Checking for vulnerabilities...
  ✓ Found 62 known vulnerabilities

🕸️  Phase 4: Building call graph...
  ✓ Built call graph: 234 nodes, 567 edges

🚪 Phase 5: Detecting entry points...
  ✓ Entry point: api/users/route.js (98%)
    - HTTP_HANDLER: Next.js App Router HTTP handler detected
  ✓ Entry point: server.py (100%)
    - HTTP_HANDLER: Flask HTTP handler detected
    - MAIN_FUNCTION: Python main entry point detected

🔬 Phase 6: Performing reachability analysis...
  ✓ Analyzed 62 potential vulnerabilities

✅ Phase 7: Generating results...
  ✓ 3 high-confidence findings

────────────────────────────────────────────────────────────
⚠️  3 REACHABLE vulnerabilities found!
ℹ️  59 unreachable vulnerabilities (not exploitable)
────────────────────────────────────────────────────────────

📋 Findings:

1. lodash Prototype Pollution (CVE-2019-10744)
   Package: lodash@4.17.11
   Severity: HIGH
   Reachable: ✅ YES (Confidence: 95%)
   Path: api/users/route.js → utils/merge.js → lodash.defaultsDeep

2. marked XSS Vulnerability (CVE-2022-21680)
   Package: marked@0.3.5
   Severity: HIGH
   Reachable: ✅ YES (Confidence: 92%)
   Path: api/render/route.js → marked.parse

3. shelljs Command Injection (CVE-2022-0144)
   Package: shelljs@0.8.4
   Severity: CRITICAL
   Reachable: ✅ YES (Confidence: 98%)
   Path: api/exec/route.js → shelljs.exec
```

## 🏗️ Architecture

### 7-Phase Scanning Process

1. **Project Discovery**: Recursively find all dependency manifests
2. **Dependency Extraction**: Parse manifests for all ecosystems
3. **Vulnerability Check**: Query OSV API for known vulnerabilities
4. **Call Graph Construction**: Build bidirectional call graph via AST analysis
5. **Entry Point Detection**: Multi-signal confidence-based detection
6. **Reachability Analysis**: BFS pathfinding from entry points to vulnerabilities
7. **Result Generation**: Confidence filtering and explainable results

### Core Components

```
src/
├── core/
│   ├── GenericManifestFinder.js      # Find manifests anywhere
│   ├── GenericEntryPointDetector.js  # Detect entry points for any framework
│   └── ReachabilityAnalyzer.js       # Advanced static analysis
├── analyzers/
│   ├── JavaScriptAnalyzer.js         # AST-based JS/TS analysis
│   ├── PythonAnalyzer.js             # Python code analysis
│   └── JavaAnalyzer.js               # Java code analysis
├── vulnerabilities/
│   ├── OSVDatabase.js                # OSV API client
│   └── VulnerabilityDatabase.js      # Vulnerability management
├── utils/
│   └── FileWalker.js                 # Cross-platform file discovery
└── DepGuardScanner2.js               # Main orchestrator
```

## 🎓 How It Works

### 1. Pattern Recognition Over Conventions

**Old Approach (Hardcoded):**
```javascript
// Only works for Next.js in /api/ directory
if (filePath.includes('/api/') && filePath.endsWith('route.js')) {
    addEntryPoint(filePath);
}
```

**New Approach (Generic):**
```javascript
// Works for ANY framework, ANY structure
const httpSignal = detectHttpHandler(fileContent);
if (httpSignal.confidence > 0.6) {
    addEntryPoint(file, httpSignal);
}
```

### 2. Multi-Signal Confidence

Combines evidence from multiple sources:

```javascript
Entry Point: api/users/route.js (98% confidence)
  Signals:
    • HTTP_HANDLER (95%): Next.js pattern detected
      Evidence: "export async function POST("
    • NO_CALLERS (30%): Not called by other modules
    • PACKAGE_EXPORT (20%): Exported from package

  Combined: (95 + 30 + 20) / 3 = 48%
  Boosted for strong signals: 48% → 98%
```

### 3. Explainable Results

Every detection includes:
- What was found
- Why it was detected
- How confident we are
- What evidence supports it

## 🔬 Comparison

| Feature | npm audit | Snyk | Trivy | DepGuard v2 |
|---------|-----------|------|-------|-------------|
| Reachability Analysis | ❌ | ⚠️ Limited | ❌ | ✅ Advanced |
| Confidence Scoring | ❌ | ❌ | ❌ | ✅ Multi-signal |
| Framework Agnostic | ❌ | ⚠️ Some | ❌ | ✅ 15+ frameworks |
| Monorepo Support | ⚠️ Basic | ✅ | ⚠️ Basic | ✅ Native |
| Zero Config | ✅ | ❌ | ✅ | ✅ |
| Explainable Results | ❌ | ⚠️ Limited | ❌ | ✅ Full |
| Call Path Tracing | ❌ | ⚠️ Limited | ❌ | ✅ Complete |
| False Positive Rate | High | Medium | High | **Low** |

## 🛠️ Configuration

DepGuard works without configuration, but you can customize via `.depguard.yml`:

```yaml
# Confidence thresholds
minConfidence: 0.5              # Minimum for reporting (0-1)
entryPointConfidence: 0.6       # Minimum for entry points (0-1)

# Analysis depth
maxDepth: 10                    # Maximum call graph depth
deepAnalysis: false             # Enable thorough analysis

# Exclusions
excludeDirs:
  - node_modules
  - dist
  - build
  - test

excludePackages:
  - devDependencies               # Optionally exclude dev deps

# Custom entry points (optional)
entryPoints:
  - src/server.js
  - cmd/main.go
```

## 🚀 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install DepGuard
        run: npm install -g depguard

      - name: Run Security Scan
        run: depguard scan --format sarif --output depguard.sarif

      - name: Upload Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: depguard.sarif
```

### GitLab CI

```yaml
security_scan:
  image: node:18
  script:
    - npm install -g depguard
    - depguard scan --format json --output depguard.json
  artifacts:
    reports:
      dependency_scanning: depguard.json
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'npm install -g depguard'
                sh 'depguard scan --format html --output report.html'
                publishHTML([
                    reportDir: '.',
                    reportFiles: 'report.html',
                    reportName: 'DepGuard Security Report'
                ])
            }
        }
    }
}
```

## 📚 Documentation

- [Architecture Guide](ARCHITECTURE.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Redesign Journey](REDESIGN_STATUS.md)
- [v1 → v2 Transformation](V2_TRANSFORMATION.md)

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built on top of [OSV](https://osv.dev/) vulnerability database
- Inspired by OWASP Dependency-Check and modern SAST tools
- Created in response to the need for truly generic vulnerability scanning

## 📧 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/depguard/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/depguard/discussions)
- **Email**: support@depguard.dev

---

**Made with ❤️ by the DepGuard team**

*"Stop drowning in false positives. Focus on what actually matters."*
