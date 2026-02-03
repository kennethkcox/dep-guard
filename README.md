# DepGuard

**Advanced Dependency Vulnerability Scanner with Reachability Analysis**

[![Tests](https://img.shields.io/badge/tests-43%20passing-brightgreen)](#testing)
[![Node.js](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

DepGuard goes beyond traditional vulnerability scanners by determining if vulnerabilities are actually **reachable** from your application's entry points. This dramatically reduces false positives and helps you focus on the vulnerabilities that truly matter.

## Why DepGuard?

Traditional dependency scanners flag every known vulnerability, but many are not exploitable because the vulnerable code paths are never executed. DepGuard uses **static analysis** to trace code execution from entry points to vulnerable functions, giving you confidence scores that indicate real risk.

```
Traditional Scanner: "lodash has 5 vulnerabilities!"
DepGuard:            "lodash has 5 vulnerabilities, but only 1 is reachable (95% confidence)"
```

## Features

### Reachability Analysis
- **Call Graph Construction** - Maps all function calls in your codebase
- **Entry Point Detection** - Automatically identifies HTTP handlers, CLI commands, main functions, and event handlers
- **Path Tracing** - Finds execution paths from entry points to vulnerable code
- **Confidence Scoring** - Assigns 0-100% confidence based on analysis certainty

### Multi-Language Support
| Language | Package Managers | Frameworks |
|----------|-----------------|------------|
| JavaScript/TypeScript | npm, yarn, pnpm | Express, Next.js, Koa, Hapi, Fastify |
| Python | pip, poetry, pipenv | Flask, FastAPI, Django |
| Java | Maven, Gradle | Spring Boot, JAX-RS |
| Go | go modules | Gin, Echo |
| Rust | Cargo | - |
| Ruby | Bundler | - |
| PHP | Composer | - |

### Production-Ready
- **Security Hardened** - Path traversal protection, XSS prevention, cache integrity (HMAC)
- **Structured Logging** - JSON and text formats with component-level filtering
- **Performance Optimized** - O(n) deduplication, efficient caching, configurable depth
- **Error Handling** - Custom error classes with context and graceful recovery

## Installation

```bash
npm install -g depguard
```

Or run directly with npx:
```bash
npx depguard scan
```

## Quick Start

```bash
# Scan current directory
depguard scan

# Scan a specific project
depguard scan /path/to/project

# Deep analysis (slower, more thorough)
depguard scan --deep

# Output as JSON
depguard scan --format json --output results.json

# Generate HTML report
depguard scan --format html --output report.html
```

## Example Output

```
============================================================
DepGuard v2.0 - Generic Vulnerability Scanner
============================================================

Phase 1: Discovering project structure...
  Found 3 manifest(s):
    - npm: 2
    - pypi: 1

Phase 2: Analyzing dependencies...
  Total dependencies: 247 (45 direct, 202 transitive)

Phase 3: Checking for vulnerabilities...
  Found 12 known vulnerabilities

Phase 4: Building call graph...
  Built call graph: 1,847 nodes, 4,293 edges

Phase 5: Detecting entry points...
  Detected 8 entry points

Phase 6: Performing reachability analysis...
  Analyzed 12 potential vulnerabilities

Phase 7: Generating results...
  3 high-confidence findings

============================================================

REACHABLE VULNERABILITIES:

[CRITICAL] CVE-2021-23337 - Prototype Pollution in lodash
  Package: lodash@4.17.20
  Confidence: 95%
  Path: src/api/handler.js:42 -> utils/transform.js:18 -> lodash.template()
  Fix: Upgrade to lodash@4.17.21

[HIGH] CVE-2022-25883 - ReDoS in semver
  Package: semver@7.3.5
  Confidence: 78%
  Path: src/cli/version.js:15 -> semver.satisfies()
  Fix: Upgrade to semver@7.5.2

UNREACHABLE (not exploitable):
  9 vulnerabilities found but not reachable from entry points
```

## CLI Options

```
Usage: depguard scan [options] [path]

Options:
  -f, --format <type>         Output format: table, json, html, sarif, markdown (default: table)
  -o, --output <file>         Save report to file
  --min-confidence <number>   Minimum confidence threshold 0-1 (default: 0.5)
  --entry-confidence <number> Entry point detection confidence (default: 0.6)
  --max-depth <number>        Maximum call graph depth (default: 10)
  --deep                      Enable deep analysis mode
  --verbose                   Verbose output
  --no-color                  Disable colored output
```

## Configuration

Create a `.depguard.yml` file in your project root:

```yaml
scan:
  depth: 10
  excludePaths:
    - test/**
    - build/**
    - dist/**

reachability:
  analysisDepth: 10
  minConfidence: 0.5
  trackDynamicCalls: true
  includeIndirectPaths: true

reporting:
  format: table
  verbosity: normal
  onlyReachable: false
```

## Testing

DepGuard maintains comprehensive test coverage across its core components:

```bash
npm test
```

```
Test Suites: 3 passed, 3 total
Tests:       43 passed, 43 total

Test Coverage:
  - ReachabilityAnalyzer: 24 tests (path finding, confidence scoring, cycle detection)
  - VulnerabilityDatabase: 14 tests (API queries, caching, integrity verification)
  - DepGuardScanner: 5 tests (scanning, statistics, reporting)
```

### Test Categories

| Component | Tests | Coverage |
|-----------|-------|----------|
| ReachabilityAnalyzer | 24 | Call graphs, BFS path finding, confidence calculation |
| VulnerabilityDatabase | 14 | OSV API integration, HMAC cache integrity, version matching |
| DepGuardScanner | 5 | End-to-end scanning, multi-ecosystem support |

## How It Works

1. **Discovery** - Finds all dependency manifests (package.json, pom.xml, requirements.txt, etc.)
2. **Analysis** - Extracts direct and transitive dependencies
3. **Vulnerability Lookup** - Queries the OSV (Open Source Vulnerabilities) database
4. **Call Graph** - Parses source code to build function call relationships
5. **Entry Points** - Detects HTTP handlers, CLI commands, main functions, event handlers
6. **Reachability** - Uses BFS to find paths from entry points to vulnerable functions
7. **Scoring** - Calculates confidence based on path length, call types, and analysis certainty

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run DepGuard
  run: |
    npx depguard scan --format sarif --output depguard.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: depguard.sarif
```

### Exit Codes

- `0` - No reachable vulnerabilities found
- `1` - Reachable vulnerabilities detected (or scan error)

## Architecture

```
┌─────────────────────────────────────────────┐
│              CLI Interface                   │
│           (bin/depguard.js)                 │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│          DepGuardScanner                     │
│       (7-Phase Orchestration)               │
└─────┬───────────┬───────────┬───────────────┘
      │           │           │
┌─────▼────┐ ┌───▼────┐ ┌────▼─────┐
│ Language │ │  Vuln  │ │Reachabi- │
│ Analyzers│ │Database│ │lity      │
│  (3)     │ │ (OSV)  │ │Analyzer  │
└──────────┘ └────────┘ └──────────┘
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed design documentation.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for version history.

## License

Apache-2.0 - see [LICENSE](./LICENSE) for details.

---

**DepGuard** - Know which vulnerabilities actually matter.
