# DepGuard

Advanced dependency vulnerability scanner with sophisticated reachability analysis capabilities.

## Features

### Advanced Reachability Detection
- **Static Call Graph Analysis**: Constructs complete call graphs for your application
- **Multi-level Depth Analysis**: Traces vulnerable code paths through multiple layers
- **Dead Code Detection**: Identifies imported but unused vulnerable dependencies
- **Transitive Reachability**: Analyzes indirect calls through multiple dependencies
- **Control Flow Awareness**: Understands conditional execution and branching

### Vulnerability Detection
- **CVE Database Integration**: Checks against known vulnerabilities
- **CVSS Scoring**: Prioritizes findings by severity
- **Exploit Maturity Tracking**: Identifies actively exploited vulnerabilities
- **Zero-day Awareness**: Flags suspicious patterns even without CVE

### Multi-Language Support
- JavaScript/TypeScript (Node.js)
- Java (Maven/Gradle)
- Python (pip/poetry)

### Smart Reporting
- **Reachability Scores**: 0-100 score indicating likelihood of exploitation
- **Call Path Visualization**: Shows exact code paths to vulnerable functions
- **Fix Recommendations**: Suggests patches and workarounds
- **False Positive Reduction**: Only reports truly reachable vulnerabilities

## Installation

```bash
npm install -g depguard
```

## Usage

```bash
# Scan current project
depguard scan

# Scan with detailed reachability analysis
depguard scan --deep-analysis

# Generate JSON report
depguard scan --output json > report.json

# Show only critical reachable vulnerabilities
depguard scan --severity critical --reachable-only
```

## Configuration

Create a `.depguard.yml` file in your project root:

```yaml
scan:
  depth: 5
  includeDevDependencies: false
  excludePaths:
    - test/**
    - build/**

reachability:
  analysisDepth: 10
  minConfidence: 0.7
  trackDynamicCalls: true

reporting:
  format: table
  verbosity: detailed
  onlyReachable: true
```

## How Reachability Works

DepGuard uses advanced static analysis to determine if vulnerable code is actually reachable from your application:

1. **Dependency Graph Construction**: Maps all dependencies and their relationships
2. **Entry Point Identification**: Finds all application entry points (main, exports, etc.)
3. **Call Graph Building**: Traces function calls throughout the codebase
4. **Vulnerability Mapping**: Identifies which functions in dependencies contain vulnerabilities
5. **Path Analysis**: Determines if there's a code path from your entry points to vulnerable functions
6. **Confidence Scoring**: Assigns probability scores based on analysis certainty

## Example Output

```
╔════════════════════════════════════════════════════════════════╗
║ DepGuard Security Report                                       ║
╠════════════════════════════════════════════════════════════════╣
║ Total Dependencies: 247                                        ║
║ Vulnerabilities Found: 12                                      ║
║ Reachable Vulnerabilities: 3                                   ║
╚════════════════════════════════════════════════════════════════╝

[CRITICAL] ⚠️  REACHABLE (95% confidence)
Package: lodash@4.17.20
Vulnerability: CVE-2021-23337
CVSS: 9.8 (Critical)
Description: Prototype Pollution in lodash

Reachable Path:
  src/app.js:15 → express-middleware
  → node_modules/body-parser/lib/types/json.js:89
  → node_modules/lodash/template.js:254 [VULNERABLE]

Recommendation: Update to lodash@4.17.21 or higher
```

## License

Apache-2.0
