# DepGuard Architecture

This document describes the architecture and design decisions of DepGuard.

## Overview

DepGuard is designed as a modular, extensible dependency vulnerability scanner with a focus on reachability analysis. The architecture separates concerns into distinct layers:

```
┌─────────────────────────────────────────────┐
│              CLI Interface                   │
│         (bin/depguard.js)                   │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│          DepGuardScanner                     │
│     (Main Orchestration Layer)              │
└─────────┬───────────┬───────────┬───────────┘
          │           │           │
    ┌─────▼────┐ ┌───▼────┐ ┌───▼─────┐
    │Language  │ │  Vuln  │ │Reachabi-│
    │Analyzers │ │Database│ │lity     │
    └──────────┘ └────────┘ └─────────┘
```

## Core Components

### 1. ReachabilityAnalyzer (`src/core/ReachabilityAnalyzer.js`)

The heart of DepGuard. Performs sophisticated static analysis to determine if vulnerable code is reachable.

**Key Features:**
- Call graph construction (forward and reverse)
- BFS-based path finding
- Confidence scoring
- Cycle detection
- Multiple analysis strategies (forward, backward, hybrid)

**Algorithm:**
1. Build bidirectional call graph from application code
2. Mark entry points (main, exports, etc.)
3. For each vulnerability, find paths from entry points to vulnerable function
4. Calculate confidence scores based on path characteristics
5. Return reachability verdict with confidence level

**Complexity:**
- Space: O(N + E) where N = nodes, E = edges
- Time: O(N + E) per vulnerability for BFS

### 2. Language Analyzers

Each language has a dedicated analyzer that understands its semantics:

#### JavaScriptAnalyzer (`src/analyzers/JavaScriptAnalyzer.js`)
- Uses Babel parser for accurate AST parsing
- Handles ES6+ features, JSX, TypeScript
- Tracks imports (ES6, CommonJS, dynamic)
- Identifies exports and entry points
- Traces function and method calls

#### PythonAnalyzer (`src/analyzers/PythonAnalyzer.js`)
- Regex-based parsing (upgradeable to Python AST)
- Handles import variations (import, from...import)
- Detects __main__ blocks
- Tracks function definitions and calls

#### JavaAnalyzer (`src/analyzers/JavaAnalyzer.js`)
- Regex-based parsing (upgradeable to JavaParser)
- Handles imports and static imports
- Tracks class hierarchies
- Identifies static and instance method calls

**Design Decision:** Language analyzers are pluggable. New languages can be added without modifying core logic.

### 3. VulnerabilityDatabase (`src/vulnerabilities/VulnerabilityDatabase.js`)

Manages vulnerability data from multiple sources:

**Data Sources:**
- OSV (Open Source Vulnerabilities)
- GitHub Advisory Database
- NVD (National Vulnerability Database)
- Snyk (optional, with API key)

**Features:**
- Caching for performance
- Version matching
- CVSS scoring
- Exploit maturity tracking
- Function-level vulnerability mapping

**Cache Strategy:**
- 24-hour TTL
- Per-package versioned cache
- Automatic invalidation

### 4. Reporter (`src/reporting/Reporter.js`)

Generates reports in multiple formats:

**Formats:**
- **Table**: Human-readable CLI output with colors
- **JSON**: Machine-readable, CI/CD integration
- **HTML**: Interactive web report
- **SARIF**: GitHub Code Scanning integration
- **Markdown**: Documentation-friendly

**Design Decision:** Report generation is separated from analysis, allowing custom formatters.

## Data Flow

1. **Initialization**
   - Parse CLI arguments
   - Load configuration
   - Initialize components

2. **Dependency Discovery**
   - Detect project type
   - Parse manifest files (package.json, pom.xml, etc.)
   - Extract dependency list

3. **Vulnerability Lookup**
   - Query vulnerability databases
   - Cache results
   - Map vulnerabilities to specific functions

4. **Call Graph Construction**
   - Parse all source files
   - Build call relationships
   - Identify entry points

5. **Reachability Analysis**
   - For each vulnerability:
     - Find paths from entry points
     - Calculate confidence
     - Assign reachability verdict

6. **Reporting**
   - Filter results
   - Format output
   - Generate report

## Key Design Decisions

### 1. Why Bidirectional Call Graphs?

Forward analysis (from entry points) is fast but can miss reachable code due to analysis limitations. Backward analysis (from vulnerabilities) provides additional coverage. Using both increases accuracy.

### 2. Why Confidence Scores?

Static analysis is inherently imprecise. Confidence scores help users prioritize:
- 90-100%: Definitely reachable
- 70-89%: Likely reachable
- 50-69%: Possibly reachable
- <50%: Unlikely reachable

### 3. Why Function-Level Mapping?

Package-level vulnerability detection (like npm audit) has high false positive rates. Function-level mapping drastically reduces false positives by identifying exactly which vulnerable functions are called.

### 4. Why Multiple Report Formats?

Different use cases require different formats:
- Developers: Table format
- CI/CD: JSON/SARIF
- Security teams: HTML
- Documentation: Markdown

## Performance Considerations

### Scalability

- **Small projects (<100 files)**: <10 seconds
- **Medium projects (100-1000 files)**: <60 seconds
- **Large projects (>1000 files)**: <5 minutes

### Optimizations

1. **Parallel file parsing**: Analyze multiple files concurrently
2. **Caching**: Cache vulnerability lookups and analysis results
3. **Pruning**: Skip test/build directories
4. **Incremental analysis**: Only re-analyze changed files (future)

### Memory Usage

- Call graph: ~100KB per 1000 nodes
- Vulnerability data: ~1KB per vulnerability
- AST parsing: ~50KB per file (transient)

## Extension Points

### Adding New Analyzers

```javascript
class MyLanguageAnalyzer {
  constructor(reachabilityAnalyzer, options) {
    this.reachabilityAnalyzer = reachabilityAnalyzer;
  }

  analyzeFile(filePath) {
    // Parse file, extract calls
    this.reachabilityAnalyzer.addCall(from, to);
  }

  analyzeProject(projectDir) {
    // Find and analyze all files
  }
}
```

### Adding New Vulnerability Sources

```javascript
async fetchFromCustomSource(packageName, version) {
  const response = await fetch(`https://api.example.com/vulns/${packageName}`);
  return this.processVulnerabilities(await response.json());
}
```

### Custom Report Formats

```javascript
generateCustomFormat(results, metadata) {
  // Transform results into your format
  return formattedOutput;
}
```

## Testing Strategy

### Unit Tests
- Individual component testing
- Mock external dependencies
- Test edge cases

### Integration Tests
- End-to-end scanning
- Real project analysis
- Cross-component interaction

### Regression Tests
- Known vulnerability detection
- False positive prevention
- Performance benchmarks

## Future Enhancements

1. **Dynamic Analysis Integration**: Runtime tracing
2. **Machine Learning**: Improve confidence scoring
3. **IDE Integration**: Real-time analysis
4. **Incremental Analysis**: Only analyze changes
5. **Cloud Backend**: Centralized vulnerability database
6. **Auto-fix**: Automated patching suggestions

## Security Considerations

- Sandboxed parsing (no code execution)
- Read-only file access
- Rate limiting for API calls
- Secure cache storage
- No sensitive data in reports

## License

Apache-2.0
