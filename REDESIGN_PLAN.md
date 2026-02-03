# DepGuard Redesign: Truly Generic Vulnerability Scanner

## Problem Statement

**Current Issues**:
1. ❌ Assumes Next.js structure (`app/api/*/route.js`)
2. ❌ Hardcoded entry point patterns
3. ❌ Limited to simple import tracking
4. ❌ No reflection/obfuscation handling
5. ❌ Framework-specific assumptions

**Goal**: Build a scanner that works with:
- ✅ ANY framework (Next.js, Express, Flask, Spring Boot, Gin, etc.)
- ✅ ANY project structure (monorepo, microservices, flat, nested)
- ✅ ANY language patterns (reflection, dynamic loading, conditionals)
- ✅ ANY vulnerability (not just web vulnerabilities)

---

## Core Principles

### 1. Zero Assumptions
- Don't assume API routes are in `/api/`
- Don't assume main is called `main()`
- Don't assume imports are at top of file
- Don't assume packages have vulnerabilities

### 2. Heuristic-Based Detection
- Learn patterns from code structure
- Detect entry points by characteristics, not location
- Build call graph from actual usage, not conventions

### 3. Confidence-Based Reporting
- Every finding has a confidence score (0-100%)
- Unclear patterns get lower confidence
- Multiple signals increase confidence

### 4. Extensible Architecture
- Plugin system for new languages
- Plugin system for vulnerability sources
- Plugin system for frameworks

---

## Redesigned Architecture

```
┌─────────────────────────────────────────────────────┐
│              DepGuard Core Engine                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌────────────────────────────────────────────┐   │
│  │  1. Discovery Phase (Generic)              │   │
│  │  • Find all source files (any structure)   │   │
│  │  • Detect project type (heuristics)        │   │
│  │  • Find manifest files (any name/location) │   │
│  │  • Extract dependencies (any format)       │   │
│  └────────────────────────────────────────────┘   │
│                                                     │
│  ┌────────────────────────────────────────────┐   │
│  │  2. Analysis Phase (Language-Specific)     │   │
│  │  • Parse source files (AST)                │   │
│  │  • Extract all calls (including dynamic)   │   │
│  │  • Track data flow (reflection, strings)   │   │
│  │  • Build complete call graph               │   │
│  └────────────────────────────────────────────┘   │
│                                                     │
│  ┌────────────────────────────────────────────┐   │
│  │  3. Entry Point Detection (Heuristic)      │   │
│  │  • HTTP handlers (any framework)           │   │
│  │  • Main functions (any name)               │   │
│  │  • Exported functions (any pattern)        │   │
│  │  • CLI commands (any structure)            │   │
│  │  • Message handlers (queues, events)       │   │
│  └────────────────────────────────────────────┘   │
│                                                     │
│  ┌────────────────────────────────────────────┐   │
│  │  4. Vulnerability Query (Multi-Source)     │   │
│  │  • OSV API (primary)                       │   │
│  │  • GitHub Advisory (secondary)             │   │
│  │  • NVD (tertiary)                          │   │
│  │  • Custom sources (plugins)                │   │
│  └────────────────────────────────────────────┘   │
│                                                     │
│  ┌────────────────────────────────────────────┐   │
│  │  5. Reachability Analysis (Advanced)       │   │
│  │  • Path finding (BFS with weights)         │   │
│  │  • Confidence scoring (multi-factor)       │   │
│  │  • Conditional analysis (if/switch)        │   │
│  │  • Reflection tracking (dynamic calls)     │   │
│  │  • Dead code detection (unreached)         │   │
│  └────────────────────────────────────────────┘   │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## Key Components to Rewrite

### 1. Generic Entry Point Detector

**Current** (Too Specific):
```javascript
if (filePath.includes('/api/') && filePath.endsWith('route.js')) {
  addEntryPoint(filePath);  // Only works for Next.js!
}
```

**New** (Generic):
```javascript
class EntryPointDetector {
  detectEntryPoints(files, callGraph) {
    const entryPoints = [];

    files.forEach(file => {
      const signals = [];

      // Signal 1: HTTP handler patterns
      if (this.hasHttpHandlerSignature(file)) {
        signals.push({ type: 'HTTP_HANDLER', confidence: 0.9 });
      }

      // Signal 2: Exported from package entry
      if (this.isExportedFromMain(file, callGraph)) {
        signals.push({ type: 'PUBLIC_API', confidence: 0.8 });
      }

      // Signal 3: Main function
      if (this.hasMainFunction(file)) {
        signals.push({ type: 'MAIN_FUNCTION', confidence: 1.0 });
      }

      // Signal 4: CLI command registration
      if (this.hasCommandRegistration(file)) {
        signals.push({ type: 'CLI_COMMAND', confidence: 0.9 });
      }

      // Signal 5: Event/message handler
      if (this.hasEventHandler(file)) {
        signals.push({ type: 'EVENT_HANDLER', confidence: 0.7 });
      }

      // Signal 6: No incoming calls (might be entry)
      if (callGraph.getIncomingCalls(file).length === 0) {
        signals.push({ type: 'NO_CALLERS', confidence: 0.5 });
      }

      if (signals.length > 0) {
        const confidence = this.calculateConfidence(signals);
        if (confidence > 0.6) {
          entryPoints.push({ file, signals, confidence });
        }
      }
    });

    return entryPoints;
  }

  hasHttpHandlerSignature(file) {
    const patterns = [
      // Express
      /app\.(get|post|put|delete|patch)\(/,
      /router\.(get|post|put|delete|patch)\(/,

      // Next.js
      /export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)/,

      // Flask
      /@app\.route\(/,
      /@blueprint\.route\(/,

      // Spring Boot
      /@(Get|Post|Put|Delete|Patch)Mapping/,
      /@RequestMapping/,

      // Gin (Go)
      /router\.(GET|POST|PUT|DELETE|PATCH)\(/,

      // FastAPI
      /@app\.(get|post|put|delete|patch)\(/,

      // Generic
      /function\s+handle(Request|Get|Post)/i,
      /def\s+handle_(request|get|post)/i
    ];

    const content = fs.readFileSync(file, 'utf-8');
    return patterns.some(pattern => pattern.test(content));
  }

  hasMainFunction(file) {
    const content = fs.readFileSync(file, 'utf-8');

    const patterns = [
      // JavaScript/TypeScript
      /if\s*\(\s*require\.main\s*===\s*module\s*\)/,

      // Python
      /if\s+__name__\s*==\s*['"]__main__['"]/,

      // Java
      /public\s+static\s+void\s+main\s*\(/,

      // Go
      /func\s+main\s*\(\s*\)/,

      // Rust
      /fn\s+main\s*\(\s*\)/
    ];

    return patterns.some(pattern => pattern.test(content));
  }

  hasCommandRegistration(file) {
    const content = fs.readFileSync(file, 'utf-8');

    const patterns = [
      // Commander.js
      /program\.(command|action)\(/,

      // Click (Python)
      /@click\.(command|group)\(/,

      // Cobra (Go)
      /cmd\.AddCommand\(/,

      // Clap (Rust)
      /Command::new\(/
    ];

    return patterns.some(pattern => pattern.test(content));
  }

  hasEventHandler(file) {
    const content = fs.readFileSync(file, 'utf-8');

    const patterns = [
      // Node.js EventEmitter
      /\.on\(['"`][\w-]+['"`]/,

      // Message queues
      /\.subscribe\(/,
      /\.consume\(/,
      /@RabbitListener/,
      /@KafkaListener/,

      // WebSockets
      /\.onmessage\s*=/,
      /ws\.on\(['"`]message['"`]/
    ];

    return patterns.some(pattern => pattern.test(content));
  }

  isExportedFromMain(file, callGraph) {
    // Check if this file/function is exported from package entry point
    const packageEntry = this.findPackageEntry();
    if (!packageEntry) return false;

    return callGraph.isReachableFrom(packageEntry, file);
  }
}
```

---

### 2. Enhanced Reflection Tracker

**New Feature**: Track dynamic calls and obfuscation

```javascript
class ReflectionTracker {
  constructor() {
    this.stringConstants = new Map();
    this.dynamicCalls = [];
  }

  trackReflection(ast, filePath) {
    traverse(ast, {
      // Track string constants (might be class names)
      StringLiteral: (path) => {
        const value = path.node.value;
        this.stringConstants.set(value, {
          file: filePath,
          line: path.node.loc.start.line,
          context: this.getContext(path)
        });
      },

      // Track Base64 strings (obfuscation)
      CallExpression: (path) => {
        if (this.isBase64Decode(path.node)) {
          const encoded = this.extractArgument(path.node);
          const decoded = Buffer.from(encoded, 'base64').toString();

          this.stringConstants.set(decoded, {
            file: filePath,
            line: path.node.loc.start.line,
            obfuscated: true,
            original: encoded
          });
        }

        // Track Class.forName (Java via similar pattern)
        if (this.isReflectiveCall(path.node)) {
          this.dynamicCalls.push({
            file: filePath,
            line: path.node.loc.start.line,
            type: 'reflection',
            target: this.resolveTarget(path.node),
            confidence: 0.7
          });
        }
      }
    });
  }

  isBase64Decode(node) {
    // JavaScript
    if (node.callee?.property?.name === 'decode' &&
        node.callee?.object?.property?.name === 'base64') {
      return true;
    }

    // Python: base64.b64decode
    if (node.func?.attr === 'b64decode') {
      return true;
    }

    // Java: Base64.getDecoder().decode()
    if (node.name?.includes('decode') &&
        this.hasBase64Context(node)) {
      return true;
    }

    return false;
  }

  isReflectiveCall(node) {
    const reflectionPatterns = [
      // Java
      'forName',
      'getDeclaredMethod',
      'invoke',

      // JavaScript
      'eval',
      'Function',
      'require',

      // Python
      '__import__',
      'getattr',
      'exec'
    ];

    const methodName = node.callee?.property?.name ||
                      node.callee?.name ||
                      node.func?.attr;

    return reflectionPatterns.includes(methodName);
  }

  resolveTarget(node) {
    // Try to resolve what's being called
    const arg = this.extractArgument(node);

    // Check if it's a known string constant
    if (this.stringConstants.has(arg)) {
      const info = this.stringConstants.get(arg);
      if (info.obfuscated) {
        return {
          target: arg,
          obfuscated: true,
          original: info.original,
          confidence: 0.6
        };
      }
      return { target: arg, confidence: 0.8 };
    }

    // Try to resolve from data flow
    const dataFlowTarget = this.dataFlowAnalysis(node);
    if (dataFlowTarget) {
      return { target: dataFlowTarget, confidence: 0.7 };
    }

    return { target: 'unknown', confidence: 0.3 };
  }
}
```

---

### 3. Conditional Reachability Analyzer

**New Feature**: Handle if/switch statements

```javascript
class ConditionalAnalyzer {
  analyzeConditional(ifStatement, callGraph) {
    const condition = this.extractCondition(ifStatement);

    const conditionType = this.classifyCondition(condition);

    switch (conditionType.type) {
      case 'STATIC':
        // Can be resolved at analysis time
        return {
          reachable: conditionType.value,
          confidence: 1.0,
          reason: 'Static condition resolved'
        };

      case 'ENVIRONMENT':
        // Depends on env var, config
        return {
          reachable: 'CONDITIONAL',
          confidence: 0.5,
          reason: `Depends on ${conditionType.variable}`,
          assumption: 'Assume worst case (condition might be true)'
        };

      case 'RUNTIME':
        // Depends on user input, request data
        return {
          reachable: 'CONDITIONAL',
          confidence: 0.6,
          reason: 'Depends on runtime data',
          assumption: 'Assume reachable (user-controlled)'
        };

      case 'FEATURE_FLAG':
        // Feature flag system
        return {
          reachable: 'CONDITIONAL',
          confidence: 0.7,
          reason: `Feature flag: ${conditionType.flag}`,
          assumption: 'Assume enabled'
        };

      default:
        return {
          reachable: 'UNKNOWN',
          confidence: 0.4,
          reason: 'Complex condition'
        };
    }
  }

  classifyCondition(condition) {
    // Static: if (true), if (false), if (NODE_ENV === "production")
    if (this.isStaticValue(condition)) {
      return { type: 'STATIC', value: this.evaluateStatic(condition) };
    }

    // Environment: if (process.env.X), if (System.getenv("X"))
    if (this.isEnvironmentCheck(condition)) {
      return {
        type: 'ENVIRONMENT',
        variable: this.extractEnvVar(condition)
      };
    }

    // Runtime: if (req.query.x), if (user.isAdmin)
    if (this.isRuntimeData(condition)) {
      return {
        type: 'RUNTIME',
        source: this.extractRuntimeSource(condition)
      };
    }

    // Feature flag: if (featureFlags.newFeature)
    if (this.isFeatureFlag(condition)) {
      return {
        type: 'FEATURE_FLAG',
        flag: this.extractFlagName(condition)
      };
    }

    return { type: 'COMPLEX' };
  }

  isEnvironmentCheck(condition) {
    const patterns = [
      /process\.env\.\w+/,           // Node.js
      /os\.getenv\(['"]\w+['"]\)/,   // Python
      /System\.getenv\(['"]\w+['"]\)/, // Java
      /os\.Getenv\(['"]\w+['"]\)/    // Go
    ];

    return patterns.some(p => p.test(condition));
  }

  isRuntimeData(condition) {
    const patterns = [
      /req\.(body|query|params|headers)/,  // Express/Next.js
      /request\.(json|args|form)/,         // Flask/FastAPI
      /user\.\w+/,                         // User object
      /session\.\w+/                       // Session data
    ];

    return patterns.some(p => p.test(condition));
  }
}
```

---

### 4. Framework-Agnostic Manifest Finder

**New Feature**: Find dependency files anywhere

```javascript
class ManifestFinder {
  findManifests(projectRoot) {
    const manifests = [];

    // Walk entire tree (not just root)
    const allFiles = this.walkDirectory(projectRoot, {
      maxDepth: 10,
      excludeDirs: ['node_modules', '.git', 'dist', 'build']
    });

    allFiles.forEach(file => {
      const manifest = this.identifyManifest(file);
      if (manifest) {
        manifests.push(manifest);
      }
    });

    return manifests;
  }

  identifyManifest(file) {
    const basename = path.basename(file);
    const content = fs.readFileSync(file, 'utf-8');

    // JavaScript/TypeScript
    if (basename === 'package.json') {
      return {
        type: 'npm',
        file: file,
        ecosystem: 'npm',
        parser: 'json'
      };
    }

    if (basename === 'yarn.lock' || basename === 'package-lock.json') {
      return {
        type: 'npm-lock',
        file: file,
        ecosystem: 'npm',
        parser: 'lockfile'
      };
    }

    // Python
    if (basename === 'requirements.txt' ||
        basename.match(/requirements[.-]\w+\.txt/)) {
      return {
        type: 'pip',
        file: file,
        ecosystem: 'PyPI',
        parser: 'requirements'
      };
    }

    if (basename === 'Pipfile' || basename === 'Pipfile.lock') {
      return {
        type: 'pipenv',
        file: file,
        ecosystem: 'PyPI',
        parser: 'toml'
      };
    }

    if (basename === 'pyproject.toml') {
      return {
        type: 'poetry',
        file: file,
        ecosystem: 'PyPI',
        parser: 'toml'
      };
    }

    if (basename === 'setup.py' || basename === 'setup.cfg') {
      return {
        type: 'setuptools',
        file: file,
        ecosystem: 'PyPI',
        parser: 'python'
      };
    }

    // Java
    if (basename === 'pom.xml') {
      return {
        type: 'maven',
        file: file,
        ecosystem: 'Maven',
        parser: 'xml'
      };
    }

    if (basename === 'build.gradle' || basename === 'build.gradle.kts') {
      return {
        type: 'gradle',
        file: file,
        ecosystem: 'Maven',
        parser: 'gradle'
      };
    }

    // Go
    if (basename === 'go.mod') {
      return {
        type: 'gomod',
        file: file,
        ecosystem: 'Go',
        parser: 'gomod'
      };
    }

    // Rust
    if (basename === 'Cargo.toml') {
      return {
        type: 'cargo',
        file: file,
        ecosystem: 'crates.io',
        parser: 'toml'
      };
    }

    // Ruby
    if (basename === 'Gemfile' || basename === 'Gemfile.lock') {
      return {
        type: 'bundler',
        file: file,
        ecosystem: 'RubyGems',
        parser: 'ruby'
      };
    }

    // .NET
    if (basename.match(/\.csproj$/) || basename.match(/\.fsproj$/)) {
      return {
        type: 'nuget',
        file: file,
        ecosystem: 'NuGet',
        parser: 'xml'
      };
    }

    if (basename === 'packages.config') {
      return {
        type: 'nuget-legacy',
        file: file,
        ecosystem: 'NuGet',
        parser: 'xml'
      };
    }

    return null;
  }

  walkDirectory(dir, options = {}) {
    const maxDepth = options.maxDepth || 10;
    const excludeDirs = options.excludeDirs || [];
    const files = [];

    function walk(currentDir, depth) {
      if (depth > maxDepth) return;

      const entries = fs.readdirSync(currentDir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);

        if (entry.isDirectory()) {
          if (!excludeDirs.includes(entry.name)) {
            walk(fullPath, depth + 1);
          }
        } else {
          files.push(fullPath);
        }
      }
    }

    walk(dir, 0);
    return files;
  }
}
```

---

### 5. Multi-Confidence Scoring System

**New Feature**: Combine multiple signals

```javascript
class ConfidenceCalculator {
  calculateReachability(vulnerability, callPath) {
    const factors = [];

    // Factor 1: Path existence (0-40 points)
    if (callPath.exists) {
      const pathScore = Math.min(40, 40 / callPath.length);
      factors.push({
        name: 'Path Found',
        score: pathScore,
        reason: `${callPath.length}-hop path from entry point`
      });
    } else {
      return { confidence: 0, factors, reachable: false };
    }

    // Factor 2: Entry point quality (0-20 points)
    const entryConfidence = callPath.entryPoint.confidence;
    factors.push({
      name: 'Entry Point',
      score: entryConfidence * 20,
      reason: `${callPath.entryPoint.type} (${Math.round(entryConfidence * 100)}%)`
    });

    // Factor 3: Call type quality (0-15 points)
    const callTypeScore = this.scoreCallTypes(callPath.calls);
    factors.push({
      name: 'Call Types',
      score: callTypeScore,
      reason: this.describeCallTypes(callPath.calls)
    });

    // Factor 4: Function match (0-15 points)
    if (vulnerability.vulnerableFunctions) {
      const matchScore = this.scoreFunctionMatch(
        callPath.targetFunction,
        vulnerability.vulnerableFunctions
      );
      factors.push({
        name: 'Function Match',
        score: matchScore,
        reason: matchScore > 0 ? 'Exact vulnerable function called' : 'Generic match'
      });
    }

    // Factor 5: User input tracing (0-10 points)
    if (this.tracesUserInput(callPath)) {
      factors.push({
        name: 'User Input',
        score: 10,
        reason: 'Vulnerable function receives user-controlled data'
      });
    }

    // Calculate total
    const totalScore = factors.reduce((sum, f) => sum + f.score, 0);
    const confidence = Math.min(100, totalScore) / 100;

    return {
      confidence,
      reachable: confidence > 0.5,
      factors,
      summary: this.generateSummary(confidence, factors)
    };
  }

  scoreCallTypes(calls) {
    let score = 15; // Start with max

    calls.forEach(call => {
      if (call.type === 'dynamic') score -= 2;
      if (call.type === 'reflection') score -= 3;
      if (call.type === 'conditional') score -= 1;
    });

    return Math.max(0, score);
  }

  scoreFunctionMatch(called, vulnerableFuncs) {
    // Exact match
    if (vulnerableFuncs.some(f => f.function === called)) {
      return 15;
    }

    // Partial match (e.g., "template" matches "_.template")
    if (vulnerableFuncs.some(f => called.includes(f.function))) {
      return 10;
    }

    // Class/module match
    if (vulnerableFuncs.some(f => this.sameModule(called, f.function))) {
      return 5;
    }

    return 0;
  }

  tracesUserInput(callPath) {
    const userInputSources = [
      'request', 'req', 'body', 'query', 'params', 'headers',
      'argv', 'args', 'input', 'stdin',
      'message', 'event', 'payload'
    ];

    return callPath.dataFlow.some(node =>
      userInputSources.some(source => node.includes(source))
    );
  }
}
```

---

## Implementation Plan

### Phase 1: Core Redesign (Week 1)
- [x] Redesign architecture document
- [ ] Implement generic manifest finder
- [ ] Implement generic entry point detector
- [ ] Implement multi-confidence scoring

### Phase 2: Enhanced Analysis (Week 2)
- [ ] Add reflection tracker
- [ ] Add conditional analyzer
- [ ] Add data-flow tracking
- [ ] Upgrade Python to AST

### Phase 3: Testing & Validation (Week 3)
- [ ] Test with 20+ different project structures
- [ ] Test with different frameworks
- [ ] Test with obfuscation patterns
- [ ] Benchmark against other tools

### Phase 4: Polish & Documentation (Week 4)
- [ ] Write comprehensive docs
- [ ] Create example projects
- [ ] Performance optimization
- [ ] Release v2.0.0

---

## Success Criteria

A **truly generic scanner** should:

1. ✅ Work with ANY framework
   - Express, Next.js, Flask, Spring Boot, Gin, etc.

2. ✅ Work with ANY project structure
   - Monorepo, microservices, flat, nested
   - Services in subdirectories
   - Multiple manifests

3. ✅ Handle ANY vulnerability pattern
   - Direct calls
   - Reflection/dynamic loading
   - Obfuscation (Base64, etc.)
   - Conditional loading

4. ✅ No hardcoded assumptions
   - No hardcoded file paths
   - No hardcoded function names
   - No hardcoded vulnerability data

5. ✅ Provide confidence scores
   - Every finding has confidence
   - Multiple factors considered
   - Transparent reasoning

---

## Expected Results

After redesign, DepGuard should score:

| Test Suite | Current | After Redesign | Target |
|------------|---------|----------------|---------|
| Basic (v1) | 100% | 100% | 100% |
| Rotated (v2) | 100% | 100% | 100% |
| Hardened (v3) | 27% | 80%+ | 90%+ |
| Real-world projects | ??? | 85%+ | 90%+ |

**Time Estimate**: 3-4 weeks for complete redesign

---

## Next Steps

1. **Immediate**: Implement generic manifest finder
2. **This Week**: Implement generic entry point detector
3. **Next Week**: Add reflection tracker
4. **Following Week**: Test with diverse projects

**Goal**: Build a scanner that works **anywhere, anytime, with anything**.
