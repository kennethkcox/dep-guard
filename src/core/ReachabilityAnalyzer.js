/**
 * Advanced Reachability Analyzer
 *
 * Performs sophisticated static analysis to determine if vulnerable code
 * is actually reachable from application entry points.
 *
 * Detection strategies (in priority order):
 * 1. Call Graph BFS: Direct forward/backward path finding in the call graph
 * 2. Import-Based Heuristics: Package-level import scanning with function-specificity
 * 3. Transitive Import Analysis: A imports B, B imports vulnerable-C → A is indirectly reachable
 * 4. Dangerous Pattern Matching: Known vulnerable API usage patterns boost confidence
 * 5. File-Level Reachability: Entry-point file proximity analysis
 */

const ImportDetector = require('../utils/ImportDetector');

// Known vulnerable function patterns for common packages (CVE-specific)
const KNOWN_VULNERABLE_PATTERNS = {
  'lodash': {
    functions: ['template', 'merge', 'defaultsDeep', 'set', 'setWith', 'zipObjectDeep'],
    patterns: [/\.template\s*\(/, /\.merge\s*\(/, /\.defaultsDeep\s*\(/, /\._\.set\s*\(/],
    description: 'Prototype pollution or command injection via template'
  },
  'express': {
    functions: ['static', 'send', 'redirect'],
    patterns: [/express\.static\s*\(/, /res\.redirect\s*\(.*req\./],
    description: 'Open redirect, path traversal'
  },
  'axios': {
    functions: ['get', 'post', 'request'],
    patterns: [/axios\.(get|post|put|delete|request)\s*\([^)]*req\.(body|query|params)/],
    description: 'SSRF via user-controlled URLs'
  },
  'requests': {
    functions: ['get', 'post', 'request'],
    patterns: [/requests\.(get|post|put|delete)\s*\(/],
    description: 'SSRF or insecure SSL verification'
  },
  'yaml': {
    functions: ['load', 'safe_load'],
    patterns: [/yaml\.load\s*\(/, /yaml\.unsafe_load\s*\(/],
    description: 'Arbitrary code execution via YAML deserialization'
  },
  'pyyaml': {
    functions: ['load'],
    patterns: [/yaml\.load\s*\(/],
    description: 'Arbitrary code execution via YAML deserialization'
  },
  'jackson-databind': {
    functions: ['readValue', 'enableDefaultTyping'],
    patterns: [/enableDefaultTyping/, /ObjectMapper.*readValue/],
    description: 'Deserialization RCE'
  },
  'log4j-core': {
    functions: ['info', 'error', 'warn', 'debug', 'fatal'],
    patterns: [/logger\.(info|error|warn|debug|fatal)\s*\(/i],
    description: 'Log4Shell RCE via JNDI lookup'
  },
  'spring-boot-starter-security': {
    functions: [],
    patterns: [/SecurityFilterChain/, /@EnableWebSecurity/],
    description: 'Spring Security bypass'
  },
  'Newtonsoft.Json': {
    functions: ['DeserializeObject', 'JsonConvert'],
    patterns: [/JsonConvert\.DeserializeObject/, /TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)/],
    description: 'Deserialization RCE via TypeNameHandling'
  },
  'System.Text.Json': {
    functions: ['Deserialize'],
    patterns: [/JsonSerializer\.Deserialize/],
    description: 'Potential deserialization issues'
  },
  'serde': {
    functions: ['deserialize'],
    patterns: [/#\[derive\(.*Deserialize/],
    description: 'Deserialization issues'
  },
  'nokogiri': {
    functions: ['parse', 'XML', 'HTML'],
    patterns: [/Nokogiri::(XML|HTML)\.parse/],
    description: 'XXE or HTML injection'
  },
  'django': {
    functions: ['raw', 'extra'],
    patterns: [/\.raw\s*\(/, /\.extra\s*\(/],
    description: 'SQL injection via raw queries'
  },
  'sqlalchemy': {
    functions: ['text', 'execute'],
    patterns: [/text\s*\(.*\+/, /execute\s*\(.*%/],
    description: 'SQL injection via string concatenation'
  }
};

class ReachabilityAnalyzer {
  constructor(options = {}) {
    this.options = {
      maxDepth: options.maxDepth || 10,
      trackDynamicCalls: options.trackDynamicCalls !== false,
      minConfidence: options.minConfidence || 0.5,
      includeIndirectPaths: options.includeIndirectPaths !== false,
      useImportHeuristics: options.useImportHeuristics !== false,
      usePatternMatching: options.usePatternMatching !== false,
      useTransitiveImports: options.useTransitiveImports !== false,
      ...options
    };

    this.callGraph = new Map(); // source -> [targets]
    this.reverseCallGraph = new Map(); // target -> [sources]
    this.entryPoints = new Set();
    this.vulnerableLocations = new Map(); // package -> vulnerable functions
    this.analysisCache = new Map();
    this.importDetector = new ImportDetector();
    this.reachableFiles = new Set(); // Files reachable from entry points
    this.projectPath = null; // Project root for import scanning
    this.importGraph = new Map(); // file -> Set of imported packages (for transitive analysis)
    this.fileContents = new Map(); // Cached file contents for pattern matching
  }

  /**
   * Sets the project path for import detection
   */
  setProjectPath(projectPath) {
    this.projectPath = projectPath;
  }

  /**
   * Adds an entry point to the analysis
   * @param {string} modulePath - The module/file path
   * @param {string|object} functionNameOrOptions - Function name (string) or options object with metadata
   */
  addEntryPoint(modulePath, functionNameOrOptions = 'main') {
    let functionName = 'main';
    let metadata = {};

    // Support both old signature (modulePath, functionName) and new (modulePath, options)
    if (typeof functionNameOrOptions === 'string') {
      functionName = functionNameOrOptions;
    } else if (typeof functionNameOrOptions === 'object') {
      metadata = functionNameOrOptions;
      functionName = metadata.function || 'main';
    }

    const key = `${modulePath}:${functionName}`;
    this.entryPoints.add(key);

    // Store metadata if provided (for future use)
    if (Object.keys(metadata).length > 0) {
      if (!this.entryPointMetadata) {
        this.entryPointMetadata = new Map();
      }
      this.entryPointMetadata.set(key, metadata);
    }
  }

  /**
   * Records a call relationship
   */
  addCall(fromModule, fromFunction, toModule, toFunction, callType = 'direct') {
    const source = `${fromModule}:${fromFunction}`;
    const target = `${toModule}:${toFunction}`;

    if (!this.callGraph.has(source)) {
      this.callGraph.set(source, []);
    }

    this.callGraph.get(source).push({
      target,
      callType,
      confidence: callType === 'direct' ? 1.0 : 0.7
    });

    // Build reverse graph for backward analysis
    if (!this.reverseCallGraph.has(target)) {
      this.reverseCallGraph.set(target, []);
    }
    this.reverseCallGraph.get(target).push({
      source,
      callType,
      confidence: callType === 'direct' ? 1.0 : 0.7
    });
  }

  /**
   * Marks a function as vulnerable
   */
  addVulnerability(packageName, modulePath, functionName, vulnerability) {
    const key = `${modulePath}:${functionName}`;

    if (!this.vulnerableLocations.has(packageName)) {
      this.vulnerableLocations.set(packageName, []);
    }

    this.vulnerableLocations.get(packageName).push({
      location: key,
      vulnerability,
      functionName,
      modulePath
    });
  }

  /**
   * Adds a vulnerability target (alias for addVulnerability with simpler API)
   * @param {string} location - Full location string (module:function) or just module path
   * @param {object} vulnerability - Vulnerability object
   */
  addVulnerabilityTarget(location, vulnerability) {
    // Parse location string
    let modulePath, functionName;

    if (location.includes(':')) {
      [modulePath, functionName] = location.split(':');
    } else {
      modulePath = location;
      functionName = 'default';
    }

    const packageName = vulnerability.package || vulnerability.name || 'unknown';
    this.addVulnerability(packageName, modulePath, functionName, vulnerability);
  }

  /**
   * Analyzes reachability for all vulnerabilities using a multi-strategy approach:
   * 1. Call Graph BFS (highest confidence)
   * 2. Import-based heuristics (medium confidence)
   * 3. Dangerous pattern matching (medium-high confidence)
   * 4. Transitive import analysis (lower confidence)
   */
  analyzeAll() {
    const results = [];
    const logger = require('../utils/logger').getLogger();

    // First, identify all files reachable from entry points
    this.identifyReachableFiles();

    // Build import graph for transitive analysis
    if (this.options.useTransitiveImports && this.projectPath) {
      this.buildImportGraph();
    }

    logger.debug('Starting reachability analysis', {
      vulnerablePackages: this.vulnerableLocations.size,
      reachableFiles: this.reachableFiles.size,
      useImportHeuristics: this.options.useImportHeuristics,
      usePatternMatching: this.options.usePatternMatching,
      useTransitiveImports: this.options.useTransitiveImports
    });

    for (const [packageName, vulnerabilities] of this.vulnerableLocations) {
      logger.debug('Analyzing package', { packageName, vulnCount: vulnerabilities.length });

      for (const vuln of vulnerabilities) {
        // Strategy 1: Traditional call graph analysis (highest confidence)
        let reachability = this.analyzeReachability(vuln.location);
        let bestMethod = reachability.isReachable ? 'call-graph' : null;

        // Strategy 2: Import-based heuristics
        if (!reachability.isReachable && this.options.useImportHeuristics) {
          const importReachability = this.analyzeViaImports(packageName, vuln);
          if (importReachability.isReachable) {
            reachability = importReachability;
            bestMethod = importReachability.method || 'import-detection';
            logger.info('Found reachable via imports', {
              package: packageName,
              confidence: reachability.confidence
            });
          }
        }

        // Strategy 3: Dangerous pattern matching
        // This can BOOST confidence of import-detected reachability
        // or detect reachability missed by import scanning
        if (this.options.usePatternMatching) {
          const patternResult = this.analyzeViaPatterns(packageName, vuln);
          if (patternResult.isReachable) {
            if (!reachability.isReachable) {
              reachability = patternResult;
              bestMethod = 'pattern-matching';
            } else {
              // Boost existing confidence if patterns also match
              reachability.confidence = Math.min(1.0,
                reachability.confidence + patternResult.confidence * 0.2
              );
              bestMethod = reachability.method ? `${reachability.method}+pattern` : 'call-graph+pattern';
            }
          }
        }

        // Strategy 4: Transitive import analysis (if still not found)
        if (!reachability.isReachable && this.options.useTransitiveImports) {
          const transitiveResult = this.analyzeViaTransitiveImports(packageName, vuln);
          if (transitiveResult.isReachable) {
            reachability = transitiveResult;
            bestMethod = 'transitive-import';
          }
        }

        // Always include the vulnerability in results, regardless of reachability
        results.push({
          package: packageName,
          vulnerability: vuln.vulnerability,
          location: vuln.location,
          functionName: vuln.functionName,
          modulePath: vuln.modulePath,
          reachability: {
            isReachable: reachability.isReachable,
            confidence: reachability.isReachable ? reachability.confidence : 0,
            shortestPathLength: reachability.shortestPathLength || 0,
            paths: reachability.paths ? reachability.paths.slice(0, 3) : [],
            totalPathsFound: reachability.paths ? reachability.paths.length : 0,
            detectionMethod: reachability.isReachable ? (bestMethod || 'call-graph') : 'none'
          },
          isReachable: reachability.isReachable,
          confidence: reachability.isReachable ? reachability.confidence : 0
        });
      }
    }

    // Sort: reachable first, then by confidence descending
    return results.sort((a, b) => {
      if (a.isReachable !== b.isReachable) return b.isReachable ? 1 : -1;
      return b.reachability.confidence - a.reachability.confidence;
    });
  }

  /**
   * Identifies all files reachable from entry points via call graph
   */
  identifyReachableFiles() {
    this.reachableFiles.clear();

    for (const entryPoint of this.entryPoints) {
      // Extract file path from entry point (format: file:function)
      const filePath = entryPoint.split(':')[0];
      this.reachableFiles.add(filePath);

      // Add all files reachable from this entry point
      this.traverseCallGraphForFiles(entryPoint);
    }
  }

  /**
   * Traverses call graph to find all reachable files
   * @param {string} startNode - Starting node for traversal
   * @param {number} maxDepth - Maximum traversal depth to prevent infinite loops
   */
  traverseCallGraphForFiles(startNode, maxDepth = 100) {
    const visited = new Set();
    const queue = [{ node: startNode, depth: 0 }];

    while (queue.length > 0) {
      const { node, depth } = queue.shift();

      // Prevent infinite loops and excessive memory usage
      if (depth > maxDepth) {
        const logger = require('../utils/logger').getLogger();
        logger.warn('Maximum traversal depth reached', {
          startNode,
          currentNode: node,
          depth
        });
        continue;
      }

      if (visited.has(node)) continue;
      visited.add(node);

      // Extract file from node
      const filePath = node.split(':')[0];
      this.reachableFiles.add(filePath);

      // Add connected nodes with depth tracking
      const targets = this.callGraph.get(node) || [];
      for (const { target } of targets) {
        if (!visited.has(target)) {
          queue.push({ node: target, depth: depth + 1 });
        }
      }
    }
  }

  /**
   * Analyzes reachability via import detection
   */
  analyzeViaImports(packageName, vuln) {
    try {
      const logger = require('../utils/logger').getLogger();

      // If we have a project path, scan it for imports
      let filesToCheck = Array.from(this.reachableFiles);

      // If reachableFiles is empty or small, scan the entire project
      if (!filesToCheck || filesToCheck.length < 10) {
        if (this.projectPath) {
          logger.debug('Scanning entire project for imports', { projectPath: this.projectPath });
          // Get all source files in project
          const allFiles = [];
          this.importDetector.walkDirectory(this.projectPath, (file) => {
            allFiles.push(file);
          });
          filesToCheck = allFiles;
          logger.debug('Found source files to scan', { count: filesToCheck.length });
        }
      }

      // Check if package is imported in any file
      const importResult = this.importDetector.isPackageImported(
        packageName,
        filesToCheck
      );

      if (importResult.imported) {
        // Package is imported in code
        const confidence = this.calculateImportBasedConfidence(importResult);

        logger.debug('Package imported', {
          package: packageName,
          file: importResult.file,
          confidence
        });

        return {
          isReachable: confidence >= this.options.minConfidence,
          confidence,
          shortestPathLength: 1,
          paths: [{
            nodes: [importResult.file, `${packageName} (imported)`],
            confidence
          }],
          method: 'import-detection'
        };
      }
    } catch (error) {
      // Ignore import detection errors
      const logger = require('../utils/logger').getLogger();
      logger.debug('Import detection error', { error: error.message });
    }

    return { isReachable: false, confidence: 0 };
  }

  /**
   * Calculates confidence for import-based reachability
   */
  calculateImportBasedConfidence(importResult) {
    let confidence = 0.6; // Base confidence for imports

    // Higher confidence if multiple imports
    if (importResult.imports && importResult.imports.length > 1) {
      confidence = Math.min(0.8, 0.6 + (importResult.imports.length * 0.05));
    }

    // Use import-specific confidence if available
    if (importResult.imports && importResult.imports.length > 0) {
      const avgImportConfidence = importResult.imports.reduce((sum, imp) =>
        sum + (imp.confidence || 0.8), 0) / importResult.imports.length;
      confidence = Math.max(confidence, avgImportConfidence * 0.9);
    }

    return Math.min(0.85, confidence); // Cap at 0.85 for import-based detection
  }

  /**
   * Analyzes if a specific location is reachable from entry points
   */
  analyzeReachability(targetLocation) {
    // Check cache first
    if (this.analysisCache.has(targetLocation)) {
      return this.analysisCache.get(targetLocation);
    }

    const paths = [];
    let maxConfidence = 0;
    let shortestPathLength = Infinity;

    // Try to find paths from each entry point to target
    for (const entryPoint of this.entryPoints) {
      const foundPaths = this.findPaths(entryPoint, targetLocation, this.options.maxDepth);

      for (const path of foundPaths) {
        paths.push(path);
        const pathConfidence = this.calculatePathConfidence(path);
        maxConfidence = Math.max(maxConfidence, pathConfidence);
        shortestPathLength = Math.min(shortestPathLength, path.length);
      }
    }

    // Also try backward analysis from target to entry points
    if (this.options.includeIndirectPaths) {
      const backwardPaths = this.backwardAnalysis(targetLocation);
      paths.push(...backwardPaths);

      for (const path of backwardPaths) {
        const pathConfidence = this.calculatePathConfidence(path);
        maxConfidence = Math.max(maxConfidence, pathConfidence);
        shortestPathLength = Math.min(shortestPathLength, path.length);
      }
    }

    const result = {
      isReachable: maxConfidence >= this.options.minConfidence && paths.length > 0,
      confidence: maxConfidence,
      shortestPathLength: shortestPathLength === Infinity ? 0 : shortestPathLength,
      paths: paths.map(p => this.formatPath(p))
    };

    this.analysisCache.set(targetLocation, result);
    return result;
  }

  /**
   * Finds all paths from source to target using BFS with depth limit
   */
  findPaths(source, target, maxDepth) {
    const paths = [];
    const queue = [{ node: source, path: [source], depth: 0, confidence: 1.0 }];
    const visited = new Set();

    while (queue.length > 0) {
      const { node, path, depth, confidence } = queue.shift();

      if (depth > maxDepth) continue;

      if (node === target) {
        paths.push({ nodes: path, confidence });
        continue;
      }

      const visitKey = `${node}-${depth}`;
      if (visited.has(visitKey)) continue;
      visited.add(visitKey);

      const callees = this.callGraph.get(node) || [];

      for (const { target: nextNode, callType, confidence: callConfidence } of callees) {
        if (!path.includes(nextNode)) { // Avoid cycles
          queue.push({
            node: nextNode,
            path: [...path, nextNode],
            depth: depth + 1,
            confidence: confidence * callConfidence
          });
        }
      }
    }

    return paths;
  }

  /**
   * Backward analysis from target to find potential entry points
   */
  backwardAnalysis(target) {
    const paths = [];
    const queue = [{ node: target, path: [target], depth: 0 }];
    const visited = new Set();

    while (queue.length > 0) {
      const { node, path, depth } = queue.shift();

      if (depth > this.options.maxDepth) continue;

      if (this.entryPoints.has(node)) {
        paths.push({ nodes: path.reverse(), confidence: 0.8 }); // Slightly lower confidence for backward
        continue;
      }

      const visitKey = `${node}-${depth}`;
      if (visited.has(visitKey)) continue;
      visited.add(visitKey);

      const callers = this.reverseCallGraph.get(node) || [];

      for (const { source: prevNode } of callers) {
        if (!path.includes(prevNode)) {
          queue.push({
            node: prevNode,
            path: [...path, prevNode],
            depth: depth + 1
          });
        }
      }
    }

    return paths;
  }

  /**
   * Calculates confidence score for a path
   */
  calculatePathConfidence(path) {
    if (!path.nodes || path.nodes.length === 0) return 0;

    let confidence = path.confidence || 1.0;

    // Decrease confidence for longer paths
    const lengthPenalty = Math.pow(0.95, path.nodes.length - 1);
    confidence *= lengthPenalty;

    // Boost confidence if path is short
    if (path.nodes.length <= 3) {
      confidence = Math.min(1.0, confidence * 1.1);
    }

    return Math.max(0, Math.min(1.0, confidence));
  }

  /**
   * Formats a path for display
   */
  formatPath(path) {
    return {
      nodes: path.nodes,
      length: path.nodes.length,
      confidence: this.calculatePathConfidence(path),
      description: path.nodes.map((node, idx) => {
        const [module, func] = node.split(':');
        return `${idx > 0 ? '→ ' : ''}${module}${func ? '::' + func : ''}`;
      }).join(' ')
    };
  }

  /**
   * Generates statistics about the call graph
   */
  getStatistics() {
    return {
      totalNodes: this.callGraph.size,
      totalEdges: Array.from(this.callGraph.values()).reduce((sum, arr) => sum + arr.length, 0),
      entryPoints: this.entryPoints.size,
      vulnerableLocations: Array.from(this.vulnerableLocations.values()).reduce((sum, arr) => sum + arr.length, 0),
      averageDegree: this.callGraph.size > 0
        ? Array.from(this.callGraph.values()).reduce((sum, arr) => sum + arr.length, 0) / this.callGraph.size
        : 0
    };
  }

  /**
   * Returns the call graph for external inspection
   */
  getCallGraph() {
    return {
      nodes: this.callGraph,
      edges: this.reverseCallGraph,
      entryPoints: this.entryPoints
    };
  }

  // ─── Strategy 3: Dangerous Pattern Matching ─────────────────────────

  /**
   * Analyzes reachability via known vulnerable API usage patterns.
   * For example, if lodash.template is a known vulnerable function and
   * we find `_.template(` in the source, that's a strong reachability signal.
   */
  analyzeViaPatterns(packageName, vuln) {
    try {
      const patterns = KNOWN_VULNERABLE_PATTERNS[packageName];
      if (!patterns) {
        return { isReachable: false, confidence: 0 };
      }

      const fs = require('fs');
      const filesToCheck = this.getFilesToCheck();

      for (const file of filesToCheck) {
        let content;
        if (this.fileContents.has(file)) {
          content = this.fileContents.get(file);
        } else {
          try {
            content = fs.readFileSync(file, 'utf8');
            this.fileContents.set(file, content);
          } catch {
            continue;
          }
        }

        // Check each dangerous pattern
        for (const pattern of patterns.patterns) {
          if (pattern.test(content)) {
            const isEntryFile = this.reachableFiles.has(file);
            const confidence = isEntryFile ? 0.85 : 0.70;

            return {
              isReachable: confidence >= this.options.minConfidence,
              confidence,
              shortestPathLength: 1,
              paths: [{
                nodes: [file, `${packageName} (dangerous pattern: ${patterns.description})`],
                confidence
              }],
              method: 'pattern-matching'
            };
          }
        }

        // Also check for specific function name usage (less specific but still useful)
        for (const funcName of patterns.functions) {
          // Look for patterns like pkg.func( or require('pkg').func(
          const funcPattern = new RegExp(`\\b${funcName}\\s*\\(`, 'g');
          if (funcPattern.test(content)) {
            // Verify the file also imports this package
            const importResult = this.importDetector.isPackageImported(packageName, [file]);
            if (importResult.imported) {
              const confidence = 0.75;
              return {
                isReachable: confidence >= this.options.minConfidence,
                confidence,
                shortestPathLength: 1,
                paths: [{
                  nodes: [file, `${packageName}.${funcName} (function match)`],
                  confidence
                }],
                method: 'pattern-matching'
              };
            }
          }
        }
      }
    } catch (error) {
      // Pattern matching is best-effort
    }

    return { isReachable: false, confidence: 0 };
  }

  // ─── Strategy 4: Transitive Import Analysis ────────────────────────

  /**
   * Builds a graph of file-to-package imports for transitive analysis.
   * If file A imports package B, and package B depends on vulnerable package C,
   * then A has a transitive path to C.
   */
  buildImportGraph() {
    const fs = require('fs');
    const filesToCheck = this.getFilesToCheck();

    for (const file of filesToCheck) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        this.fileContents.set(file, content);

        const imports = this.importDetector.detectImports(content, file);
        const packageNames = new Set();
        for (const imp of imports) {
          if (imp.package) {
            packageNames.add(imp.package);
          }
        }
        this.importGraph.set(file, packageNames);
      } catch {
        // Skip unreadable files
      }
    }
  }

  /**
   * Checks if a vulnerable package is reachable transitively via imports.
   * This handles cases like:
   *   app.js → lodash → (vulnerable function in lodash internals)
   * where the call graph doesn't have explicit edges to internal lodash modules.
   */
  analyzeViaTransitiveImports(packageName, vuln) {
    try {
      // Check if any entry-point-reachable file imports a package that depends on the vulnerable one
      for (const [file, imports] of this.importGraph) {
        if (!this.reachableFiles.has(file)) continue;

        // Direct import of vulnerable package from an entry-reachable file
        if (imports.has(packageName)) {
          return {
            isReachable: true,
            confidence: 0.55,
            shortestPathLength: 2,
            paths: [{
              nodes: [file, `${packageName} (transitive import)`],
              confidence: 0.55
            }],
            method: 'transitive-import'
          };
        }

        // Check if any imported package name is a prefix/alias of the vulnerable one
        // e.g., importing "@org/core" which internally uses "vulnerable-pkg"
        for (const importedPkg of imports) {
          if (packageName.startsWith(importedPkg + '/') || importedPkg.startsWith(packageName + '/')) {
            return {
              isReachable: true,
              confidence: 0.45,
              shortestPathLength: 3,
              paths: [{
                nodes: [file, importedPkg, `${packageName} (transitive)`],
                confidence: 0.45
              }],
              method: 'transitive-import'
            };
          }
        }
      }
    } catch (error) {
      // Transitive analysis is best-effort
    }

    return { isReachable: false, confidence: 0 };
  }

  // ─── Helper Methods ────────────────────────────────────────────────

  /**
   * Gets the list of files to check for import/pattern analysis.
   * Prioritizes reachable files, then scans project if needed.
   */
  getFilesToCheck() {
    let filesToCheck = Array.from(this.reachableFiles);

    if (filesToCheck.length < 10 && this.projectPath) {
      const allFiles = [];
      try {
        this.importDetector.walkDirectory(this.projectPath, (file) => {
          allFiles.push(file);
        });
      } catch {
        // Ignore walk errors
      }
      filesToCheck = allFiles;
    }

    return filesToCheck;
  }

  /**
   * Clears all analysis data
   */
  clear() {
    this.callGraph.clear();
    this.reverseCallGraph.clear();
    this.entryPoints.clear();
    this.vulnerableLocations.clear();
    this.analysisCache.clear();
    this.importGraph.clear();
    this.fileContents.clear();
  }
}

module.exports = ReachabilityAnalyzer;
