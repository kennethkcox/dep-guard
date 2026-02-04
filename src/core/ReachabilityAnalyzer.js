/**
 * Advanced Reachability Analyzer
 * Performs sophisticated static analysis to determine if vulnerable code is actually reachable
 */

const ImportDetector = require('../utils/ImportDetector');

class ReachabilityAnalyzer {
  constructor(options = {}) {
    this.options = {
      maxDepth: options.maxDepth || 10,
      trackDynamicCalls: options.trackDynamicCalls !== false,
      minConfidence: options.minConfidence || 0.5,
      includeIndirectPaths: options.includeIndirectPaths !== false,
      useImportHeuristics: options.useImportHeuristics !== false,
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
   * Analyzes reachability for all vulnerabilities
   */
  analyzeAll() {
    const results = [];
    const logger = require('../utils/logger').getLogger();

    // First, identify all files reachable from entry points
    this.identifyReachableFiles();

    logger.debug('Starting reachability analysis', {
      vulnerablePackages: this.vulnerableLocations.size,
      reachableFiles: this.reachableFiles.size,
      useImportHeuristics: this.options.useImportHeuristics
    });

    for (const [packageName, vulnerabilities] of this.vulnerableLocations) {
      logger.debug('Analyzing package', { packageName, vulnCount: vulnerabilities.length });

      for (const vuln of vulnerabilities) {
        // Try traditional call graph analysis first
        let reachability = this.analyzeReachability(vuln.location);

        // If not reachable via call graph, try import-based heuristics
        if (!reachability.isReachable && this.options.useImportHeuristics) {
          const importReachability = this.analyzeViaImports(packageName, vuln);
          if (importReachability.isReachable) {
            reachability = importReachability;
            logger.info('Found reachable via imports', {
              package: packageName,
              confidence: reachability.confidence
            });
          }
        }

        if (reachability.isReachable) {
          results.push({
            package: packageName,
            vulnerability: vuln.vulnerability,
            location: vuln.location,
            functionName: vuln.functionName,
            modulePath: vuln.modulePath,
            reachability: {
              isReachable: true,
              confidence: reachability.confidence,
              shortestPathLength: reachability.shortestPathLength || 0,
              paths: reachability.paths ? reachability.paths.slice(0, 3) : [],
              totalPathsFound: reachability.paths ? reachability.paths.length : 0,
              detectionMethod: reachability.method || 'call-graph'
            },
            isReachable: true,
            confidence: reachability.confidence
          });
        }
      }
    }

    return results.sort((a, b) =>
      b.reachability.confidence - a.reachability.confidence
    );
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

  /**
   * Clears all analysis data
   */
  clear() {
    this.callGraph.clear();
    this.reverseCallGraph.clear();
    this.entryPoints.clear();
    this.vulnerableLocations.clear();
    this.analysisCache.clear();
  }
}

module.exports = ReachabilityAnalyzer;
