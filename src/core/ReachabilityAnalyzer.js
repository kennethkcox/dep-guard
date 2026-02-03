/**
 * Advanced Reachability Analyzer
 * Performs sophisticated static analysis to determine if vulnerable code is actually reachable
 */

class ReachabilityAnalyzer {
  constructor(options = {}) {
    this.options = {
      maxDepth: options.maxDepth || 10,
      trackDynamicCalls: options.trackDynamicCalls !== false,
      minConfidence: options.minConfidence || 0.5,
      includeIndirectPaths: options.includeIndirectPaths !== false,
      ...options
    };

    this.callGraph = new Map(); // source -> [targets]
    this.reverseCallGraph = new Map(); // target -> [sources]
    this.entryPoints = new Set();
    this.vulnerableLocations = new Map(); // package -> vulnerable functions
    this.analysisCache = new Map();
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

    for (const [packageName, vulnerabilities] of this.vulnerableLocations) {
      for (const vuln of vulnerabilities) {
        const reachability = this.analyzeReachability(vuln.location);

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
              shortestPathLength: reachability.shortestPathLength,
              paths: reachability.paths.slice(0, 3), // Top 3 paths
              totalPathsFound: reachability.paths.length
            }
          });
        }
      }
    }

    return results.sort((a, b) =>
      b.reachability.confidence - a.reachability.confidence
    );
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
