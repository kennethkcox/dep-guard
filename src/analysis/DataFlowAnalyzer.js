/**
 * Data Flow Analyzer - Taint Tracking
 *
 * Tracks data flow from sources (user input) to sinks (vulnerable functions)
 * to determine if vulnerabilities are actually exploitable.
 *
 * Taint Sources (user-controlled input):
 * - HTTP: req.body, req.query, req.params, req.headers, req.cookies
 * - CLI: process.argv, process.env
 * - Files: fs.readFile(userPath), fs.readFileSync(userPath)
 * - Network: socket data, WebSocket messages
 *
 * Taint Sinks (vulnerable functions):
 * - From OSV/NVD: lodash.template, eval, etc.
 * - Command execution: child_process.exec, spawn
 * - SQL queries: db.query(tainted)
 *
 * Sanitizers (data cleaning):
 * - validator.escape, DOMPurify.sanitize
 * - Custom validation functions
 */

const { getLogger } = require('../utils/logger');

class DataFlowAnalyzer {
    constructor(options = {}) {
        this.options = options;
        this.logger = getLogger().child({ component: 'DataFlowAnalyzer' });

        // Taint sources by category
        this.taintSources = new Map();
        this.initializeTaintSources();

        // Known sanitizers
        this.sanitizers = new Set();
        this.initializeSanitizers();

        // Taint propagation rules
        this.propagationRules = new Map();
        this.initializePropagationRules();

        // Taint tracking state
        this.taintedVariables = new Map(); // variable -> taint info
        this.dataFlowPaths = new Map(); // sink -> [paths from sources]

        // Call graph reference (set externally)
        this.callGraph = null;
        this.reachabilityAnalyzer = null;
    }

    /**
     * Initialize taint sources (user inputs)
     */
    initializeTaintSources() {
        // HTTP Request sources (Express, Koa, Fastify, etc.)
        this.addTaintSource('req.body', { type: 'http', risk: 'HIGH' });
        this.addTaintSource('req.query', { type: 'http', risk: 'HIGH' });
        this.addTaintSource('req.params', { type: 'http', risk: 'HIGH' });
        this.addTaintSource('req.headers', { type: 'http', risk: 'MEDIUM' });
        this.addTaintSource('req.cookies', { type: 'http', risk: 'MEDIUM' });
        this.addTaintSource('request.body', { type: 'http', risk: 'HIGH' });
        this.addTaintSource('request.query', { type: 'http', risk: 'HIGH' });

        // Context-based (Koa, Hapi)
        this.addTaintSource('ctx.request.body', { type: 'http', risk: 'HIGH' });
        this.addTaintSource('ctx.query', { type: 'http', risk: 'HIGH' });
        this.addTaintSource('ctx.params', { type: 'http', risk: 'HIGH' });

        // CLI arguments
        this.addTaintSource('process.argv', { type: 'cli', risk: 'HIGH' });
        this.addTaintSource('process.env', { type: 'env', risk: 'MEDIUM' });

        // File system (when path is user-controlled)
        this.addTaintSource('fs.readFile', { type: 'file', risk: 'HIGH' });
        this.addTaintSource('fs.readFileSync', { type: 'file', risk: 'HIGH' });
        this.addTaintSource('fs.readdir', { type: 'file', risk: 'MEDIUM' });

        // Network
        this.addTaintSource('socket.data', { type: 'network', risk: 'HIGH' });
        this.addTaintSource('ws.message', { type: 'network', risk: 'HIGH' });

        // Database (if query contains user input)
        this.addTaintSource('db.query', { type: 'database', risk: 'HIGH' });
    }

    /**
     * Add a taint source
     */
    addTaintSource(source, metadata) {
        this.taintSources.set(source, metadata);
    }

    /**
     * Initialize known sanitizers
     */
    initializeSanitizers() {
        // Validation libraries
        this.sanitizers.add('validator.escape');
        this.sanitizers.add('validator.isEmail');
        this.sanitizers.add('validator.isURL');
        this.sanitizers.add('validator.normalizeEmail');

        // XSS prevention
        this.sanitizers.add('DOMPurify.sanitize');
        this.sanitizers.add('xss');
        this.sanitizers.add('sanitize-html');

        // SQL escaping
        this.sanitizers.add('mysql.escape');
        this.sanitizers.add('pg.escape');
        this.sanitizers.add('sequelize.escape');

        // Path sanitization
        this.sanitizers.add('path.normalize');
        this.sanitizers.add('path.resolve');

        // Common patterns
        this.sanitizers.add('parseInt');
        this.sanitizers.add('parseFloat');
        this.sanitizers.add('Number');
        this.sanitizers.add('String');
        this.sanitizers.add('JSON.parse');
    }

    /**
     * Initialize taint propagation rules
     */
    initializePropagationRules() {
        // String operations propagate taint
        this.addPropagationRule('String.concat', true);
        this.addPropagationRule('String.replace', true);
        this.addPropagationRule('String.slice', true);
        this.addPropagationRule('String.substring', true);
        this.addPropagationRule('String.toLowerCase', true);
        this.addPropagationRule('String.toUpperCase', true);
        this.addPropagationRule('String.trim', true);

        // Template literals propagate taint
        this.addPropagationRule('TemplateLiteral', true);

        // Array operations propagate taint
        this.addPropagationRule('Array.map', true);
        this.addPropagationRule('Array.filter', true);
        this.addPropagationRule('Array.reduce', true);
        this.addPropagationRule('Array.join', true);

        // Object operations
        this.addPropagationRule('Object.assign', true);
        this.addPropagationRule('Object.values', true);
        this.addPropagationRule('Object.keys', true);

        // Lodash operations
        this.addPropagationRule('_.map', true);
        this.addPropagationRule('_.filter', true);
        this.addPropagationRule('_.merge', true);
        this.addPropagationRule('_.clone', true);
        this.addPropagationRule('_.cloneDeep', true);
    }

    /**
     * Add a propagation rule
     */
    addPropagationRule(operation, propagates) {
        this.propagationRules.set(operation, propagates);
    }

    /**
     * Set call graph reference
     */
    setCallGraph(callGraph) {
        this.callGraph = callGraph;
    }

    /**
     * Set reachability analyzer reference
     */
    setReachabilityAnalyzer(analyzer) {
        this.reachabilityAnalyzer = analyzer;
    }

    /**
     * Analyze data flow from sources to a specific vulnerability
     *
     * @param {Object} vulnerability - Vulnerability info with location
     * @param {Array} entryPoints - Entry points to trace from
     * @returns {Object} Data flow analysis result
     */
    analyzeFlow(vulnerability, entryPoints) {
        const sinkLocation = vulnerability.location;
        const paths = [];

        // For each entry point, check if tainted data can reach the sink
        for (const entryPoint of entryPoints) {
            const flowPaths = this.findTaintPaths(entryPoint, sinkLocation);
            paths.push(...flowPaths);
        }

        // Determine if vulnerability is exploitable based on data flow
        const isTainted = paths.length > 0;
        const confidence = this.calculateTaintConfidence(paths, vulnerability);

        return {
            isTainted,
            confidence,
            paths,
            sources: this.extractSources(paths),
            sanitizers: this.extractSanitizers(paths),
            risk: this.calculateRisk(paths, vulnerability)
        };
    }

    /**
     * Find all taint paths from an entry point to a sink
     */
    findTaintPaths(entryPoint, sinkLocation) {
        const paths = [];
        const visited = new Set();
        const queue = [{
            location: entryPoint,
            path: [entryPoint],
            taintedVars: new Set(),
            sanitized: false
        }];

        while (queue.length > 0) {
            const { location, path, taintedVars, sanitized } = queue.shift();

            // Skip if already visited
            const key = `${location}:${Array.from(taintedVars).sort().join(',')}`;
            if (visited.has(key)) continue;
            visited.add(key);

            // Check if we reached the sink
            if (location === sinkLocation) {
                paths.push({
                    path,
                    taintedVars: Array.from(taintedVars),
                    sanitized,
                    length: path.length
                });
                continue;
            }

            // Stop if path is too long (prevent infinite loops)
            if (path.length > 20) continue;

            // Find taint sources at this location
            const sources = this.findTaintSourcesAt(location);
            const newTaintedVars = new Set([...taintedVars, ...sources]);

            // Check for sanitizers
            const isSanitized = sanitized || this.hasSanitizerAt(location);

            // Get outgoing edges from call graph
            if (this.callGraph && this.callGraph.nodes) {
                const edges = this.callGraph.get(location) || [];

                for (const edge of edges) {
                    const nextLocation = edge.target;

                    // Check if taint propagates through this edge
                    const propagates = this.taintPropagatesThrough(edge);

                    if (propagates && newTaintedVars.size > 0) {
                        queue.push({
                            location: nextLocation,
                            path: [...path, nextLocation],
                            taintedVars: newTaintedVars,
                            sanitized: isSanitized
                        });
                    }
                }
            }
        }

        return paths;
    }

    /**
     * Find taint sources at a specific location
     */
    findTaintSourcesAt(location) {
        const sources = [];

        // Check if location contains known taint sources
        for (const [source, metadata] of this.taintSources) {
            if (location.includes(source)) {
                sources.push(source);
            }
        }

        return sources;
    }

    /**
     * Check if location has a sanitizer
     */
    hasSanitizerAt(location) {
        for (const sanitizer of this.sanitizers) {
            if (location.includes(sanitizer)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if taint propagates through an edge
     */
    taintPropagatesThrough(edge) {
        // By default, taint propagates through function calls
        // unless explicitly blocked by sanitizer

        const target = edge.target;

        // Check propagation rules
        for (const [operation, propagates] of this.propagationRules) {
            if (target.includes(operation)) {
                return propagates;
            }
        }

        // Default: propagate
        return true;
    }

    /**
     * Calculate confidence based on taint paths
     */
    calculateTaintConfidence(paths, vulnerability) {
        if (paths.length === 0) {
            return 0.30; // No taint path found, but vulnerability exists
        }

        let maxConfidence = 0.50; // Base confidence with taint

        // Factor 1: Multiple paths increase confidence
        if (paths.length > 1) {
            maxConfidence += 0.10;
        }

        // Factor 2: Short paths are more reliable
        const shortestPath = Math.min(...paths.map(p => p.length));
        if (shortestPath <= 3) {
            maxConfidence += 0.20;
        } else if (shortestPath <= 5) {
            maxConfidence += 0.10;
        }

        // Factor 3: Sanitizers reduce confidence
        const hasSanitizer = paths.some(p => p.sanitized);
        if (hasSanitizer) {
            maxConfidence -= 0.30;
        }

        // Factor 4: Direct taint sources increase confidence
        const hasDirectSource = paths.some(p =>
            p.taintedVars.some(v => v.includes('req.body') || v.includes('req.query'))
        );
        if (hasDirectSource) {
            maxConfidence += 0.15;
        }

        // Ensure confidence is in valid range
        return Math.max(0.10, Math.min(0.98, maxConfidence));
    }

    /**
     * Extract unique sources from paths
     */
    extractSources(paths) {
        const sources = new Set();

        paths.forEach(path => {
            path.taintedVars.forEach(v => sources.add(v));
        });

        return Array.from(sources).map(source => {
            const metadata = this.taintSources.get(source) || { type: 'unknown', risk: 'MEDIUM' };
            return { source, ...metadata };
        });
    }

    /**
     * Extract sanitizers from paths
     */
    extractSanitizers(paths) {
        const sanitizers = new Set();

        paths.forEach(path => {
            path.path.forEach(location => {
                this.sanitizers.forEach(sanitizer => {
                    if (location.includes(sanitizer)) {
                        sanitizers.add(sanitizer);
                    }
                });
            });
        });

        return Array.from(sanitizers);
    }

    /**
     * Calculate overall risk
     */
    calculateRisk(paths, vulnerability) {
        if (paths.length === 0) {
            return 'LOW';
        }

        // Get sources
        const sources = this.extractSources(paths);
        const sanitizers = this.extractSanitizers(paths);

        // Highest source risk
        const sourceRisks = sources.map(s => s.risk);
        const hasHighRiskSource = sourceRisks.includes('HIGH');
        const hasSanitizer = sanitizers.length > 0;

        // Calculate risk
        if (hasHighRiskSource && !hasSanitizer) {
            return 'CRITICAL';
        } else if (hasHighRiskSource && hasSanitizer) {
            return 'HIGH';
        } else if (sources.length > 0 && !hasSanitizer) {
            return 'HIGH';
        } else if (sources.length > 0 && hasSanitizer) {
            return 'MEDIUM';
        }

        return 'LOW';
    }

    /**
     * Analyze all vulnerabilities with data flow
     */
    analyzeAllVulnerabilities(vulnerabilities, entryPoints) {
        const results = [];

        this.logger.info('Starting data flow analysis', {
            vulnerabilities: vulnerabilities.length,
            entryPoints: entryPoints.length
        });

        for (const vuln of vulnerabilities) {
            try {
                const flowResult = this.analyzeFlow(vuln, entryPoints);

                results.push({
                    vulnerability: vuln,
                    dataFlow: flowResult,
                    enhancedConfidence: this.mergeConfidence(
                        vuln.confidence,
                        flowResult.confidence
                    )
                });

                if (flowResult.isTainted) {
                    this.logger.info('Taint path found', {
                        vulnerability: vuln.id,
                        paths: flowResult.paths.length,
                        sources: flowResult.sources.length
                    });
                }
            } catch (error) {
                this.logger.error('Data flow analysis failed', {
                    vulnerability: vuln.id,
                    error: error.message
                });
            }
        }

        return results;
    }

    /**
     * Merge reachability confidence with data flow confidence
     */
    mergeConfidence(reachabilityConf, dataFlowConf) {
        // If user input reaches vulnerability, boost confidence significantly
        if (dataFlowConf > 0.60) {
            return Math.min(0.98, reachabilityConf + (dataFlowConf * 0.4));
        }

        // If no taint path but vulnerability is reachable, use reachability confidence
        return reachabilityConf;
    }

    /**
     * Get statistics
     */
    getStatistics() {
        return {
            taintSources: this.taintSources.size,
            sanitizers: this.sanitizers.size,
            propagationRules: this.propagationRules.size,
            dataFlowPaths: this.dataFlowPaths.size
        };
    }

    /**
     * Export learned patterns (for ML training)
     */
    exportPatterns() {
        return {
            sources: Array.from(this.taintSources.entries()),
            sanitizers: Array.from(this.sanitizers),
            propagation: Array.from(this.propagationRules.entries()),
            paths: Array.from(this.dataFlowPaths.entries())
        };
    }

    /**
     * Import learned patterns (from ML model)
     */
    importPatterns(patterns) {
        if (patterns.sources) {
            patterns.sources.forEach(([source, metadata]) => {
                this.addTaintSource(source, metadata);
            });
        }

        if (patterns.sanitizers) {
            patterns.sanitizers.forEach(sanitizer => {
                this.sanitizers.add(sanitizer);
            });
        }

        if (patterns.propagation) {
            patterns.propagation.forEach(([operation, propagates]) => {
                this.addPropagationRule(operation, propagates);
            });
        }
    }
}

module.exports = DataFlowAnalyzer;
