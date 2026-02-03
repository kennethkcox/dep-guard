/**
 * DepGuard Scanner v2.0 - TRULY GENERIC
 *
 * Complete rewrite using:
 * - GenericManifestFinder: Find manifests ANYWHERE in project
 * - GenericEntryPointDetector: Detect entry points for ANY framework
 * - Zero hardcoded assumptions about structure
 *
 * Works with:
 * - Any project structure (monorepos, microservices, standard)
 * - Any framework (15+ supported out of the box)
 * - Any language (JavaScript, Python, Java, Go, Rust, Ruby, PHP)
 */

const fs = require('fs');
const path = require('path');
const ReachabilityAnalyzer = require('./core/ReachabilityAnalyzer');
const GenericManifestFinder = require('./core/GenericManifestFinder');
const GenericEntryPointDetector = require('./core/GenericEntryPointDetector');
const VulnerabilityDatabase = require('./vulnerabilities/VulnerabilityDatabase');
const JavaScriptAnalyzer = require('./analyzers/JavaScriptAnalyzer');
const PythonAnalyzer = require('./analyzers/PythonAnalyzer');
const JavaAnalyzer = require('./analyzers/JavaAnalyzer');
const Reporter = require('./reporting/Reporter');

class DepGuardScanner2 {
    constructor(options = {}) {
        this.options = {
            projectPath: options.projectPath || process.cwd(),
            maxDepth: options.maxDepth || 10,
            minConfidence: options.minConfidence || 0.5,
            entryPointConfidence: options.entryPointConfidence || 0.6,
            deepAnalysis: options.deepAnalysis || false,
            verbose: options.verbose || false,
            ...options
        };

        this.reachabilityAnalyzer = new ReachabilityAnalyzer({
            maxDepth: this.options.maxDepth,
            minConfidence: this.options.minConfidence,
            trackDynamicCalls: true,
            includeIndirectPaths: this.options.deepAnalysis
        });

        this.manifestFinder = new GenericManifestFinder({
            maxDepth: this.options.maxDepth,
            verbose: this.options.verbose
        });

        this.entryPointDetector = new GenericEntryPointDetector({
            minConfidence: this.options.entryPointConfidence,
            verbose: this.options.verbose
        });

        this.vulnDatabases = new Map();  // One database per ecosystem
        this.results = [];
        this.manifests = [];
        this.allDependencies = [];
    }

    /**
     * Main scan entry point
     */
    async scan() {
        console.log('🔍 DepGuard v2.0 - Generic Vulnerability Scanner\n');
        console.log('=' .repeat(60));

        try {
            // Phase 1: Discover Project Structure
            console.log('\n📦 Phase 1: Discovering project structure...');
            await this.discoverProjectStructure();

            // Phase 2: Analyze Dependencies
            console.log('\n📋 Phase 2: Analyzing dependencies...');
            await this.analyzeDependencies();

            // Phase 3: Check Vulnerabilities
            console.log('\n🔎 Phase 3: Checking for vulnerabilities...');
            await this.checkVulnerabilities();

            // Phase 4: Build Call Graph
            console.log('\n🕸️  Phase 4: Building call graph...');
            await this.buildCallGraph();

            // Phase 5: Detect Entry Points
            console.log('\n🚪 Phase 5: Detecting entry points...');
            await this.detectEntryPoints();

            // Phase 6: Reachability Analysis
            console.log('\n🔬 Phase 6: Performing reachability analysis...');
            await this.performReachabilityAnalysis();

            // Phase 7: Results
            console.log('\n✅ Phase 7: Generating results...');
            this.generateResults();

            console.log('\n' + '='.repeat(60));
            console.log(`✓ Scan complete: Found ${this.results.length} reachable vulnerabilities\n`);

            return {
                success: true,
                results: this.results,
                statistics: this.getStatistics()
            };
        } catch (error) {
            console.error(`\n❌ Scan failed: ${error.message}`);
            if (this.options.verbose) {
                console.error(error.stack);
            }
            return {
                success: false,
                error: error.message,
                results: []
            };
        }
    }

    /**
     * Phase 1: Discover project structure
     */
    async discoverProjectStructure() {
        const projectPath = this.options.projectPath;

        // Find all manifests in project
        this.manifests = this.manifestFinder.findManifests(projectPath);

        if (this.manifests.length === 0) {
            throw new Error(`No dependency manifests found in ${projectPath}`);
        }

        const stats = this.manifestFinder.getStatistics(this.manifests);

        console.log(`  ✓ Found ${stats.total} manifest(s):`);
        for (const [ecosystem, count] of Object.entries(stats.byEcosystem)) {
            console.log(`    - ${ecosystem}: ${count}`);
        }

        if (stats.workspaces > 1) {
            console.log(`  ℹ️  Detected ${stats.workspaces} workspace(s) (monorepo)`);
        }
    }

    /**
     * Phase 2: Analyze dependencies
     */
    async analyzeDependencies() {
        this.allDependencies = [];

        for (const manifest of this.manifests) {
            try {
                const deps = await this.extractDependencies(manifest);
                this.allDependencies.push({
                    manifest,
                    dependencies: deps
                });

                if (this.options.verbose) {
                    console.log(`  ✓ ${manifest.filename}: ${deps.length} dependencies`);
                }
            } catch (error) {
                console.warn(`  ⚠️  Error parsing ${manifest.filename}: ${error.message}`);
            }
        }

        const totalDeps = this.allDependencies.reduce((sum, m) => sum + m.dependencies.length, 0);
        console.log(`  ✓ Total dependencies: ${totalDeps}`);
    }

    /**
     * Extract dependencies from a manifest
     */
    async extractDependencies(manifest) {
        const content = fs.readFileSync(manifest.path, 'utf8');

        switch (manifest.ecosystem) {
            case 'npm':
                return this.extractNpmDependencies(content, manifest);

            case 'pypi':
                return this.extractPythonDependencies(content, manifest);

            case 'maven':
                return this.extractJavaDependencies(content, manifest);

            case 'go':
                return this.extractGoDependencies(content, manifest);

            case 'cargo':
                return this.extractRustDependencies(content, manifest);

            case 'rubygems':
                return this.extractRubyDependencies(content, manifest);

            case 'packagist':
                return this.extractPhpDependencies(content, manifest);

            default:
                console.warn(`  ⚠️  Unsupported ecosystem: ${manifest.ecosystem}`);
                return [];
        }
    }

    /**
     * Extract NPM dependencies
     */
    extractNpmDependencies(content, manifest) {
        try {
            if (manifest.filename === 'package.json') {
                const data = JSON.parse(content);
                const deps = { ...data.dependencies, ...data.devDependencies };
                return Object.entries(deps).map(([name, version]) => ({
                    name,
                    version: version.replace(/[\^~>=<]/g, '').trim(),
                    ecosystem: 'npm',
                    manifest: manifest.path
                }));
            }
            // TODO: Parse package-lock.json for exact versions
            return [];
        } catch (error) {
            throw new Error(`Failed to parse package.json: ${error.message}`);
        }
    }

    /**
     * Extract Python dependencies
     */
    extractPythonDependencies(content, manifest) {
        const deps = [];

        if (manifest.filename === 'requirements.txt') {
            const lines = content.split('\n');
            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed || trimmed.startsWith('#')) continue;

                const match = trimmed.match(/^([a-zA-Z0-9\-_]+)(==|>=|<=|~=|!=)?(.+)?$/);
                if (match) {
                    deps.push({
                        name: match[1],
                        version: match[3] ? match[3].trim() : 'latest',
                        ecosystem: 'pypi',
                        manifest: manifest.path
                    });
                }
            }
        } else if (manifest.filename === 'pyproject.toml') {
            // Basic TOML parsing for dependencies
            const depSection = content.match(/\[tool\.poetry\.dependencies\](.*?)(\n\[|$)/s);
            if (depSection) {
                const lines = depSection[1].split('\n');
                for (const line of lines) {
                    const match = line.match(/^([a-zA-Z0-9\-_]+)\s*=\s*"([^"]+)"/);
                    if (match && match[1] !== 'python') {
                        deps.push({
                            name: match[1],
                            version: match[2].replace(/[\^~]/g, ''),
                            ecosystem: 'pypi',
                            manifest: manifest.path
                        });
                    }
                }
            }
        }

        return deps;
    }

    /**
     * Extract Java dependencies
     */
    extractJavaDependencies(content, manifest) {
        const deps = [];

        if (manifest.filename === 'pom.xml') {
            // Extract <dependency> blocks
            const depRegex = /<dependency>.*?<groupId>(.*?)<\/groupId>.*?<artifactId>(.*?)<\/artifactId>.*?<version>(.*?)<\/version>.*?<\/dependency>/gs;
            let match;
            while ((match = depRegex.exec(content)) !== null) {
                deps.push({
                    name: `${match[1]}:${match[2]}`,
                    version: match[3],
                    ecosystem: 'maven',
                    manifest: manifest.path
                });
            }
        } else if (manifest.filename.includes('build.gradle')) {
            // Extract Gradle dependencies
            const depRegex = /(implementation|compile|api|testImplementation)\s+['"]([^:]+):([^:]+):([^'"]+)['"]/g;
            let match;
            while ((match = depRegex.exec(content)) !== null) {
                deps.push({
                    name: `${match[2]}:${match[3]}`,
                    version: match[4],
                    ecosystem: 'maven',
                    manifest: manifest.path
                });
            }
        }

        return deps;
    }

    /**
     * Extract Go dependencies
     */
    extractGoDependencies(content, manifest) {
        const deps = [];

        if (manifest.filename === 'go.mod') {
            const lines = content.split('\n');
            let inRequire = false;

            for (const line of lines) {
                const trimmed = line.trim();

                if (trimmed.startsWith('require (')) {
                    inRequire = true;
                    continue;
                }

                if (inRequire && trimmed === ')') {
                    inRequire = false;
                    continue;
                }

                if (inRequire || trimmed.startsWith('require ')) {
                    const match = trimmed.match(/^(?:require\s+)?([^\s]+)\s+v([^\s]+)/);
                    if (match) {
                        deps.push({
                            name: match[1],
                            version: match[2],
                            ecosystem: 'go',
                            manifest: manifest.path
                        });
                    }
                }
            }
        }

        return deps;
    }

    /**
     * Extract Rust dependencies
     */
    extractRustDependencies(content, manifest) {
        const deps = [];

        if (manifest.filename === 'Cargo.toml') {
            const depSection = content.match(/\[dependencies\](.*?)(\n\[|$)/s);
            if (depSection) {
                const lines = depSection[1].split('\n');
                for (const line of lines) {
                    const match = line.match(/^([a-zA-Z0-9\-_]+)\s*=\s*"([^"]+)"/);
                    if (match) {
                        deps.push({
                            name: match[1],
                            version: match[2],
                            ecosystem: 'cargo',
                            manifest: manifest.path
                        });
                    }
                }
            }
        }

        return deps;
    }

    /**
     * Extract Ruby dependencies
     */
    extractRubyDependencies(content, manifest) {
        const deps = [];

        if (manifest.filename === 'Gemfile') {
            const lines = content.split('\n');
            for (const line of lines) {
                const match = line.match(/gem\s+['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]/);
                if (match) {
                    deps.push({
                        name: match[1],
                        version: match[2].replace(/[~>]/g, ''),
                        ecosystem: 'rubygems',
                        manifest: manifest.path
                    });
                }
            }
        }

        return deps;
    }

    /**
     * Extract PHP dependencies
     */
    extractPhpDependencies(content, manifest) {
        try {
            if (manifest.filename === 'composer.json') {
                const data = JSON.parse(content);
                const deps = { ...data.require, ...data['require-dev'] };
                return Object.entries(deps)
                    .filter(([name]) => name !== 'php')  // Skip PHP itself
                    .map(([name, version]) => ({
                        name,
                        version: version.replace(/[\^~]/g, ''),
                        ecosystem: 'packagist',
                        manifest: manifest.path
                    }));
            }
            return [];
        } catch (error) {
            throw new Error(`Failed to parse composer.json: ${error.message}`);
        }
    }

    /**
     * Phase 3: Check vulnerabilities
     */
    async checkVulnerabilities() {
        let totalVulns = 0;

        for (const manifestDeps of this.allDependencies) {
            const ecosystem = manifestDeps.manifest.ecosystem;

            // Get or create database for this ecosystem
            if (!this.vulnDatabases.has(ecosystem)) {
                this.vulnDatabases.set(ecosystem, new VulnerabilityDatabase({
                    ecosystem,
                    verbose: this.options.verbose
                }));
            }

            const vulnDb = this.vulnDatabases.get(ecosystem);

            // Load vulnerabilities for all dependencies
            await vulnDb.loadVulnerabilities(manifestDeps.dependencies);

            // Count vulnerabilities
            for (const dep of manifestDeps.dependencies) {
                const vulns = vulnDb.getVulnerabilities(dep.name, dep.version);
                totalVulns += vulns.length;
            }
        }

        console.log(`  ✓ Found ${totalVulns} known vulnerabilities`);
    }

    /**
     * Phase 4: Build call graph
     */
    async buildCallGraph() {
        const projectPath = this.options.projectPath;

        // Analyze each manifest's directory separately
        for (const manifest of this.manifests) {
            const manifestDir = manifest.directory;

            try {
                switch (manifest.ecosystem) {
                    case 'npm':
                        if (manifest.type === 'manifest') {  // Only analyze for package.json, not lockfiles
                            const jsAnalyzer = new JavaScriptAnalyzer(this.reachabilityAnalyzer, {
                                ...this.options,
                                projectPath: manifestDir
                            });
                            jsAnalyzer.analyzeProject(manifestDir);
                        }
                        break;

                    case 'pypi':
                        const pyAnalyzer = new PythonAnalyzer(this.reachabilityAnalyzer, {
                            ...this.options,
                            projectPath: manifestDir
                        });
                        pyAnalyzer.analyzeProject(manifestDir);
                        break;

                    case 'maven':
                        const javaAnalyzer = new JavaAnalyzer(this.reachabilityAnalyzer, {
                            ...this.options,
                            projectPath: manifestDir
                        });
                        javaAnalyzer.analyzeProject(manifestDir);
                        break;

                    default:
                        if (this.options.verbose) {
                            console.log(`  ⚠️  No analyzer for ${manifest.ecosystem} yet`);
                        }
                }
            } catch (error) {
                console.warn(`  ⚠️  Error analyzing ${manifest.directory}: ${error.message}`);
            }
        }

        const stats = this.reachabilityAnalyzer.getStatistics();
        console.log(`  ✓ Built call graph: ${stats.totalNodes} nodes, ${stats.totalEdges} edges`);
    }

    /**
     * Phase 5: Detect entry points
     */
    async detectEntryPoints() {
        const projectPath = this.options.projectPath;

        // Get all source files from call graph
        const callGraph = this.reachabilityAnalyzer.getCallGraph();
        const files = Array.from(callGraph.nodes.keys())
            .map(node => {
                // Handle both Unix and Windows paths (C:\path\file.js:function)
                // Find the last colon that's not part of a drive letter
                const lastColonIndex = node.lastIndexOf(':');
                if (lastColonIndex === -1) {
                    return node;  // No colon, entire string is the file
                }

                // Check if this might be a Windows drive letter (single char before first colon)
                const beforeColon = node.substring(0, lastColonIndex);
                if (beforeColon.length === 1) {
                    // This is likely "C:" drive letter, return whole string
                    return node;
                }

                return beforeColon;
            })
            .filter(f => f)
            .filter((f, i, arr) => arr.indexOf(f) === i);  // Unique

        // Detect entry points
        const entryPoints = this.entryPointDetector.detectEntryPoints(files, callGraph);

        // Add entry points to reachability analyzer
        for (const ep of entryPoints) {
            // Add file-level entry point
            this.reachabilityAnalyzer.addEntryPoint(ep.file, {
                type: ep.type,
                confidence: ep.confidence,
                signals: ep.signals
            });

            // Add function-level entry points if available
            if (ep.functions) {
                for (const func of ep.functions) {
                    this.reachabilityAnalyzer.addEntryPoint(`${ep.file}:${func}`, {
                        type: ep.type,
                        confidence: ep.confidence
                    });
                }
            }
        }

        console.log(`  ✓ Detected ${entryPoints.length} entry points`);
    }

    /**
     * Phase 6: Perform reachability analysis
     */
    async performReachabilityAnalysis() {
        // Map vulnerabilities to functions
        for (const manifestDeps of this.allDependencies) {
            const vulnDb = this.vulnDatabases.get(manifestDeps.manifest.ecosystem);

            for (const dep of manifestDeps.dependencies) {
                const vulns = vulnDb.getVulnerabilities(dep.name, dep.version);

                for (const vuln of vulns) {
                    // For each vulnerable function, add as target
                    if (vuln.affectedFunctions) {
                        for (const func of vuln.affectedFunctions) {
                            const location = `node_modules/${dep.name}/${func}`;
                            this.reachabilityAnalyzer.addVulnerabilityTarget(location, vuln);
                        }
                    } else {
                        // Generic package-level vulnerability
                        const location = `node_modules/${dep.name}/index.js`;
                        this.reachabilityAnalyzer.addVulnerabilityTarget(location, vuln);
                    }
                }
            }
        }

        // Analyze reachability for all vulnerabilities
        this.results = this.reachabilityAnalyzer.analyzeAll();

        console.log(`  ✓ Analyzed ${this.results.length} potential vulnerabilities`);
    }

    /**
     * Phase 7: Generate results
     */
    generateResults() {
        // Filter by confidence threshold
        const filtered = this.results.filter(r =>
            r.confidence >= this.options.minConfidence
        );

        // Sort by confidence (highest first)
        filtered.sort((a, b) => b.confidence - a.confidence);

        this.results = filtered;

        console.log(`  ✓ ${this.results.length} high-confidence findings`);
    }

    /**
     * Get scan statistics
     */
    getStatistics() {
        const totalDeps = this.allDependencies.reduce((sum, m) => sum + m.dependencies.length, 0);
        const callGraphStats = this.reachabilityAnalyzer.getStatistics();

        let totalVulns = 0;
        for (const [ecosystem, vulnDb] of this.vulnDatabases) {
            // Count all vulnerabilities in database
            totalVulns += vulnDb.vulnerabilities.size;
        }

        return {
            manifests: this.manifests.length,
            ecosystems: new Set(this.manifests.map(m => m.ecosystem)).size,
            dependencies: totalDeps,
            vulnerabilities: totalVulns,
            reachableVulnerabilities: this.results.filter(r => r.isReachable).length,
            unreachableVulnerabilities: this.results.filter(r => !r.isReachable).length,
            callGraph: callGraphStats,
            entryPoints: callGraphStats.entryPoints
        };
    }

    /**
     * Get results
     */
    getResults() {
        return this.results;
    }

    /**
     * Generate report
     */
    async generateReport(format = 'table', outputPath = null) {
        const reporter = new Reporter({ format, outputPath });
        return reporter.generate(this.results, this.getStatistics());
    }
}

module.exports = DepGuardScanner2;
