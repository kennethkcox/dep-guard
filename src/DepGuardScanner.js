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
const DependencyResolver = require('./utils/DependencyResolver');
const ImportDetector = require('./utils/ImportDetector');
const FileWalker = require('./utils/FileWalker');
const DataFlowAnalyzer = require('./analysis/DataFlowAnalyzer');
const ShaiHuludDetector = require('./analysis/ShaiHuludDetector');
const MLManager = require('./ml/MLManager');
const { getLogger } = require('./utils/logger');
const { ManifestParsingError, FileSystemError } = require('./utils/errors');
const Validator = require('./utils/validator');

// Configuration constants
const CONFIG = {
    MAX_FILE_SIZE: 50 * 1024 * 1024,  // 50MB max file size
    MAX_JSON_SIZE: 10 * 1024 * 1024,  // 10MB max JSON size
    MAX_DEPENDENCIES: 10000,          // Max dependencies per manifest
    MAX_DEPTH_DEFAULT: 10,            // Default call graph depth
    MIN_CONFIDENCE_DEFAULT: 0.5,      // Default minimum confidence score
    MAX_TRAVERSAL_DEPTH: 100          // Maximum graph traversal depth (anti-infinite-loop)
};

class DepGuardScanner2 {
    constructor(options = {}) {
        // Validate options before processing
        Validator.validateOptions(options, {
            projectPath: { type: 'string', mustExist: false },
            maxDepth: { type: 'number', min: 1, max: 100, integer: true },
            minConfidence: { type: 'number', min: 0, max: 1 },
            entryPointConfidence: { type: 'number', min: 0, max: 1 },
            deepAnalysis: { type: 'boolean' },
            verbose: { type: 'boolean' },
            enableDataFlow: { type: 'boolean' },
            enableML: { type: 'boolean' },
            resolveTransitive: { type: 'boolean' },
            enableNVD: { type: 'boolean' },
            enableGitHub: { type: 'boolean' },
            disableEPSS: { type: 'boolean' },
            disableKEV: { type: 'boolean' },
            nvdApiKey: { type: 'string', mustExist: false },
            githubToken: { type: 'string', mustExist: false }
        });

        this.options = {
            projectPath: options.projectPath || process.cwd(),
            maxDepth: options.maxDepth || CONFIG.MAX_DEPTH_DEFAULT,
            minConfidence: options.minConfidence || CONFIG.MIN_CONFIDENCE_DEFAULT,
            entryPointConfidence: options.entryPointConfidence || 0.6,
            deepAnalysis: options.deepAnalysis || false,
            verbose: options.verbose || false,
            enableDataFlow: options.enableDataFlow !== false,  // Enabled by default
            enableML: options.enableML !== false,              // Enabled by default
            ...options
        };

        this.logger = getLogger().child({ component: 'DepGuardScanner' });

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

        // Data Flow Analyzer (NEW)
        this.dataFlowAnalyzer = null;
        if (this.options.enableDataFlow) {
            this.dataFlowAnalyzer = new DataFlowAnalyzer(this.options);
        }

        // ML Manager (NEW)
        this.mlManager = null;
        if (this.options.enableML) {
            this.mlManager = new MLManager(this.options);
        }

        this.vulnDatabases = new Map();  // One database per ecosystem
        this.results = [];
        this.manifests = [];
        this.allDependencies = [];
        this.failedManifests = [];  // Track manifests that failed to parse
        this.transitiveCache = new Map();  // Cache for transitive dependency resolution
        this.dependencyResolver = new DependencyResolver(this.options);

        // Shai-Hulud Detector (shadow deps, typosquatting, dependency confusion)
        this.shaiHuludDetector = new ShaiHuludDetector(this.options);
    }

    /**
     * Main scan entry point
     */
    async scan() {
        console.log('DepGuard v2.0 - Generic Vulnerability Scanner\n');
        console.log('=' .repeat(60));

        try {
            // Phase 1: Discover Project Structure
            console.log('\n[1/7] Phase 1: Discovering project structure...');
            await this.discoverProjectStructure();

            // Phase 2: Analyze Dependencies
            console.log('\n[2/7] Phase 2: Analyzing dependencies...');
            await this.analyzeDependencies();

            // Phase 2.5: Shai-Hulud Detection (shadow deps, typosquatting, dependency confusion)
            console.log('\n[2.5/7] Shai-Hulud: Hunting hidden dependency dangers...');
            await this.performShaiHuludDetection();

            // Phase 3: Check Vulnerabilities
            console.log('\n[3/7] Phase 3: Checking for vulnerabilities...');
            await this.checkVulnerabilities();

            // Phase 4: Build Call Graph
            console.log('\n[4/7] Phase 4: Building call graph...');
            await this.buildCallGraph();

            // Phase 5: Detect Entry Points
            console.log('\n[5/7] Phase 5: Detecting entry points...');
            await this.detectEntryPoints();

            // Phase 6: Reachability Analysis
            console.log('\n[6/7] Phase 6: Performing reachability analysis...');
            await this.performReachabilityAnalysis();

            // Phase 6.3: Dangerous API Pattern Detection
            console.log('\n[6.3/7] Scanning for dangerous API patterns...');
            await this.detectDangerousPatterns();

            // Phase 6.5: Data Flow Analysis (NEW)
            if (this.options.enableDataFlow) {
                await this.performDataFlowAnalysis();
            }

            // Phase 6.8: ML Risk Prediction (NEW)
            if (this.options.enableML) {
                await this.performMLAnalysis();
            }

            // Phase 7: Results
            console.log('\n[7/7] Phase 7: Generating results...');
            this.generateResults();

            const reachableCount = this.results.filter(r => r.isReachable).length;
            const totalCount = this.results.length;
            console.log('\n' + '='.repeat(60));
            console.log(`[OK] Scan complete: Found ${totalCount} vulnerabilities (${reachableCount} reachable, ${totalCount - reachableCount} unreachable)\n`);

            return {
                success: true,
                results: this.results,
                shaiHuludFindings: this.shaiHuludFindings || [],
                statistics: this.getStatistics()
            };
        } catch (error) {
            console.error(`\n[ERROR] Scan failed: ${error.message}`);
            if (this.options.verbose) {
                console.error(error.stack);
            }
            // Clean up on error
            this.cleanup();
            return {
                success: false,
                error: error.message,
                results: [],
                failedManifests: this.failedManifests
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

        console.log(`  [OK]Found ${stats.total} manifest(s):`);
        for (const [ecosystem, count] of Object.entries(stats.byEcosystem)) {
            console.log(`    - ${ecosystem}: ${count}`);
        }

        if (stats.workspaces > 1) {
            console.log(`  [i]Detected ${stats.workspaces} workspace(s) (monorepo)`);
        }

        // Detect workspace configuration
        const workspaceConfig = this.manifestFinder.detectWorkspaces(projectPath);
        if (workspaceConfig.length > 0) {
            console.log(`  [i]Workspace patterns detected:`);
            for (const ws of workspaceConfig) {
                console.log(`    - ${ws.pattern} (${ws.source})`);
            }
            this.workspaceConfig = workspaceConfig;
        }
    }

    /**
     * Phase 2: Analyze dependencies
     */
    async analyzeDependencies() {
        this.allDependencies = [];

        for (const manifest of this.manifests) {
            try {
                // Extract direct dependencies from manifest
                const directDeps = await this.extractDependencies(manifest);

                // Resolve transitive dependencies
                let transitiveDeps = [];
                if (this.options.resolveTransitive !== false) {
                    transitiveDeps = await this.resolveTransitiveDependencies(manifest);
                }

                // Merge and deduplicate
                const allDeps = this.mergeDependencies(directDeps, transitiveDeps);

                this.allDependencies.push({
                    manifest,
                    dependencies: allDeps
                });

                if (this.options.verbose) {
                    const directCount = directDeps.length;
                    const transitiveCount = allDeps.length - directCount;
                    console.log(`  [OK]${manifest.filename}: ${directCount} direct, ${transitiveCount} transitive`);
                } else {
                    console.log(`  [OK]${manifest.filename}: ${allDeps.length} dependencies`);
                }
            } catch (error) {
                this.logger.warn('Error parsing manifest', {
                    manifest: manifest.filename,
                    error: error.message,
                    stack: error.stack
                });

                // Track failed manifest for reporting
                this.failedManifests.push({
                    manifest,
                    error: {
                        message: error.message,
                        type: error.constructor.name,
                        stack: this.options.verbose ? error.stack : undefined
                    }
                });

                // Re-throw critical errors, allow scanner to continue for non-critical
                if (error instanceof ManifestParsingError || error instanceof FileSystemError) {
                    // Log but continue - don't fail entire scan for one bad manifest
                    console.warn(`  [!]Error parsing ${manifest.filename}: ${error.message}`);
                } else {
                    throw error;
                }
            }
        }

        const totalDeps = this.allDependencies.reduce((sum, m) => sum + m.dependencies.length, 0);
        const directDeps = this.allDependencies.reduce((sum, m) =>
            sum + m.dependencies.filter(d => !d.transitive).length, 0);
        const transitiveDeps = totalDeps - directDeps;

        console.log(`  [OK]Total dependencies: ${totalDeps} (${directDeps} direct, ${transitiveDeps} transitive)`);
    }

    /**
     * Phase 2.5: Shai-Hulud Detection
     * Hunts for shadow dependencies, typosquatting, and dependency confusion
     */
    async performShaiHuludDetection() {
        const importDetector = new ImportDetector(this.options);
        const fileWalker = new FileWalker({
            maxDepth: this.options.maxDepth,
            excludeDirs: ['node_modules', '.git', 'dist', 'build', 'target', '__pycache__', 'venv', '.venv', 'vendor']
        });

        const context = {
            manifests: this.manifests,
            allDependencies: this.allDependencies,
            projectPath: this.options.projectPath,
            importDetector,
            fileWalker
        };

        this.shaiHuludFindings = await this.shaiHuludDetector.detect(context);

        if (this.shaiHuludFindings.length > 0) {
            const summary = this.shaiHuludDetector.getSummary();
            console.log(`  [!]Found ${summary.total} hidden dependency issue(s):`);
            for (const [type, count] of Object.entries(summary.byType)) {
                console.log(`    - ${type}: ${count}`);
            }
            if (summary.highSeverity > 0) {
                console.log(`  [!!]${summary.highSeverity} HIGH severity finding(s) require attention`);
            }
        } else {
            console.log('  [OK]No hidden dependency dangers detected');
        }
    }

    /**
     * Resolves transitive dependencies for a manifest with caching
     */
    async resolveTransitiveDependencies(manifest) {
        // Create cache key from manifest path and ecosystem
        const cacheKey = `${manifest.ecosystem}:${manifest.path}`;

        // Check cache first
        if (this.transitiveCache.has(cacheKey)) {
            this.logger.debug('Using cached transitive dependencies', { manifest: manifest.filename });
            return this.transitiveCache.get(cacheKey);
        }

        try {
            let result = [];

            switch (manifest.ecosystem) {
                case 'maven':
                    result = await this.dependencyResolver.resolveMavenDependencies(manifest.path);
                    break;

                case 'npm':
                    result = await this.dependencyResolver.resolveNpmDependencies(manifest.path);
                    break;

                case 'pypi':
                    result = await this.dependencyResolver.resolvePythonDependencies(manifest.path);
                    break;

                case 'nuget':
                    result = await this.dependencyResolver.resolveNuGetDependencies(manifest.path);
                    break;

                case 'go':
                    result = await this.dependencyResolver.resolveGoDependencies(manifest.path);
                    break;

                case 'cargo':
                    result = await this.dependencyResolver.resolveRustDependencies(manifest.path);
                    break;

                case 'rubygems':
                    result = await this.dependencyResolver.resolveRubyDependencies(manifest.path);
                    break;

                default:
                    // No transitive resolution for other ecosystems yet
                    result = [];
            }

            // Cache the result
            this.transitiveCache.set(cacheKey, result);
            return result;

        } catch (error) {
            this.logger.warn('Failed to resolve transitive dependencies', {
                manifest: manifest.filename,
                error: error.message
            });
            // Cache empty result to avoid repeated failures
            this.transitiveCache.set(cacheKey, []);
            return [];
        }
    }

    /**
     * Merges direct and transitive dependencies, removing duplicates
     */
    mergeDependencies(directDeps, transitiveDeps) {
        const merged = new Map();

        // Add direct dependencies first
        for (const dep of directDeps) {
            const key = `${dep.name}@${dep.version}`;
            merged.set(key, { ...dep, transitive: false });
        }

        // Add transitive dependencies (don't override direct ones)
        for (const dep of transitiveDeps) {
            const key = `${dep.name}@${dep.version}`;
            if (!merged.has(key)) {
                merged.set(key, { ...dep, transitive: true });
            }
        }

        return Array.from(merged.values());
    }

    /**
     * Extract dependencies from a manifest
     */
    async extractDependencies(manifest) {
        let content;

        try {
            // Validate file size before reading
            Validator.validateFileSize(manifest.path, CONFIG.MAX_FILE_SIZE);
            content = fs.readFileSync(manifest.path, 'utf8');
        } catch (error) {
            throw new FileSystemError(
                `Failed to read manifest: ${error.message}`,
                manifest.path,
                'read'
            );
        }

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

            case 'nuget':
                return this.extractNuGetDependencies(content, manifest);

            case 'pub':
                return this.extractPubDependencies(content, manifest);

            case 'swift':
                return this.extractSwiftDependencies(content, manifest);

            case 'hex':
                return this.extractHexDependencies(content, manifest);

            case 'hackage':
                return this.extractHaskellDependencies(content, manifest);

            default:
                console.warn(`  [!]Unsupported ecosystem: ${manifest.ecosystem}`);
                return [];
        }
    }

    /**
     * Extract NPM dependencies
     */
    extractNpmDependencies(content, manifest) {
        try {
            if (manifest.filename === 'package.json') {
                // Validate JSON size
                Validator.validateJSONSize(content);

                const data = JSON.parse(content);
                const deps = { ...data.dependencies, ...data.devDependencies };

                // Validate dependency count
                const depCount = Object.keys(deps).length;
                Validator.validateDependencyCount(depCount);

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
            throw new ManifestParsingError(
                `Failed to parse package.json: ${error.message}`,
                manifest.path,
                { ecosystem: 'npm' }
            );
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
            // Basic TOML parsing for Poetry dependencies
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

            // PEP 621 project.dependencies
            const pep621Section = content.match(/\[project\]\s*\n([\s\S]*?)(\n\[|$)/);
            if (pep621Section) {
                const depsMatch = pep621Section[1].match(/dependencies\s*=\s*\[([\s\S]*?)\]/);
                if (depsMatch) {
                    const depLines = depsMatch[1].split('\n');
                    for (const line of depLines) {
                        const match = line.match(/["']([a-zA-Z0-9\-_]+)\s*([>=<~!]+\s*[\d.]+)?["']/);
                        if (match) {
                            deps.push({
                                name: match[1],
                                version: match[2] ? match[2].replace(/[>=<~!\s]/g, '') : 'latest',
                                ecosystem: 'pypi',
                                manifest: manifest.path
                            });
                        }
                    }
                }
            }
        } else if (manifest.filename === 'setup.cfg') {
            // Parse setup.cfg [options] install_requires
            const installReqSection = content.match(/install_requires\s*=\s*\n?([\s\S]*?)(?=\n\S|\n\[|$)/);
            if (installReqSection) {
                const lines = installReqSection[1].split('\n');
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
        } else if (manifest.filename === 'build.sbt') {
            // Extract SBT dependencies: "org" %% "artifact" % "version"
            const sbtRegex = /"([^"]+)"\s*%%?\s*"([^"]+)"\s*%\s*"([^"]+)"/g;
            let match;
            while ((match = sbtRegex.exec(content)) !== null) {
                deps.push({
                    name: `${match[1]}:${match[2]}`,
                    version: match[3],
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
                // Validate JSON size
                Validator.validateJSONSize(content);

                const data = JSON.parse(content);
                const deps = { ...data.require, ...data['require-dev'] };

                // Validate dependency count
                const depCount = Object.keys(deps).length;
                Validator.validateDependencyCount(depCount);

                // Optimized: single pass instead of filter + map
                return Object.entries(deps).reduce((acc, [name, version]) => {
                    if (name !== 'php') {  // Skip PHP itself
                        acc.push({
                            name,
                            version: version.replace(/[\^~]/g, ''),
                            ecosystem: 'packagist',
                            manifest: manifest.path
                        });
                    }
                    return acc;
                }, []);
            }
            return [];
        } catch (error) {
            throw new ManifestParsingError(
                `Failed to parse composer.json: ${error.message}`,
                manifest.path,
                { ecosystem: 'packagist' }
            );
        }
    }

    /**
     * Extract NuGet (.NET) dependencies from .csproj, .fsproj, .vbproj,
     * packages.config, .nuspec, Directory.Build.props, Directory.Packages.props files
     */
    extractNuGetDependencies(content, manifest) {
        const deps = [];
        const seen = new Set();

        const addDep = (name, version) => {
            if (name && !seen.has(name)) {
                seen.add(name);
                deps.push({
                    name,
                    version: version ? version.replace(/[\[\]\(\)]/g, '').split(',')[0].trim() : 'centrally-managed',
                    ecosystem: 'nuget',
                    manifest: manifest.path
                });
            }
        };

        try {
            // ── PackageReference: universal regex that handles all attribute orders,
            // multi-line, extra attributes, self-closing and non-self-closing tags ──

            // Strategy: find ALL PackageReference elements, then extract Include/Version from attributes
            const allPackageRefs = content.matchAll(/<PackageReference\b([^>]*?)(?:\/>|>([\s\S]*?)<\/PackageReference>)/gi);
            for (const m of allPackageRefs) {
                const attrs = m[1];
                const innerContent = m[2] || '';

                const includeMatch = attrs.match(/Include\s*=\s*["']([^"']+)["']/i);
                if (!includeMatch) continue;
                const name = includeMatch[1];

                // Version from attribute
                const versionAttrMatch = attrs.match(/Version\s*=\s*["']([^"']+)["']/i);
                if (versionAttrMatch) {
                    addDep(name, versionAttrMatch[1]);
                    continue;
                }

                // Version from child element
                const versionElemMatch = innerContent.match(/<Version>([^<]+)<\/Version>/i);
                if (versionElemMatch) {
                    addDep(name, versionElemMatch[1].trim());
                    continue;
                }

                // No version found (centrally managed)
                addDep(name, null);
            }

            // ── PackageVersion (Directory.Packages.props central management) ──
            if (manifest.filename === 'Directory.Packages.props') {
                const allPkgVersions = content.matchAll(/<PackageVersion\b([^>]*?)(?:\/>|>([\s\S]*?)<\/PackageVersion>)/gi);
                for (const m of allPkgVersions) {
                    const attrs = m[1];
                    const includeMatch = attrs.match(/Include\s*=\s*["']([^"']+)["']/i);
                    const versionMatch = attrs.match(/Version\s*=\s*["']([^"']+)["']/i);
                    if (includeMatch) {
                        addDep(includeMatch[1], versionMatch ? versionMatch[1] : null);
                    }
                }
            }

            // ── Legacy packages.config format ──
            if (manifest.filename === 'packages.config') {
                const allPackages = content.matchAll(/<package\b([^>]*?)\/?>/gi);
                for (const m of allPackages) {
                    const attrs = m[1];
                    const idMatch = attrs.match(/id\s*=\s*["']([^"']+)["']/i);
                    const versionMatch = attrs.match(/version\s*=\s*["']([^"']+)["']/i);
                    if (idMatch) {
                        addDep(idMatch[1], versionMatch ? versionMatch[1] : null);
                    }
                }
            }

            // ── .nuspec format ──
            if (manifest.filename.endsWith('.nuspec')) {
                const allNuspecDeps = content.matchAll(/<dependency\b([^>]*?)\/?>/gi);
                for (const m of allNuspecDeps) {
                    const attrs = m[1];
                    const idMatch = attrs.match(/id\s*=\s*["']([^"']+)["']/i);
                    const versionMatch = attrs.match(/version\s*=\s*["']([^"']+)["']/i);
                    if (idMatch) {
                        addDep(idMatch[1], versionMatch ? versionMatch[1] : null);
                    }
                }
            }

            // ── packages.lock.json ──
            if (manifest.filename === 'packages.lock.json') {
                try {
                    const lockData = JSON.parse(content);
                    if (lockData.dependencies) {
                        for (const [framework, packages] of Object.entries(lockData.dependencies)) {
                            for (const [name, info] of Object.entries(packages)) {
                                if (!seen.has(name)) {
                                    seen.add(name);
                                    deps.push({
                                        name,
                                        version: info.resolved || 'unknown',
                                        ecosystem: 'nuget',
                                        manifest: manifest.path,
                                        transitive: info.type === 'Transitive'
                                    });
                                }
                            }
                        }
                    }
                } catch (e) {
                    // Fall through
                }
            }

            if (deps.length > 0) {
                Validator.validateDependencyCount(deps.length);
            }

            return deps;
        } catch (error) {
            throw new ManifestParsingError(
                `Failed to parse .NET manifest: ${error.message}`,
                manifest.path,
                { ecosystem: 'nuget' }
            );
        }
    }

    /**
     * Extract Dart/Flutter dependencies from pubspec.yaml
     */
    extractPubDependencies(content, manifest) {
        const deps = [];

        if (manifest.filename === 'pubspec.yaml') {
            // Simple YAML parsing for dependencies section
            const sections = content.split(/\n(?=\w)/);
            for (const section of sections) {
                if (section.startsWith('dependencies:') || section.startsWith('dev_dependencies:')) {
                    const lines = section.split('\n').slice(1);
                    for (const line of lines) {
                        // Match: "  package_name: ^1.0.0" or "  package_name: any"
                        const match = line.match(/^\s{2}(\w[\w_-]*)\s*:\s*[\^~]?(\d[\d.]*\S*)/);
                        if (match) {
                            deps.push({
                                name: match[1],
                                version: match[2],
                                ecosystem: 'pub',
                                manifest: manifest.path
                            });
                        }
                    }
                }
            }
        }

        return deps;
    }

    /**
     * Extract Swift Package Manager dependencies from Package.swift
     */
    extractSwiftDependencies(content, manifest) {
        const deps = [];

        if (manifest.filename === 'Package.swift') {
            // Match .package(url: "https://github.com/org/repo.git", from: "1.0.0")
            const urlFromRegex = /\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*from\s*:\s*"([^"]+)"/g;
            let match;
            while ((match = urlFromRegex.exec(content)) !== null) {
                const url = match[1];
                const name = url.replace(/\.git$/, '').split('/').pop();
                deps.push({
                    name: name,
                    version: match[2],
                    ecosystem: 'swift',
                    manifest: manifest.path,
                    url: url
                });
            }

            // Match .package(url: "...", .upToNextMajor(from: "1.0.0"))
            const upToNextRegex = /\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.upToNext(?:Major|Minor)\s*\(\s*from\s*:\s*"([^"]+)"\s*\)/g;
            while ((match = upToNextRegex.exec(content)) !== null) {
                const url = match[1];
                const name = url.replace(/\.git$/, '').split('/').pop();
                if (!deps.find(d => d.name === name)) {
                    deps.push({
                        name: name,
                        version: match[2],
                        ecosystem: 'swift',
                        manifest: manifest.path,
                        url: url
                    });
                }
            }
        }

        return deps;
    }

    /**
     * Extract Elixir dependencies from mix.exs
     */
    extractHexDependencies(content, manifest) {
        const deps = [];

        if (manifest.filename === 'mix.exs') {
            // Match {:package_name, "~> 1.0"} or {:package_name, ">= 1.0.0"}
            const depRegex = /\{:(\w+)\s*,\s*"([^"]+)"\s*\}/g;
            let match;
            while ((match = depRegex.exec(content)) !== null) {
                deps.push({
                    name: match[1],
                    version: match[2].replace(/[~>=<\s]/g, ''),
                    ecosystem: 'hex',
                    manifest: manifest.path
                });
            }

            // Match {:package_name, "~> 1.0", only: :test}
            const depWithOptsRegex = /\{:(\w+)\s*,\s*"([^"]+)"\s*,\s*[^}]+\}/g;
            while ((match = depWithOptsRegex.exec(content)) !== null) {
                if (!deps.find(d => d.name === match[1])) {
                    deps.push({
                        name: match[1],
                        version: match[2].replace(/[~>=<\s]/g, ''),
                        ecosystem: 'hex',
                        manifest: manifest.path
                    });
                }
            }
        }

        return deps;
    }

    /**
     * Extract Haskell dependencies from package.yaml or .cabal files
     */
    extractHaskellDependencies(content, manifest) {
        const deps = [];

        if (manifest.filename === 'package.yaml') {
            // Match dependencies section in hpack format
            const depSection = content.match(/dependencies:\s*\n((?:\s+-\s+.+\n?)*)/);
            if (depSection) {
                const lines = depSection[1].split('\n');
                for (const line of lines) {
                    // Match: "  - package-name >= 1.0"
                    const match = line.match(/^\s+-\s+([a-zA-Z][\w-]*)\s*(.+)?$/);
                    if (match) {
                        const version = match[2] ? match[2].replace(/[>=<\s^]/g, '').trim() : 'any';
                        deps.push({
                            name: match[1],
                            version: version || 'any',
                            ecosystem: 'hackage',
                            manifest: manifest.path
                        });
                    }
                }
            }
        } else if (manifest.filename.endsWith('.cabal')) {
            // Match build-depends lines
            const buildDepsRegex = /build-depends\s*:\s*([\s\S]*?)(?=\n\S|\n\n|$)/gi;
            let section;
            while ((section = buildDepsRegex.exec(content)) !== null) {
                const depsStr = section[1];
                const depEntries = depsStr.split(',');
                for (const entry of depEntries) {
                    const match = entry.trim().match(/^([a-zA-Z][\w-]*)\s*(.*)?$/);
                    if (match && match[1] !== 'base') {
                        const version = match[2] ? match[2].replace(/[>=<&|\s^]/g, '').trim() : 'any';
                        deps.push({
                            name: match[1],
                            version: version || 'any',
                            ecosystem: 'hackage',
                            manifest: manifest.path
                        });
                    }
                }
            }
        }

        return deps;
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
                    verbose: this.options.verbose,
                    enableNVD: this.options.enableNVD,
                    enableGitHub: this.options.enableGitHub,
                    disableEPSS: this.options.disableEPSS,
                    disableKEV: this.options.disableKEV,
                    nvdApiKey: this.options.nvdApiKey,
                    githubToken: this.options.githubToken
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

        // Report which sources are active
        const firstDb = this.vulnDatabases.values().next().value;
        if (firstDb && firstDb.enabledSources) {
            const activeSources = Object.entries(firstDb.enabledSources)
                .filter(([, enabled]) => enabled)
                .map(([name]) => name.toUpperCase());
            console.log(`  [i]Active vulnerability sources: ${activeSources.join(', ')}`);
        }

        console.log(`  [OK]Found ${totalVulns} known vulnerabilities`);
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

                    case 'pypi': {
                        const pyAnalyzer = new PythonAnalyzer(this.reachabilityAnalyzer, {
                            ...this.options,
                            projectPath: manifestDir
                        });
                        pyAnalyzer.analyzeProject(manifestDir);
                        break;
                    }

                    case 'maven': {
                        const javaAnalyzer = new JavaAnalyzer(this.reachabilityAnalyzer, {
                            ...this.options,
                            projectPath: manifestDir
                        });
                        javaAnalyzer.analyzeProject(manifestDir);
                        break;
                    }

                    default:
                        if (this.options.verbose) {
                            console.log(`  [!]No analyzer for ${manifest.ecosystem} yet`);
                        }
                }
            } catch (error) {
                this.logger.warn('Error analyzing manifest directory', {
                    directory: manifest.directory,
                    ecosystem: manifest.ecosystem,
                    error: error.message
                });
                console.warn(`  [!]Error analyzing ${manifest.directory}: ${error.message}`);
            }
        }

        const stats = this.reachabilityAnalyzer.getStatistics();
        console.log(`  [OK]Built call graph: ${stats.totalNodes} nodes, ${stats.totalEdges} edges`);
    }

    /**
     * Phase 5: Detect entry points
     */
    async detectEntryPoints() {
        const projectPath = this.options.projectPath;

        // Get all source files from call graph
        const callGraph = this.reachabilityAnalyzer.getCallGraph();
        const fileSet = new Set(); // Use Set for O(1) uniqueness check

        for (const node of callGraph.nodes.keys()) {
            // Handle both Unix and Windows paths (C:\path\file.js:function)
            // Find the last colon that's not part of a drive letter
            const lastColonIndex = node.lastIndexOf(':');
            let file;

            if (lastColonIndex === -1) {
                file = node;  // No colon, entire string is the file
            } else {
                // Check if this might be a Windows drive letter (single char before first colon)
                const beforeColon = node.substring(0, lastColonIndex);
                if (beforeColon.length === 1) {
                    // This is likely "C:" drive letter, return whole string
                    file = node;
                } else {
                    file = beforeColon;
                }
            }

            if (file) {
                fileSet.add(file);
            }
        }

        const files = Array.from(fileSet);

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

        console.log(`  [OK]Detected ${entryPoints.length} entry points`);
    }

    /**
     * Phase 6: Perform reachability analysis
     */
    async performReachabilityAnalysis() {
        let vulnerabilityCount = 0;

        // Set the project path for import detection
        this.reachabilityAnalyzer.setProjectPath(this.options.projectPath);

        // Map vulnerabilities to functions
        for (const manifestDeps of this.allDependencies) {
            const vulnDb = this.vulnDatabases.get(manifestDeps.manifest.ecosystem);

            if (!vulnDb) {
                this.logger.debug('No vulnerability database for ecosystem', {
                    ecosystem: manifestDeps.manifest.ecosystem
                });
                continue;
            }

            for (const dep of manifestDeps.dependencies) {
                const vulns = vulnDb.getVulnerabilities(dep.name, dep.version);

                if (vulns.length > 0) {
                    this.logger.debug('Found vulnerabilities for dependency', {
                        package: dep.name,
                        version: dep.version,
                        count: vulns.length
                    });
                }

                for (const vuln of vulns) {
                    vulnerabilityCount++;

                    // Ensure package name is set in vulnerability
                    if (!vuln.package) {
                        vuln.package = dep.name;
                    }
                    if (!vuln.name) {
                        vuln.name = dep.name;
                    }

                    // For each vulnerable function, add as target
                    if (vuln.affectedFunctions && vuln.affectedFunctions.length > 0) {
                        for (const func of vuln.affectedFunctions) {
                            const location = `node_modules/${dep.name}/${func}`;
                            this.reachabilityAnalyzer.addVulnerabilityTarget(location, vuln);
                        }
                    } else {
                        // Generic package-level vulnerability - use package name as location
                        const location = dep.name;
                        this.reachabilityAnalyzer.addVulnerabilityTarget(location, vuln);
                    }
                }
            }
        }

        this.logger.info('Added vulnerabilities to analyzer', { count: vulnerabilityCount });

        // Analyze reachability for all vulnerabilities
        this.results = this.reachabilityAnalyzer.analyzeAll();

        console.log(`  [OK]Analyzed ${this.results.length} potential vulnerabilities`);
    }

    /**
     * Phase 6.3: Detect dangerous API usage patterns across the codebase
     */
    async detectDangerousPatterns() {
        const importDetector = new ImportDetector(this.options);
        const fileWalker = new FileWalker({
            maxDepth: this.options.maxDepth,
            excludeDirs: ['node_modules', '.git', 'dist', 'build', 'target', '__pycache__', 'venv', '.venv', 'vendor']
        });

        const projectPath = this.options.projectPath;
        const sourceFiles = fileWalker.findFiles(projectPath, [
            '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
            '.py', '.java', '.go', '.rs', '.rb', '.php', '.cs'
        ]);

        let totalPatterns = 0;
        this.dangerousPatterns = [];

        for (const file of sourceFiles) {
            try {
                const content = fs.readFileSync(file, 'utf-8');
                if (content.length > 5 * 1024 * 1024) continue; // Skip files > 5MB

                const patterns = importDetector.detectDangerousPatterns(content, file);
                if (patterns.length > 0) {
                    this.dangerousPatterns.push(...patterns);
                    totalPatterns += patterns.length;
                }
            } catch (error) {
                // Skip unreadable files
            }
        }

        if (totalPatterns > 0) {
            // Group by category
            const byCategory = {};
            for (const p of this.dangerousPatterns) {
                byCategory[p.category] = (byCategory[p.category] || 0) + 1;
            }

            console.log(`  [!]Found ${totalPatterns} dangerous API patterns:`);
            for (const [category, count] of Object.entries(byCategory)) {
                console.log(`    - ${category}: ${count}`);
            }

            // Cross-reference dangerous patterns with vulnerability results
            // If a vulnerable package is used in a dangerous pattern, boost confidence
            for (const result of this.results) {
                if (!result.vulnerability) continue;
                const vulnPkg = result.vulnerability.package || result.vulnerability.name;
                if (!vulnPkg) continue;

                for (const pattern of this.dangerousPatterns) {
                    // Check if the dangerous pattern is in a file that imports the vulnerable package
                    const fileImports = importDetector.detectImportsInFile(pattern.filePath, vulnPkg);
                    if (fileImports.length > 0) {
                        result.dangerousPatternMatch = pattern;
                        result.confidence = Math.min(0.99, result.confidence + 0.15);
                        if (!result.riskFactors) result.riskFactors = [];
                        result.riskFactors.push({
                            type: 'dangerous-api-pattern',
                            category: pattern.category,
                            severity: pattern.severity,
                            description: `${pattern.description} in ${path.basename(pattern.filePath)}:${pattern.lineNumber}`
                        });
                    }
                }
            }
        } else {
            console.log('  [OK]No dangerous API patterns detected');
        }
    }

    /**
     * Phase 6.5: Data Flow Analysis (NEW)
     */
    async performDataFlowAnalysis() {
        if (!this.dataFlowAnalyzer || this.results.length === 0) {
            return;
        }

        console.log('\n[6.5/7] Performing data flow analysis...');

        // Set call graph
        this.dataFlowAnalyzer.setCallGraph(this.reachabilityAnalyzer.getCallGraph());

        // Get entry points
        const entryPoints = Array.from(this.reachabilityAnalyzer.entryPoints);

        // Analyze each result
        let taintedCount = 0;
        for (const result of this.results) {
            try {
                const flowResult = this.dataFlowAnalyzer.analyzeFlow(result, entryPoints);

                // Enrich result with data flow info
                result.dataFlow = flowResult;

                // Merge confidence scores
                if (flowResult.isTainted && flowResult.confidence > 0.60) {
                    result.enhancedConfidence = Math.min(
                        0.98,
                        result.confidence + (flowResult.confidence * 0.3)
                    );
                } else {
                    result.enhancedConfidence = result.confidence;
                }

                if (flowResult.isTainted) {
                    taintedCount++;
                }
            } catch (error) {
                this.logger.warn('Data flow analysis failed for finding', {
                    vulnerability: result.vulnerability?.id,
                    error: error.message
                });
            }
        }

        console.log(`  [OK] Found ${taintedCount} vulnerabilities with user input taint paths`);
    }

    /**
     * Phase 6.8: ML Risk Prediction (NEW)
     */
    async performMLAnalysis() {
        if (!this.mlManager || this.results.length === 0) {
            return;
        }

        console.log('\n[6.8/7] Applying ML risk prediction...');

        try {
            // Enrich all results with ML predictions
            this.results = this.mlManager.enrichFindings(this.results);

            const modelInfo = this.mlManager.getModelInfo();

            if (modelInfo.status === 'trained') {
                console.log(`  [OK]Using trained model (accuracy: ${(modelInfo.accuracy * 100).toFixed(1)}%, ${modelInfo.samples} samples)`);
            } else {
                console.log(`  [OK]Using default risk scoring (collect feedback to train custom model)`);
            }
        } catch (error) {
            this.logger.error('ML analysis failed', { error: error.message });
            console.log(`  [!]ML analysis failed: ${error.message}`);
        }
    }

    /**
     * Phase 7: Generate results
     */
    generateResults() {
        // Filter by confidence threshold
        const filtered = this.results.filter(r =>
            r.confidence >= this.options.minConfidence
        );

        // Sort by ML risk score if available, otherwise by confidence
        filtered.sort((a, b) => {
            if (a.mlPrediction && b.mlPrediction) {
                return b.mlPrediction.riskScore - a.mlPrediction.riskScore;
            }
            return b.confidence - a.confidence;
        });

        this.results = filtered;

        console.log(`  [OK]${this.results.length} high-confidence findings`);
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
            entryPoints: callGraphStats.entryPoints,
            dangerousPatterns: this.dangerousPatterns ? this.dangerousPatterns.length : 0,
            workspaces: this.workspaceConfig ? this.workspaceConfig.length : 0,
            shaiHulud: this.shaiHuludFindings ? this.shaiHuludDetector.getSummary() : { total: 0, byType: {}, highSeverity: 0 }
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

    /**
     * Cleanup resources and reset state
     * Call this on errors or when scanner is no longer needed
     */
    cleanup() {
        if (this.reachabilityAnalyzer) {
            this.reachabilityAnalyzer.clear();
        }

        if (this.vulnDatabases) {
            this.vulnDatabases.clear();
        }

        if (this.transitiveCache) {
            this.transitiveCache.clear();
        }

        this.results = [];
        this.manifests = [];
        this.allDependencies = [];
        this.failedManifests = [];
        this.shaiHuludFindings = [];

        this.logger.debug('Scanner cleanup completed');
    }

    /**
     * Dispose of scanner and free resources
     * Alias for cleanup()
     */
    dispose() {
        this.cleanup();
    }
}

module.exports = DepGuardScanner2;
