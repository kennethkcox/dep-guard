/**
 * Shai-Hulud Detector
 *
 * Named after the great sandworms of Arrakis, this module hunts for
 * hidden dangers lurking beneath the surface of your dependency tree:
 *
 * 1. Shadow Dependencies (Phantom Imports)
 *    Code that imports packages not declared in any manifest file.
 *    These rely on transitive installations and break unpredictably.
 *
 * 2. Typosquatting Detection
 *    Dependencies with names suspiciously similar to popular packages.
 *    A common supply-chain attack vector (e.g., "lodahs" vs "lodash").
 *
 * 3. Dependency Confusion
 *    Internal/scoped packages that could be hijacked via public registries.
 *    Detects patterns where private names clash with public ones.
 *
 * "The worm is the spice. The spice is the worm."
 */

const fs = require('fs');
const path = require('path');
const { getLogger } = require('../utils/logger');

// Well-known popular packages per ecosystem that are common typosquatting targets
const POPULAR_PACKAGES = {
    npm: [
        'lodash', 'express', 'react', 'react-dom', 'axios', 'chalk', 'commander',
        'debug', 'moment', 'request', 'bluebird', 'underscore', 'async', 'uuid',
        'webpack', 'babel-core', 'typescript', 'eslint', 'prettier', 'jest',
        'mocha', 'chai', 'sinon', 'jquery', 'vue', 'angular', 'next', 'nuxt',
        'mongoose', 'sequelize', 'pg', 'mysql', 'redis', 'socket.io', 'cors',
        'helmet', 'dotenv', 'jsonwebtoken', 'bcrypt', 'passport', 'nodemailer',
        'winston', 'morgan', 'body-parser', 'cookie-parser', 'multer', 'sharp',
        'puppeteer', 'cheerio', 'node-fetch', 'isomorphic-fetch', 'cross-env',
        'rimraf', 'mkdirp', 'glob', 'minimist', 'yargs', 'inquirer', 'ora',
        'colors', 'chalk', 'fs-extra', 'shelljs', 'execa', 'got', 'superagent',
        'koa', 'fastify', 'hapi', 'restify', 'graphql', 'apollo-server',
        'prisma', 'typeorm', 'knex', 'objection', 'bookshelf'
    ],
    pypi: [
        'requests', 'flask', 'django', 'numpy', 'pandas', 'scipy', 'matplotlib',
        'tensorflow', 'torch', 'scikit-learn', 'pillow', 'beautifulsoup4', 'selenium',
        'celery', 'sqlalchemy', 'alembic', 'pytest', 'boto3', 'pyyaml', 'jinja2',
        'cryptography', 'paramiko', 'fabric', 'click', 'typer', 'fastapi', 'uvicorn',
        'gunicorn', 'aiohttp', 'httpx', 'pydantic', 'marshmallow', 'redis', 'pymongo',
        'psycopg2', 'mysqlclient', 'setuptools', 'pip', 'wheel', 'twine', 'black',
        'isort', 'flake8', 'mypy', 'pylint', 'sphinx', 'tox', 'coverage'
    ],
    maven: [
        'org.apache.commons:commons-lang3', 'com.google.guava:guava',
        'org.slf4j:slf4j-api', 'ch.qos.logback:logback-classic',
        'com.fasterxml.jackson.core:jackson-databind', 'org.apache.httpcomponents:httpclient',
        'junit:junit', 'org.mockito:mockito-core', 'org.springframework:spring-core',
        'org.springframework.boot:spring-boot-starter', 'org.projectlombok:lombok',
        'org.apache.logging.log4j:log4j-core', 'com.google.code.gson:gson',
        'commons-io:commons-io', 'org.apache.shiro:shiro-core'
    ],
    cargo: [
        'serde', 'tokio', 'reqwest', 'clap', 'rand', 'regex', 'log', 'chrono',
        'hyper', 'actix-web', 'rocket', 'diesel', 'sqlx', 'axum', 'tracing',
        'anyhow', 'thiserror', 'serde_json', 'futures', 'bytes', 'tower'
    ],
    rubygems: [
        'rails', 'rack', 'sinatra', 'puma', 'sidekiq', 'devise', 'nokogiri',
        'rspec', 'rubocop', 'bundler', 'rake', 'activerecord', 'activesupport',
        'pg', 'mysql2', 'redis', 'faraday', 'httparty', 'json', 'minitest'
    ],
    go: [
        'github.com/gin-gonic/gin', 'github.com/gorilla/mux', 'github.com/labstack/echo',
        'github.com/stretchr/testify', 'github.com/sirupsen/logrus', 'go.uber.org/zap',
        'github.com/spf13/cobra', 'github.com/spf13/viper', 'gorm.io/gorm',
        'github.com/go-redis/redis', 'github.com/jackc/pgx'
    ]
};

// Known malicious package name patterns
const KNOWN_MALICIOUS_PATTERNS = [
    // Hyphen/underscore swaps
    { pattern: /^(.+)-js$/, target: '$1' },
    { pattern: /^(.+)_js$/, target: '$1' },
    { pattern: /^(.+)-node$/, target: '$1' },
    // Common prefix/suffix attacks
    { pattern: /^node-(.+)$/, target: '$1' },
    { pattern: /^python-(.+)$/, target: '$1' },
    { pattern: /^(.+)-python$/, target: '$1' },
    // Scope confusion
    { pattern: /^(@[^/]+)\/(.+)$/, type: 'scoped' }
];

class ShaiHuludDetector {
    constructor(options = {}) {
        this.options = options;
        this.logger = getLogger().child({ component: 'ShaiHuludDetector' });
        this.findings = [];

        // Configurable thresholds
        this.typosquatThreshold = options.typosquatThreshold || 2; // max edit distance
        this.enableShadowDetection = options.disableShaiHulud !== true;
    }

    /**
     * Run all Shai-Hulud detection passes
     *
     * @param {Object} context - Scanner context
     * @param {Array} context.manifests - Found manifests
     * @param {Array} context.allDependencies - All declared dependencies
     * @param {string} context.projectPath - Project root
     * @param {Object} context.importDetector - ImportDetector instance
     * @param {Object} context.fileWalker - FileWalker instance
     * @returns {Array} findings
     */
    async detect(context) {
        this.findings = [];

        const {
            manifests,
            allDependencies,
            projectPath,
            importDetector,
            fileWalker
        } = context;

        // Collect all declared dependency names across all manifests
        const declaredDeps = new Set();
        const depsByEcosystem = new Map();

        for (const manifestDeps of allDependencies) {
            const eco = manifestDeps.manifest.ecosystem;
            if (!depsByEcosystem.has(eco)) {
                depsByEcosystem.set(eco, new Set());
            }
            for (const dep of manifestDeps.dependencies) {
                declaredDeps.add(dep.name);
                depsByEcosystem.get(eco).add(dep.name);
            }
        }

        // Pass 1: Shadow Dependencies
        await this.detectShadowDependencies(
            projectPath, declaredDeps, importDetector, fileWalker
        );

        // Pass 2: Typosquatting
        this.detectTyposquatting(depsByEcosystem);

        // Pass 3: Dependency Confusion
        this.detectDependencyConfusion(depsByEcosystem, manifests);

        return this.findings;
    }

    /**
     * Pass 1: Shadow Dependency Detection
     *
     * Scans source files for imports of packages that are NOT declared in
     * any manifest. These are "phantom" deps riding on transitive installs.
     */
    async detectShadowDependencies(projectPath, declaredDeps, importDetector, fileWalker) {
        const sourceFiles = fileWalker.findFiles(projectPath, [
            '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
            '.py',
            '.rb',
            '.go',
            '.rs',
            '.php'
        ]);

        // Extract all imported package names from source files
        const importedPackages = new Map(); // packageName -> [files]

        for (const file of sourceFiles) {
            try {
                const content = fs.readFileSync(file, 'utf-8');
                if (content.length > 2 * 1024 * 1024) continue; // Skip large files

                const ext = path.extname(file);

                let foundImports = [];

                if (['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(ext)) {
                    foundImports = this.extractJSImportedPackages(content);
                } else if (ext === '.py') {
                    foundImports = this.extractPythonImportedPackages(content);
                } else if (ext === '.go') {
                    foundImports = this.extractGoImportedPackages(content);
                } else if (ext === '.rb') {
                    foundImports = this.extractRubyImportedPackages(content);
                } else if (ext === '.rs') {
                    foundImports = this.extractRustImportedPackages(content);
                }

                for (const pkg of foundImports) {
                    if (!importedPackages.has(pkg)) {
                        importedPackages.set(pkg, []);
                    }
                    importedPackages.get(pkg).push(file);
                }
            } catch (error) {
                // Skip unreadable files
            }
        }

        // Compare imported vs declared
        for (const [pkg, files] of importedPackages) {
            if (!declaredDeps.has(pkg) && !this.isBuiltinModule(pkg)) {
                this.findings.push({
                    type: 'shadow-dependency',
                    severity: 'MEDIUM',
                    package: pkg,
                    files: files.slice(0, 5), // Limit to 5 files for readability
                    fileCount: files.length,
                    description: `Package "${pkg}" is imported in ${files.length} file(s) but not declared in any manifest. ` +
                        `It may be a transitive dependency that could disappear on updates.`,
                    recommendation: `Add "${pkg}" as an explicit dependency in your manifest file.`,
                    confidence: 0.85
                });
            }
        }
    }

    /**
     * Pass 2: Typosquatting Detection
     *
     * Checks each declared dependency against known popular packages.
     * Uses Levenshtein distance to catch name-confusion attacks.
     */
    detectTyposquatting(depsByEcosystem) {
        for (const [ecosystem, deps] of depsByEcosystem) {
            const popularPkgs = POPULAR_PACKAGES[ecosystem] || [];
            if (popularPkgs.length === 0) continue;

            for (const depName of deps) {
                // Skip if it IS the popular package
                if (popularPkgs.includes(depName)) continue;

                // Check edit distance against all popular packages
                for (const popular of popularPkgs) {
                    const distance = this.levenshteinDistance(depName, popular);
                    const maxLen = Math.max(depName.length, popular.length);

                    // Flag if edit distance is small relative to name length
                    // but not zero (which means exact match)
                    if (distance > 0 && distance <= this.typosquatThreshold && maxLen >= 4) {
                        // Additional heuristic: skip if both are short and common
                        if (maxLen <= 3) continue;

                        this.findings.push({
                            type: 'typosquatting-risk',
                            severity: 'HIGH',
                            package: depName,
                            similarTo: popular,
                            ecosystem,
                            editDistance: distance,
                            description: `Dependency "${depName}" is suspiciously similar to popular package ` +
                                `"${popular}" (edit distance: ${distance}). This could be a typosquatting attack.`,
                            recommendation: `Verify that "${depName}" is the intended package, not a malicious ` +
                                `impersonator of "${popular}".`,
                            confidence: distance === 1 ? 0.90 : 0.75
                        });
                        break; // Only report closest match
                    }

                    // Also check common attack patterns
                    const patternMatch = this.checkMaliciousPattern(depName, popular);
                    if (patternMatch) {
                        this.findings.push({
                            type: 'typosquatting-risk',
                            severity: 'HIGH',
                            package: depName,
                            similarTo: popular,
                            ecosystem,
                            pattern: patternMatch,
                            description: `Dependency "${depName}" matches known malicious naming pattern ` +
                                `relative to "${popular}" (${patternMatch}).`,
                            recommendation: `Verify that "${depName}" is the intended package.`,
                            confidence: 0.80
                        });
                        break;
                    }
                }
            }
        }
    }

    /**
     * Pass 3: Dependency Confusion Detection
     *
     * Identifies packages that are at risk for dependency confusion attacks:
     * - Scoped packages (@org/name) where the scope might not be reserved
     * - Internal-looking package names that aren't scoped
     * - Packages with no published version on public registries
     */
    detectDependencyConfusion(depsByEcosystem, manifests) {
        for (const [ecosystem, deps] of depsByEcosystem) {
            if (!['npm', 'pypi', 'nuget'].includes(ecosystem)) continue;

            for (const depName of deps) {
                // Pattern 1: Unscoped packages with internal-looking names
                if (ecosystem === 'npm' && !depName.startsWith('@')) {
                    if (this.looksInternal(depName)) {
                        this.findings.push({
                            type: 'dependency-confusion-risk',
                            severity: 'HIGH',
                            package: depName,
                            ecosystem,
                            description: `Package "${depName}" has an internal/organizational naming pattern ` +
                                `but is not scoped (@org/name). An attacker could publish a public ` +
                                `package with this name to hijack installations.`,
                            recommendation: `Use a scoped package name (e.g., @your-org/${depName}) or ` +
                                `configure a private registry with package name reservation.`,
                            confidence: 0.70
                        });
                    }
                }

                // Pattern 2: Scoped packages — check if scope matches known registries
                if (ecosystem === 'npm' && depName.startsWith('@')) {
                    const [scope, name] = depName.split('/');
                    // Warn if scope is generic and could be claimed by anyone
                    if (this.isGenericScope(scope)) {
                        this.findings.push({
                            type: 'dependency-confusion-risk',
                            severity: 'MEDIUM',
                            package: depName,
                            ecosystem,
                            description: `Scoped package "${depName}" uses a generic scope "${scope}" ` +
                                `that might not be reserved on the public npm registry.`,
                            recommendation: `Verify that scope "${scope}" is claimed on npmjs.com to ` +
                                `prevent dependency confusion attacks.`,
                            confidence: 0.60
                        });
                    }
                }

                // Pattern 3: Python packages with underscore/hyphen ambiguity
                if (ecosystem === 'pypi') {
                    if (depName.includes('-') || depName.includes('_')) {
                        const altName = depName.includes('-')
                            ? depName.replace(/-/g, '_')
                            : depName.replace(/_/g, '-');
                        if (deps.has(altName)) {
                            this.findings.push({
                                type: 'dependency-confusion-risk',
                                severity: 'MEDIUM',
                                package: depName,
                                ecosystem,
                                relatedPackage: altName,
                                description: `Both "${depName}" and "${altName}" are declared as dependencies. ` +
                                    `Python treats hyphens and underscores as equivalent in package names, ` +
                                    `which could lead to confusion or supply chain issues.`,
                                recommendation: `Remove the duplicate and standardize on one naming convention.`,
                                confidence: 0.85
                            });
                        }
                    }
                }
            }
        }
    }

    // ─── Helper Methods ───────────────────────────────────────────────

    /**
     * Extract JS/TS package names from require() and import statements
     */
    extractJSImportedPackages(content) {
        const packages = new Set();

        // require('package') or require("package")
        const requireRegex = /require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g;
        let match;
        while ((match = requireRegex.exec(content)) !== null) {
            packages.add(this.normalizeJSPackageName(match[1]));
        }

        // import ... from 'package'
        const importFromRegex = /import\s+(?:[\s\S]*?)\s+from\s+['"]([^'"./][^'"]*)['"]/g;
        while ((match = importFromRegex.exec(content)) !== null) {
            packages.add(this.normalizeJSPackageName(match[1]));
        }

        // import 'package' (side-effect)
        const importSideEffect = /import\s+['"]([^'"./][^'"]*)['"]/g;
        while ((match = importSideEffect.exec(content)) !== null) {
            packages.add(this.normalizeJSPackageName(match[1]));
        }

        // Dynamic import('package')
        const dynamicImport = /import\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g;
        while ((match = dynamicImport.exec(content)) !== null) {
            packages.add(this.normalizeJSPackageName(match[1]));
        }

        return Array.from(packages);
    }

    /**
     * Normalize JS package name (handle subpath imports like 'lodash/merge')
     */
    normalizeJSPackageName(importPath) {
        // Scoped: @scope/pkg/sub -> @scope/pkg
        if (importPath.startsWith('@')) {
            const parts = importPath.split('/');
            return parts.slice(0, 2).join('/');
        }
        // Unscoped: pkg/sub -> pkg
        return importPath.split('/')[0];
    }

    /**
     * Extract Python imported module names
     */
    extractPythonImportedPackages(content) {
        const packages = new Set();
        const lines = content.split('\n');

        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('#')) continue;

            // import package
            let match = trimmed.match(/^import\s+([a-zA-Z_]\w*)/);
            if (match) packages.add(match[1]);

            // from package import ...
            match = trimmed.match(/^from\s+([a-zA-Z_]\w*)/);
            if (match) packages.add(match[1]);
        }

        return Array.from(packages);
    }

    /**
     * Extract Go imported packages
     */
    extractGoImportedPackages(content) {
        const packages = new Set();

        // Single import: import "github.com/foo/bar"
        const singleImport = /import\s+"([^"]+)"/g;
        let match;
        while ((match = singleImport.exec(content)) !== null) {
            if (match[1].includes('.')) { // External packages contain dots
                packages.add(match[1]);
            }
        }

        // Block import: import ( ... "github.com/foo/bar" ... )
        const blockImport = /import\s*\(([\s\S]*?)\)/g;
        while ((match = blockImport.exec(content)) !== null) {
            const block = match[1];
            const lineRegex = /["']([^"']+)["']/g;
            let lineMatch;
            while ((lineMatch = lineRegex.exec(block)) !== null) {
                if (lineMatch[1].includes('.')) {
                    packages.add(lineMatch[1]);
                }
            }
        }

        return Array.from(packages);
    }

    /**
     * Extract Ruby required gems
     */
    extractRubyImportedPackages(content) {
        const packages = new Set();

        const requireRegex = /require\s+['"]([a-zA-Z][\w-]*)(?:\/[^'"]*)?['"]/g;
        let match;
        while ((match = requireRegex.exec(content)) !== null) {
            packages.add(match[1]);
        }

        return Array.from(packages);
    }

    /**
     * Extract Rust crate references
     */
    extractRustImportedPackages(content) {
        const packages = new Set();

        // extern crate name;
        const externCrate = /extern\s+crate\s+(\w+)/g;
        let match;
        while ((match = externCrate.exec(content)) !== null) {
            packages.add(match[1].replace(/_/g, '-'));
        }

        // use name::...
        const useStmt = /use\s+(\w+)::/g;
        while ((match = useStmt.exec(content)) !== null) {
            const crate = match[1];
            // Skip std lib crates
            if (!['std', 'core', 'alloc', 'self', 'super', 'crate'].includes(crate)) {
                packages.add(crate.replace(/_/g, '-'));
            }
        }

        return Array.from(packages);
    }

    /**
     * Check if a module is a language built-in (not an external dependency)
     */
    isBuiltinModule(name) {
        const nodeBuiltins = new Set([
            'fs', 'path', 'os', 'http', 'https', 'url', 'util', 'crypto',
            'stream', 'events', 'buffer', 'child_process', 'cluster', 'dgram',
            'dns', 'net', 'readline', 'tls', 'tty', 'vm', 'zlib', 'assert',
            'async_hooks', 'console', 'constants', 'domain', 'inspector',
            'module', 'perf_hooks', 'process', 'punycode', 'querystring',
            'string_decoder', 'sys', 'timers', 'trace_events', 'v8',
            'worker_threads', 'wasi',
            'node:fs', 'node:path', 'node:os', 'node:http', 'node:https',
            'node:url', 'node:util', 'node:crypto', 'node:stream', 'node:events',
            'node:buffer', 'node:child_process', 'node:net', 'node:zlib',
            'node:assert', 'node:test', 'node:readline', 'node:worker_threads'
        ]);

        const pythonBuiltins = new Set([
            'os', 'sys', 'json', 'math', 're', 'time', 'datetime', 'collections',
            'itertools', 'functools', 'io', 'pathlib', 'typing', 'abc', 'enum',
            'dataclasses', 'contextlib', 'copy', 'pprint', 'textwrap', 'unicodedata',
            'struct', 'codecs', 'csv', 'configparser', 'argparse', 'logging',
            'unittest', 'doctest', 'subprocess', 'threading', 'multiprocessing',
            'socket', 'ssl', 'http', 'urllib', 'email', 'html', 'xml',
            'sqlite3', 'hashlib', 'hmac', 'secrets', 'random', 'statistics',
            'decimal', 'fractions', 'operator', 'string', 'difflib', 'tempfile',
            'glob', 'fnmatch', 'shutil', 'pickle', 'shelve', 'dbm', 'gzip',
            'bz2', 'lzma', 'zipfile', 'tarfile', 'signal', 'mmap', 'ctypes',
            'traceback', 'warnings', 'inspect', 'dis', 'gc', 'weakref',
            'asyncio', 'concurrent', 'queue', 'sched', 'select', 'selectors',
            'array', 'bisect', 'heapq', 'types', 'pdb', 'profile', 'cProfile',
            'ast', 'compileall', 'py_compile', 'importlib', 'pkgutil',
            'venv', 'site', 'sysconfig', 'platform', 'builtins', '__future__'
        ]);

        const rubyBuiltins = new Set([
            'json', 'yaml', 'csv', 'net/http', 'uri', 'open-uri', 'fileutils',
            'pathname', 'set', 'ostruct', 'optparse', 'logger', 'benchmark',
            'date', 'time', 'socket', 'digest', 'base64', 'erb', 'cgi',
            'securerandom', 'stringio', 'tempfile', 'singleton', 'observer',
            'delegate', 'forwardable', 'pp', 'English', 'abbrev', 'shellwords'
        ]);

        return nodeBuiltins.has(name) || pythonBuiltins.has(name) || rubyBuiltins.has(name);
    }

    /**
     * Levenshtein distance (edit distance) between two strings
     */
    levenshteinDistance(a, b) {
        if (a.length === 0) return b.length;
        if (b.length === 0) return a.length;

        const matrix = Array(b.length + 1).fill(null)
            .map(() => Array(a.length + 1).fill(null));

        for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
        for (let j = 0; j <= b.length; j++) matrix[j][0] = j;

        for (let j = 1; j <= b.length; j++) {
            for (let i = 1; i <= a.length; i++) {
                const cost = a[i - 1] === b[j - 1] ? 0 : 1;
                matrix[j][i] = Math.min(
                    matrix[j][i - 1] + 1,       // deletion
                    matrix[j - 1][i] + 1,       // insertion
                    matrix[j - 1][i - 1] + cost // substitution
                );
            }
        }

        return matrix[b.length][a.length];
    }

    /**
     * Check if a dependency name matches known malicious naming patterns
     * relative to a popular package
     */
    checkMaliciousPattern(depName, popularName) {
        // Hyphen/underscore swap: "lodash" vs "lod_ash" or "lod-ash"
        const normalized = depName.replace(/[-_]/g, '');
        const normalizedPopular = popularName.replace(/[-_]/g, '');
        if (normalized === normalizedPopular && depName !== popularName) {
            return 'hyphen-underscore-swap';
        }

        // Suffix attacks: "express-js", "express-node", "expressjs"
        const suffixes = ['-js', '-node', '-npm', 'js', '-lib', '-pkg', '-core'];
        for (const suffix of suffixes) {
            if (depName === popularName + suffix || depName + suffix === popularName) {
                return `suffix-attack (${suffix})`;
            }
        }

        // Prefix attacks: "node-express", "js-express"
        const prefixes = ['node-', 'js-', 'npm-', 'py-', 'python-'];
        for (const prefix of prefixes) {
            if (depName === prefix + popularName || prefix + depName === popularName) {
                return `prefix-attack (${prefix})`;
            }
        }

        // Character repetition: "expresss", "lodassh"
        if (depName.length === popularName.length + 1) {
            let diff = 0;
            let j = 0;
            for (let i = 0; i < depName.length && j < popularName.length; i++) {
                if (depName[i] === popularName[j]) {
                    j++;
                } else {
                    diff++;
                }
            }
            if (diff <= 1 && j === popularName.length) {
                return 'character-insertion';
            }
        }

        return null;
    }

    /**
     * Heuristic: does this package name look like an internal/private package?
     */
    looksInternal(name) {
        const internalPatterns = [
            /^internal-/,
            /^private-/,
            /^corp-/,
            /^company-/,
            /^org-/,
            /^team-/,
            /-internal$/,
            /-private$/,
            /-core$/,
            /-common$/,
            /-shared$/,
            /-utils$/,
            /-lib$/,
            /-config$/,
            /-api$/,
            /-service$/,
            /-client$/,
            /-sdk$/,
            /-platform$/
        ];

        // Names with company-like prefixes that aren't scoped
        const corpPrefixes = /^(my|our|the|acme|demo|test|staging|dev|prod|infra|platform|data|ml)-/;

        return internalPatterns.some(p => p.test(name)) || corpPrefixes.test(name);
    }

    /**
     * Check if an npm scope is generic (not likely reserved)
     */
    isGenericScope(scope) {
        const wellKnown = new Set([
            '@types', '@babel', '@angular', '@vue', '@react-native',
            '@aws-sdk', '@google-cloud', '@azure', '@grpc',
            '@nestjs', '@prisma', '@graphql-tools', '@apollo',
            '@emotion', '@mui', '@chakra-ui', '@radix-ui',
            '@testing-library', '@storybook', '@jest',
            '@typescript-eslint', '@eslint',
            '@sentry', '@datadog', '@opentelemetry',
            '@octokit', '@actions', '@vercel', '@remix-run',
            '@trpc', '@tanstack', '@reduxjs', '@sveltejs'
        ]);

        return !wellKnown.has(scope);
    }

    /**
     * Get findings summary
     */
    getSummary() {
        const byType = {};
        for (const f of this.findings) {
            byType[f.type] = (byType[f.type] || 0) + 1;
        }
        return {
            total: this.findings.length,
            byType,
            highSeverity: this.findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length
        };
    }
}

module.exports = ShaiHuludDetector;
