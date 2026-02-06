const fs = require('fs');
const path = require('path');

/**
 * GenericManifestFinder
 *
 * Finds dependency manifest files ANYWHERE in a project tree.
 *
 * ZERO ASSUMPTIONS:
 * - No hardcoded locations (not just root directory)
 * - No expected structure (works with monorepos, microservices, etc.)
 * - Pattern-based identification (recognizes 10+ manifest types)
 *
 * SUPPORTS:
 * - Node.js: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
 * - Python: requirements.txt, Pipfile, Pipfile.lock, pyproject.toml, setup.py
 * - Java: pom.xml, build.gradle, build.gradle.kts, gradle.properties
 * - Go: go.mod, go.sum
 * - Rust: Cargo.toml, Cargo.lock
 * - Ruby: Gemfile, Gemfile.lock
 * - PHP: composer.json, composer.lock
 * - .NET: *.csproj, *.fsproj, *.vbproj, packages.config, *.nuspec,
 *         Directory.Build.props, Directory.Packages.props, packages.lock.json
 * - Swift: Package.swift, Package.resolved
 * - Elixir: mix.exs, mix.lock
 * - Scala: build.sbt
 * - Haskell: cabal.project, stack.yaml, package.yaml
 *
 * FEATURES:
 * - Recursive directory walking with depth limits
 * - Smart filtering (excludes node_modules, .git, build artifacts)
 * - Manifest type detection with confidence scoring
 * - Monorepo support (finds all manifests in all services)
 * - Duplicate detection (handles workspaces correctly)
 */

class GenericManifestFinder {
    constructor(options = {}) {
        this.options = {
            maxDepth: options.maxDepth || 10,
            followSymlinks: options.followSymlinks || false,
            excludeDirs: options.excludeDirs || [
                'node_modules',
                '.git',
                '.svn',
                '.hg',
                'dist',
                'build',
                'target',
                'out',
                '.next',
                '.nuxt',
                '__pycache__',
                'venv',
                'env',
                '.venv',
                'vendor'
            ],
            excludePatterns: options.excludePatterns || [
                /\/test\//i,
                /\/tests\//i,
                /\/__tests__\//i,
                /\/fixtures\//i,
                /\/mocks\//i,
                /\.test\./i,
                /\.spec\./i
            ],
            verbose: options.verbose || false
        };

        // Manifest patterns with confidence scores
        this.manifestPatterns = [
            // Node.js ecosystem
            {
                filename: 'package.json',
                ecosystem: 'npm',
                type: 'manifest',
                confidence: 1.0,
                validator: this.validatePackageJson.bind(this)
            },
            {
                filename: 'package-lock.json',
                ecosystem: 'npm',
                type: 'lockfile',
                confidence: 0.9,
                validator: this.validatePackageLockJson.bind(this)
            },
            {
                filename: 'yarn.lock',
                ecosystem: 'npm',
                type: 'lockfile',
                confidence: 0.9,
                validator: null
            },
            {
                filename: 'pnpm-lock.yaml',
                ecosystem: 'npm',
                type: 'lockfile',
                confidence: 0.9,
                validator: null
            },

            // Python ecosystem
            {
                filename: 'requirements.txt',
                ecosystem: 'pypi',
                type: 'manifest',
                confidence: 0.95,
                validator: this.validateRequirementsTxt.bind(this)
            },
            {
                filename: 'Pipfile',
                ecosystem: 'pypi',
                type: 'manifest',
                confidence: 1.0,
                validator: null
            },
            {
                filename: 'Pipfile.lock',
                ecosystem: 'pypi',
                type: 'lockfile',
                confidence: 0.95,
                validator: null
            },
            {
                filename: 'pyproject.toml',
                ecosystem: 'pypi',
                type: 'manifest',
                confidence: 0.9,
                validator: this.validatePyprojectToml.bind(this)
            },
            {
                filename: 'setup.py',
                ecosystem: 'pypi',
                type: 'manifest',
                confidence: 0.85,
                validator: this.validateSetupPy.bind(this)
            },

            // Java ecosystem
            {
                filename: 'pom.xml',
                ecosystem: 'maven',
                type: 'manifest',
                confidence: 1.0,
                validator: this.validatePomXml.bind(this)
            },
            {
                filename: 'build.gradle',
                ecosystem: 'maven',
                type: 'manifest',
                confidence: 1.0,
                validator: this.validateBuildGradle.bind(this)
            },
            {
                filename: 'build.gradle.kts',
                ecosystem: 'maven',
                type: 'manifest',
                confidence: 1.0,
                validator: null
            },

            // Go ecosystem
            {
                filename: 'go.mod',
                ecosystem: 'go',
                type: 'manifest',
                confidence: 1.0,
                validator: this.validateGoMod.bind(this)
            },
            {
                filename: 'go.sum',
                ecosystem: 'go',
                type: 'lockfile',
                confidence: 0.95,
                validator: null
            },

            // Rust ecosystem
            {
                filename: 'Cargo.toml',
                ecosystem: 'cargo',
                type: 'manifest',
                confidence: 1.0,
                validator: this.validateCargoToml.bind(this)
            },
            {
                filename: 'Cargo.lock',
                ecosystem: 'cargo',
                type: 'lockfile',
                confidence: 0.95,
                validator: null
            },

            // Ruby ecosystem
            {
                filename: 'Gemfile',
                ecosystem: 'rubygems',
                type: 'manifest',
                confidence: 1.0,
                validator: this.validateGemfile.bind(this)
            },
            {
                filename: 'Gemfile.lock',
                ecosystem: 'rubygems',
                type: 'lockfile',
                confidence: 0.95,
                validator: null
            },

            // PHP ecosystem
            {
                filename: 'composer.json',
                ecosystem: 'packagist',
                type: 'manifest',
                confidence: 1.0,
                validator: this.validateComposerJson.bind(this)
            },
            {
                filename: 'composer.lock',
                ecosystem: 'packagist',
                type: 'lockfile',
                confidence: 0.95,
                validator: null
            },

            // .NET ecosystem
            {
                filename: 'packages.config',
                ecosystem: 'nuget',
                type: 'manifest',
                confidence: 0.95,
                validator: this.validatePackagesConfig.bind(this)
            },
            {
                filename: 'Directory.Build.props',
                ecosystem: 'nuget',
                type: 'manifest',
                confidence: 0.85,
                validator: this.validateDirectoryBuildProps.bind(this)
            },
            {
                filename: 'Directory.Packages.props',
                ecosystem: 'nuget',
                type: 'manifest',
                confidence: 0.95,
                validator: this.validateDirectoryPackagesProps.bind(this)
            },
            {
                filename: 'packages.lock.json',
                ecosystem: 'nuget',
                type: 'lockfile',
                confidence: 0.95,
                validator: this.validateNuGetLockfile.bind(this)
            },

            // Dart/Flutter ecosystem
            {
                filename: 'pubspec.yaml',
                ecosystem: 'pub',
                type: 'manifest',
                confidence: 1.0,
                validator: this.validatePubspec.bind(this)
            },
            {
                filename: 'pubspec.lock',
                ecosystem: 'pub',
                type: 'lockfile',
                confidence: 0.95,
                validator: null
            },

            // Python ecosystem (additional)
            {
                filename: 'poetry.lock',
                ecosystem: 'pypi',
                type: 'lockfile',
                confidence: 0.95,
                validator: this.validatePoetryLock.bind(this)
            },
            {
                filename: 'setup.cfg',
                ecosystem: 'pypi',
                type: 'manifest',
                confidence: 0.85,
                validator: this.validateSetupCfg.bind(this)
            },

            // Node.js ecosystem (additional)
            {
                filename: 'bun.lockb',
                ecosystem: 'npm',
                type: 'lockfile',
                confidence: 0.9,
                validator: null
            },

            // Swift ecosystem
            {
                filename: 'Package.swift',
                ecosystem: 'swift',
                type: 'manifest',
                confidence: 1.0,
                validator: this.validatePackageSwift.bind(this)
            },
            {
                filename: 'Package.resolved',
                ecosystem: 'swift',
                type: 'lockfile',
                confidence: 0.95,
                validator: null
            },

            // Elixir ecosystem
            {
                filename: 'mix.exs',
                ecosystem: 'hex',
                type: 'manifest',
                confidence: 1.0,
                validator: this.validateMixExs.bind(this)
            },
            {
                filename: 'mix.lock',
                ecosystem: 'hex',
                type: 'lockfile',
                confidence: 0.95,
                validator: null
            },

            // Scala ecosystem
            {
                filename: 'build.sbt',
                ecosystem: 'maven',
                type: 'manifest',
                confidence: 1.0,
                validator: this.validateBuildSbt.bind(this)
            },

            // Haskell ecosystem
            {
                filename: 'package.yaml',
                ecosystem: 'hackage',
                type: 'manifest',
                confidence: 0.85,
                validator: this.validateHaskellPackageYaml.bind(this)
            },
            {
                filename: 'stack.yaml',
                ecosystem: 'hackage',
                type: 'manifest',
                confidence: 0.90,
                validator: this.validateStackYaml.bind(this)
            },

            // Java ecosystem (additional)
            {
                filename: 'gradle.lockfile',
                ecosystem: 'maven',
                type: 'lockfile',
                confidence: 0.95,
                validator: null
            }
        ];
    }

    /**
     * Find all manifests in a project
     */
    findManifests(projectRoot) {
        if (this.options.verbose) {
            console.log(` Searching for manifests in: ${projectRoot}`);
        }

        const manifests = [];
        const seen = new Set();

        try {
            this.walkDirectory(projectRoot, 0, (file) => {
                const manifest = this.identifyManifest(file);
                if (manifest) {
                    const key = `${manifest.ecosystem}:${manifest.path}`;
                    if (!seen.has(key)) {
                        seen.add(key);
                        manifests.push(manifest);
                        if (this.options.verbose) {
                            console.log(`  [OK]Found: ${manifest.filename} (${manifest.ecosystem})`);
                        }
                    }
                }
            });
        } catch (error) {
            console.error(`Error walking directory: ${error.message}`);
        }

        if (this.options.verbose) {
            console.log(`\n📦 Found ${manifests.length} manifest(s)`);
        }

        return manifests;
    }

    /**
     * Recursively walk directory tree
     */
    walkDirectory(dir, depth, callback) {
        if (depth > this.options.maxDepth) {
            return;
        }

        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch (error) {
            // Skip directories we can't read
            return;
        }

        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);

            // Check exclude patterns
            if (this.shouldExclude(fullPath, entry.name)) {
                continue;
            }

            try {
                let stats;
                if (entry.isSymbolicLink()) {
                    if (!this.options.followSymlinks) {
                        continue;
                    }
                    stats = fs.statSync(fullPath);
                } else {
                    stats = entry.isDirectory()
                        ? { isDirectory: () => true, isFile: () => false }
                        : { isDirectory: () => false, isFile: () => true };
                }

                if (stats.isDirectory && stats.isDirectory()) {
                    this.walkDirectory(fullPath, depth + 1, callback);
                } else if (stats.isFile && stats.isFile()) {
                    callback(fullPath);
                }
            } catch (error) {
                // Skip files/dirs we can't access
                continue;
            }
        }
    }

    /**
     * Check if path should be excluded
     */
    shouldExclude(fullPath, filename) {
        // Check directory excludes
        const pathParts = fullPath.split(path.sep);
        for (const excludeDir of this.options.excludeDirs) {
            if (pathParts.includes(excludeDir)) {
                return true;
            }
        }

        // Check pattern excludes
        for (const pattern of this.options.excludePatterns) {
            if (pattern.test(fullPath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Identify manifest type from file path
     */
    identifyManifest(filePath) {
        const filename = path.basename(filePath);

        // Check against all known patterns
        for (const pattern of this.manifestPatterns) {
            if (filename === pattern.filename) {
                // Validate content if validator exists
                let isValid = true;
                let validationMessage = null;

                if (pattern.validator) {
                    const validation = pattern.validator(filePath);
                    isValid = validation.valid;
                    validationMessage = validation.message;
                }

                if (isValid) {
                    return {
                        path: filePath,
                        filename: filename,
                        ecosystem: pattern.ecosystem,
                        type: pattern.type,
                        confidence: pattern.confidence,
                        directory: path.dirname(filePath),
                        validationMessage
                    };
                }
            }
        }

        // Check for .NET project files (regex patterns)
        if (/\.(csproj|fsproj|vbproj)$/.test(filename)) {
            return {
                path: filePath,
                filename: filename,
                ecosystem: 'nuget',
                type: 'manifest',
                confidence: 1.0,
                directory: path.dirname(filePath)
            };
        }

        // Check for .nuspec files
        if (/\.nuspec$/.test(filename)) {
            return {
                path: filePath,
                filename: filename,
                ecosystem: 'nuget',
                type: 'manifest',
                confidence: 0.9,
                directory: path.dirname(filePath)
            };
        }

        // Check for Haskell .cabal files
        if (/\.cabal$/.test(filename)) {
            return {
                path: filePath,
                filename: filename,
                ecosystem: 'hackage',
                type: 'manifest',
                confidence: 0.95,
                directory: path.dirname(filePath)
            };
        }

        return null;
    }

    /**
     * Validators for manifest files
     */

    validatePackageJson(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            const data = JSON.parse(content);

            // Must have dependencies or devDependencies
            if (!data.dependencies && !data.devDependencies) {
                return { valid: false, message: 'No dependencies found' };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Invalid JSON: ${error.message}` };
        }
    }

    validatePackageLockJson(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            const data = JSON.parse(content);

            // Must have lockfileVersion
            if (!data.lockfileVersion) {
                return { valid: false, message: 'Not a valid package-lock.json' };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Invalid JSON: ${error.message}` };
        }
    }

    validateRequirementsTxt(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');

            // Must have at least one package line
            const lines = content.split('\n')
                .map(l => l.trim())
                .filter(l => l && !l.startsWith('#'));

            if (lines.length === 0) {
                return { valid: false, message: 'Empty requirements file' };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validatePyprojectToml(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');

            // Must contain [tool.poetry.dependencies] or [project.dependencies]
            if (!content.includes('[tool.poetry.dependencies]') &&
                !content.includes('[project.dependencies]')) {
                return { valid: false, message: 'Not a dependency manifest' };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateSetupPy(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');

            // Must contain setup() call with install_requires
            if (!content.includes('install_requires')) {
                return { valid: false, message: 'No install_requires found' };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validatePomXml(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');

            // Must contain <dependencies> tag
            if (!content.includes('<dependencies>')) {
                return { valid: false, message: 'No dependencies found' };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateBuildGradle(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');

            // Must contain dependencies block
            if (!content.includes('dependencies')) {
                return { valid: false, message: 'No dependencies block found' };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateGoMod(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');

            // Must start with module declaration
            if (!content.trim().startsWith('module ')) {
                return { valid: false, message: 'Invalid go.mod format' };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateCargoToml(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');

            // Must contain [dependencies] or [dev-dependencies]
            if (!content.includes('[dependencies]') &&
                !content.includes('[dev-dependencies]')) {
                return { valid: false, message: 'No dependencies found' };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateGemfile(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');

            // Must contain gem declarations
            if (!content.includes('gem ')) {
                return { valid: false, message: 'No gem declarations found' };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateComposerJson(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            const data = JSON.parse(content);

            // Must have require or require-dev
            if (!data.require && !data['require-dev']) {
                return { valid: false, message: 'No dependencies found' };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Invalid JSON: ${error.message}` };
        }
    }

    validatePackagesConfig(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');

            // Must contain <package elements
            if (!content.includes('<package ') && !content.includes('<packages')) {
                return { valid: false, message: 'Not a valid packages.config' };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validatePubspec(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');

            // Must contain dependencies section
            if (!content.includes('dependencies:')) {
                return { valid: false, message: 'No dependencies found' };
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateDirectoryBuildProps(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            if (!content.includes('PackageReference')) {
                return { valid: false, message: 'No PackageReference elements found' };
            }
            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateDirectoryPackagesProps(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            if (!content.includes('PackageVersion') && !content.includes('PackageReference')) {
                return { valid: false, message: 'No PackageVersion elements found' };
            }
            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateNuGetLockfile(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            const data = JSON.parse(content);
            if (!data.version || !data.dependencies) {
                return { valid: false, message: 'Not a valid NuGet lock file' };
            }
            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Invalid JSON: ${error.message}` };
        }
    }

    validatePoetryLock(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            if (!content.includes('[[package]]')) {
                return { valid: false, message: 'Not a valid poetry.lock' };
            }
            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateSetupCfg(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            if (!content.includes('install_requires') && !content.includes('[options]')) {
                return { valid: false, message: 'No dependency section found' };
            }
            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validatePackageSwift(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            if (!content.includes('dependencies') && !content.includes('.package(')) {
                return { valid: false, message: 'No dependencies found' };
            }
            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateMixExs(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            if (!content.includes('defp deps') && !content.includes('def deps')) {
                return { valid: false, message: 'No deps function found' };
            }
            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateBuildSbt(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            if (!content.includes('libraryDependencies') && !content.includes('%%')) {
                return { valid: false, message: 'No library dependencies found' };
            }
            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateHaskellPackageYaml(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            if (!content.includes('dependencies:')) {
                return { valid: false, message: 'No dependencies found' };
            }
            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    validateStackYaml(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            if (!content.includes('resolver:') && !content.includes('packages:')) {
                return { valid: false, message: 'Not a valid stack.yaml' };
            }
            return { valid: true };
        } catch (error) {
            return { valid: false, message: `Cannot read file: ${error.message}` };
        }
    }

    /**
     * Detect monorepo workspace configuration and resolve workspace paths
     */
    detectWorkspaces(projectRoot) {
        const workspaces = [];

        try {
            // npm/yarn workspaces from package.json
            const rootPkgJson = path.join(projectRoot, 'package.json');
            if (fs.existsSync(rootPkgJson)) {
                const content = fs.readFileSync(rootPkgJson, 'utf8');
                const data = JSON.parse(content);
                if (data.workspaces) {
                    const wsPatterns = Array.isArray(data.workspaces)
                        ? data.workspaces
                        : (data.workspaces.packages || []);
                    for (const pattern of wsPatterns) {
                        workspaces.push({ pattern, source: 'package.json', ecosystem: 'npm' });
                    }
                }
            }

            // pnpm-workspace.yaml
            const pnpmWorkspace = path.join(projectRoot, 'pnpm-workspace.yaml');
            if (fs.existsSync(pnpmWorkspace)) {
                const content = fs.readFileSync(pnpmWorkspace, 'utf8');
                const packagesMatch = content.match(/packages:\s*\n((?:\s+-\s+.+\n?)*)/);
                if (packagesMatch) {
                    const lines = packagesMatch[1].split('\n');
                    for (const line of lines) {
                        const match = line.match(/^\s+-\s+['"]?([^'"]+)['"]?\s*$/);
                        if (match) {
                            workspaces.push({ pattern: match[1], source: 'pnpm-workspace.yaml', ecosystem: 'npm' });
                        }
                    }
                }
            }

            // lerna.json
            const lernaJson = path.join(projectRoot, 'lerna.json');
            if (fs.existsSync(lernaJson)) {
                const content = fs.readFileSync(lernaJson, 'utf8');
                const data = JSON.parse(content);
                if (data.packages) {
                    for (const pattern of data.packages) {
                        workspaces.push({ pattern, source: 'lerna.json', ecosystem: 'npm' });
                    }
                }
            }

            // Cargo workspace (Rust)
            const cargoToml = path.join(projectRoot, 'Cargo.toml');
            if (fs.existsSync(cargoToml)) {
                const content = fs.readFileSync(cargoToml, 'utf8');
                const wsSection = content.match(/\[workspace\]\s*\nmembers\s*=\s*\[([\s\S]*?)\]/);
                if (wsSection) {
                    const members = wsSection[1].match(/"([^"]+)"/g);
                    if (members) {
                        for (const m of members) {
                            workspaces.push({ pattern: m.replace(/"/g, ''), source: 'Cargo.toml', ecosystem: 'cargo' });
                        }
                    }
                }
            }

            // Go workspace (go.work)
            const goWork = path.join(projectRoot, 'go.work');
            if (fs.existsSync(goWork)) {
                const content = fs.readFileSync(goWork, 'utf8');
                const useMatch = content.match(/use\s*\(([\s\S]*?)\)/);
                if (useMatch) {
                    const dirs = useMatch[1].split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('//'));
                    for (const dir of dirs) {
                        workspaces.push({ pattern: dir, source: 'go.work', ecosystem: 'go' });
                    }
                }
            }

            // .NET solution files (.sln)
            this.walkDirectory(projectRoot, 0, (filePath) => {
                if (filePath.endsWith('.sln')) {
                    const content = fs.readFileSync(filePath, 'utf8');
                    const projMatches = content.matchAll(/Project\("[^"]*"\)\s*=\s*"[^"]*"\s*,\s*"([^"]+\.(csproj|fsproj|vbproj))"/gi);
                    for (const match of projMatches) {
                        const projDir = path.dirname(match[1]).replace(/\\/g, '/');
                        if (projDir && projDir !== '.') {
                            workspaces.push({ pattern: projDir, source: path.basename(filePath), ecosystem: 'nuget' });
                        }
                    }
                }
            });

        } catch (error) {
            // Workspace detection is best-effort
        }

        return workspaces;
    }

    /**
     * Group manifests by workspace/service
     */
    groupManifestsByWorkspace(manifests) {
        const workspaces = new Map();

        for (const manifest of manifests) {
            const workspace = manifest.directory;
            if (!workspaces.has(workspace)) {
                workspaces.set(workspace, []);
            }
            workspaces.get(workspace).push(manifest);
        }

        return Array.from(workspaces.entries()).map(([dir, manifests]) => ({
            directory: dir,
            manifests: manifests
        }));
    }

    /**
     * Get statistics about found manifests
     */
    getStatistics(manifests) {
        const stats = {
            total: manifests.length,
            byEcosystem: {},
            byType: {},
            workspaces: this.groupManifestsByWorkspace(manifests).length
        };

        for (const manifest of manifests) {
            // Count by ecosystem
            stats.byEcosystem[manifest.ecosystem] =
                (stats.byEcosystem[manifest.ecosystem] || 0) + 1;

            // Count by type
            stats.byType[manifest.type] =
                (stats.byType[manifest.type] || 0) + 1;
        }

        return stats;
    }
}

module.exports = GenericManifestFinder;
