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
 * - .NET: *.csproj, packages.config, *.nuspec
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

            // .NET ecosystem (legacy packages.config)
            {
                filename: 'packages.config',
                ecosystem: 'nuget',
                type: 'manifest',
                confidence: 0.95,
                validator: this.validatePackagesConfig.bind(this)
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

        // Check for .csproj files (regex pattern)
        if (/\.csproj$/.test(filename)) {
            return {
                path: filePath,
                filename: filename,
                ecosystem: 'nuget',
                type: 'manifest',
                confidence: 1.0,
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
