/**
 * FileWalker - Cross-platform file discovery utility
 *
 * Provides reliable file discovery that works on Windows, Linux, and macOS
 * without relying on glob patterns that can fail on Windows.
 */

const fs = require('fs');
const path = require('path');

class FileWalker {
    constructor(options = {}) {
        this.options = {
            maxDepth: options.maxDepth || 10,
            followSymlinks: options.followSymlinks || false,
            excludeDirs: options.excludeDirs || [
                'node_modules',
                '.git',
                '.svn',
                'dist',
                'build',
                'target',
                'out',
                '.next',
                '__pycache__',
                'venv',
                'vendor'
            ],
            excludePatterns: options.excludePatterns || [
                /\/test\//i,
                /\/tests\//i,
                /\/__tests__\//i,
                /\/fixtures\//i,
                /\/mocks\//i,
                /\.test\./i,
                /\.spec\./i,
                /\.min\./i
            ],
            ...options
        };
    }

    /**
     * Find all files matching extensions
     */
    findFiles(rootDir, extensions = []) {
        const files = [];
        const extensionsSet = new Set(extensions.map(ext => ext.toLowerCase()));

        this.walkDirectory(rootDir, 0, (filePath) => {
            if (extensionsSet.size === 0) {
                // No filter, return all files
                files.push(filePath);
            } else {
                const ext = path.extname(filePath).toLowerCase();
                if (extensionsSet.has(ext)) {
                    files.push(filePath);
                }
            }
        });

        return files;
    }

    /**
     * Find JavaScript/TypeScript files
     */
    findJavaScriptFiles(rootDir) {
        return this.findFiles(rootDir, ['.js', '.mjs', '.jsx', '.ts', '.tsx']);
    }

    /**
     * Find Python files
     */
    findPythonFiles(rootDir) {
        return this.findFiles(rootDir, ['.py']);
    }

    /**
     * Find Java files
     */
    findJavaFiles(rootDir) {
        return this.findFiles(rootDir, ['.java']);
    }

    /**
     * Find Go files
     */
    findGoFiles(rootDir) {
        return this.findFiles(rootDir, ['.go']);
    }

    /**
     * Find Rust files
     */
    findRustFiles(rootDir) {
        return this.findFiles(rootDir, ['.rs']);
    }

    /**
     * Find Ruby files
     */
    findRubyFiles(rootDir) {
        return this.findFiles(rootDir, ['.rb']);
    }

    /**
     * Find PHP files
     */
    findPhpFiles(rootDir) {
        return this.findFiles(rootDir, ['.php']);
    }

    /**
     * Recursively walk directory
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
                let isDirectory, isFile;

                if (entry.isSymbolicLink()) {
                    if (!this.options.followSymlinks) {
                        continue;
                    }
                    const stats = fs.statSync(fullPath);
                    isDirectory = stats.isDirectory();
                    isFile = stats.isFile();
                } else {
                    isDirectory = entry.isDirectory();
                    isFile = entry.isFile();
                }

                if (isDirectory) {
                    this.walkDirectory(fullPath, depth + 1, callback);
                } else if (isFile) {
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

        // Check hidden files
        if (filename.startsWith('.') && filename !== '.') {
            return true;
        }

        return false;
    }

    /**
     * Get file statistics
     */
    getStats(files) {
        const stats = {
            total: files.length,
            byExtension: {},
            totalSize: 0,
            largestFile: null,
            largestSize: 0
        };

        for (const file of files) {
            const ext = path.extname(file).toLowerCase();
            stats.byExtension[ext] = (stats.byExtension[ext] || 0) + 1;

            try {
                const fileStats = fs.statSync(file);
                stats.totalSize += fileStats.size;

                if (fileStats.size > stats.largestSize) {
                    stats.largestSize = fileStats.size;
                    stats.largestFile = file;
                }
            } catch (error) {
                // Skip if can't stat
            }
        }

        return stats;
    }
}

module.exports = FileWalker;
