/**
 * Import Detector
 * Detects package imports/requires in source code
 */

const fs = require('fs');
const { getLogger } = require('./logger');

class ImportDetector {
  constructor(options = {}) {
    this.options = options;
    this.logger = getLogger().child({ component: 'ImportDetector' });
  }

  /**
   * Detects if a package is imported in a file
   */
  detectImportsInFile(filePath, packageName) {
    try {
      if (!fs.existsSync(filePath)) {
        return [];
      }

      const content = fs.readFileSync(filePath, 'utf-8');
      return this.detectImportsInContent(content, packageName, filePath);

    } catch (error) {
      this.logger.debug('Error reading file for import detection', {
        filePath,
        error: error.message
      });
      return [];
    }
  }

  /**
   * Detects imports in content
   */
  detectImportsInContent(content, packageName, filePath = 'unknown') {
    const imports = [];

    // JavaScript/TypeScript patterns
    const jsPatterns = [
      // require('package')
      new RegExp(`require\\s*\\(\\s*['"\`]${this.escapeRegex(packageName)}['"\`]\\s*\\)`, 'g'),
      // require('package/submodule')
      new RegExp(`require\\s*\\(\\s*['"\`]${this.escapeRegex(packageName)}/[^'"\`]*['"\`]\\s*\\)`, 'g'),
      // import ... from 'package'
      new RegExp(`import\\s+.*?\\s+from\\s+['"\`]${this.escapeRegex(packageName)}['"\`]`, 'g'),
      // import 'package'
      new RegExp(`import\\s+['"\`]${this.escapeRegex(packageName)}['"\`]`, 'g'),
      // import('package') - dynamic import
      new RegExp(`import\\s*\\(\\s*['"\`]${this.escapeRegex(packageName)}['"\`]\\s*\\)`, 'g')
    ];

    // Python patterns
    const pythonPatterns = [
      // import package
      new RegExp(`^\\s*import\\s+${this.escapeRegex(packageName)}\\s*`, 'gm'),
      // from package import ...
      new RegExp(`^\\s*from\\s+${this.escapeRegex(packageName)}\\s+import\\s+`, 'gm'),
      // import package as alias
      new RegExp(`^\\s*import\\s+${this.escapeRegex(packageName)}\\s+as\\s+`, 'gm')
    ];

    // Java patterns
    const javaPatterns = [
      // import package.Class;
      new RegExp(`^\\s*import\\s+${this.escapeRegex(packageName)}(\\.\\w+)*\\s*;`, 'gm'),
      // import static package.Class.method;
      new RegExp(`^\\s*import\\s+static\\s+${this.escapeRegex(packageName)}(\\.\\w+)*\\s*;`, 'gm')
    ];

    // Go patterns
    const goPatterns = [
      // import "package"
      new RegExp(`import\\s+['"\`]${this.escapeRegex(packageName)}['"\`]`, 'g'),
      // import ( ... "package" ... )
      new RegExp(`['"\`]${this.escapeRegex(packageName)}['"\`]`, 'g')
    ];

    // C# patterns
    const csharpPatterns = [
      // using Package.Namespace;
      new RegExp(`^\\s*using\\s+${this.escapeRegex(packageName)}(\\.[\\w.]+)?\\s*;`, 'gm'),
      // using static Package.Namespace.Class;
      new RegExp(`^\\s*using\\s+static\\s+${this.escapeRegex(packageName)}(\\.[\\w.]+)?\\s*;`, 'gm'),
      // using alias = Package.Namespace;
      new RegExp(`^\\s*using\\s+\\w+\\s*=\\s*${this.escapeRegex(packageName)}(\\.[\\w.]+)?\\s*;`, 'gm')
    ];

    // Rust patterns
    const rustPatterns = [
      // use package::module;
      new RegExp(`^\\s*use\\s+${this.escapeRegex(packageName)}(::.*)?;`, 'gm'),
      // extern crate package;
      new RegExp(`^\\s*extern\\s+crate\\s+${this.escapeRegex(packageName)}\\s*;`, 'gm')
    ];

    // Ruby patterns
    const rubyPatterns = [
      // require 'package'
      new RegExp(`^\\s*require\\s+['"]${this.escapeRegex(packageName)}['"]`, 'gm'),
      // require_relative 'package'
      new RegExp(`^\\s*require_relative\\s+['"]${this.escapeRegex(packageName)}['"]`, 'gm'),
      // gem 'package'
      new RegExp(`^\\s*gem\\s+['"]${this.escapeRegex(packageName)}['"]`, 'gm')
    ];

    // PHP patterns
    const phpPatterns = [
      // use Package\Namespace;
      new RegExp(`^\\s*use\\s+${this.escapeRegex(packageName).replace(/\//g, '\\\\\\\\')}(\\\\[\\w]+)*\\s*;`, 'gm'),
      // require 'vendor/package/...'
      new RegExp(`(require|include)(_once)?\\s+['"].*${this.escapeRegex(packageName)}.*['"]`, 'gm')
    ];

    // Dart patterns
    const dartPatterns = [
      // import 'package:package_name/...';
      new RegExp(`^\\s*import\\s+['"]package:${this.escapeRegex(packageName)}/[^'"]*['"]\\s*;`, 'gm'),
      // export 'package:package_name/...';
      new RegExp(`^\\s*export\\s+['"]package:${this.escapeRegex(packageName)}/[^'"]*['"]\\s*;`, 'gm')
    ];

    // Elixir patterns
    const elixirPatterns = [
      // {:package_name, "~> 1.0"}
      new RegExp(`\\{:${this.escapeRegex(packageName)}\\s*,`, 'g')
    ];

    // Check all patterns
    const allPatterns = [
      ...jsPatterns.map(p => ({ pattern: p, language: 'javascript' })),
      ...pythonPatterns.map(p => ({ pattern: p, language: 'python' })),
      ...javaPatterns.map(p => ({ pattern: p, language: 'java' })),
      ...goPatterns.map(p => ({ pattern: p, language: 'go' })),
      ...csharpPatterns.map(p => ({ pattern: p, language: 'csharp' })),
      ...rustPatterns.map(p => ({ pattern: p, language: 'rust' })),
      ...rubyPatterns.map(p => ({ pattern: p, language: 'ruby' })),
      ...phpPatterns.map(p => ({ pattern: p, language: 'php' })),
      ...dartPatterns.map(p => ({ pattern: p, language: 'dart' })),
      ...elixirPatterns.map(p => ({ pattern: p, language: 'elixir' }))
    ];

    for (const { pattern, language } of allPatterns) {
      const matches = content.matchAll(pattern);

      for (const match of matches) {
        imports.push({
          packageName,
          statement: match[0].trim(),
          language,
          filePath,
          index: match.index,
          confidence: this.calculateImportConfidence(match[0], language)
        });
      }
    }

    return imports;
  }

  /**
   * Detects all imports in a codebase
   */
  detectAllImportsInDirectory(directory, packageNames) {
    const imports = new Map(); // packageName -> [imports]

    for (const packageName of packageNames) {
      imports.set(packageName, []);
    }

    // Walk directory and check files
    this.walkDirectory(directory, (filePath) => {
      for (const packageName of packageNames) {
        const fileImports = this.detectImportsInFile(filePath, packageName);
        if (fileImports.length > 0) {
          imports.get(packageName).push(...fileImports);
        }
      }
    });

    return imports;
  }

  /**
   * Walks directory recursively
   */
  walkDirectory(dir, callback) {
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = require('path').join(dir, entry.name);

        // Skip node_modules, .git, etc.
        if (this.shouldSkip(entry.name)) continue;

        if (entry.isDirectory()) {
          this.walkDirectory(fullPath, callback);
        } else if (entry.isFile() && this.isSourceFile(entry.name)) {
          callback(fullPath);
        }
      }
    } catch (error) {
      // Ignore directory read errors
    }
  }

  /**
   * Checks if directory/file should be skipped
   */
  shouldSkip(name) {
    const skipList = [
      'node_modules', '.git', '.svn', '.hg',
      'dist', 'build', 'target', '__pycache__',
      '.depguard-cache', 'coverage', '.venv', 'venv'
    ];
    return skipList.includes(name) || name.startsWith('.');
  }

  /**
   * Checks if file is a source code file
   */
  isSourceFile(filename) {
    const extensions = [
      '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
      '.py', '.pyi',
      '.java', '.kt', '.kts', '.scala',
      '.go',
      '.rs',
      '.rb', '.erb',
      '.php',
      '.cs', '.fs', '.vb',
      '.dart',
      '.swift',
      '.ex', '.exs',
      '.hs'
    ];
    return extensions.some(ext => filename.endsWith(ext));
  }

  /**
   * Calculates confidence score for an import
   */
  calculateImportConfidence(statement, language) {
    let confidence = 0.8; // Base confidence

    // Higher confidence for specific patterns
    if (statement.includes('require(')) confidence = 0.9;
    if (statement.includes('import ') && language === 'javascript') confidence = 0.95;
    if (statement.includes('from ') && language === 'python') confidence = 0.95;
    if (statement.includes('using ') && language === 'csharp') confidence = 0.95;
    if (statement.includes('use ') && language === 'rust') confidence = 0.95;
    if (statement.includes('extern crate') && language === 'rust') confidence = 0.98;
    if (statement.includes('require ') && language === 'ruby') confidence = 0.9;
    if (statement.includes('use ') && language === 'php') confidence = 0.9;
    if (statement.includes('package:') && language === 'dart') confidence = 0.95;

    // Lower confidence for commented imports
    if (statement.trim().startsWith('//') || statement.trim().startsWith('#') || statement.trim().startsWith('--')) {
      confidence = 0.2;
    }

    return confidence;
  }

  /**
   * Escapes special regex characters
   */
  escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /**
   * Checks if package is imported in any reachable file
   */
  isPackageImported(packageName, reachableFiles) {
    for (const file of reachableFiles) {
      const imports = this.detectImportsInFile(file, packageName);
      if (imports.length > 0) {
        return {
          imported: true,
          imports,
          file
        };
      }
    }

    return { imported: false };
  }
}

module.exports = ImportDetector;
