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
   * Detects conditional/dynamic imports that may be missed by standard detection
   * These are imports inside if/else, try/catch, or behind feature flags
   */
  detectConditionalImports(content, packageName, filePath = 'unknown') {
    const imports = [];

    // JavaScript: require inside try/catch
    const tryCatchRequire = new RegExp(
      `try\\s*\\{[\\s\\S]*?require\\s*\\(\\s*['"\`]${this.escapeRegex(packageName)}['"\`]\\s*\\)[\\s\\S]*?\\}\\s*catch`,
      'gi'
    );

    // JavaScript: require inside if/else blocks
    const conditionalRequire = new RegExp(
      `if\\s*\\([^)]*\\)\\s*\\{[\\s\\S]*?require\\s*\\(\\s*['"\`]${this.escapeRegex(packageName)}['"\`]\\s*\\)[\\s\\S]*?\\}`,
      'gi'
    );

    // JavaScript: variable-based dynamic require (e.g., const pkg = condition ? require('a') : require('b'))
    const ternaryRequire = new RegExp(
      `\\?\\s*require\\s*\\(\\s*['"\`]${this.escapeRegex(packageName)}['"\`]\\s*\\)|:\\s*require\\s*\\(\\s*['"\`]${this.escapeRegex(packageName)}['"\`]\\s*\\)`,
      'gi'
    );

    // Python: conditional imports
    const pyConditionalImport = new RegExp(
      `(?:try:|if\\s+[^:]+:)\\s*\\n\\s+(?:import\\s+${this.escapeRegex(packageName)}|from\\s+${this.escapeRegex(packageName)}\\s+import)`,
      'gm'
    );

    // JavaScript: lazy/deferred import patterns
    const lazyImport = new RegExp(
      `(?:lazy|deferred|optional)\\w*\\s*(?:=|:)\\s*(?:\\(\\)\\s*=>\\s*)?(?:require|import)\\s*\\(?\\s*['"\`]${this.escapeRegex(packageName)}['"\`]`,
      'gi'
    );

    const conditionalPatterns = [
      { pattern: tryCatchRequire, type: 'try-catch', confidence: 0.65 },
      { pattern: conditionalRequire, type: 'conditional', confidence: 0.60 },
      { pattern: ternaryRequire, type: 'ternary', confidence: 0.55 },
      { pattern: pyConditionalImport, type: 'python-conditional', confidence: 0.60 },
      { pattern: lazyImport, type: 'lazy-load', confidence: 0.50 }
    ];

    for (const { pattern, type, confidence } of conditionalPatterns) {
      const matches = content.matchAll(pattern);
      for (const match of matches) {
        imports.push({
          packageName,
          statement: match[0].trim().substring(0, 200),
          language: type.includes('python') ? 'python' : 'javascript',
          filePath,
          index: match.index,
          confidence,
          importType: 'conditional',
          conditionalType: type
        });
      }
    }

    return imports;
  }

  /**
   * Detects dangerous API usage patterns that are commonly associated with vulnerabilities
   * Returns patterns that indicate risky usage of a package
   */
  detectDangerousPatterns(content, filePath = 'unknown') {
    const patterns = [];

    const dangerousAPIs = [
      // Prototype pollution vectors
      { regex: /(\w+\.merge|Object\.assign|_\.extend|_\.merge|_\.defaultsDeep)\s*\([^,]+,\s*(req\.|request\.|params\.|body\.|query\.)/gi,
        category: 'prototype-pollution', severity: 'HIGH', description: 'User input passed to deep merge/extend function' },

      // Command injection
      { regex: /(exec|execSync|spawn|spawnSync|execFile)\s*\([^)]*(\$\{|`|\+\s*\w+|\breq\.|\bparams\.|\bbody\.|\bquery\.)/gi,
        category: 'command-injection', severity: 'CRITICAL', description: 'User input in command execution' },

      // SQL injection
      { regex: /(query|execute|raw)\s*\(\s*(['"`].*\$\{|['"`].*\+\s*\w+|`[^`]*\$\{)/gi,
        category: 'sql-injection', severity: 'CRITICAL', description: 'String concatenation in SQL query' },

      // Path traversal
      { regex: /(readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\([^)]*(\breq\.|\bparams\.|\bbody\.|\bquery\.)/gi,
        category: 'path-traversal', severity: 'HIGH', description: 'User input in file path operation' },

      // Unsafe deserialization
      { regex: /(unserialize|deserialize|yaml\.load|pickle\.loads?|eval\s*\(|Function\s*\(|new\s+Function\s*\()/gi,
        category: 'unsafe-deserialization', severity: 'CRITICAL', description: 'Potentially unsafe deserialization' },

      // SSRF patterns
      { regex: /(fetch|axios|request|http\.get|urllib)\s*\([^)]*(\breq\.|\bparams\.|\bbody\.|\bquery\.|\burl\b)/gi,
        category: 'ssrf', severity: 'HIGH', description: 'User-controlled URL in HTTP request' },

      // Unsafe regex (ReDoS)
      { regex: /new\s+RegExp\s*\([^)]*(\breq\.|\bparams\.|\bbody\.|\bquery\.)/gi,
        category: 'redos', severity: 'MEDIUM', description: 'User input in RegExp constructor' },

      // Hardcoded secrets
      { regex: /(password|secret|api[_-]?key|token|auth)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
        category: 'hardcoded-secret', severity: 'HIGH', description: 'Potential hardcoded secret' },

      // Unsafe HTML rendering
      { regex: /(innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|v-html)\s*[=:]/gi,
        category: 'xss', severity: 'HIGH', description: 'Direct HTML injection point' },

      // Insecure crypto
      { regex: /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/gi,
        category: 'weak-crypto', severity: 'MEDIUM', description: 'Weak hash algorithm (MD5/SHA1)' },

      // Insecure TLS
      { regex: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/gi,
        category: 'insecure-tls', severity: 'HIGH', description: 'TLS certificate validation disabled' }
    ];

    for (const api of dangerousAPIs) {
      const matches = content.matchAll(api.regex);
      for (const match of matches) {
        // Determine line number
        const linesBefore = content.substring(0, match.index).split('\n');
        const lineNumber = linesBefore.length;

        patterns.push({
          filePath,
          lineNumber,
          match: match[0].substring(0, 200),
          category: api.category,
          severity: api.severity,
          description: api.description,
          confidence: 0.80
        });
      }
    }

    return patterns;
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
