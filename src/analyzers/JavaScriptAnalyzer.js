/**
 * JavaScript/TypeScript Call Graph Builder
 * Uses AST parsing to construct accurate call graphs
 */

const fs = require('fs');
const path = require('path');
const { parse } = require('@babel/parser');
const traverse = require('@babel/traverse').default;

class JavaScriptAnalyzer {
  constructor(reachabilityAnalyzer, options = {}) {
    this.reachabilityAnalyzer = reachabilityAnalyzer;
    this.options = options;
    this.moduleExports = new Map(); // module -> exported functions
    this.moduleImports = new Map(); // module -> imports
    this.currentModule = null;
    this.currentFunction = null;
  }

  /**
   * Analyzes a JavaScript/TypeScript file
   */
  analyzeFile(filePath) {
    try {
      const code = fs.readFileSync(filePath, 'utf-8');
      this.currentModule = filePath;

      const ast = parse(code, {
        sourceType: 'module',
        plugins: [
          'jsx',
          'typescript',
          'classProperties',
          'dynamicImport',
          'exportDefaultFrom',
          'exportNamespaceFrom'
        ]
      });

      this.analyzeAST(ast, filePath);
    } catch (error) {
      console.error(`Error analyzing ${filePath}: ${error.message}`);
    }
  }

  /**
   * Analyzes the AST to build call graph
   */
  analyzeAST(ast, filePath) {
    const imports = new Map(); // local name -> {module, imported}
    const exports = new Set();
    const functionScopes = [];

    traverse(ast, {
      // Track imports
      ImportDeclaration: (nodePath) => {
        const source = nodePath.node.source.value;

        nodePath.node.specifiers.forEach(spec => {
          if (spec.type === 'ImportDefaultSpecifier') {
            imports.set(spec.local.name, { module: source, imported: 'default' });
          } else if (spec.type === 'ImportSpecifier') {
            imports.set(spec.local.name, { module: source, imported: spec.imported.name });
          } else if (spec.type === 'ImportNamespaceSpecifier') {
            imports.set(spec.local.name, { module: source, imported: '*' });
          }
        });
      },

      // Track require() calls
      CallExpression: (nodePath) => {
        if (nodePath.node.callee.name === 'require' &&
            nodePath.node.arguments.length > 0 &&
            nodePath.node.arguments[0].type === 'StringLiteral') {

          const moduleName = nodePath.node.arguments[0].value;
          const parent = nodePath.parent;

          if (parent.type === 'VariableDeclarator') {
            const localName = parent.id.name;
            imports.set(localName, { module: moduleName, imported: 'default' });
          }
        }

        // Track function calls
        if (this.currentFunction) {
          this.trackFunctionCall(nodePath, imports, filePath);
        }
      },

      // Track function declarations
      FunctionDeclaration: (nodePath) => {
        const funcName = nodePath.node.id ? nodePath.node.id.name : 'anonymous';
        functionScopes.push(funcName);
        this.currentFunction = funcName;

        // Add as potential entry point if exported or main
        if (funcName === 'main' || exports.has(funcName)) {
          this.reachabilityAnalyzer.addEntryPoint(filePath, funcName);
        }
      },

      'FunctionDeclaration|FunctionExpression|ArrowFunctionExpression': {
        exit: () => {
          functionScopes.pop();
          this.currentFunction = functionScopes[functionScopes.length - 1] || null;
        }
      },

      // Track exports
      ExportNamedDeclaration: (nodePath) => {
        if (nodePath.node.declaration) {
          if (nodePath.node.declaration.type === 'FunctionDeclaration') {
            const funcName = nodePath.node.declaration.id.name;
            exports.add(funcName);
            this.reachabilityAnalyzer.addEntryPoint(filePath, funcName);
          }
        }

        if (nodePath.node.specifiers) {
          nodePath.node.specifiers.forEach(spec => {
            exports.add(spec.exported.name);
          });
        }
      },

      ExportDefaultDeclaration: (nodePath) => {
        exports.add('default');
        if (nodePath.node.declaration.type === 'FunctionDeclaration' ||
            nodePath.node.declaration.type === 'FunctionExpression') {
          this.reachabilityAnalyzer.addEntryPoint(filePath, 'default');
        }
      },

      // Track method calls
      MemberExpression: (nodePath) => {
        if (nodePath.parent.type === 'CallExpression' &&
            nodePath.parent.callee === nodePath.node) {
          this.trackMethodCall(nodePath, imports, filePath);
        }
      }
    });

    this.moduleImports.set(filePath, imports);
    this.moduleExports.set(filePath, exports);
  }

  /**
   * Tracks a function call and adds to call graph
   */
  trackFunctionCall(nodePath, imports, filePath) {
    const callee = nodePath.node.callee;

    if (callee.type === 'Identifier') {
      const funcName = callee.name;

      // Check if it's an imported function
      if (imports.has(funcName)) {
        const importInfo = imports.get(funcName);
        const targetModule = this.resolveModule(importInfo.module, filePath);

        this.reachabilityAnalyzer.addCall(
          filePath,
          this.currentFunction || 'module',
          targetModule,
          importInfo.imported,
          'direct'
        );
      } else {
        // Local function call
        this.reachabilityAnalyzer.addCall(
          filePath,
          this.currentFunction || 'module',
          filePath,
          funcName,
          'direct'
        );
      }
    }
  }

  /**
   * Tracks a method call (obj.method())
   */
  trackMethodCall(nodePath, imports, filePath) {
    const obj = nodePath.node.object;
    const prop = nodePath.node.property;

    if (obj.type === 'Identifier' && prop.type === 'Identifier') {
      const objName = obj.name;
      const methodName = prop.name;

      // Check if object is an imported module
      if (imports.has(objName)) {
        const importInfo = imports.get(objName);
        const targetModule = this.resolveModule(importInfo.module, filePath);

        this.reachabilityAnalyzer.addCall(
          filePath,
          this.currentFunction || 'module',
          targetModule,
          methodName,
          importInfo.imported === '*' ? 'dynamic' : 'direct'
        );
      }
    }
  }

  /**
   * Resolves a module path to absolute path
   */
  resolveModule(moduleName, fromFile) {
    // Handle relative imports
    if (moduleName.startsWith('.')) {
      return path.resolve(path.dirname(fromFile), moduleName);
    }

    // Handle node_modules
    if (!moduleName.startsWith('/')) {
      return `node_modules/${moduleName}`;
    }

    return moduleName;
  }

  /**
   * Analyzes package.json to find entry points
   */
  analyzePackageJson(packageJsonPath) {
    try {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      const baseDir = path.dirname(packageJsonPath);

      // Main entry point
      if (packageJson.main) {
        const mainFile = path.resolve(baseDir, packageJson.main);
        this.reachabilityAnalyzer.addEntryPoint(mainFile, 'module');
      }

      // Bin entry points
      if (packageJson.bin) {
        if (typeof packageJson.bin === 'string') {
          const binFile = path.resolve(baseDir, packageJson.bin);
          this.reachabilityAnalyzer.addEntryPoint(binFile, 'module');
        } else {
          Object.values(packageJson.bin).forEach(binPath => {
            const binFile = path.resolve(baseDir, binPath);
            this.reachabilityAnalyzer.addEntryPoint(binFile, 'module');
          });
        }
      }

      return packageJson;
    } catch (error) {
      console.error(`Error analyzing package.json: ${error.message}`);
      return null;
    }
  }

  /**
   * Finds all JavaScript files in a directory
   */
  findJavaScriptFiles(dir, excludePatterns = ['node_modules', 'test', 'tests', 'dist', 'build']) {
    const FileWalker = require('../utils/FileWalker');
    const walker = new FileWalker({
      excludeDirs: excludePatterns,
      maxDepth: 10
    });

    return walker.findJavaScriptFiles(dir);
  }

  /**
   * Analyzes entire project
   */
  analyzeProject(projectDir) {
    // Analyze package.json first
    const packageJsonPath = path.join(projectDir, 'package.json');
    const packageJson = this.analyzePackageJson(packageJsonPath);

    // Find and analyze all JS files
    const jsFiles = this.findJavaScriptFiles(projectDir);

    console.log(`Found ${jsFiles.length} JavaScript files to analyze`);

    jsFiles.forEach((file, index) => {
      if (index % 10 === 0) {
        console.log(`Analyzing file ${index + 1}/${jsFiles.length}`);
      }
      this.analyzeFile(file);
    });

    return {
      filesAnalyzed: jsFiles.length,
      packageJson
    };
  }
}

module.exports = JavaScriptAnalyzer;
