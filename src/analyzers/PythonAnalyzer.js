/**
 * Python Call Graph Builder
 * Analyzes Python code for dependency usage and call patterns
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class PythonAnalyzer {
  constructor(reachabilityAnalyzer, options = {}) {
    this.reachabilityAnalyzer = reachabilityAnalyzer;
    this.options = options;
    this.imports = new Map(); // module -> imports
    this.functions = new Map(); // module -> functions
  }

  /**
   * Analyzes a Python file using regex-based parsing
   * (In production, would use Python AST or a proper parser)
   */
  analyzeFile(filePath) {
    try {
      const code = fs.readFileSync(filePath, 'utf-8');
      const lines = code.split('\n');

      const imports = [];
      const functions = [];
      let currentFunction = null;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();

        // Parse import statements
        if (line.startsWith('import ')) {
          const modules = line.replace('import ', '').split(',');
          modules.forEach(mod => {
            const cleaned = mod.trim();
            imports.push({ module: cleaned, name: cleaned, line: i + 1 });
          });
        } else if (line.startsWith('from ')) {
          const match = line.match(/from\s+(\S+)\s+import\s+(.+)/);
          if (match) {
            const module = match[1];
            const imported = match[2].split(',').map(n => n.trim());
            imported.forEach(name => {
              const cleanName = name.replace(/\s+as\s+\S+/, '').trim();
              imports.push({ module, name: cleanName, line: i + 1 });
            });
          }
        }

        // Parse function definitions
        if (line.startsWith('def ')) {
          const match = line.match(/def\s+(\w+)\s*\(/);
          if (match) {
            currentFunction = match[1];
            functions.push({ name: currentFunction, line: i + 1 });

            // Check if it's a main entry point
            if (currentFunction === 'main' || line.includes('if __name__')) {
              this.reachabilityAnalyzer.addEntryPoint(filePath, currentFunction);
            }
          }
        }

        // Parse function calls
        if (currentFunction) {
          const callMatches = line.matchAll(/(\w+)\s*\(/g);
          for (const match of callMatches) {
            const funcName = match[1];

            // Check if it's an imported function
            const importInfo = imports.find(imp => imp.name === funcName);
            if (importInfo) {
              const targetModule = this.resolveModule(importInfo.module, filePath);
              this.reachabilityAnalyzer.addCall(
                filePath,
                currentFunction,
                targetModule,
                funcName,
                'direct'
              );
            } else {
              // Local function call
              this.reachabilityAnalyzer.addCall(
                filePath,
                currentFunction,
                filePath,
                funcName,
                'direct'
              );
            }
          }
        }
      }

      this.imports.set(filePath, imports);
      this.functions.set(filePath, functions);

      // Check for main block
      if (code.includes('if __name__ == "__main__"')) {
        this.reachabilityAnalyzer.addEntryPoint(filePath, '__main__');
      }
    } catch (error) {
      console.error(`Error analyzing ${filePath}: ${error.message}`);
    }
  }

  /**
   * Resolves Python module path
   */
  resolveModule(moduleName, fromFile) {
    // Handle relative imports
    if (moduleName.startsWith('.')) {
      return path.resolve(path.dirname(fromFile), moduleName.replace(/\./g, '/'));
    }

    // Handle standard library and installed packages
    return `site-packages/${moduleName}`;
  }

  /**
   * Analyzes requirements.txt or pyproject.toml
   */
  analyzeDependencies(projectDir) {
    const dependencies = [];

    // Try requirements.txt
    const reqPath = path.join(projectDir, 'requirements.txt');
    if (fs.existsSync(reqPath)) {
      const content = fs.readFileSync(reqPath, 'utf-8');
      const lines = content.split('\n');

      lines.forEach(line => {
        line = line.trim();
        if (line && !line.startsWith('#')) {
          const match = line.match(/^([a-zA-Z0-9_-]+)[=<>~]/);
          if (match) {
            const name = match[1];
            const versionMatch = line.match(/[=<>~]+([0-9.]+)/);
            const version = versionMatch ? versionMatch[1] : 'latest';
            dependencies.push({ name, version });
          }
        }
      });
    }

    // Try pyproject.toml (Poetry)
    const pyprojectPath = path.join(projectDir, 'pyproject.toml');
    if (fs.existsSync(pyprojectPath)) {
      const content = fs.readFileSync(pyprojectPath, 'utf-8');
      const depMatches = content.matchAll(/(\w+)\s*=\s*"([^"]+)"/g);

      for (const match of depMatches) {
        const name = match[1];
        const versionSpec = match[2];
        const version = versionSpec.replace(/[\^~>=<]/, '').trim();
        dependencies.push({ name, version });
      }
    }

    return dependencies;
  }

  /**
   * Finds all Python files in directory
   */
  findPythonFiles(dir, excludePatterns = ['venv', '__pycache__', 'tests', 'dist', 'build']) {
    const FileWalker = require('../utils/FileWalker');
    const walker = new FileWalker({
      excludeDirs: excludePatterns,
      maxDepth: 10
    });

    return walker.findPythonFiles(dir);
  }

  /**
   * Analyzes entire Python project
   */
  analyzeProject(projectDir) {
    const dependencies = this.analyzeDependencies(projectDir);
    const pyFiles = this.findPythonFiles(projectDir);

    console.log(`Found ${pyFiles.length} Python files to analyze`);
    console.log(`Found ${dependencies.length} dependencies`);

    pyFiles.forEach((file, index) => {
      if (index % 10 === 0) {
        console.log(`Analyzing file ${index + 1}/${pyFiles.length}`);
      }
      this.analyzeFile(file);
    });

    return {
      filesAnalyzed: pyFiles.length,
      dependencies
    };
  }
}

module.exports = PythonAnalyzer;
