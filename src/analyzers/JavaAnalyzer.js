/**
 * Java Call Graph Builder
 * Analyzes Java code for dependency usage and call patterns
 */

const fs = require('fs');
const path = require('path');

class JavaAnalyzer {
  constructor(reachabilityAnalyzer, options = {}) {
    this.reachabilityAnalyzer = reachabilityAnalyzer;
    this.options = options;
    this.imports = new Map();
    this.classes = new Map();
  }

  /**
   * Analyzes a Java file using regex-based parsing
   * (In production, would use a proper Java parser like JavaParser)
   */
  analyzeFile(filePath) {
    try {
      const code = fs.readFileSync(filePath, 'utf-8');
      const lines = code.split('\n');

      const imports = [];
      const methods = [];
      let currentClass = null;
      let currentMethod = null;
      let packageName = '';

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();

        // Parse package declaration
        if (line.startsWith('package ')) {
          packageName = line.replace('package ', '').replace(';', '').trim();
        }

        // Parse imports
        if (line.startsWith('import ')) {
          const importPath = line.replace('import ', '').replace(';', '').trim();
          const className = importPath.split('.').pop();
          imports.push({ path: importPath, className, line: i + 1 });
        }

        // Parse class declarations
        if (line.match(/^\s*(public|private|protected)?\s*(static)?\s*class\s+(\w+)/)) {
          const match = line.match(/class\s+(\w+)/);
          if (match) {
            currentClass = match[1];
          }
        }

        // Parse method declarations
        if (line.match(/^\s*(public|private|protected)?\s*(static)?\s*\w+\s+(\w+)\s*\(/)) {
          const match = line.match(/\s+(\w+)\s*\(/);
          if (match) {
            currentMethod = match[1];
            methods.push({ name: currentMethod, line: i + 1 });

            // Mark main methods as entry points
            if (currentMethod === 'main' && line.includes('static')) {
              this.reachabilityAnalyzer.addEntryPoint(filePath, `${currentClass}.${currentMethod}`);
            }
          }
        }

        // Parse method calls
        if (currentMethod) {
          // Simple method call: object.method()
          const callMatches = line.matchAll(/(\w+)\.(\w+)\s*\(/g);
          for (const match of callMatches) {
            const obj = match[1];
            const method = match[2];

            // Check if obj is an imported class
            const importInfo = imports.find(imp => imp.className === obj);
            if (importInfo) {
              this.reachabilityAnalyzer.addCall(
                filePath,
                `${currentClass}.${currentMethod}`,
                importInfo.path,
                method,
                'direct'
              );
            }
          }

          // Static method calls: Class.method()
          const staticMatches = line.matchAll(/([A-Z]\w+)\.(\w+)\s*\(/g);
          for (const match of staticMatches) {
            const className = match[1];
            const method = match[2];

            const importInfo = imports.find(imp => imp.className === className);
            if (importInfo) {
              this.reachabilityAnalyzer.addCall(
                filePath,
                `${currentClass}.${currentMethod}`,
                importInfo.path,
                method,
                'direct'
              );
            }
          }
        }
      }

      this.imports.set(filePath, imports);
    } catch (error) {
      console.error(`Error analyzing ${filePath}: ${error.message}`);
    }
  }

  /**
   * Analyzes Maven pom.xml
   */
  analyzeMavenDependencies(pomPath) {
    const dependencies = [];

    try {
      const content = fs.readFileSync(pomPath, 'utf-8');

      // Extract dependencies (simple regex-based parsing)
      const depMatches = content.matchAll(/<dependency>[\s\S]*?<\/dependency>/g);

      for (const match of depMatches) {
        const dep = match[0];
        const groupMatch = dep.match(/<groupId>(.*?)<\/groupId>/);
        const artifactMatch = dep.match(/<artifactId>(.*?)<\/artifactId>/);
        const versionMatch = dep.match(/<version>(.*?)<\/version>/);

        if (groupMatch && artifactMatch) {
          dependencies.push({
            name: `${groupMatch[1]}:${artifactMatch[1]}`,
            version: versionMatch ? versionMatch[1] : 'latest'
          });
        }
      }
    } catch (error) {
      console.error(`Error analyzing pom.xml: ${error.message}`);
    }

    return dependencies;
  }

  /**
   * Analyzes Gradle build.gradle
   */
  analyzeGradleDependencies(gradlePath) {
    const dependencies = [];

    try {
      const content = fs.readFileSync(gradlePath, 'utf-8');

      // Extract dependencies
      const depMatches = content.matchAll(/['"]([\w.-]+):([\w.-]+):([^'"]+)['"]/g);

      for (const match of depMatches) {
        dependencies.push({
          name: `${match[1]}:${match[2]}`,
          version: match[3]
        });
      }
    } catch (error) {
      console.error(`Error analyzing build.gradle: ${error.message}`);
    }

    return dependencies;
  }

  /**
   * Finds all Java files in directory
   */
  findJavaFiles(dir, excludePatterns = ['target', 'build', 'test']) {
    const FileWalker = require('../utils/FileWalker');
    const walker = new FileWalker({
      excludeDirs: excludePatterns,
      maxDepth: 10
    });

    return walker.findJavaFiles(dir);
  }

  /**
   * Analyzes entire Java project
   */
  analyzeProject(projectDir) {
    let dependencies = [];

    // Check for Maven
    const pomPath = path.join(projectDir, 'pom.xml');
    if (fs.existsSync(pomPath)) {
      dependencies = this.analyzeMavenDependencies(pomPath);
      console.log('Detected Maven project');
    }

    // Check for Gradle
    const gradlePath = path.join(projectDir, 'build.gradle');
    if (fs.existsSync(gradlePath)) {
      dependencies = this.analyzeGradleDependencies(gradlePath);
      console.log('Detected Gradle project');
    }

    const javaFiles = this.findJavaFiles(projectDir);

    console.log(`Found ${javaFiles.length} Java files to analyze`);
    console.log(`Found ${dependencies.length} dependencies`);

    javaFiles.forEach((file, index) => {
      if (index % 10 === 0) {
        console.log(`Analyzing file ${index + 1}/${javaFiles.length}`);
      }
      this.analyzeFile(file);
    });

    return {
      filesAnalyzed: javaFiles.length,
      dependencies
    };
  }
}

module.exports = JavaAnalyzer;
