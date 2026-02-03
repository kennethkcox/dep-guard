/**
 * Dependency Resolver for Transitive Dependencies
 * Resolves transitive dependencies using native package manager tools
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { getLogger } = require('./logger');
const { FileSystemError } = require('./errors');

class DependencyResolver {
  constructor(options = {}) {
    this.options = options;
    this.logger = getLogger().child({ component: 'DependencyResolver' });
    this.timeout = options.timeout || 60000; // 60 seconds default
  }

  /**
   * Resolves Maven transitive dependencies using mvn dependency:tree
   */
  resolveMavenDependencies(manifestPath) {
    const manifestDir = path.dirname(manifestPath);

    try {
      this.logger.info('Resolving Maven transitive dependencies', { manifestPath });

      // Check if Maven is available
      try {
        execSync('mvn --version', { stdio: 'ignore' });
      } catch (error) {
        this.logger.warn('Maven not found in PATH, skipping transitive resolution');
        return [];
      }

      // Run mvn dependency:tree
      const command = 'mvn dependency:tree -DoutputType=text -DoutputFile=depguard-deps.txt';

      this.logger.debug('Executing Maven command', { command, dir: manifestDir });

      execSync(command, {
        cwd: manifestDir,
        timeout: this.timeout,
        stdio: 'pipe'
      });

      // Read the output file
      const outputFile = path.join(manifestDir, 'depguard-deps.txt');

      if (!fs.existsSync(outputFile)) {
        this.logger.warn('Maven dependency tree file not created');
        return [];
      }

      const content = fs.readFileSync(outputFile, 'utf-8');

      // Clean up
      try {
        fs.unlinkSync(outputFile);
      } catch (e) {
        // Ignore cleanup errors
      }

      // Parse the dependency tree
      const dependencies = this.parseMavenDependencyTree(content);

      this.logger.info('Resolved Maven dependencies', {
        count: dependencies.length,
        transitive: dependencies.filter(d => d.transitive).length
      });

      return dependencies;

    } catch (error) {
      this.logger.error('Failed to resolve Maven dependencies', {
        error: error.message,
        manifestPath
      });
      return [];
    }
  }

  /**
   * Parses Maven dependency tree output
   * Format: [INFO] +- groupId:artifactId:type:version:scope
   */
  parseMavenDependencyTree(content) {
    const dependencies = [];
    const lines = content.split('\n');

    for (const line of lines) {
      // Match dependency lines like: [INFO] +- org.apache.shiro:shiro-core:jar:1.2.3:compile
      const match = line.match(/\[INFO\]\s+[+\\|-]\s+([^:]+):([^:]+):([^:]+):([^:]+)(?::([^:]+))?/);

      if (match) {
        const [, groupId, artifactId, type, version, scope] = match;

        // Determine if transitive (indented with \- or +-)
        const isTransitive = line.includes('\\-') || (line.match(/[+\\|-]/g) || []).length > 1;

        dependencies.push({
          name: `${groupId}:${artifactId}`,
          version: version,
          groupId,
          artifactId,
          type,
          scope: scope || 'compile',
          ecosystem: 'maven',
          transitive: isTransitive
        });
      }
    }

    return dependencies;
  }

  /**
   * Resolves npm transitive dependencies from package-lock.json
   */
  resolveNpmDependencies(manifestPath) {
    try {
      this.logger.info('Resolving npm transitive dependencies', { manifestPath });

      const manifestDir = path.dirname(manifestPath);
      const lockfilePath = path.join(manifestDir, 'package-lock.json');

      if (!fs.existsSync(lockfilePath)) {
        this.logger.debug('No package-lock.json found, trying npm ls');
        return this.resolveNpmDependenciesViaLs(manifestDir);
      }

      const content = fs.readFileSync(lockfilePath, 'utf-8');
      const lockfile = JSON.parse(content);

      const dependencies = [];

      // Parse npm lockfile v1 and v2/v3 formats
      if (lockfile.dependencies) {
        // Lockfile v1 format
        this.parseNpmLockfileV1(lockfile.dependencies, dependencies);
      } else if (lockfile.packages) {
        // Lockfile v2/v3 format
        this.parseNpmLockfileV2(lockfile.packages, dependencies);
      }

      this.logger.info('Resolved npm dependencies', {
        count: dependencies.length,
        transitive: dependencies.filter(d => d.transitive).length
      });

      return dependencies;

    } catch (error) {
      this.logger.error('Failed to resolve npm dependencies', {
        error: error.message,
        manifestPath
      });
      return [];
    }
  }

  /**
   * Parses npm lockfile v1 format (dependencies object)
   */
  parseNpmLockfileV1(deps, result, isTransitive = false) {
    for (const [name, info] of Object.entries(deps)) {
      result.push({
        name,
        version: info.version,
        ecosystem: 'npm',
        transitive: isTransitive,
        dev: info.dev || false
      });

      // Recursively parse nested dependencies (these are transitive)
      if (info.dependencies) {
        this.parseNpmLockfileV1(info.dependencies, result, true);
      }
    }
  }

  /**
   * Parses npm lockfile v2/v3 format (packages object)
   */
  parseNpmLockfileV2(packages, result) {
    for (const [pkgPath, info] of Object.entries(packages)) {
      // Skip root package
      if (pkgPath === '') continue;

      // Extract package name from path
      const name = pkgPath.replace(/^node_modules\//, '').replace(/\/node_modules\/.*$/, '');

      // Determine if transitive (nested in node_modules)
      const isTransitive = (pkgPath.match(/node_modules/g) || []).length > 1;

      result.push({
        name,
        version: info.version,
        ecosystem: 'npm',
        transitive: isTransitive,
        dev: info.dev || info.devOptional || false
      });
    }
  }

  /**
   * Resolves npm dependencies using npm ls command
   */
  resolveNpmDependenciesViaLs(projectDir) {
    try {
      this.logger.debug('Attempting npm ls for dependency resolution');

      // Check if npm is available
      try {
        execSync('npm --version', { stdio: 'ignore' });
      } catch (error) {
        this.logger.warn('npm not found in PATH');
        return [];
      }

      const output = execSync('npm ls --all --json --depth=10', {
        cwd: projectDir,
        timeout: this.timeout,
        stdio: 'pipe'
      }).toString();

      const data = JSON.parse(output);
      const dependencies = [];

      this.parseNpmLsOutput(data.dependencies || {}, dependencies, false);

      return dependencies;

    } catch (error) {
      // npm ls returns non-zero exit code if there are issues, but still outputs JSON
      if (error.stdout) {
        try {
          const data = JSON.parse(error.stdout.toString());
          const dependencies = [];
          this.parseNpmLsOutput(data.dependencies || {}, dependencies, false);
          return dependencies;
        } catch (parseError) {
          this.logger.warn('Failed to parse npm ls output', { error: parseError.message });
        }
      }
      return [];
    }
  }

  /**
   * Parses npm ls JSON output
   */
  parseNpmLsOutput(deps, result, isTransitive) {
    for (const [name, info] of Object.entries(deps)) {
      if (info.version) {
        result.push({
          name,
          version: info.version,
          ecosystem: 'npm',
          transitive: isTransitive
        });
      }

      // Recursively parse nested dependencies
      if (info.dependencies) {
        this.parseNpmLsOutput(info.dependencies, result, true);
      }
    }
  }

  /**
   * Resolves Python transitive dependencies
   */
  resolvePythonDependencies(manifestPath) {
    try {
      this.logger.info('Resolving Python transitive dependencies', { manifestPath });

      const manifestDir = path.dirname(manifestPath);

      // Try to find lockfiles first
      const pipfileLock = path.join(manifestDir, 'Pipfile.lock');
      const poetryLock = path.join(manifestDir, 'poetry.lock');
      const requirementsTxt = path.join(manifestDir, 'requirements.txt');

      if (fs.existsSync(pipfileLock)) {
        return this.parsePipfileLock(pipfileLock);
      }

      if (fs.existsSync(poetryLock)) {
        return this.parsePoetryLock(poetryLock);
      }

      // Fallback: try pip freeze if in virtual environment
      return this.resolvePythonDependenciesViaPip(manifestDir);

    } catch (error) {
      this.logger.error('Failed to resolve Python dependencies', {
        error: error.message,
        manifestPath
      });
      return [];
    }
  }

  /**
   * Parses Pipfile.lock for Python dependencies
   */
  parsePipfileLock(lockfilePath) {
    try {
      const content = fs.readFileSync(lockfilePath, 'utf-8');
      const lockfile = JSON.parse(content);
      const dependencies = [];

      // Parse default dependencies
      if (lockfile.default) {
        for (const [name, info] of Object.entries(lockfile.default)) {
          dependencies.push({
            name,
            version: info.version.replace(/[=><]/g, ''),
            ecosystem: 'pypi',
            transitive: false // Pipfile.lock doesn't distinguish
          });
        }
      }

      // Parse dev dependencies
      if (lockfile.develop) {
        for (const [name, info] of Object.entries(lockfile.develop)) {
          dependencies.push({
            name,
            version: info.version.replace(/[=><]/g, ''),
            ecosystem: 'pypi',
            transitive: false,
            dev: true
          });
        }
      }

      this.logger.info('Resolved Python dependencies from Pipfile.lock', { count: dependencies.length });
      return dependencies;

    } catch (error) {
      this.logger.error('Failed to parse Pipfile.lock', { error: error.message });
      return [];
    }
  }

  /**
   * Parses poetry.lock for Python dependencies
   */
  parsePoetryLock(lockfilePath) {
    try {
      const content = fs.readFileSync(lockfilePath, 'utf-8');
      const dependencies = [];

      // Parse TOML format (simplified - matches [[package]] sections)
      const packageSections = content.split('[[package]]').slice(1);

      for (const section of packageSections) {
        const nameMatch = section.match(/name\s*=\s*"([^"]+)"/);
        const versionMatch = section.match(/version\s*=\s*"([^"]+)"/);

        if (nameMatch && versionMatch) {
          dependencies.push({
            name: nameMatch[1],
            version: versionMatch[1],
            ecosystem: 'pypi',
            transitive: false // Poetry.lock doesn't distinguish easily
          });
        }
      }

      this.logger.info('Resolved Python dependencies from poetry.lock', { count: dependencies.length });
      return dependencies;

    } catch (error) {
      this.logger.error('Failed to parse poetry.lock', { error: error.message });
      return [];
    }
  }

  /**
   * Resolves Python dependencies using pip
   */
  resolvePythonDependenciesViaPip(projectDir) {
    try {
      this.logger.debug('Attempting pip freeze for dependency resolution');

      // Check if pip is available
      try {
        execSync('pip --version', { stdio: 'ignore' });
      } catch (error) {
        this.logger.warn('pip not found in PATH');
        return [];
      }

      const output = execSync('pip list --format=json', {
        cwd: projectDir,
        timeout: this.timeout,
        stdio: 'pipe'
      }).toString();

      const packages = JSON.parse(output);
      const dependencies = [];

      for (const pkg of packages) {
        dependencies.push({
          name: pkg.name,
          version: pkg.version,
          ecosystem: 'pypi',
          transitive: true // Assume all are potentially transitive
        });
      }

      this.logger.info('Resolved Python dependencies via pip', { count: dependencies.length });
      return dependencies;

    } catch (error) {
      this.logger.warn('Failed to resolve via pip', { error: error.message });
      return [];
    }
  }
}

module.exports = DependencyResolver;
