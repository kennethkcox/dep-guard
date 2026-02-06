/**
 * Integration tests for DepGuardScanner v2
 */

const DepGuardScanner = require('../src/DepGuardScanner');
const fs = require('fs');
const path = require('path');

describe('DepGuardScanner', () => {
  let scanner;
  const testProjectDir = path.join(__dirname, 'fixtures', 'test-project');

  beforeEach(() => {
    // Create test project directory
    if (!fs.existsSync(testProjectDir)) {
      fs.mkdirSync(testProjectDir, { recursive: true });
    }
  });

  afterEach(() => {
    // Cleanup
    if (fs.existsSync(testProjectDir)) {
      fs.rmSync(testProjectDir, { recursive: true, force: true });
    }
  });

  describe('constructor', () => {
    test('should initialize with default options', () => {
      scanner = new DepGuardScanner({ projectPath: testProjectDir });

      expect(scanner.options.projectPath).toBe(testProjectDir);
      expect(scanner.options.maxDepth).toBe(10);
      expect(scanner.options.minConfidence).toBe(0.5);
    });

    test('should accept custom options', () => {
      scanner = new DepGuardScanner({
        projectPath: testProjectDir,
        maxDepth: 15,
        minConfidence: 0.7,
        deepAnalysis: true
      });

      expect(scanner.options.maxDepth).toBe(15);
      expect(scanner.options.minConfidence).toBe(0.7);
      expect(scanner.options.deepAnalysis).toBe(true);
    });

    test('should initialize required components', () => {
      scanner = new DepGuardScanner({ projectPath: testProjectDir });

      expect(scanner.reachabilityAnalyzer).toBeDefined();
      expect(scanner.manifestFinder).toBeDefined();
      expect(scanner.entryPointDetector).toBeDefined();
    });
  });

  describe('scan', () => {
    test('should return error for project without manifests', async () => {
      scanner = new DepGuardScanner({ projectPath: testProjectDir });
      const result = await scanner.scan();

      expect(result.success).toBe(false);
      expect(result.error).toContain('No dependency manifests found');
    });

    test('should initialize shaiHuludDetector', () => {
      scanner = new DepGuardScanner({ projectPath: testProjectDir });
      expect(scanner.shaiHuludDetector).toBeDefined();
    });
  });

  describe('getStatistics', () => {
    test('should return statistics object', () => {
      scanner = new DepGuardScanner({ projectPath: testProjectDir });

      // Set some test results
      scanner.results = [
        { severity: 'CRITICAL', confidence: 0.9 },
        { severity: 'HIGH', confidence: 0.7 }
      ];
      scanner.manifests = [{ path: 'package.json' }];
      scanner.allDependencies = [{ dependencies: [{ name: 'lodash' }] }];

      const stats = scanner.getStatistics();

      expect(stats).toBeDefined();
      expect(typeof stats.manifests).toBe('number');
      expect(typeof stats.dependencies).toBe('number');
    });

    test('should count vulnerabilities by severity', () => {
      scanner = new DepGuardScanner({ projectPath: testProjectDir });
      scanner.results = [
        { severity: 'CRITICAL', confidence: 0.9, isReachable: true },
        { severity: 'CRITICAL', confidence: 0.8, isReachable: true },
        { severity: 'HIGH', confidence: 0.7, isReachable: true },
        { severity: 'MEDIUM', confidence: 0.6, isReachable: false }
      ];
      scanner.manifests = [];
      scanner.allDependencies = [];

      const stats = scanner.getStatistics();

      expect(stats.reachableVulnerabilities).toBe(3);
      expect(stats.unreachableVulnerabilities).toBe(1);
    });
  });

  describe('generateReport', () => {
    test('should generate table report', async () => {
      // Ensure directory exists
      if (!fs.existsSync(testProjectDir)) {
        fs.mkdirSync(testProjectDir, { recursive: true });
      }

      const packageJson = {
        name: 'test-project',
        version: '1.0.0',
        dependencies: {}
      };

      fs.writeFileSync(
        path.join(testProjectDir, 'package.json'),
        JSON.stringify(packageJson, null, 2)
      );

      scanner = new DepGuardScanner({ projectPath: testProjectDir });
      await scanner.scan();

      // Should not throw
      await expect(scanner.generateReport('table')).resolves.not.toThrow();
    });

    test('should generate JSON report', async () => {
      // Ensure directory exists
      if (!fs.existsSync(testProjectDir)) {
        fs.mkdirSync(testProjectDir, { recursive: true });
      }

      const packageJson = {
        name: 'test-project',
        version: '1.0.0',
        dependencies: {}
      };

      fs.writeFileSync(
        path.join(testProjectDir, 'package.json'),
        JSON.stringify(packageJson, null, 2)
      );

      scanner = new DepGuardScanner({ projectPath: testProjectDir });
      await scanner.scan();

      const report = await scanner.generateReport('json');
      expect(typeof report).toBe('string');

      const parsed = JSON.parse(report);
      expect(parsed).toBeDefined();
    });
  });
});
