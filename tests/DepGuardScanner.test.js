/**
 * Integration tests for DepGuardScanner
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

  describe('detectProjectType', () => {
    test('should detect JavaScript project', () => {
      const packageJson = { name: 'test', version: '1.0.0', dependencies: {} };
      fs.writeFileSync(
        path.join(testProjectDir, 'package.json'),
        JSON.stringify(packageJson)
      );

      scanner = new DepGuardScanner({ projectPath: testProjectDir });
      const type = scanner.detectProjectType();

      expect(type).toBe('javascript');
    });

    test('should detect Python project', () => {
      fs.writeFileSync(path.join(testProjectDir, 'requirements.txt'), '');

      scanner = new DepGuardScanner({ projectPath: testProjectDir });
      const type = scanner.detectProjectType();

      expect(type).toBe('python');
    });

    test('should detect Java project', () => {
      fs.writeFileSync(path.join(testProjectDir, 'pom.xml'), '<project></project>');

      scanner = new DepGuardScanner({ projectPath: testProjectDir });
      const type = scanner.detectProjectType();

      expect(type).toBe('java');
    });
  });

  describe('parsePackageJson', () => {
    test('should parse dependencies', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        dependencies: {
          'lodash': '^4.17.20',
          'express': '~4.17.1'
        },
        devDependencies: {
          'jest': '^29.0.0'
        }
      };

      fs.writeFileSync(
        path.join(testProjectDir, 'package.json'),
        JSON.stringify(packageJson)
      );

      scanner = new DepGuardScanner({ projectPath: testProjectDir });
      const deps = scanner.parsePackageJson(path.join(testProjectDir, 'package.json'));

      expect(deps.length).toBe(3);
      expect(deps.some(d => d.name === 'lodash')).toBe(true);
      expect(deps.some(d => d.name === 'express')).toBe(true);
      expect(deps.some(d => d.name === 'jest')).toBe(true);
    });

    test('should clean version strings', () => {
      const packageJson = {
        name: 'test',
        dependencies: {
          'lodash': '^4.17.20'
        }
      };

      fs.writeFileSync(
        path.join(testProjectDir, 'package.json'),
        JSON.stringify(packageJson)
      );

      scanner = new DepGuardScanner({ projectPath: testProjectDir });
      const deps = scanner.parsePackageJson(path.join(testProjectDir, 'package.json'));

      expect(deps[0].version).toBe('4.17.20');
    });
  });

  describe('getStatistics', () => {
    test('should return statistics', () => {
      scanner = new DepGuardScanner({ projectPath: testProjectDir });
      scanner.results = [
        {
          vulnerability: { severity: 'CRITICAL' },
          reachability: { isReachable: true }
        },
        {
          vulnerability: { severity: 'HIGH' },
          reachability: { isReachable: false }
        }
      ];

      const stats = scanner.getStatistics();

      expect(stats.totalVulnerabilities).toBe(2);
      expect(stats.reachableVulnerabilities).toBe(1);
      expect(stats.critical).toBe(1);
      expect(stats.high).toBe(1);
    });
  });
});
