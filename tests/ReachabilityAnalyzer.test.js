/**
 * Tests for ReachabilityAnalyzer
 */

const ReachabilityAnalyzer = require('../src/core/ReachabilityAnalyzer');

describe('ReachabilityAnalyzer', () => {
  let analyzer;

  beforeEach(() => {
    analyzer = new ReachabilityAnalyzer({
      maxDepth: 5,
      minConfidence: 0.5
    });
  });

  afterEach(() => {
    analyzer.clear();
  });

  describe('addEntryPoint', () => {
    test('should add entry point', () => {
      analyzer.addEntryPoint('main.js', 'main');
      expect(analyzer.entryPoints.has('main.js:main')).toBe(true);
    });
  });

  describe('addCall', () => {
    test('should record call relationship', () => {
      analyzer.addCall('app.js', 'handleRequest', 'auth.js', 'authenticate', 'direct');

      const calls = analyzer.callGraph.get('app.js:handleRequest');
      expect(calls).toBeDefined();
      expect(calls.length).toBe(1);
      expect(calls[0].target).toBe('auth.js:authenticate');
    });

    test('should build reverse call graph', () => {
      analyzer.addCall('app.js', 'main', 'lib.js', 'helper', 'direct');

      const callers = analyzer.reverseCallGraph.get('lib.js:helper');
      expect(callers).toBeDefined();
      expect(callers.length).toBe(1);
      expect(callers[0].source).toBe('app.js:main');
    });
  });

  describe('addVulnerability', () => {
    test('should add vulnerability', () => {
      const vuln = { id: 'CVE-2021-1234', severity: 'HIGH' };
      analyzer.addVulnerability('lodash', 'lodash/template.js', 'template', vuln);

      const vulns = analyzer.vulnerableLocations.get('lodash');
      expect(vulns).toBeDefined();
      expect(vulns.length).toBe(1);
      expect(vulns[0].vulnerability.id).toBe('CVE-2021-1234');
    });
  });

  describe('findPaths', () => {
    beforeEach(() => {
      // Build simple call graph: main -> foo -> bar -> vulnerable
      analyzer.addCall('app.js', 'main', 'app.js', 'foo', 'direct');
      analyzer.addCall('app.js', 'foo', 'lib.js', 'bar', 'direct');
      analyzer.addCall('lib.js', 'bar', 'vuln.js', 'vulnerable', 'direct');
    });

    test('should find path from source to target', () => {
      const paths = analyzer.findPaths('app.js:main', 'vuln.js:vulnerable', 5);

      expect(paths.length).toBeGreaterThan(0);
      expect(paths[0].nodes).toContain('app.js:main');
      expect(paths[0].nodes).toContain('vuln.js:vulnerable');
    });

    test('should respect max depth', () => {
      const paths = analyzer.findPaths('app.js:main', 'vuln.js:vulnerable', 2);
      expect(paths.length).toBe(0);
    });

    test('should avoid cycles', () => {
      // Add cycle: bar -> foo
      analyzer.addCall('lib.js', 'bar', 'app.js', 'foo', 'direct');

      const paths = analyzer.findPaths('app.js:main', 'vuln.js:vulnerable', 10);

      // Should still find path without infinite loop
      expect(paths.length).toBeGreaterThan(0);
    });
  });

  describe('analyzeReachability', () => {
    beforeEach(() => {
      analyzer.addEntryPoint('app.js', 'main');
      analyzer.addCall('app.js', 'main', 'lib.js', 'helper', 'direct');
      analyzer.addCall('lib.js', 'helper', 'vuln.js', 'vulnerable', 'direct');
    });

    test('should detect reachable vulnerability', () => {
      const result = analyzer.analyzeReachability('vuln.js:vulnerable');

      expect(result.isReachable).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.5);
      expect(result.paths.length).toBeGreaterThan(0);
    });

    test('should detect unreachable vulnerability', () => {
      const result = analyzer.analyzeReachability('other.js:notCalled');

      expect(result.isReachable).toBe(false);
      expect(result.paths.length).toBe(0);
    });

    test('should calculate confidence scores', () => {
      const result = analyzer.analyzeReachability('vuln.js:vulnerable');

      expect(result.confidence).toBeGreaterThan(0);
      expect(result.confidence).toBeLessThanOrEqual(1);
    });

    test('should cache results', () => {
      const result1 = analyzer.analyzeReachability('vuln.js:vulnerable');
      const result2 = analyzer.analyzeReachability('vuln.js:vulnerable');

      expect(result1).toBe(result2); // Same object reference
    });
  });

  describe('analyzeAll', () => {
    test('should analyze all vulnerabilities', () => {
      analyzer.addEntryPoint('app.js', 'main');
      analyzer.addCall('app.js', 'main', 'vuln1.js', 'vulnerable1', 'direct');
      analyzer.addCall('app.js', 'main', 'vuln2.js', 'vulnerable2', 'direct');

      const vuln1 = { id: 'CVE-2021-0001', severity: 'HIGH' };
      const vuln2 = { id: 'CVE-2021-0002', severity: 'CRITICAL' };

      analyzer.addVulnerability('pkg1', 'vuln1.js', 'vulnerable1', vuln1);
      analyzer.addVulnerability('pkg2', 'vuln2.js', 'vulnerable2', vuln2);

      const results = analyzer.analyzeAll();

      expect(results.length).toBe(2);
      expect(results.every(r => r.reachability.isReachable)).toBe(true);
    });

    test('should sort by confidence', () => {
      analyzer.addEntryPoint('app.js', 'main');

      // Short path (high confidence)
      analyzer.addCall('app.js', 'main', 'vuln1.js', 'vulnerable1', 'direct');

      // Long path (lower confidence)
      analyzer.addCall('app.js', 'main', 'mid1.js', 'func1', 'direct');
      analyzer.addCall('mid1.js', 'func1', 'mid2.js', 'func2', 'direct');
      analyzer.addCall('mid2.js', 'func2', 'vuln2.js', 'vulnerable2', 'direct');

      analyzer.addVulnerability('pkg1', 'vuln1.js', 'vulnerable1', { id: 'CVE-1' });
      analyzer.addVulnerability('pkg2', 'vuln2.js', 'vulnerable2', { id: 'CVE-2' });

      const results = analyzer.analyzeAll();

      expect(results.length).toBe(2);
      expect(results[0].reachability.confidence).toBeGreaterThan(results[1].reachability.confidence);
    });
  });

  describe('calculatePathConfidence', () => {
    test('should decrease confidence for longer paths', () => {
      const shortPath = { nodes: ['a:f1', 'b:f2'], confidence: 1.0 };
      const longPath = { nodes: ['a:f1', 'b:f2', 'c:f3', 'd:f4', 'e:f5'], confidence: 1.0 };

      const shortConf = analyzer.calculatePathConfidence(shortPath);
      const longConf = analyzer.calculatePathConfidence(longPath);

      expect(shortConf).toBeGreaterThan(longConf);
    });

    test('should boost confidence for short paths', () => {
      const veryShortPath = { nodes: ['a:f1', 'b:f2'], confidence: 0.9 };

      const conf = analyzer.calculatePathConfidence(veryShortPath);

      expect(conf).toBeGreaterThan(0.9);
    });
  });

  describe('getStatistics', () => {
    test('should return statistics', () => {
      analyzer.addEntryPoint('app.js', 'main');
      analyzer.addCall('app.js', 'main', 'lib.js', 'func', 'direct');
      analyzer.addVulnerability('pkg', 'vuln.js', 'vulnerable', { id: 'CVE-1' });

      const stats = analyzer.getStatistics();

      expect(stats.totalNodes).toBeGreaterThan(0);
      expect(stats.totalEdges).toBeGreaterThan(0);
      expect(stats.entryPoints).toBe(1);
      expect(stats.vulnerableLocations).toBe(1);
    });
  });

  describe('backwardAnalysis', () => {
    test('should find paths backward from target', () => {
      analyzer.addEntryPoint('app.js', 'main');
      analyzer.addCall('app.js', 'main', 'lib.js', 'helper', 'direct');
      analyzer.addCall('lib.js', 'helper', 'vuln.js', 'vulnerable', 'direct');

      const paths = analyzer.backwardAnalysis('vuln.js:vulnerable');

      expect(paths.length).toBeGreaterThan(0);
      expect(paths[0].nodes[0]).toBe('app.js:main');
    });
  });
});
