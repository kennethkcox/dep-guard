/**
 * Tests for DataFlowAnalyzer
 */

const DataFlowAnalyzer = require('../src/analysis/DataFlowAnalyzer');

describe('DataFlowAnalyzer', () => {
    let analyzer;

    beforeEach(() => {
        analyzer = new DataFlowAnalyzer();
    });

    describe('Taint Sources', () => {
        test('should identify HTTP request sources', () => {
            const sources = analyzer.findTaintSourcesAt('req.body.username');
            expect(sources).toContain('req.body');
        });

        test('should identify query parameters', () => {
            const sources = analyzer.findTaintSourcesAt('req.query.search');
            expect(sources).toContain('req.query');
        });

        test('should identify CLI arguments', () => {
            const sources = analyzer.findTaintSourcesAt('process.argv[2]');
            expect(sources).toContain('process.argv');
        });

        test('should not identify non-taint sources', () => {
            const sources = analyzer.findTaintSourcesAt('hardcoded.value');
            expect(sources).toHaveLength(0);
        });
    });

    describe('Sanitizers', () => {
        test('should detect validator.escape', () => {
            const hasSanitizer = analyzer.hasSanitizerAt('validator.escape(input)');
            expect(hasSanitizer).toBe(true);
        });

        test('should detect DOMPurify.sanitize', () => {
            const hasSanitizer = analyzer.hasSanitizerAt('DOMPurify.sanitize(html)');
            expect(hasSanitizer).toBe(true);
        });

        test('should detect parseInt', () => {
            const hasSanitizer = analyzer.hasSanitizerAt('parseInt(userInput)');
            expect(hasSanitizer).toBe(true);
        });

        test('should not detect non-sanitizers', () => {
            const hasSanitizer = analyzer.hasSanitizerAt('someFunction(input)');
            expect(hasSanitizer).toBe(false);
        });
    });

    describe('Taint Propagation', () => {
        test('should propagate through string operations', () => {
            const edge = { target: 'String.concat(input)' };
            expect(analyzer.taintPropagatesThrough(edge)).toBe(true);
        });

        test('should propagate through array operations', () => {
            const edge = { target: 'Array.map(input)' };
            expect(analyzer.taintPropagatesThrough(edge)).toBe(true);
        });

        test('should propagate through lodash', () => {
            const edge = { target: '_.map(input)' };
            expect(analyzer.taintPropagatesThrough(edge)).toBe(true);
        });
    });

    describe('Confidence Calculation', () => {
        test('should return low confidence when no paths found', () => {
            const confidence = analyzer.calculateTaintConfidence([], {});
            expect(confidence).toBeLessThan(0.5);
        });

        test('should return higher confidence for short paths', () => {
            const paths = [{
                path: ['a', 'b', 'c'],
                taintedVars: ['req.body'],
                sanitized: false,
                length: 3
            }];
            const confidence = analyzer.calculateTaintConfidence(paths, {});
            expect(confidence).toBeGreaterThan(0.60);
        });

        test('should reduce confidence when sanitizer present', () => {
            const pathsWithoutSanitizer = [{
                path: ['a', 'b'],
                taintedVars: ['req.body'],
                sanitized: false,
                length: 2
            }];
            const pathsWithSanitizer = [{
                path: ['a', 'b'],
                taintedVars: ['req.body'],
                sanitized: true,
                length: 2
            }];

            const confWithout = analyzer.calculateTaintConfidence(pathsWithoutSanitizer, {});
            const confWith = analyzer.calculateTaintConfidence(pathsWithSanitizer, {});

            expect(confWith).toBeLessThan(confWithout);
        });

        test('should increase confidence for direct HTTP sources', () => {
            const paths = [{
                path: ['a', 'b'],
                taintedVars: ['req.body'],
                sanitized: false,
                length: 2
            }];
            const confidence = analyzer.calculateTaintConfidence(paths, {});
            expect(confidence).toBeGreaterThan(0.60);
        });
    });

    describe('Risk Calculation', () => {
        test('should return CRITICAL for high-risk source without sanitizer', () => {
            const paths = [{
                path: ['a', 'b'],
                taintedVars: ['req.body'],
                sanitized: false
            }];
            const risk = analyzer.calculateRisk(paths, {});
            expect(risk).toBe('CRITICAL');
        });

        test('should return HIGH for high-risk source with sanitizer', () => {
            const paths = [{
                path: ['a', 'validator.escape(input)', 'b'],
                taintedVars: ['req.body'],
                sanitized: true
            }];
            const risk = analyzer.calculateRisk(paths, {});
            expect(risk).toBe('HIGH');
        });

        test('should return LOW when no paths', () => {
            const risk = analyzer.calculateRisk([], {});
            expect(risk).toBe('LOW');
        });
    });

    describe('Pattern Export/Import', () => {
        test('should export patterns', () => {
            const patterns = analyzer.exportPatterns();
            expect(patterns.sources).toBeDefined();
            expect(patterns.sanitizers).toBeDefined();
            expect(patterns.propagation).toBeDefined();
        });

        test('should import patterns', () => {
            const patterns = {
                sources: [['custom.source', { type: 'custom', risk: 'HIGH' }]],
                sanitizers: ['custom.sanitize'],
                propagation: [['custom.op', true]]
            };

            analyzer.importPatterns(patterns);

            expect(analyzer.taintSources.has('custom.source')).toBe(true);
            expect(analyzer.sanitizers.has('custom.sanitize')).toBe(true);
            expect(analyzer.propagationRules.has('custom.op')).toBe(true);
        });
    });

    describe('Statistics', () => {
        test('should return statistics', () => {
            const stats = analyzer.getStatistics();
            expect(stats.taintSources).toBeGreaterThan(0);
            expect(stats.sanitizers).toBeGreaterThan(0);
            expect(stats.propagationRules).toBeGreaterThan(0);
        });
    });
});
