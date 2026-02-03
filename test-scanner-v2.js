#!/usr/bin/env node

/**
 * Test DepGuard Scanner v2.0
 *
 * Tests the fully integrated generic scanner against the test suite
 */

const path = require('path');
const DepGuardScanner2 = require('./src/DepGuardScanner2');

console.log('🧪 Testing DepGuard Scanner v2.0\n');
console.log('=' .repeat(60));

async function runTest() {
    const testSuitePath = path.join(__dirname, '..', 'dependency-bad');

    console.log(`\n📂 Scanning: ${testSuitePath}\n`);

    const scanner = new DepGuardScanner2({
        projectPath: testSuitePath,
        minConfidence: 0.5,
        entryPointConfidence: 0.6,
        deepAnalysis: true,
        verbose: true
    });

    try {
        const result = await scanner.scan();

        if (result.success) {
            console.log('\n📊 Scan Statistics:');
            console.log('=' .repeat(60));
            console.log(`Manifests found: ${result.statistics.manifests}`);
            console.log(`Ecosystems: ${result.statistics.ecosystems}`);
            console.log(`Dependencies: ${result.statistics.dependencies}`);
            console.log(`Known vulnerabilities: ${result.statistics.vulnerabilities}`);
            console.log(`Entry points: ${result.statistics.entryPoints}`);
            console.log(`Call graph nodes: ${result.statistics.callGraph.totalNodes}`);
            console.log(`Call graph edges: ${result.statistics.callGraph.totalEdges}`);
            console.log('');
            console.log(`✅ Reachable vulnerabilities: ${result.statistics.reachableVulnerabilities}`);
            console.log(`❌ Unreachable vulnerabilities: ${result.statistics.unreachableVulnerabilities}`);

            console.log('\n📋 Findings:');
            console.log('=' .repeat(60));

            if (result.results.length === 0) {
                console.log('✓ No reachable vulnerabilities found!');
            } else {
                result.results.forEach((finding, index) => {
                    console.log(`\n${index + 1}. ${finding.vulnerability.id || 'Unknown CVE'}`);
                    console.log(`   Package: ${finding.vulnerability.package}`);
                    console.log(`   Severity: ${finding.vulnerability.severity || 'Unknown'}`);
                    console.log(`   Reachable: ${finding.isReachable ? '✅ YES' : '❌ NO'}`);
                    console.log(`   Confidence: ${(finding.confidence * 100).toFixed(0)}%`);

                    if (finding.paths && finding.paths.length > 0) {
                        console.log(`   Path (${finding.paths[0].length} steps):`);
                        finding.paths[0].slice(0, 3).forEach(step => {
                            console.log(`     → ${step}`);
                        });
                        if (finding.paths[0].length > 3) {
                            console.log(`     ... and ${finding.paths[0].length - 3} more steps`);
                        }
                    }
                });
            }

            // Generate report
            console.log('\n\n📄 Generating reports...');
            console.log('=' .repeat(60));

            await scanner.generateReport('table');
            console.log('✓ Table report displayed above');

            await scanner.generateReport('json', path.join(__dirname, 'scan-results-v2.json'));
            console.log('✓ JSON report: scan-results-v2.json');

            await scanner.generateReport('markdown', path.join(__dirname, 'scan-results-v2.md'));
            console.log('✓ Markdown report: scan-results-v2.md');
        } else {
            console.error(`\n❌ Scan failed: ${result.error}`);
        }
    } catch (error) {
        console.error(`\n❌ Test failed: ${error.message}`);
        console.error(error.stack);
    }
}

console.log('\n🚀 Starting scan...\n');
runTest();
