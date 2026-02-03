#!/usr/bin/env node

/**
 * Test script for GenericManifestFinder
 *
 * Tests the manifest finder against the test suite and validates:
 * - Finds all manifest files correctly
 * - Works with different project structures
 * - Validates manifest content
 * - Groups manifests by workspace
 */

const path = require('path');
const GenericManifestFinder = require('./src/core/GenericManifestFinder');

console.log('🧪 Testing GenericManifestFinder\n');
console.log('=' .repeat(60));

// Test 1: Find manifests in the test suite
console.log('\n📦 Test 1: Find manifests in dependency-bad test suite');
console.log('-'.repeat(60));

const testSuitePath = path.join(__dirname, '..', 'dependency-bad');
const finder = new GenericManifestFinder({ verbose: true });

try {
    const manifests = finder.findManifests(testSuitePath);

    console.log('\n📊 Results:');
    console.log('-'.repeat(60));

    if (manifests.length === 0) {
        console.log('❌ No manifests found!');
    } else {
        console.log(`✅ Found ${manifests.length} manifest(s):\n`);

        manifests.forEach((manifest, index) => {
            console.log(`${index + 1}. ${manifest.filename}`);
            console.log(`   Path: ${manifest.path}`);
            console.log(`   Ecosystem: ${manifest.ecosystem}`);
            console.log(`   Type: ${manifest.type}`);
            console.log(`   Confidence: ${(manifest.confidence * 100).toFixed(0)}%`);
            if (manifest.validationMessage) {
                console.log(`   Note: ${manifest.validationMessage}`);
            }
            console.log('');
        });

        // Show statistics
        const stats = finder.getStatistics(manifests);
        console.log('📈 Statistics:');
        console.log(`   Total manifests: ${stats.total}`);
        console.log(`   Workspaces: ${stats.workspaces}`);
        console.log(`   By ecosystem:`);
        Object.entries(stats.byEcosystem).forEach(([eco, count]) => {
            console.log(`     - ${eco}: ${count}`);
        });
        console.log(`   By type:`);
        Object.entries(stats.byType).forEach(([type, count]) => {
            console.log(`     - ${type}: ${count}`);
        });
    }
} catch (error) {
    console.error(`❌ Error: ${error.message}`);
    console.error(error.stack);
}

// Test 2: Group by workspace
console.log('\n\n📁 Test 2: Group manifests by workspace');
console.log('-'.repeat(60));

try {
    const manifests = finder.findManifests(testSuitePath);
    const workspaces = finder.groupManifestsByWorkspace(manifests);

    console.log(`\nFound ${workspaces.length} workspace(s):\n`);

    workspaces.forEach((workspace, index) => {
        console.log(`${index + 1}. ${workspace.directory}`);
        workspace.manifests.forEach(m => {
            console.log(`   - ${m.filename} (${m.ecosystem})`);
        });
        console.log('');
    });
} catch (error) {
    console.error(`❌ Error: ${error.message}`);
}

// Test 3: Test against current project (appservice-scan)
console.log('\n\n📦 Test 3: Find manifests in current project (appservice-scan)');
console.log('-'.repeat(60));

const currentProjectPath = __dirname;
const currentFinder = new GenericManifestFinder({ verbose: false });

try {
    const manifests = currentFinder.findManifests(currentProjectPath);

    console.log(`\n✅ Found ${manifests.length} manifest(s) in current project:\n`);

    manifests.forEach((manifest, index) => {
        console.log(`${index + 1}. ${manifest.filename} (${manifest.ecosystem})`);
        console.log(`   ${manifest.path}`);
    });
} catch (error) {
    console.error(`❌ Error: ${error.message}`);
}

// Test 4: Test with different depth limits
console.log('\n\n🔍 Test 4: Test depth limits');
console.log('-'.repeat(60));

for (const maxDepth of [1, 3, 5]) {
    const depthFinder = new GenericManifestFinder({ maxDepth, verbose: false });
    const manifests = depthFinder.findManifests(testSuitePath);
    console.log(`Depth ${maxDepth}: Found ${manifests.length} manifest(s)`);
}

console.log('\n' + '='.repeat(60));
console.log('✅ GenericManifestFinder tests complete!\n');
