#!/usr/bin/env node
/**
 * Validation script: Compare DepGuard results against npm audit
 *
 * This script helps verify DepGuard's accuracy by:
 * 1. Running npm audit on a project
 * 2. Running DepGuard scan on the same project
 * 3. Comparing the results to find:
 *    - True positives (both tools found)
 *    - False positives (DepGuard found, npm audit didn't)
 *    - False negatives (npm audit found, DepGuard missed)
 *    - Unique findings (only DepGuard found due to reachability analysis)
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

function runNpmAudit(projectPath) {
  console.log('\n[1/3] Running npm audit...');
  try {
    const output = execSync('npm audit --json', {
      cwd: projectPath,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'ignore'] // Ignore stderr
    });
    return JSON.parse(output);
  } catch (error) {
    // npm audit exits with code 1 if vulnerabilities found
    if (error.stdout) {
      return JSON.parse(error.stdout);
    }
    throw error;
  }
}

function runDepGuard(projectPath) {
  console.log('\n[2/3] Running DepGuard scan...');
  const depguardPath = path.join(__dirname, '..', 'bin', 'depguard.js');
  const outputFile = path.join(projectPath, 'depguard-validation.json');

  try {
    execSync(`node "${depguardPath}" scan -p "${projectPath}" --deep-analysis -o json -f "${outputFile}"`, {
      encoding: 'utf8',
      stdio: 'inherit'
    });
  } catch (error) {
    // DepGuard may exit with code 1 if vulnerabilities found
  }

  if (fs.existsSync(outputFile)) {
    const data = JSON.parse(fs.readFileSync(outputFile, 'utf8'));
    fs.unlinkSync(outputFile); // Cleanup
    return data;
  }

  return { results: [], statistics: {} };
}

function compareResults(npmAudit, depGuard) {
  console.log('\n[3/3] Comparing results...\n');

  // Extract vulnerability IDs from npm audit
  const npmVulns = new Set();
  const npmVulnDetails = {};

  if (npmAudit.vulnerabilities) {
    Object.entries(npmAudit.vulnerabilities).forEach(([pkg, data]) => {
      if (!data || !data.via) return;

      const vias = Array.isArray(data.via) ? data.via : [data.via];
      vias.forEach(v => {
        if (typeof v === 'object' && v.source) {
          npmVulns.add(v.source);
          npmVulnDetails[v.source] = {
            package: pkg,
            severity: data.severity || 'unknown',
            title: v.title || 'Unknown'
          };
        }
      });
    });
  }

  // Extract vulnerability IDs from DepGuard
  const depGuardVulns = new Set();
  const depGuardReachable = new Set();
  const depGuardDetails = {};

  const results = depGuard.vulnerabilities || depGuard.results || [];
  results.forEach(result => {
    const id = result.vulnerability?.id || result.id;
    if (id) {
      depGuardVulns.add(id);
      depGuardDetails[id] = {
        package: result.package,
        severity: result.severity,
        confidence: result.confidence,
        isReachable: result.isReachable,
        title: result.vulnerability?.title || 'Unknown'
      };

      if (result.isReachable) {
        depGuardReachable.add(id);
      }
    }
  });

  // Calculate metrics
  const both = new Set([...npmVulns].filter(id => depGuardVulns.has(id)));
  const onlyNpm = new Set([...npmVulns].filter(id => !depGuardVulns.has(id)));
  const onlyDepGuard = new Set([...depGuardVulns].filter(id => !npmVulns.has(id)));
  const depGuardFilteredOut = new Set([...both].filter(id => !depGuardReachable.has(id)));

  // Print results
  console.log('='.repeat(70));
  console.log('VALIDATION RESULTS');
  console.log('='.repeat(70));
  console.log(`\nTotal vulnerabilities found by npm audit: ${npmVulns.size}`);
  console.log(`Total vulnerabilities found by DepGuard: ${depGuardVulns.size}`);
  console.log(`DepGuard reachable vulnerabilities: ${depGuardReachable.size}`);

  console.log('\n' + '-'.repeat(70));
  console.log('TRUE POSITIVES (Found by both tools): ' + both.size);
  console.log('-'.repeat(70));
  if (both.size > 0) {
    [...both].slice(0, 5).forEach(id => {
      const npm = npmVulnDetails[id];
      const dg = depGuardDetails[id];
      console.log(`  ${id}`);
      console.log(`    Package: ${npm.package}`);
      console.log(`    Severity: ${npm.severity}`);
      console.log(`    Reachable: ${dg.isReachable ? 'YES' : 'NO'} (confidence: ${dg.confidence})`);
    });
    if (both.size > 5) {
      console.log(`  ... and ${both.size - 5} more`);
    }
  }

  console.log('\n' + '-'.repeat(70));
  console.log('FILTERED BY REACHABILITY (Both found, DepGuard marked unreachable): ' + depGuardFilteredOut.size);
  console.log('-'.repeat(70));
  if (depGuardFilteredOut.size > 0) {
    [...depGuardFilteredOut].slice(0, 5).forEach(id => {
      const dg = depGuardDetails[id];
      console.log(`  ${id}`);
      console.log(`    Package: ${dg.package}`);
      console.log(`    Severity: ${dg.severity}`);
      console.log(`    Confidence: ${dg.confidence}`);
    });
    if (depGuardFilteredOut.size > 5) {
      console.log(`  ... and ${depGuardFilteredOut.size - 5} more`);
    }
  }

  console.log('\n' + '-'.repeat(70));
  console.log('FALSE NEGATIVES (npm audit found, DepGuard missed): ' + onlyNpm.size);
  console.log('-'.repeat(70));
  if (onlyNpm.size > 0) {
    [...onlyNpm].slice(0, 5).forEach(id => {
      const npm = npmVulnDetails[id];
      console.log(`  ${id}`);
      console.log(`    Package: ${npm.package}`);
      console.log(`    Severity: ${npm.severity}`);
    });
    if (onlyNpm.size > 5) {
      console.log(`  ... and ${onlyNpm.size - 5} more`);
    }
  }

  console.log('\n' + '-'.repeat(70));
  console.log('UNIQUE FINDINGS (DepGuard found, npm audit missed): ' + onlyDepGuard.size);
  console.log('-'.repeat(70));
  if (onlyDepGuard.size > 0) {
    [...onlyDepGuard].slice(0, 5).forEach(id => {
      const dg = depGuardDetails[id];
      console.log(`  ${id}`);
      console.log(`    Package: ${dg.package}`);
      console.log(`    Severity: ${dg.severity}`);
      console.log(`    Reachable: ${dg.isReachable ? 'YES' : 'NO'}`);
    });
    if (onlyDepGuard.size > 5) {
      console.log(`  ... and ${onlyDepGuard.size - 5} more`);
    }
  }

  // Calculate accuracy metrics
  const precision = both.size / (both.size + onlyDepGuard.size) || 0;
  const recall = both.size / (both.size + onlyNpm.size) || 0;
  const f1Score = 2 * (precision * recall) / (precision + recall) || 0;
  const reachabilityReduction = ((depGuardFilteredOut.size / npmVulns.size) * 100) || 0;

  console.log('\n' + '='.repeat(70));
  console.log('ACCURACY METRICS');
  console.log('='.repeat(70));
  console.log(`Precision: ${(precision * 100).toFixed(1)}% (how many DepGuard findings are valid)`);
  console.log(`Recall: ${(recall * 100).toFixed(1)}% (how many npm audit findings DepGuard caught)`);
  console.log(`F1 Score: ${(f1Score * 100).toFixed(1)}% (balanced accuracy)`);
  console.log(`Reachability Reduction: ${reachabilityReduction.toFixed(1)}% (noise filtered by reachability)`);

  console.log('\n' + '='.repeat(70));
  console.log('SUMMARY');
  console.log('='.repeat(70));
  console.log(`DepGuard's reachability analysis filtered out ${depGuardFilteredOut.size} unreachable vulnerabilities`);
  console.log(`This reduces false positives by ${reachabilityReduction.toFixed(1)}%, focusing on real risks`);
  console.log('='.repeat(70) + '\n');

  return {
    precision,
    recall,
    f1Score,
    reachabilityReduction,
    counts: {
      npmTotal: npmVulns.size,
      depGuardTotal: depGuardVulns.size,
      depGuardReachable: depGuardReachable.size,
      truePositives: both.size,
      falseNegatives: onlyNpm.size,
      uniqueFindings: onlyDepGuard.size,
      filteredByReachability: depGuardFilteredOut.size
    }
  };
}

// Main execution
if (require.main === module) {
  const projectPath = process.argv[2] || process.cwd();

  console.log('='.repeat(70));
  console.log('DepGuard Validation Tool');
  console.log('='.repeat(70));
  console.log(`Project: ${projectPath}\n`);

  try {
    const npmAudit = runNpmAudit(projectPath);
    const depGuard = runDepGuard(projectPath);
    const metrics = compareResults(npmAudit, depGuard);

    process.exit(0);
  } catch (error) {
    console.error('\n[ERROR]', error.message);
    process.exit(1);
  }
}

module.exports = { runNpmAudit, runDepGuard, compareResults };
