const OSVDatabase = require('./src/vulnerabilities/OSVDatabase.js');
const osv = new OSVDatabase();

// Updated packages from the new scan
const packages = [
  { name: 'next', version: '14.2.3' },
  { name: 'react', version: '18.3.1' },
  { name: 'react-dom', version: '18.3.1' },
  { name: 'lodash', version: '4.17.11' },
  { name: 'semver', version: '5.7.1' },
  { name: 'node-fetch', version: '2.6.0' },
  { name: 'eslint', version: '8.0.0' }
];

(async () => {
  console.log('╔══════════════════════════════════════════════════════════════════╗');
  console.log('║  Querying OSV API for Updated Package Vulnerabilities           ║');
  console.log('╚══════════════════════════════════════════════════════════════════╝\n');

  let totalVulns = 0;
  let criticalCount = 0;
  let highCount = 0;

  for (const pkg of packages) {
    try {
      const vulns = await osv.query(pkg.name, pkg.version, 'javascript');
      totalVulns += vulns.length;

      if (vulns.length > 0) {
        console.log(`\n${'='.repeat(65)}`);
        console.log(`📦 ${pkg.name}@${pkg.version}`);
        console.log(`${'='.repeat(65)}`);
        console.log(`Found: ${vulns.length} vulnerabilities\n`);

        vulns.forEach((v, idx) => {
          console.log(`[${idx + 1}] ${v.id}`);
          console.log(`    Title: ${v.title.substring(0, 70)}`);
          console.log(`    Severity: ${v.severity} | CVSS: ${v.cvss}`);

          if (v.severity === 'CRITICAL') criticalCount++;
          if (v.severity === 'HIGH') highCount++;

          if (v.vulnerableFunctions && v.vulnerableFunctions.length > 0) {
            const funcs = v.vulnerableFunctions.slice(0, 3).map(f => f.function).join(', ');
            console.log(`    Functions: ${funcs}`);
          }

          if (v.fixedVersion) {
            console.log(`    Fix: Upgrade to ${v.fixedVersion}+`);
          }
          console.log('');
        });
      } else {
        console.log(`✅ ${pkg.name}@${pkg.version}: No known vulnerabilities`);
      }
    } catch (error) {
      console.error(`❌ Error querying ${pkg.name}: ${error.message}`);
    }
  }

  console.log('\n' + '='.repeat(65));
  console.log('SUMMARY');
  console.log('='.repeat(65));
  console.log(`Total Vulnerabilities: ${totalVulns}`);
  console.log(`Critical: ${criticalCount}`);
  console.log(`High: ${highCount}`);
  console.log('='.repeat(65) + '\n');
})();
