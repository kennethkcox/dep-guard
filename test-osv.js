const OSVDatabase = require('./src/vulnerabilities/OSVDatabase.js');
const osv = new OSVDatabase();

const packages = [
  { name: 'moment', version: '2.24.0' },
  { name: 'axios', version: '0.21.1' },
  { name: 'ws', version: '7.4.0' },
  { name: 'next', version: '15.1.3' }
];

(async () => {
  console.log('Querying OSV API for vulnerabilities...\n');

  for (const pkg of packages) {
    try {
      const vulns = await osv.query(pkg.name, pkg.version, 'javascript');
      console.log(`${pkg.name}@${pkg.version}: ${vulns.length} vulnerabilities found`);
      vulns.forEach(v => {
        console.log(`  - ${v.id}: ${v.title.substring(0, 80)}`);
        console.log(`    Severity: ${v.severity}, CVSS: ${v.cvss}`);
        if (v.vulnerableFunctions && v.vulnerableFunctions.length > 0) {
          console.log(`    Vulnerable functions: ${v.vulnerableFunctions.map(f => f.function).join(', ')}`);
        }
      });
      console.log('');
    } catch (error) {
      console.error(`Error querying ${pkg.name}: ${error.message}`);
    }
  }
})();
