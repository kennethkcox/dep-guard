/**
 * OSV (Open Source Vulnerabilities) Database Integration
 * Real vulnerability data from https://osv.dev
 */

const https = require('https');

class OSVDatabase {
  constructor(options = {}) {
    this.baseUrl = 'https://api.osv.dev';
    this.timeout = options.timeout || 10000;
  }

  /**
   * Query OSV API for vulnerabilities
   */
  async query(packageName, version, ecosystem) {
    const ecosystemMap = {
      'javascript': 'npm',
      'python': 'PyPI',
      'java': 'Maven',
      'go': 'Go'
    };

    const query = {
      package: {
        name: packageName,
        ecosystem: ecosystemMap[ecosystem] || 'npm'
      }
    };

    if (version) {
      query.version = version;
    }

    try {
      const result = await this.makeRequest('/v1/query', 'POST', query);
      return this.processResults(result, packageName, version);
    } catch (error) {
      console.error(`OSV query failed for ${packageName}: ${error.message}`);
      return [];
    }
  }

  /**
   * Get vulnerability details by ID
   */
  async getVulnerability(vulnId) {
    try {
      return await this.makeRequest(`/v1/vulns/${vulnId}`, 'GET');
    } catch (error) {
      console.error(`Failed to fetch ${vulnId}: ${error.message}`);
      return null;
    }
  }

  /**
   * Batch query multiple packages
   */
  async queryBatch(packages, ecosystem) {
    const queries = packages.map(pkg => ({
      package: {
        name: pkg.name,
        ecosystem: this.getEcosystem(ecosystem)
      },
      version: pkg.version
    }));

    try {
      const result = await this.makeRequest('/v1/querybatch', 'POST', { queries });
      return this.processBatchResults(result, packages);
    } catch (error) {
      console.error(`Batch query failed: ${error.message}`);
      return [];
    }
  }

  /**
   * Make HTTP request to OSV API
   */
  makeRequest(path, method, data = null) {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.osv.dev',
        port: 443,
        path: path,
        method: method,
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: this.timeout
      };

      const req = https.request(options, (res) => {
        let body = '';

        res.on('data', (chunk) => {
          body += chunk;
        });

        res.on('end', () => {
          if (res.statusCode === 200) {
            try {
              resolve(JSON.parse(body));
            } catch (e) {
              reject(new Error(`Invalid JSON response: ${e.message}`));
            }
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${body}`));
          }
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      if (data) {
        req.write(JSON.stringify(data));
      }

      req.end();
    });
  }

  /**
   * Process OSV query results
   */
  processResults(result, packageName, version) {
    if (!result || !result.vulns) {
      return [];
    }

    return result.vulns.map(vuln => ({
      id: vuln.id,
      source: 'OSV',
      title: vuln.summary || vuln.details?.substring(0, 100) || vuln.id,
      description: vuln.details || vuln.summary || 'No description available',
      severity: this.extractSeverity(vuln),
      cvss: this.extractCVSS(vuln),
      affectedVersions: this.extractAffectedVersions(vuln),
      fixedVersion: this.extractFixedVersion(vuln),
      exploitMaturity: this.guessExploitMaturity(vuln),
      vulnerableFunctions: this.extractVulnerableFunctions(vuln),
      references: this.extractReferences(vuln),
      package: packageName,
      version: version,
      isAffected: true
    }));
  }

  /**
   * Process batch query results
   */
  processBatchResults(result, packages) {
    if (!result || !result.results) {
      return [];
    }

    const allVulns = [];

    result.results.forEach((queryResult, index) => {
      if (queryResult && queryResult.vulns) {
        const pkg = packages[index];
        const vulns = this.processResults(queryResult, pkg.name, pkg.version);
        allVulns.push(...vulns);
      }
    });

    return allVulns;
  }

  /**
   * Extract severity from vulnerability data
   */
  extractSeverity(vuln) {
    // Try CVSS score first
    if (vuln.severity) {
      for (const sev of vuln.severity) {
        if (sev.type === 'CVSS_V3') {
          const score = parseFloat(sev.score);
          if (score >= 9.0) return 'CRITICAL';
          if (score >= 7.0) return 'HIGH';
          if (score >= 4.0) return 'MEDIUM';
          return 'LOW';
        }
      }
    }

    // Fallback to database-specific severity
    if (vuln.database_specific?.severity) {
      return vuln.database_specific.severity.toUpperCase();
    }

    return 'MEDIUM'; // Default
  }

  /**
   * Extract CVSS score
   */
  extractCVSS(vuln) {
    if (vuln.severity) {
      for (const sev of vuln.severity) {
        if (sev.type === 'CVSS_V3' || sev.type === 'CVSS_V2') {
          return parseFloat(sev.score) || 5.0;
        }
      }
    }
    return 5.0; // Default medium
  }

  /**
   * Extract affected version ranges
   */
  extractAffectedVersions(vuln) {
    const ranges = [];

    if (vuln.affected) {
      vuln.affected.forEach(affected => {
        if (affected.ranges) {
          affected.ranges.forEach(range => {
            if (range.events) {
              let lower = null;
              let upper = null;

              range.events.forEach(event => {
                if (event.introduced) lower = event.introduced;
                if (event.fixed) upper = event.fixed;
              });

              if (upper) {
                ranges.push(`<${upper}`);
              } else if (lower && lower !== '0') {
                ranges.push(`>=${lower}`);
              }
            }
          });
        }
      });
    }

    return ranges;
  }

  /**
   * Extract fixed version
   */
  extractFixedVersion(vuln) {
    if (vuln.affected) {
      for (const affected of vuln.affected) {
        if (affected.ranges) {
          for (const range of affected.ranges) {
            if (range.events) {
              for (const event of range.events) {
                if (event.fixed) {
                  return event.fixed;
                }
              }
            }
          }
        }
      }
    }
    return null;
  }

  /**
   * Guess exploit maturity based on available data
   */
  guessExploitMaturity(vuln) {
    const details = (vuln.details || vuln.summary || '').toLowerCase();

    if (details.includes('actively exploited') || details.includes('in the wild')) {
      return 'high';
    }
    if (details.includes('proof of concept') || details.includes('poc')) {
      return 'proof-of-concept';
    }
    if (details.includes('exploit')) {
      return 'functional';
    }

    // Check references for exploit code
    if (vuln.references) {
      for (const ref of vuln.references) {
        const refUrl = (ref.url || '').toLowerCase();
        if (refUrl.includes('exploit') || refUrl.includes('poc')) {
          return 'proof-of-concept';
        }
      }
    }

    return 'unproven';
  }

  /**
   * Extract vulnerable functions (OSV sometimes provides this)
   */
  extractVulnerableFunctions(vuln) {
    const functions = [];

    // OSV doesn't always provide function-level data
    // We'll try to extract from descriptions
    if (vuln.details) {
      const funcMatches = vuln.details.match(/`(\w+)(?:\(\))?`/g);
      if (funcMatches) {
        funcMatches.forEach(match => {
          const funcName = match.replace(/`/g, '').replace('()', '');
          functions.push({
            path: 'unknown',
            function: funcName,
            line: 0
          });
        });
      }
    }

    // If database_specific has symbols
    if (vuln.database_specific?.symbols) {
      vuln.database_specific.symbols.forEach(symbol => {
        functions.push({
          path: 'unknown',
          function: symbol,
          line: 0
        });
      });
    }

    return functions;
  }

  /**
   * Extract references
   */
  extractReferences(vuln) {
    const refs = [];

    if (vuln.references) {
      vuln.references.forEach(ref => {
        refs.push(ref.url);
      });
    }

    return refs;
  }

  /**
   * Get ecosystem name for OSV
   */
  getEcosystem(ecosystem) {
    const map = {
      'javascript': 'npm',
      'python': 'PyPI',
      'java': 'Maven',
      'go': 'Go',
      'rust': 'crates.io',
      'ruby': 'RubyGems'
    };
    return map[ecosystem] || 'npm';
  }
}

module.exports = OSVDatabase;
