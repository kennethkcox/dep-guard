/**
 * OSV (Open Source Vulnerabilities) Database Integration
 * Real vulnerability data from https://osv.dev
 */

const https = require('https');

class OSVDatabase {
  constructor(options = {}) {
    this.baseUrl = 'https://api.osv.dev';
    this.timeout = options.timeout || 10000;
    this.batchSize = options.batchSize || 20; // Max packages per batch request (OSV limit)
    this.delayBetweenBatches = options.delayBetweenBatches || 1000; // 1s delay between batches
  }

  /**
   * Sleep for rate limiting
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
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
   * Batch query multiple packages (with chunking for large lists)
   */
  async queryBatch(packages, ecosystem) {
    if (packages.length === 0) {
      return [];
    }

    const allVulns = [];
    const chunks = this.chunkArray(packages, this.batchSize);

    console.log(`  Querying OSV for ${packages.length} packages in ${chunks.length} batch(es)...`);

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      const queries = chunk.map(pkg => ({
        package: {
          name: pkg.name,
          ecosystem: this.getEcosystem(ecosystem)
        },
        version: pkg.version
      }));

      try {
        const result = await this.makeRequestWithRetry('/v1/querybatch', 'POST', { queries });
        const vulns = this.processBatchResults(result, chunk);
        allVulns.push(...vulns);
      } catch (error) {
        console.error(`  Batch ${i + 1}/${chunks.length} failed: ${error.message}`);
        // Continue with other batches
      }

      // Rate limiting: delay between batches (except after last one)
      if (i < chunks.length - 1) {
        await this.sleep(this.delayBetweenBatches);
      }
    }

    return allVulns;
  }

  /**
   * Split array into chunks
   */
  chunkArray(array, size) {
    const chunks = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }

  /**
   * Make request with retry and exponential backoff
   */
  async makeRequestWithRetry(path, method, data, maxRetries = 3) {
    let lastError;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        return await this.makeRequest(path, method, data);
      } catch (error) {
        lastError = error;

        // If rate limited (HTTP 400/429), wait longer before retry
        if (error.message.includes('400') || error.message.includes('429')) {
          const delay = Math.pow(2, attempt) * 2000; // 2s, 4s, 8s
          console.log(`  Rate limited, waiting ${delay/1000}s before retry...`);
          await this.sleep(delay);
        } else {
          // For other errors, shorter delay
          await this.sleep(1000);
        }
      }
    }

    throw lastError;
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
    // Try to get a numeric CVSS score
    const cvss = this.extractCVSS(vuln);
    if (cvss !== null && !isNaN(cvss)) {
      if (cvss >= 9.0) return 'CRITICAL';
      if (cvss >= 7.0) return 'HIGH';
      if (cvss >= 4.0) return 'MEDIUM';
      if (cvss > 0) return 'LOW';
    }

    // Fallback to database-specific severity
    if (vuln.database_specific?.severity) {
      return vuln.database_specific.severity.toUpperCase();
    }

    return 'UNKNOWN';
  }

  /**
   * Extract CVSS score from vulnerability data
   * OSV returns CVSS as vector strings (e.g., "CVSS:3.1/AV:N/AC:L/...")
   * or occasionally as numeric scores
   */
  extractCVSS(vuln) {
    if (vuln.severity) {
      for (const sev of vuln.severity) {
        if (sev.type === 'CVSS_V3' || sev.type === 'CVSS_V2') {
          // Try parsing as numeric score first
          const numeric = parseFloat(sev.score);
          if (!isNaN(numeric) && numeric >= 0 && numeric <= 10) {
            return numeric;
          }

          // Parse CVSS vector string to derive base score
          if (typeof sev.score === 'string' && sev.score.startsWith('CVSS:')) {
            return this.parseCVSSVector(sev.score);
          }
        }
      }
    }

    // Try database_specific CVSS
    if (vuln.database_specific?.cvss_score) {
      return parseFloat(vuln.database_specific.cvss_score) || null;
    }

    return null; // Unknown - don't guess
  }

  /**
   * Parse a CVSS v3 vector string into an approximate base score
   * Vector format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
   */
  parseCVSSVector(vector) {
    const metrics = {};
    const parts = vector.split('/');
    for (const part of parts) {
      const [key, value] = part.split(':');
      if (key && value) metrics[key] = value;
    }

    // CVSS v3 base metric weights (simplified but accurate approximation)
    const avWeights = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };  // Attack Vector
    const acWeights = { L: 0.77, H: 0.44 };                      // Attack Complexity
    const prWeightsU = { N: 0.85, L: 0.62, H: 0.27 };           // Privileges Required (Scope Unchanged)
    const prWeightsC = { N: 0.85, L: 0.68, H: 0.50 };           // Privileges Required (Scope Changed)
    const uiWeights = { N: 0.85, R: 0.62 };                      // User Interaction
    const impactWeights = { H: 0.56, L: 0.22, N: 0 };           // Impact (C/I/A)

    const scopeChanged = metrics['S'] === 'C';
    const prWeights = scopeChanged ? prWeightsC : prWeightsU;

    const av = avWeights[metrics['AV']] || 0.55;
    const ac = acWeights[metrics['AC']] || 0.44;
    const pr = prWeights[metrics['PR']] || 0.62;
    const ui = uiWeights[metrics['UI']] || 0.62;
    const cImpact = impactWeights[metrics['C']] || 0;
    const iImpact = impactWeights[metrics['I']] || 0;
    const aImpact = impactWeights[metrics['A']] || 0;

    // Calculate exploitability sub-score
    const exploitability = 8.22 * av * ac * pr * ui;

    // Calculate impact sub-score (ISS then Impact)
    const iss = 1 - ((1 - cImpact) * (1 - iImpact) * (1 - aImpact));
    let impact;
    if (scopeChanged) {
      impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    } else {
      impact = 6.42 * iss;
    }

    if (impact <= 0) return 0.0;

    // Calculate base score
    let baseScore;
    if (scopeChanged) {
      baseScore = Math.min(1.08 * (impact + exploitability), 10);
    } else {
      baseScore = Math.min(impact + exploitability, 10);
    }

    // Round up to nearest 0.1
    return Math.ceil(baseScore * 10) / 10;
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
      'npm': 'npm',
      'python': 'PyPI',
      'pypi': 'PyPI',
      'java': 'Maven',
      'maven': 'Maven',
      'go': 'Go',
      'rust': 'crates.io',
      'cargo': 'crates.io',
      'ruby': 'RubyGems',
      'rubygems': 'RubyGems',
      'nuget': 'NuGet',
      'dotnet': 'NuGet',
      'packagist': 'Packagist',
      'php': 'Packagist'
    };
    return map[ecosystem] || ecosystem;
  }
}

module.exports = OSVDatabase;
