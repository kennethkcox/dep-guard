/**
 * EPSS (Exploit Prediction Scoring System) Enrichment
 * Provides exploit probability scores from FIRST.org
 * https://www.first.org/epss/
 *
 * EPSS predicts the likelihood that a CVE will be exploited in the wild
 * within the next 30 days based on real-world exploitation data.
 */

const https = require('https');

class EPSSEnricher {
    constructor(options = {}) {
        this.baseUrl = 'https://api.first.org/data/v1';
        this.timeout = options.timeout || 15000;
        this.cache = new Map(); // Cache EPSS scores
        this.cacheExpiry = 24 * 60 * 60 * 1000; // 24 hours
    }

    /**
     * Get EPSS score for a CVE
     * Returns probability (0-1) and percentile (0-100)
     */
    async getEPSSScore(cveId) {
        // Check cache first
        const cached = this.cache.get(cveId);
        if (cached && (Date.now() - cached.timestamp) < this.cacheExpiry) {
            return cached.data;
        }

        try {
            const url = `${this.baseUrl}/epss?cve=${cveId}`;
            const result = await this.makeRequest(url);
            const epssData = this.processResult(result, cveId);

            // Cache the result
            this.cache.set(cveId, {
                data: epssData,
                timestamp: Date.now()
            });

            return epssData;
        } catch (error) {
            console.error(`EPSS query failed for ${cveId}: ${error.message}`);
            return null;
        }
    }

    /**
     * Get EPSS scores for multiple CVEs in batch
     */
    async getEPSSScoresBatch(cveIds) {
        if (!cveIds || cveIds.length === 0) {
            return [];
        }

        // Check cache first
        const results = [];
        const uncached = [];

        for (const cveId of cveIds) {
            const cached = this.cache.get(cveId);
            if (cached && (Date.now() - cached.timestamp) < this.cacheExpiry) {
                results.push({ cveId, ...cached.data });
            } else {
                uncached.push(cveId);
            }
        }

        // Fetch uncached CVEs
        if (uncached.length > 0) {
            try {
                const cveList = uncached.join(',');
                const url = `${this.baseUrl}/epss?cve=${cveList}`;
                const result = await this.makeRequest(url);
                const epssData = this.processBatchResults(result);

                // Cache and add to results
                epssData.forEach(data => {
                    this.cache.set(data.cveId, {
                        data: {
                            epss: data.epss,
                            percentile: data.percentile,
                            date: data.date
                        },
                        timestamp: Date.now()
                    });

                    results.push(data);
                });
            } catch (error) {
                console.error(`EPSS batch query failed: ${error.message}`);
            }
        }

        return results;
    }

    /**
     * Enrich vulnerability data with EPSS scores
     */
    async enrichVulnerability(vulnerability) {
        if (!vulnerability.id) {
            return vulnerability;
        }

        // Extract CVE ID if it's a CVE
        const cveId = this.extractCVE(vulnerability.id);
        if (!cveId) {
            return vulnerability; // Not a CVE, can't get EPSS
        }

        const epss = await this.getEPSSScore(cveId);
        if (epss) {
            return {
                ...vulnerability,
                epss: {
                    score: epss.epss,
                    percentile: epss.percentile,
                    date: epss.date,
                    interpretation: this.interpretEPSS(epss.epss, epss.percentile)
                }
            };
        }

        return vulnerability;
    }

    /**
     * Enrich multiple vulnerabilities with EPSS scores
     */
    async enrichVulnerabilities(vulnerabilities) {
        if (!vulnerabilities || vulnerabilities.length === 0) {
            return vulnerabilities;
        }

        // Extract all CVE IDs
        const cveIds = vulnerabilities
            .map(v => this.extractCVE(v.id))
            .filter(id => id !== null);

        if (cveIds.length === 0) {
            return vulnerabilities;
        }

        // Get EPSS scores in batch
        const epssScores = await this.getEPSSScoresBatch(cveIds);

        // Create lookup map
        const epssMap = new Map();
        epssScores.forEach(score => {
            epssMap.set(score.cveId, score);
        });

        // Enrich vulnerabilities
        return vulnerabilities.map(vuln => {
            const cveId = this.extractCVE(vuln.id);
            if (!cveId || !epssMap.has(cveId)) {
                return vuln;
            }

            const epss = epssMap.get(cveId);
            return {
                ...vuln,
                epss: {
                    score: epss.epss,
                    percentile: epss.percentile,
                    date: epss.date,
                    interpretation: this.interpretEPSS(epss.epss, epss.percentile)
                }
            };
        });
    }

    /**
     * Extract CVE ID from various formats
     */
    extractCVE(identifier) {
        if (!identifier) return null;

        // Direct CVE format
        if (identifier.match(/^CVE-\d{4}-\d{4,}$/i)) {
            return identifier.toUpperCase();
        }

        // Extract from GHSA or other formats (if they contain CVE reference)
        const match = identifier.match(/CVE-\d{4}-\d{4,}/i);
        return match ? match[0].toUpperCase() : null;
    }

    /**
     * Interpret EPSS score for human readability
     */
    interpretEPSS(score, percentile) {
        let risk = 'UNKNOWN';
        let description = '';

        // Categorize based on EPSS score
        if (score >= 0.75) {
            risk = 'CRITICAL';
            description = 'Very high probability of exploitation';
        } else if (score >= 0.50) {
            risk = 'HIGH';
            description = 'High probability of exploitation';
        } else if (score >= 0.25) {
            risk = 'MEDIUM';
            description = 'Moderate probability of exploitation';
        } else if (score >= 0.10) {
            risk = 'LOW';
            description = 'Low probability of exploitation';
        } else {
            risk = 'VERY LOW';
            description = 'Very low probability of exploitation';
        }

        return {
            risk,
            description,
            recommendation: this.getRecommendation(score, percentile)
        };
    }

    /**
     * Get remediation recommendation based on EPSS
     */
    getRecommendation(score, percentile) {
        if (score >= 0.50) {
            return 'URGENT: Prioritize remediation immediately - high exploitation risk';
        } else if (score >= 0.25) {
            return 'HIGH PRIORITY: Address within 7 days - moderate exploitation risk';
        } else if (score >= 0.10) {
            return 'MEDIUM PRIORITY: Address within 30 days';
        } else if (percentile >= 90) {
            return 'MONITOR: Low exploitation risk but higher than 90% of CVEs';
        } else {
            return 'STANDARD: Follow normal patching schedule';
        }
    }

    /**
     * Make HTTP request to EPSS API
     */
    makeRequest(url) {
        return new Promise((resolve, reject) => {
            const req = https.get(url, { timeout: this.timeout }, (res) => {
                let data = '';

                res.on('data', chunk => {
                    data += chunk;
                });

                res.on('end', () => {
                    if (res.statusCode === 200) {
                        try {
                            resolve(JSON.parse(data));
                        } catch (error) {
                            reject(new Error(`Invalid JSON response: ${error.message}`));
                        }
                    } else if (res.statusCode === 404) {
                        reject(new Error('CVE not found in EPSS database'));
                    } else {
                        reject(new Error(`EPSS API returned status ${res.statusCode}`));
                    }
                });
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('EPSS API request timeout'));
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.end();
        });
    }

    /**
     * Process single result
     */
    processResult(data, cveId) {
        if (!data || !data.data || data.data.length === 0) {
            return null;
        }

        const result = data.data[0];
        return {
            epss: parseFloat(result.epss),
            percentile: parseFloat(result.percentile),
            date: result.date
        };
    }

    /**
     * Process batch results
     */
    processBatchResults(data) {
        if (!data || !data.data) {
            return [];
        }

        return data.data.map(result => ({
            cveId: result.cve,
            epss: parseFloat(result.epss),
            percentile: parseFloat(result.percentile),
            date: result.date
        }));
    }

    /**
     * Clear cache
     */
    clearCache() {
        this.cache.clear();
    }

    /**
     * Health check
     */
    async healthCheck() {
        try {
            // Query for a known CVE
            const result = await this.getEPSSScore('CVE-2021-44228'); // Log4Shell
            return result !== null && result.epss !== undefined;
        } catch (error) {
            return false;
        }
    }
}

module.exports = EPSSEnricher;
