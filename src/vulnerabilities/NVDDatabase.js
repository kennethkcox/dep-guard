/**
 * NVD (National Vulnerability Database) Integration
 * Provides additional vulnerability data from NIST NVD API 2.0
 * https://nvd.nist.gov/developers/vulnerabilities
 */

const https = require('https');

class NVDDatabase {
    constructor(options = {}) {
        this.baseUrl = 'https://services.nvd.nist.gov/rest/json';
        this.apiVersion = 'cves/2.0';
        this.timeout = options.timeout || 15000;
        this.apiKey = options.nvdApiKey || process.env.NVD_API_KEY; // Optional but recommended
        this.requestDelay = this.apiKey ? 50 : 6000; // 20 req/sec with key, 5 req/30sec without
        this.lastRequestTime = 0;
    }

    /**
     * Query NVD for vulnerabilities by CPE (Common Platform Enumeration)
     */
    async queryByCPE(cpe) {
        await this.rateLimit();

        const params = new URLSearchParams({
            cpeName: cpe,
            resultsPerPage: 100
        });

        try {
            const url = `${this.baseUrl}/${this.apiVersion}?${params}`;
            const result = await this.makeRequest(url);
            return this.processResults(result);
        } catch (error) {
            console.error(`NVD CPE query failed: ${error.message}`);
            return [];
        }
    }

    /**
     * Query NVD by CVE ID
     */
    async queryByCVE(cveId) {
        await this.rateLimit();

        try {
            const url = `${this.baseUrl}/${this.apiVersion}?cveId=${cveId}`;
            const result = await this.makeRequest(url);
            return this.processResults(result);
        } catch (error) {
            console.error(`NVD CVE query failed for ${cveId}: ${error.message}`);
            return null;
        }
    }

    /**
     * Query NVD by keyword (e.g., package name)
     */
    async queryByKeyword(keyword, ecosystem) {
        await this.rateLimit();

        // Build keyword with ecosystem context
        const searchTerm = this.buildSearchTerm(keyword, ecosystem);

        const params = new URLSearchParams({
            keywordSearch: searchTerm,
            keywordExactMatch: false,
            resultsPerPage: 100
        });

        try {
            const url = `${this.baseUrl}/${this.apiVersion}?${params}`;
            const result = await this.makeRequest(url);
            return this.processResults(result);
        } catch (error) {
            console.error(`NVD keyword query failed: ${error.message}`);
            return [];
        }
    }

    /**
     * Build search term with ecosystem context
     */
    buildSearchTerm(packageName, ecosystem) {
        const ecosystemKeywords = {
            'npm': ['node', 'npm', 'javascript'],
            'pypi': ['python', 'pypi', 'pip'],
            'maven': ['java', 'maven'],
            'go': ['golang', 'go']
        };

        const keywords = ecosystemKeywords[ecosystem] || [];
        // Try package name with ecosystem context
        return packageName;
    }

    /**
     * Rate limiting to respect NVD API limits
     * With API key: 20 requests per second
     * Without API key: 5 requests per 30 seconds
     */
    async rateLimit() {
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequestTime;

        if (timeSinceLastRequest < this.requestDelay) {
            const waitTime = this.requestDelay - timeSinceLastRequest;
            await this.sleep(waitTime);
        }

        this.lastRequestTime = Date.now();
    }

    /**
     * Make HTTP request to NVD API
     */
    makeRequest(url) {
        return new Promise((resolve, reject) => {
            const headers = {
                'User-Agent': 'DepGuard-Scanner/2.0'
            };

            // Add API key if available
            if (this.apiKey) {
                headers['apiKey'] = this.apiKey;
            }

            const req = https.get(url, { headers, timeout: this.timeout }, (res) => {
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
                    } else if (res.statusCode === 403) {
                        reject(new Error('NVD API access forbidden - check API key'));
                    } else if (res.statusCode === 503) {
                        reject(new Error('NVD API temporarily unavailable'));
                    } else {
                        reject(new Error(`NVD API returned status ${res.statusCode}`));
                    }
                });
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('NVD API request timeout'));
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.end();
        });
    }

    /**
     * Process NVD API results into standardized format
     */
    processResults(data) {
        if (!data || !data.vulnerabilities) {
            return [];
        }

        return data.vulnerabilities.map(item => {
            const cve = item.cve;
            const vulnData = {
                id: cve.id,
                source: 'NVD',
                published: cve.published,
                lastModified: cve.lastModified,
                summary: this.extractDescription(cve.descriptions),
                cvssV3: this.extractCVSSv3(cve.metrics),
                cvssV2: this.extractCVSSv2(cve.metrics),
                severity: this.extractSeverity(cve.metrics),
                cwe: this.extractCWE(cve.weaknesses),
                references: this.extractReferences(cve.references),
                cpe: this.extractCPE(cve.configurations)
            };

            return vulnData;
        });
    }

    /**
     * Extract description from NVD data
     */
    extractDescription(descriptions) {
        if (!descriptions || descriptions.length === 0) return '';

        // Prefer English description
        const enDesc = descriptions.find(d => d.lang === 'en');
        return enDesc ? enDesc.value : descriptions[0].value;
    }

    /**
     * Extract CVSS v3 metrics
     */
    extractCVSSv3(metrics) {
        if (!metrics || !metrics.cvssMetricV31 && !metrics.cvssMetricV30) {
            return null;
        }

        const v31 = metrics.cvssMetricV31?.[0];
        const v30 = metrics.cvssMetricV30?.[0];
        const metric = v31 || v30;

        if (!metric) return null;

        return {
            version: v31 ? '3.1' : '3.0',
            vectorString: metric.cvssData.vectorString,
            baseScore: metric.cvssData.baseScore,
            baseSeverity: metric.cvssData.baseSeverity,
            exploitabilityScore: metric.exploitabilityScore,
            impactScore: metric.impactScore
        };
    }

    /**
     * Extract CVSS v2 metrics
     */
    extractCVSSv2(metrics) {
        if (!metrics || !metrics.cvssMetricV2) {
            return null;
        }

        const metric = metrics.cvssMetricV2[0];
        if (!metric) return null;

        return {
            version: '2.0',
            vectorString: metric.cvssData.vectorString,
            baseScore: metric.cvssData.baseScore,
            exploitabilityScore: metric.exploitabilityScore,
            impactScore: metric.impactScore
        };
    }

    /**
     * Extract severity rating
     */
    extractSeverity(metrics) {
        const cvss3 = this.extractCVSSv3(metrics);
        if (cvss3) {
            return cvss3.baseSeverity;
        }

        const cvss2 = this.extractCVSSv2(metrics);
        if (cvss2) {
            // Map CVSS v2 score to severity
            const score = cvss2.baseScore;
            if (score >= 7.0) return 'HIGH';
            if (score >= 4.0) return 'MEDIUM';
            return 'LOW';
        }

        return 'UNKNOWN';
    }

    /**
     * Extract CWE (Common Weakness Enumeration)
     */
    extractCWE(weaknesses) {
        if (!weaknesses || weaknesses.length === 0) return [];

        return weaknesses.flatMap(w =>
            w.description.map(d => d.value)
        ).filter(cwe => cwe.startsWith('CWE-'));
    }

    /**
     * Extract references
     */
    extractReferences(references) {
        if (!references || references.length === 0) return [];

        return references.map(ref => ({
            url: ref.url,
            source: ref.source,
            tags: ref.tags || []
        }));
    }

    /**
     * Extract CPE (Common Platform Enumeration)
     */
    extractCPE(configurations) {
        if (!configurations || configurations.length === 0) return [];

        const cpes = [];

        configurations.forEach(config => {
            if (config.nodes) {
                config.nodes.forEach(node => {
                    if (node.cpeMatch) {
                        node.cpeMatch.forEach(match => {
                            if (match.vulnerable) {
                                cpes.push({
                                    cpe23Uri: match.criteria,
                                    versionStartIncluding: match.versionStartIncluding,
                                    versionEndExcluding: match.versionEndExcluding,
                                    versionStartExcluding: match.versionStartExcluding,
                                    versionEndIncluding: match.versionEndIncluding
                                });
                            }
                        });
                    }
                });
            }
        });

        return cpes;
    }

    /**
     * Sleep utility
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Check if NVD API is available
     */
    async healthCheck() {
        try {
            // Query for a known CVE
            const result = await this.queryByCVE('CVE-2021-44228'); // Log4Shell
            return result !== null;
        } catch (error) {
            return false;
        }
    }
}

module.exports = NVDDatabase;
