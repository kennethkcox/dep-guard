/**
 * GitHub Security Advisory Database Integration
 * Provides vulnerability data from GitHub's advisory database
 * https://github.com/advisories
 */

const https = require('https');

class GitHubAdvisoryDatabase {
    constructor(options = {}) {
        this.baseUrl = 'https://api.github.com';
        this.timeout = options.timeout || 15000;
        this.githubToken = options.githubToken || process.env.GITHUB_TOKEN;
        this.requestDelay = this.githubToken ? 100 : 1000; // Authenticated: faster
        this.lastRequestTime = 0;
    }

    /**
     * Query GitHub Advisory Database by package
     */
    async queryByPackage(packageName, ecosystem) {
        await this.rateLimit();

        const ecosystemMap = {
            'npm': 'NPM',
            'pypi': 'PIP',
            'maven': 'MAVEN',
            'go': 'GO',
            'cargo': 'RUBYGEMS',
            'rubygems': 'RUBYGEMS',
            'packagist': 'COMPOSER',
            'nuget': 'NUGET'
        };

        const ghEcosystem = ecosystemMap[ecosystem] || 'NPM';

        try {
            const query = `
                query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
                    securityVulnerabilities(
                        first: 100,
                        ecosystem: $ecosystem,
                        package: $package
                    ) {
                        nodes {
                            advisory {
                                ghsaId
                                cvss {
                                    score
                                    vectorString
                                }
                                cwes(first: 10) {
                                    nodes {
                                        cweId
                                        name
                                    }
                                }
                                description
                                identifiers {
                                    type
                                    value
                                }
                                permalink
                                publishedAt
                                severity
                                summary
                                updatedAt
                                withdrawnAt
                                references {
                                    url
                                }
                            }
                            package {
                                name
                            }
                            vulnerableVersionRange
                            firstPatchedVersion {
                                identifier
                            }
                        }
                    }
                }
            `;

            const variables = {
                ecosystem: ghEcosystem,
                package: packageName
            };

            const result = await this.makeGraphQLRequest(query, variables);
            return this.processResults(result, packageName);
        } catch (error) {
            console.error(`GitHub Advisory query failed for ${packageName}: ${error.message}`);
            return [];
        }
    }

    /**
     * Query by GHSA ID
     */
    async queryByGHSA(ghsaId) {
        await this.rateLimit();

        try {
            const query = `
                query($ghsaId: String!) {
                    securityAdvisory(ghsaId: $ghsaId) {
                        ghsaId
                        cvss {
                            score
                            vectorString
                        }
                        cwes(first: 10) {
                            nodes {
                                cweId
                                name
                            }
                        }
                        description
                        identifiers {
                            type
                            value
                        }
                        permalink
                        publishedAt
                        severity
                        summary
                        updatedAt
                        withdrawnAt
                        references {
                            url
                        }
                        vulnerabilities(first: 10) {
                            nodes {
                                package {
                                    name
                                    ecosystem
                                }
                                vulnerableVersionRange
                                firstPatchedVersion {
                                    identifier
                                }
                            }
                        }
                    }
                }
            `;

            const variables = { ghsaId };
            const result = await this.makeGraphQLRequest(query, variables);
            return this.processSingleResult(result);
        } catch (error) {
            console.error(`GitHub Advisory query failed for ${ghsaId}: ${error.message}`);
            return null;
        }
    }

    /**
     * Make GraphQL request to GitHub API
     */
    makeGraphQLRequest(query, variables) {
        return new Promise((resolve, reject) => {
            const payload = JSON.stringify({ query, variables });

            const headers = {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
                'User-Agent': 'DepGuard-Scanner/2.0',
                'Accept': 'application/vnd.github.v4+json'
            };

            // Add GitHub token if available (highly recommended for rate limits)
            if (this.githubToken) {
                headers['Authorization'] = `Bearer ${this.githubToken}`;
            }

            const options = {
                hostname: 'api.github.com',
                port: 443,
                path: '/graphql',
                method: 'POST',
                headers,
                timeout: this.timeout
            };

            const req = https.request(options, (res) => {
                let data = '';

                res.on('data', chunk => {
                    data += chunk;
                });

                res.on('end', () => {
                    if (res.statusCode === 200) {
                        try {
                            const parsed = JSON.parse(data);

                            if (parsed.errors) {
                                reject(new Error(`GraphQL errors: ${JSON.stringify(parsed.errors)}`));
                            } else {
                                resolve(parsed.data);
                            }
                        } catch (error) {
                            reject(new Error(`Invalid JSON response: ${error.message}`));
                        }
                    } else if (res.statusCode === 401) {
                        reject(new Error('GitHub API authentication failed - check token'));
                    } else if (res.statusCode === 403) {
                        reject(new Error('GitHub API rate limit exceeded or access denied'));
                    } else {
                        reject(new Error(`GitHub API returned status ${res.statusCode}`));
                    }
                });
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('GitHub API request timeout'));
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.write(payload);
            req.end();
        });
    }

    /**
     * Process query results
     */
    processResults(data, packageName) {
        if (!data || !data.securityVulnerabilities || !data.securityVulnerabilities.nodes) {
            return [];
        }

        return data.securityVulnerabilities.nodes
            .filter(node => node.advisory && !node.advisory.withdrawnAt)
            .map(node => ({
                id: node.advisory.ghsaId,
                source: 'GitHub Advisory',
                package: packageName,
                summary: node.advisory.summary,
                description: node.advisory.description,
                severity: node.advisory.severity,
                cvss: node.advisory.cvss ? {
                    score: node.advisory.cvss.score,
                    vectorString: node.advisory.cvss.vectorString
                } : null,
                cwe: node.advisory.cwes?.nodes.map(cwe => ({
                    id: cwe.cweId,
                    name: cwe.name
                })) || [],
                identifiers: node.advisory.identifiers.map(id => ({
                    type: id.type,
                    value: id.value
                })),
                references: node.advisory.references.map(ref => ref.url),
                vulnerableVersionRange: node.vulnerableVersionRange,
                firstPatchedVersion: node.firstPatchedVersion?.identifier,
                publishedAt: node.advisory.publishedAt,
                updatedAt: node.advisory.updatedAt,
                permalink: node.advisory.permalink
            }));
    }

    /**
     * Process single advisory result
     */
    processSingleResult(data) {
        if (!data || !data.securityAdvisory) {
            return null;
        }

        const advisory = data.securityAdvisory;

        if (advisory.withdrawnAt) {
            return null; // Skip withdrawn advisories
        }

        return {
            id: advisory.ghsaId,
            source: 'GitHub Advisory',
            summary: advisory.summary,
            description: advisory.description,
            severity: advisory.severity,
            cvss: advisory.cvss ? {
                score: advisory.cvss.score,
                vectorString: advisory.cvss.vectorString
            } : null,
            cwe: advisory.cwes?.nodes.map(cwe => ({
                id: cwe.cweId,
                name: cwe.name
            })) || [],
            identifiers: advisory.identifiers.map(id => ({
                type: id.type,
                value: id.value
            })),
            references: advisory.references.map(ref => ref.url),
            vulnerabilities: advisory.vulnerabilities?.nodes.map(vuln => ({
                package: vuln.package.name,
                ecosystem: vuln.package.ecosystem,
                vulnerableVersionRange: vuln.vulnerableVersionRange,
                firstPatchedVersion: vuln.firstPatchedVersion?.identifier
            })) || [],
            publishedAt: advisory.publishedAt,
            updatedAt: advisory.updatedAt,
            permalink: advisory.permalink
        };
    }

    /**
     * Rate limiting
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
     * Sleep utility
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Health check
     */
    async healthCheck() {
        try {
            const result = await this.queryByGHSA('GHSA-257v-vj4p-3w2h'); // Known advisory
            return result !== null;
        } catch (error) {
            return false;
        }
    }
}

module.exports = GitHubAdvisoryDatabase;
