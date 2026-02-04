/**
 * CISA KEV (Known Exploited Vulnerabilities) Checker
 * Checks against CISA's catalog of vulnerabilities actively exploited in the wild
 * https://www.cisa.gov/known-exploited-vulnerabilities-catalog
 *
 * If a CVE is in KEV, it means there is confirmed real-world exploitation
 * and CISA requires federal agencies to patch it by the given due date.
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

class CISAKEVChecker {
    constructor(options = {}) {
        this.catalogUrl = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
        this.timeout = options.timeout || 20000;
        this.cacheDir = options.cacheDir || path.join(process.cwd(), '.depguard-cache');
        this.cacheFile = path.join(this.cacheDir, 'cisa-kev.json');
        this.cacheExpiry = 24 * 60 * 60 * 1000; // 24 hours
        this.kevCatalog = null;
        this.kevMap = new Map(); // CVE ID -> KEV entry
    }

    /**
     * Initialize and load KEV catalog
     */
    async initialize() {
        // Try to load from cache first
        if (this.loadFromCache()) {
            return true;
        }

        // Fetch fresh data
        try {
            await this.fetchKEVCatalog();
            return true;
        } catch (error) {
            console.error(`Failed to fetch CISA KEV catalog: ${error.message}`);
            return false;
        }
    }

    /**
     * Check if a CVE is in the KEV catalog
     */
    isKnownExploited(cveId) {
        if (!this.kevMap || this.kevMap.size === 0) {
            return null; // Catalog not loaded
        }

        const normalized = this.normalizeCVE(cveId);
        return this.kevMap.has(normalized);
    }

    /**
     * Get KEV entry for a CVE
     */
    getKEVEntry(cveId) {
        if (!this.kevMap || this.kevMap.size === 0) {
            return null;
        }

        const normalized = this.normalizeCVE(cveId);
        return this.kevMap.get(normalized);
    }

    /**
     * Enrich vulnerability with KEV data
     */
    enrichVulnerability(vulnerability) {
        const cveId = this.extractCVE(vulnerability.id);
        if (!cveId) {
            return vulnerability;
        }

        const kevEntry = this.getKEVEntry(cveId);
        if (kevEntry) {
            return {
                ...vulnerability,
                kev: {
                    isKnownExploited: true,
                    dateAdded: kevEntry.dateAdded,
                    dueDate: kevEntry.dueDate,
                    requiredAction: kevEntry.requiredAction,
                    knownRansomwareCampaignUse: kevEntry.knownRansomwareCampaignUse,
                    notes: kevEntry.notes,
                    interpretation: {
                        risk: 'CRITICAL',
                        description: 'CONFIRMED EXPLOITATION IN THE WILD',
                        recommendation: `IMMEDIATE ACTION REQUIRED: ${kevEntry.requiredAction}`
                    }
                }
            };
        }

        return vulnerability;
    }

    /**
     * Enrich multiple vulnerabilities with KEV data
     */
    enrichVulnerabilities(vulnerabilities) {
        if (!vulnerabilities || vulnerabilities.length === 0) {
            return vulnerabilities;
        }

        return vulnerabilities.map(vuln => this.enrichVulnerability(vuln));
    }

    /**
     * Fetch KEV catalog from CISA
     */
    async fetchKEVCatalog() {
        return new Promise((resolve, reject) => {
            const req = https.get(this.catalogUrl, { timeout: this.timeout }, (res) => {
                let data = '';

                res.on('data', chunk => {
                    data += chunk;
                });

                res.on('end', () => {
                    if (res.statusCode === 200) {
                        try {
                            const catalog = JSON.parse(data);
                            this.processCatalog(catalog);
                            this.saveToCache(catalog);
                            resolve(catalog);
                        } catch (error) {
                            reject(new Error(`Invalid JSON response: ${error.message}`));
                        }
                    } else {
                        reject(new Error(`CISA KEV API returned status ${res.statusCode}`));
                    }
                });
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('CISA KEV API request timeout'));
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.end();
        });
    }

    /**
     * Process KEV catalog into searchable map
     */
    processCatalog(catalog) {
        this.kevCatalog = catalog;
        this.kevMap.clear();

        if (!catalog || !catalog.vulnerabilities) {
            return;
        }

        catalog.vulnerabilities.forEach(vuln => {
            const cveId = this.normalizeCVE(vuln.cveID);
            this.kevMap.set(cveId, {
                cveId: vuln.cveID,
                vendorProject: vuln.vendorProject,
                product: vuln.product,
                vulnerabilityName: vuln.vulnerabilityName,
                dateAdded: vuln.dateAdded,
                shortDescription: vuln.shortDescription,
                requiredAction: vuln.requiredAction,
                dueDate: vuln.dueDate,
                knownRansomwareCampaignUse: vuln.knownRansomwareCampaignUse === 'Known',
                notes: vuln.notes || ''
            });
        });

        console.log(`  ✓ Loaded CISA KEV catalog: ${this.kevMap.size} known exploited vulnerabilities`);
    }

    /**
     * Load KEV catalog from cache
     */
    loadFromCache() {
        try {
            if (!fs.existsSync(this.cacheFile)) {
                return false;
            }

            const stats = fs.statSync(this.cacheFile);
            const age = Date.now() - stats.mtimeMs;

            if (age > this.cacheExpiry) {
                console.log('  ℹ️  CISA KEV cache expired, will fetch fresh data');
                return false;
            }

            const data = fs.readFileSync(this.cacheFile, 'utf8');
            const catalog = JSON.parse(data);

            this.processCatalog(catalog);
            console.log('  ✓ Loaded CISA KEV catalog from cache');
            return true;
        } catch (error) {
            console.error(`Failed to load KEV cache: ${error.message}`);
            return false;
        }
    }

    /**
     * Save KEV catalog to cache
     */
    saveToCache(catalog) {
        try {
            if (!fs.existsSync(this.cacheDir)) {
                fs.mkdirSync(this.cacheDir, { recursive: true });
            }

            fs.writeFileSync(
                this.cacheFile,
                JSON.stringify(catalog, null, 2),
                'utf8'
            );

            console.log('  ✓ Saved CISA KEV catalog to cache');
        } catch (error) {
            console.error(`Failed to save KEV cache: ${error.message}`);
        }
    }

    /**
     * Normalize CVE ID
     */
    normalizeCVE(cveId) {
        if (!cveId) return null;
        return cveId.toUpperCase().trim();
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

        // Extract from GHSA or other formats
        const match = identifier.match(/CVE-\d{4}-\d{4,}/i);
        return match ? match[0].toUpperCase() : null;
    }

    /**
     * Get statistics about KEV catalog
     */
    getStatistics() {
        if (!this.kevCatalog) {
            return null;
        }

        const stats = {
            totalVulnerabilities: this.kevMap.size,
            catalogVersion: this.kevCatalog.catalogVersion,
            dateReleased: this.kevCatalog.dateReleased,
            title: this.kevCatalog.title,
            ransomwareUse: 0
        };

        // Count vulnerabilities with known ransomware use
        this.kevMap.forEach(entry => {
            if (entry.knownRansomwareCampaignUse) {
                stats.ransomwareUse++;
            }
        });

        return stats;
    }

    /**
     * Search KEV catalog by vendor/product
     */
    searchByVendorProduct(vendor, product) {
        const results = [];

        this.kevMap.forEach(entry => {
            const vendorMatch = vendor && entry.vendorProject.toLowerCase().includes(vendor.toLowerCase());
            const productMatch = product && entry.product.toLowerCase().includes(product.toLowerCase());

            if (vendorMatch || productMatch) {
                results.push(entry);
            }
        });

        return results;
    }

    /**
     * Get all CVEs with due dates in the future
     */
    getUpcomingDueDates() {
        const now = new Date();
        const upcoming = [];

        this.kevMap.forEach(entry => {
            if (entry.dueDate) {
                const dueDate = new Date(entry.dueDate);
                if (dueDate > now) {
                    const daysUntilDue = Math.ceil((dueDate - now) / (1000 * 60 * 60 * 24));
                    upcoming.push({
                        ...entry,
                        daysUntilDue
                    });
                }
            }
        });

        // Sort by due date (soonest first)
        upcoming.sort((a, b) => a.daysUntilDue - b.daysUntilDue);

        return upcoming;
    }

    /**
     * Check if catalog is loaded
     */
    isLoaded() {
        return this.kevMap && this.kevMap.size > 0;
    }

    /**
     * Force refresh from CISA
     */
    async refresh() {
        try {
            await this.fetchKEVCatalog();
            return true;
        } catch (error) {
            console.error(`Failed to refresh KEV catalog: ${error.message}`);
            return false;
        }
    }

    /**
     * Health check
     */
    async healthCheck() {
        if (!this.isLoaded()) {
            await this.initialize();
        }

        // Check for a known exploited CVE (Log4Shell)
        return this.isKnownExploited('CVE-2021-44228');
    }
}

module.exports = CISAKEVChecker;
