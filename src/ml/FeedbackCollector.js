/**
 * Feedback Collector
 *
 * Collects user feedback on vulnerability findings to train ML models.
 * Learns from:
 * - True positives: User confirms vulnerability is exploitable
 * - False positives: User marks as not exploitable
 * - Custom risk assessments: User overrides risk ratings
 *
 * Data collected (anonymized):
 * - Code patterns
 * - Call graph structure
 * - Data flow patterns
 * - CVSS + EPSS + KEV indicators
 * - User decision (TP/FP)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { getLogger } = require('../utils/logger');

class FeedbackCollector {
    constructor(options = {}) {
        this.options = options;
        this.logger = getLogger().child({ component: 'FeedbackCollector' });

        // Feedback storage
        this.feedbackDir = options.feedbackDir || path.join(process.cwd(), '.depguard-feedback');
        this.feedbackFile = path.join(this.feedbackDir, 'feedback.jsonl');

        // In-memory feedback for current session
        this.sessionFeedback = [];

        this.initializeStorage();
    }

    /**
     * Initialize feedback storage
     */
    initializeStorage() {
        try {
            if (!fs.existsSync(this.feedbackDir)) {
                fs.mkdirSync(this.feedbackDir, { recursive: true });
            }

            if (!fs.existsSync(this.feedbackFile)) {
                fs.writeFileSync(this.feedbackFile, '', 'utf8');
            }
        } catch (error) {
            this.logger.error('Failed to initialize feedback storage', {
                error: error.message
            });
        }
    }

    /**
     * Record feedback on a vulnerability finding
     */
    recordFeedback(finding, feedback) {
        const feedbackEntry = {
            id: this.generateFeedbackId(finding),
            timestamp: new Date().toISOString(),
            verdict: feedback.verdict, // 'true-positive', 'false-positive', 'unsure'
            reason: feedback.reason || '',
            riskOverride: feedback.riskOverride || null,

            // Vulnerability metadata
            vulnerability: {
                id: finding.vulnerability.id,
                package: finding.vulnerability.package,
                version: finding.vulnerability.version,
                cvss: finding.vulnerability.cvss,
                epss: finding.vulnerability.epss,
                kev: finding.vulnerability.kev?.isKnownExploited || false
            },

            // Reachability metadata
            reachability: {
                confidence: finding.confidence,
                pathLength: finding.path?.length || 0,
                entryPointType: finding.entryPointType || 'unknown'
            },

            // Data flow metadata (if available)
            dataFlow: finding.dataFlow ? {
                isTainted: finding.dataFlow.isTainted,
                confidence: finding.dataFlow.confidence,
                sources: finding.dataFlow.sources?.map(s => s.type) || [],
                hasSanitizer: finding.dataFlow.sanitizers?.length > 0
            } : null,

            // Code patterns (anonymized)
            codePatterns: this.extractCodePatterns(finding),

            // User context
            projectType: this.options.projectType || 'unknown',
            framework: this.options.framework || 'unknown'
        };

        // Add to session
        this.sessionFeedback.push(feedbackEntry);

        // Persist to disk
        this.persistFeedback(feedbackEntry);

        this.logger.info('Feedback recorded', {
            findingId: feedbackEntry.id,
            verdict: feedbackEntry.verdict
        });

        return feedbackEntry;
    }

    /**
     * Generate unique feedback ID
     */
    generateFeedbackId(finding) {
        const data = `${finding.vulnerability.id}-${finding.vulnerability.package}-${Date.now()}`;
        return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
    }

    /**
     * Extract code patterns (anonymized)
     */
    extractCodePatterns(finding) {
        const patterns = {
            // Call pattern
            callDepth: finding.path?.length || 0,
            hasConditional: finding.isConditional || false,
            hasErrorHandler: finding.isErrorPath || false,
            isBackground: finding.isBackgroundJob || false,

            // Function usage pattern
            functionCalled: finding.vulnerability.affectedFunction || 'unknown',
            callType: finding.callType || 'direct',

            // Context pattern
            inMainFlow: !finding.isErrorPath && !finding.isBackgroundJob,
            afterAuthentication: finding.requiresAuth || false
        };

        return patterns;
    }

    /**
     * Persist feedback to disk (JSONL format)
     */
    persistFeedback(entry) {
        try {
            const line = JSON.stringify(entry) + '\n';
            fs.appendFileSync(this.feedbackFile, line, 'utf8');
        } catch (error) {
            this.logger.error('Failed to persist feedback', {
                error: error.message
            });
        }
    }

    /**
     * Load all historical feedback
     */
    loadFeedback() {
        try {
            if (!fs.existsSync(this.feedbackFile)) {
                return [];
            }

            const content = fs.readFileSync(this.feedbackFile, 'utf8');
            const lines = content.split('\n').filter(line => line.trim());

            return lines.map(line => {
                try {
                    return JSON.parse(line);
                } catch (error) {
                    this.logger.warn('Invalid feedback line', { error: error.message });
                    return null;
                }
            }).filter(entry => entry !== null);
        } catch (error) {
            this.logger.error('Failed to load feedback', {
                error: error.message
            });
            return [];
        }
    }

    /**
     * Get feedback statistics
     */
    getStatistics() {
        const feedback = this.loadFeedback();

        const stats = {
            total: feedback.length,
            truePositives: feedback.filter(f => f.verdict === 'true-positive').length,
            falsePositives: feedback.filter(f => f.verdict === 'false-positive').length,
            unsure: feedback.filter(f => f.verdict === 'unsure').length,
            byPackage: {},
            byRisk: {},
            withDataFlow: feedback.filter(f => f.dataFlow && f.dataFlow.isTainted).length
        };

        // Group by package
        feedback.forEach(f => {
            const pkg = f.vulnerability.package;
            if (!stats.byPackage[pkg]) {
                stats.byPackage[pkg] = { tp: 0, fp: 0, unsure: 0 };
            }
            if (f.verdict === 'true-positive') stats.byPackage[pkg].tp++;
            else if (f.verdict === 'false-positive') stats.byPackage[pkg].fp++;
            else stats.byPackage[pkg].unsure++;
        });

        return stats;
    }

    /**
     * Export feedback for ML training
     */
    exportForTraining() {
        const feedback = this.loadFeedback();

        // Filter out 'unsure' entries for training
        const trainingData = feedback
            .filter(f => f.verdict !== 'unsure')
            .map(f => ({
                // Features
                features: {
                    // Vulnerability characteristics
                    cvss: f.vulnerability.cvss?.score || 0,
                    epss: f.vulnerability.epss?.score || 0,
                    kev: f.vulnerability.kev ? 1 : 0,

                    // Reachability characteristics
                    reachabilityConfidence: f.reachability.confidence,
                    pathLength: f.reachability.pathLength,
                    entryPointType: this.encodeEntryPointType(f.reachability.entryPointType),

                    // Data flow characteristics
                    isTainted: f.dataFlow?.isTainted ? 1 : 0,
                    dataFlowConfidence: f.dataFlow?.confidence || 0,
                    hasHttpSource: f.dataFlow?.sources?.includes('http') ? 1 : 0,
                    hasSanitizer: f.dataFlow?.hasSanitizer ? 1 : 0,

                    // Code patterns
                    callDepth: f.codePatterns.callDepth,
                    hasConditional: f.codePatterns.hasConditional ? 1 : 0,
                    hasErrorHandler: f.codePatterns.hasErrorHandler ? 1 : 0,
                    isBackground: f.codePatterns.isBackground ? 1 : 0,
                    inMainFlow: f.codePatterns.inMainFlow ? 1 : 0,
                    afterAuth: f.codePatterns.afterAuthentication ? 1 : 0
                },

                // Label (target)
                label: f.verdict === 'true-positive' ? 1 : 0,

                // Metadata (for analysis, not training)
                metadata: {
                    id: f.id,
                    timestamp: f.timestamp,
                    package: f.vulnerability.package,
                    vulnId: f.vulnerability.id
                }
            }));

        return trainingData;
    }

    /**
     * Encode entry point type as number
     */
    encodeEntryPointType(type) {
        const encoding = {
            'http': 1.0,
            'cli': 0.8,
            'background': 0.5,
            'unknown': 0.3
        };
        return encoding[type] || 0.3;
    }

    /**
     * Clear all feedback (use with caution!)
     */
    clearFeedback() {
        try {
            if (fs.existsSync(this.feedbackFile)) {
                fs.unlinkSync(this.feedbackFile);
            }
            this.sessionFeedback = [];
            this.initializeStorage();

            this.logger.info('Feedback cleared');
        } catch (error) {
            this.logger.error('Failed to clear feedback', {
                error: error.message
            });
        }
    }

    /**
     * Export feedback to JSON for analysis
     */
    exportToJSON(outputPath) {
        const feedback = this.loadFeedback();
        const stats = this.getStatistics();

        const exportData = {
            generatedAt: new Date().toISOString(),
            statistics: stats,
            feedback: feedback
        };

        try {
            fs.writeFileSync(
                outputPath,
                JSON.stringify(exportData, null, 2),
                'utf8'
            );

            this.logger.info('Feedback exported', { path: outputPath });
            return true;
        } catch (error) {
            this.logger.error('Failed to export feedback', {
                error: error.message
            });
            return false;
        }
    }
}

module.exports = FeedbackCollector;
