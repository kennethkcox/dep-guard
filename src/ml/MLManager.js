/**
 * ML Manager
 *
 * Orchestrates the machine learning workflow:
 * 1. Collect feedback from users
 * 2. Train models on feedback data
 * 3. Predict risk for new findings
 * 4. Continuously improve over time
 */

const FeedbackCollector = require('./FeedbackCollector');
const RiskPredictor = require('./RiskPredictor');
const { getLogger } = require('../utils/logger');

class MLManager {
    constructor(options = {}) {
        this.options = options;
        this.logger = getLogger().child({ component: 'MLManager' });

        // Initialize components
        this.feedbackCollector = new FeedbackCollector(options);
        this.riskPredictor = new RiskPredictor(options);

        // Auto-train threshold
        this.autoTrainThreshold = options.autoTrainThreshold || 50;

        this.checkAutoTrain();
    }

    /**
     * Record user feedback on a finding
     */
    recordFeedback(finding, feedback) {
        const entry = this.feedbackCollector.recordFeedback(finding, feedback);

        this.logger.info('Feedback recorded', {
            verdict: feedback.verdict,
            vulnId: finding.vulnerability.id
        });

        // Check if we should auto-train
        this.checkAutoTrain();

        return entry;
    }

    /**
     * Check if we should auto-train
     */
    checkAutoTrain() {
        const stats = this.feedbackCollector.getStatistics();
        const newFeedback = stats.total;

        // Only auto-train if we have enough feedback and haven't trained recently
        const modelInfo = this.riskPredictor.getModelInfo();
        const shouldTrain = newFeedback >= this.autoTrainThreshold &&
                           (!modelInfo.samples || newFeedback > modelInfo.samples * 1.5);

        if (shouldTrain) {
            this.logger.info('Auto-training triggered', {
                feedbackCount: newFeedback,
                threshold: this.autoTrainThreshold
            });
            this.trainModel();
        }
    }

    /**
     * Train the risk prediction model
     */
    trainModel() {
        this.logger.info('Training risk prediction model');

        // Export feedback as training data
        const trainingData = this.feedbackCollector.exportForTraining();

        if (trainingData.length < 10) {
            this.logger.warn('Insufficient training data', {
                count: trainingData.length,
                required: 10
            });
            return {
                success: false,
                message: 'Need at least 10 feedback entries to train model',
                currentCount: trainingData.length
            };
        }

        // Train the model
        const success = this.riskPredictor.train(trainingData);

        if (success) {
            const modelInfo = this.riskPredictor.getModelInfo();
            this.logger.info('Model training complete', {
                accuracy: modelInfo.accuracy,
                samples: modelInfo.samples
            });

            return {
                success: true,
                accuracy: modelInfo.accuracy,
                samples: modelInfo.samples,
                trainedAt: modelInfo.trainedAt
            };
        } else {
            return {
                success: false,
                message: 'Training failed. Check logs for details.'
            };
        }
    }

    /**
     * Predict risk for a finding
     */
    predictRisk(finding) {
        return this.riskPredictor.predict(finding);
    }

    /**
     * Enrich findings with ML predictions
     */
    enrichFindings(findings) {
        this.logger.info('Enriching findings with ML predictions', {
            count: findings.length
        });

        return findings.map(finding => {
            const prediction = this.predictRisk(finding);

            return {
                ...finding,
                mlPrediction: prediction,
                enhancedRisk: prediction.riskLevel,
                enhancedScore: prediction.riskScore
            };
        });
    }

    /**
     * Get feedback statistics
     */
    getFeedbackStats() {
        return this.feedbackCollector.getStatistics();
    }

    /**
     * Get model information
     */
    getModelInfo() {
        return this.riskPredictor.getModelInfo();
    }

    /**
     * Export feedback for external analysis
     */
    exportFeedback(outputPath) {
        return this.feedbackCollector.exportToJSON(outputPath);
    }

    /**
     * Export training data
     */
    exportTrainingData() {
        return this.feedbackCollector.exportForTraining();
    }

    /**
     * Clear all feedback
     */
    clearFeedback() {
        this.feedbackCollector.clearFeedback();
        this.logger.info('Feedback cleared');
    }

    /**
     * Reset model to defaults
     */
    resetModel() {
        this.riskPredictor.resetModel();
        this.logger.info('Model reset to defaults');
    }

    /**
     * Get complete ML status
     */
    getStatus() {
        const feedbackStats = this.getFeedbackStats();
        const modelInfo = this.getModelInfo();

        return {
            feedback: feedbackStats,
            model: modelInfo,
            autoTrainThreshold: this.autoTrainThreshold,
            readyForTraining: feedbackStats.total >= 10,
            trainingRecommended: feedbackStats.total >= this.autoTrainThreshold
        };
    }

    /**
     * Interactive feedback prompt (for CLI)
     */
    async promptForFeedback(finding) {
        // This would integrate with CLI to prompt user
        // For now, return structure
        return {
            question: `Is ${finding.vulnerability.id} in ${finding.vulnerability.package} exploitable in your code?`,
            options: [
                { value: 'true-positive', label: 'Yes, it\'s exploitable' },
                { value: 'false-positive', label: 'No, it\'s not exploitable' },
                { value: 'unsure', label: 'Not sure' },
                { value: 'skip', label: 'Skip' }
            ]
        };
    }

    /**
     * Batch predict risks
     */
    batchPredict(findings) {
        return findings.map(finding => ({
            finding,
            prediction: this.predictRisk(finding)
        }));
    }

    /**
     * Get feature importance for a finding
     */
    explainFinding(finding) {
        const prediction = this.predictRisk(finding);

        return {
            riskScore: prediction.riskScore,
            riskLevel: prediction.riskLevel,
            topFactors: prediction.explanation,
            recommendation: this.getRecommendation(prediction)
        };
    }

    /**
     * Get remediation recommendation based on risk
     */
    getRecommendation(prediction) {
        const score = prediction.riskScore;

        if (score >= 80) {
            return {
                priority: 'CRITICAL',
                action: 'Fix immediately - very high exploitation risk',
                timeline: 'Within 24 hours'
            };
        } else if (score >= 60) {
            return {
                priority: 'HIGH',
                action: 'Fix within 1 week - high exploitation risk',
                timeline: 'Within 7 days'
            };
        } else if (score >= 40) {
            return {
                priority: 'MEDIUM',
                action: 'Fix within 1 month - moderate risk',
                timeline: 'Within 30 days'
            };
        } else if (score >= 20) {
            return {
                priority: 'LOW',
                action: 'Schedule for next release',
                timeline: 'Next release cycle'
            };
        } else {
            return {
                priority: 'VERY LOW',
                action: 'Monitor and follow standard patching schedule',
                timeline: 'Standard schedule'
            };
        }
    }
}

module.exports = MLManager;
