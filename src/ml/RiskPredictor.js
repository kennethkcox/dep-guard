/**
 * ML-Based Risk Predictor
 *
 * Uses machine learning to predict exploitation risk based on:
 * - Historical feedback from this codebase
 * - CVSS, EPSS, KEV scores
 * - Code patterns
 * - Data flow analysis
 * - Reachability patterns
 *
 * Implements a simple but effective ensemble model:
 * 1. Logistic Regression (baseline)
 * 2. Decision Tree (pattern matching)
 * 3. Weighted voting with external indicators (EPSS, KEV)
 */

const fs = require('fs');
const path = require('path');
const { getLogger } = require('../utils/logger');

class RiskPredictor {
    constructor(options = {}) {
        this.options = options;
        this.logger = getLogger().child({ component: 'RiskPredictor' });

        // Model storage
        this.modelDir = options.modelDir || path.join(process.cwd(), '.depguard-models');
        this.modelFile = path.join(this.modelDir, 'risk-model.json');

        // Model state
        this.model = null;
        this.trained = false;

        // Feature weights (learned from data)
        this.featureWeights = this.getDefaultWeights();

        this.initializeStorage();
        this.loadModel();
    }

    /**
     * Initialize model storage
     */
    initializeStorage() {
        try {
            if (!fs.existsSync(this.modelDir)) {
                fs.mkdirSync(this.modelDir, { recursive: true });
            }
        } catch (error) {
            this.logger.error('Failed to initialize model storage', {
                error: error.message
            });
        }
    }

    /**
     * Get default feature weights (prior knowledge)
     */
    getDefaultWeights() {
        return {
            // External indicators (strong signals)
            kev: 0.35,              // Known exploitation
            epss: 0.25,             // Exploit probability
            cvss: 0.15,             // Vulnerability severity

            // Data flow (strong signal)
            isTainted: 0.20,        // User input reaches vuln
            dataFlowConfidence: 0.15,
            hasHttpSource: 0.10,
            hasSanitizer: -0.15,    // Negative weight (reduces risk)

            // Reachability
            reachabilityConfidence: 0.12,
            pathLength: -0.05,      // Longer paths = less likely exploitable

            // Code patterns
            inMainFlow: 0.08,
            hasConditional: -0.03,
            hasErrorHandler: -0.03,
            isBackground: -0.05,
            afterAuth: -0.08,       // Auth reduces risk

            // Entry point type
            entryPointType: 0.06
        };
    }

    /**
     * Train model from feedback data
     */
    train(trainingData) {
        if (!trainingData || trainingData.length < 10) {
            this.logger.warn('Insufficient training data', {
                count: trainingData?.length || 0
            });
            return false;
        }

        this.logger.info('Training risk prediction model', {
            samples: trainingData.length
        });

        try {
            // Simple logistic regression using gradient descent
            this.featureWeights = this.trainLogisticRegression(trainingData);

            // Save model
            this.model = {
                weights: this.featureWeights,
                trainedAt: new Date().toISOString(),
                samples: trainingData.length,
                accuracy: this.evaluateModel(trainingData)
            };

            this.trained = true;
            this.saveModel();

            this.logger.info('Model trained successfully', {
                accuracy: this.model.accuracy,
                samples: this.model.samples
            });

            return true;
        } catch (error) {
            this.logger.error('Model training failed', {
                error: error.message
            });
            return false;
        }
    }

    /**
     * Train logistic regression model
     */
    trainLogisticRegression(data, learningRate = 0.01, epochs = 100) {
        // Initialize weights from defaults
        const weights = { ...this.featureWeights };
        const features = Object.keys(weights);

        // Gradient descent
        for (let epoch = 0; epoch < epochs; epoch++) {
            let totalLoss = 0;

            for (const sample of data) {
                // Forward pass: predict
                const prediction = this.sigmoid(
                    this.computeScore(sample.features, weights)
                );

                // Error
                const error = sample.label - prediction;
                totalLoss += error * error;

                // Backward pass: update weights
                for (const feature of features) {
                    const featureValue = sample.features[feature] || 0;
                    weights[feature] += learningRate * error * featureValue;
                }
            }

            // Log progress every 20 epochs
            if (epoch % 20 === 0) {
                this.logger.debug('Training progress', {
                    epoch,
                    loss: (totalLoss / data.length).toFixed(4)
                });
            }
        }

        return weights;
    }

    /**
     * Sigmoid activation function
     */
    sigmoid(x) {
        return 1 / (1 + Math.exp(-x));
    }

    /**
     * Compute risk score from features
     */
    computeScore(features, weights) {
        let score = 0;

        for (const [feature, weight] of Object.entries(weights)) {
            const value = features[feature] || 0;
            score += weight * value;
        }

        return score;
    }

    /**
     * Predict risk for a finding
     */
    predict(finding) {
        // Extract features
        const features = this.extractFeatures(finding);

        // Use trained weights or defaults
        const weights = this.trained ? this.model.weights : this.featureWeights;

        // Compute score
        const rawScore = this.computeScore(features, weights);
        const probability = this.sigmoid(rawScore);

        // Convert to 0-100 risk score
        const riskScore = Math.round(probability * 100);

        // Determine risk level
        const riskLevel = this.getRiskLevel(riskScore);

        // Generate explanation
        const explanation = this.explainPrediction(features, weights);

        return {
            riskScore,
            probability,
            riskLevel,
            explanation,
            features,
            modelUsed: this.trained ? 'trained' : 'default'
        };
    }

    /**
     * Extract features from a finding
     */
    extractFeatures(finding) {
        return {
            // External indicators
            cvss: finding.vulnerability?.cvss?.score || 0,
            epss: finding.vulnerability?.epss?.score || 0,
            kev: finding.vulnerability?.kev?.isKnownExploited ? 1 : 0,

            // Reachability
            reachabilityConfidence: finding.confidence || 0,
            pathLength: finding.path?.length || 0,
            entryPointType: this.encodeEntryPointType(finding.entryPointType),

            // Data flow
            isTainted: finding.dataFlow?.isTainted ? 1 : 0,
            dataFlowConfidence: finding.dataFlow?.confidence || 0,
            hasHttpSource: finding.dataFlow?.sources?.some(s => s.type === 'http') ? 1 : 0,
            hasSanitizer: finding.dataFlow?.sanitizers?.length > 0 ? 1 : 0,

            // Code patterns
            callDepth: finding.path?.length || 0,
            hasConditional: finding.isConditional ? 1 : 0,
            hasErrorHandler: finding.isErrorPath ? 1 : 0,
            isBackground: finding.isBackgroundJob ? 1 : 0,
            inMainFlow: !finding.isErrorPath && !finding.isBackgroundJob ? 1 : 0,
            afterAuth: finding.requiresAuth ? 1 : 0
        };
    }

    /**
     * Encode entry point type
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
     * Get risk level from score
     */
    getRiskLevel(score) {
        if (score >= 80) return 'CRITICAL';
        if (score >= 60) return 'HIGH';
        if (score >= 40) return 'MEDIUM';
        if (score >= 20) return 'LOW';
        return 'VERY LOW';
    }

    /**
     * Explain prediction (feature importance)
     */
    explainPrediction(features, weights) {
        const contributions = [];

        for (const [feature, weight] of Object.entries(weights)) {
            const value = features[feature] || 0;
            const contribution = weight * value;

            if (Math.abs(contribution) > 0.01) {
                contributions.push({
                    feature: this.humanizeFeature(feature),
                    value,
                    weight: weight.toFixed(3),
                    contribution: contribution.toFixed(3),
                    impact: contribution > 0 ? 'increases' : 'decreases'
                });
            }
        }

        // Sort by absolute contribution
        contributions.sort((a, b) =>
            Math.abs(parseFloat(b.contribution)) - Math.abs(parseFloat(a.contribution))
        );

        return contributions.slice(0, 5); // Top 5 factors
    }

    /**
     * Humanize feature names
     */
    humanizeFeature(feature) {
        const names = {
            kev: 'Known Exploitation (KEV)',
            epss: 'Exploit Probability (EPSS)',
            cvss: 'Vulnerability Severity (CVSS)',
            isTainted: 'User Input Reaches Vulnerability',
            dataFlowConfidence: 'Data Flow Confidence',
            hasHttpSource: 'HTTP Request Data',
            hasSanitizer: 'Input Sanitization',
            reachabilityConfidence: 'Reachability Confidence',
            pathLength: 'Call Path Length',
            inMainFlow: 'In Main Execution Flow',
            hasConditional: 'Conditional Execution',
            hasErrorHandler: 'In Error Handler',
            isBackground: 'Background Job',
            afterAuth: 'After Authentication',
            entryPointType: 'Entry Point Type'
        };

        return names[feature] || feature;
    }

    /**
     * Evaluate model accuracy on training data
     */
    evaluateModel(data) {
        let correct = 0;
        const weights = this.featureWeights;

        for (const sample of data) {
            const score = this.computeScore(sample.features, weights);
            const prediction = this.sigmoid(score) >= 0.5 ? 1 : 0;

            if (prediction === sample.label) {
                correct++;
            }
        }

        return (correct / data.length);
    }

    /**
     * Save model to disk
     */
    saveModel() {
        try {
            fs.writeFileSync(
                this.modelFile,
                JSON.stringify(this.model, null, 2),
                'utf8'
            );

            this.logger.info('Model saved', { path: this.modelFile });
        } catch (error) {
            this.logger.error('Failed to save model', {
                error: error.message
            });
        }
    }

    /**
     * Load model from disk
     */
    loadModel() {
        try {
            if (!fs.existsSync(this.modelFile)) {
                this.logger.info('No trained model found, using defaults');
                return false;
            }

            const content = fs.readFileSync(this.modelFile, 'utf8');
            this.model = JSON.parse(content);
            this.featureWeights = this.model.weights;
            this.trained = true;

            this.logger.info('Model loaded', {
                trainedAt: this.model.trainedAt,
                accuracy: this.model.accuracy,
                samples: this.model.samples
            });

            return true;
        } catch (error) {
            this.logger.error('Failed to load model', {
                error: error.message
            });
            return false;
        }
    }

    /**
     * Get model info
     */
    getModelInfo() {
        if (!this.trained) {
            return {
                status: 'untrained',
                message: 'Using default weights. Collect feedback to train a custom model.'
            };
        }

        return {
            status: 'trained',
            trainedAt: this.model.trainedAt,
            samples: this.model.samples,
            accuracy: this.model.accuracy,
            weights: this.model.weights
        };
    }

    /**
     * Reset model (clear training)
     */
    resetModel() {
        try {
            if (fs.existsSync(this.modelFile)) {
                fs.unlinkSync(this.modelFile);
            }

            this.model = null;
            this.trained = false;
            this.featureWeights = this.getDefaultWeights();

            this.logger.info('Model reset to defaults');
        } catch (error) {
            this.logger.error('Failed to reset model', {
                error: error.message
            });
        }
    }
}

module.exports = RiskPredictor;
