/**
 * Tests for ML Risk Predictor
 */

const RiskPredictor = require('../src/ml/RiskPredictor');
const path = require('path');
const fs = require('fs');

describe('RiskPredictor', () => {
    let predictor;
    const testModelDir = path.join(__dirname, '.test-models');

    beforeEach(() => {
        predictor = new RiskPredictor({ modelDir: testModelDir });
    });

    afterEach(() => {
        // Clean up test models
        if (fs.existsSync(testModelDir)) {
            fs.rmSync(testModelDir, { recursive: true, force: true });
        }
    });

    describe('Feature Extraction', () => {
        test('should extract features from finding', () => {
            const finding = {
                vulnerability: {
                    cvss: { score: 9.8 },
                    epss: { score: 0.75 },
                    kev: { isKnownExploited: true }
                },
                confidence: 0.85,
                path: ['a', 'b', 'c'],
                entryPointType: 'http',
                dataFlow: {
                    isTainted: true,
                    confidence: 0.90,
                    sources: [{ type: 'http' }],
                    sanitizers: []
                },
                isConditional: false,
                isErrorPath: false,
                isBackgroundJob: false,
                requiresAuth: false
            };

            const features = predictor.extractFeatures(finding);

            expect(features.cvss).toBe(9.8);
            expect(features.epss).toBe(0.75);
            expect(features.kev).toBe(1);
            expect(features.isTainted).toBe(1);
            expect(features.hasHttpSource).toBe(1);
        });

        test('should handle missing data flow', () => {
            const finding = {
                vulnerability: { cvss: { score: 7.5 } },
                confidence: 0.70
            };

            const features = predictor.extractFeatures(finding);

            expect(features.isTainted).toBe(0);
            expect(features.dataFlowConfidence).toBe(0);
        });
    });

    describe('Risk Prediction', () => {
        test('should predict high risk for KEV vulnerability', () => {
            const finding = {
                vulnerability: {
                    cvss: { score: 9.0 },
                    epss: { score: 0.80 },
                    kev: { isKnownExploited: true }
                },
                confidence: 0.85,
                dataFlow: {
                    isTainted: true,
                    confidence: 0.90
                }
            };

            const prediction = predictor.predict(finding);

            expect(prediction.riskScore).toBeGreaterThan(70);
            expect(prediction.riskLevel).toMatch(/CRITICAL|HIGH/);
        });

        test('should predict lower risk for sanitized vulnerability', () => {
            const findingWithoutSanitizer = {
                vulnerability: {
                    cvss: { score: 7.0 },
                    epss: { score: 0.30 }
                },
                confidence: 0.70,
                dataFlow: {
                    isTainted: true,
                    confidence: 0.60,
                    sources: [{ type: 'http' }],
                    sanitizers: []
                }
            };

            const findingWithSanitizer = {
                vulnerability: {
                    cvss: { score: 7.0 },
                    epss: { score: 0.30 }
                },
                confidence: 0.70,
                dataFlow: {
                    isTainted: true,
                    confidence: 0.60,
                    sources: [{ type: 'http' }],
                    sanitizers: ['validator.escape']
                }
            };

            const predictionWithout = predictor.predict(findingWithoutSanitizer);
            const predictionWith = predictor.predict(findingWithSanitizer);

            // Sanitizer should reduce risk
            expect(predictionWith.riskScore).toBeLessThan(predictionWithout.riskScore);
        });

        test('should provide explanation', () => {
            const finding = {
                vulnerability: {
                    cvss: { score: 8.0 },
                    kev: { isKnownExploited: true }
                },
                confidence: 0.80
            };

            const prediction = predictor.predict(finding);

            expect(prediction.explanation).toBeDefined();
            expect(Array.isArray(prediction.explanation)).toBe(true);
            expect(prediction.explanation.length).toBeGreaterThan(0);
        });
    });

    describe('Model Training', () => {
        test('should train model with sufficient data', () => {
            const trainingData = generateTrainingData(20);
            const success = predictor.train(trainingData);

            expect(success).toBe(true);
            expect(predictor.trained).toBe(true);
        });

        test('should fail training with insufficient data', () => {
            const trainingData = generateTrainingData(5);
            const success = predictor.train(trainingData);

            expect(success).toBe(false);
        });

        test('should save and load model', () => {
            const trainingData = generateTrainingData(20);
            predictor.train(trainingData);

            // Create new predictor instance
            const predictor2 = new RiskPredictor({ modelDir: testModelDir });

            expect(predictor2.trained).toBe(true);
            const modelInfo = predictor2.getModelInfo();
            expect(modelInfo.status).toBe('trained');
        });
    });

    describe('Model Evaluation', () => {
        test('should evaluate model accuracy', () => {
            const trainingData = generateTrainingData(30);
            predictor.train(trainingData);

            const modelInfo = predictor.getModelInfo();
            expect(modelInfo.accuracy).toBeGreaterThan(0);
            expect(modelInfo.accuracy).toBeLessThanOrEqual(1);
        });
    });

    describe('Risk Levels', () => {
        test('should categorize risk levels correctly', () => {
            expect(predictor.getRiskLevel(85)).toBe('CRITICAL');
            expect(predictor.getRiskLevel(70)).toBe('HIGH');
            expect(predictor.getRiskLevel(50)).toBe('MEDIUM');
            expect(predictor.getRiskLevel(30)).toBe('LOW');
            expect(predictor.getRiskLevel(10)).toBe('VERY LOW');
        });
    });

    describe('Feature Importance', () => {
        test('should identify top contributing features', () => {
            const finding = {
                vulnerability: {
                    cvss: { score: 9.0 },
                    epss: { score: 0.90 },
                    kev: { isKnownExploited: true }
                },
                confidence: 0.85,
                dataFlow: {
                    isTainted: true,
                    confidence: 0.95
                }
            };

            const prediction = predictor.predict(finding);
            const explanation = prediction.explanation;

            expect(explanation.length).toBeGreaterThan(0);
            expect(explanation[0]).toHaveProperty('feature');
            expect(explanation[0]).toHaveProperty('contribution');
            expect(explanation[0]).toHaveProperty('impact');
        });
    });

    describe('Model Reset', () => {
        test('should reset model to defaults', () => {
            const trainingData = generateTrainingData(20);
            predictor.train(trainingData);

            expect(predictor.trained).toBe(true);

            predictor.resetModel();

            expect(predictor.trained).toBe(false);
            const modelInfo = predictor.getModelInfo();
            expect(modelInfo.status).toBe('untrained');
        });
    });
});

// Helper function to generate training data
function generateTrainingData(count) {
    const data = [];

    for (let i = 0; i < count; i++) {
        const isExploitable = i % 2 === 0;

        data.push({
            features: {
                cvss: isExploitable ? 8 + Math.random() * 2 : 4 + Math.random() * 3,
                epss: isExploitable ? 0.7 + Math.random() * 0.3 : Math.random() * 0.3,
                kev: isExploitable ? 1 : 0,
                reachabilityConfidence: 0.5 + Math.random() * 0.5,
                pathLength: Math.floor(Math.random() * 10),
                entryPointType: 1.0,
                isTainted: isExploitable ? 1 : Math.random() > 0.7 ? 1 : 0,
                dataFlowConfidence: isExploitable ? 0.8 + Math.random() * 0.2 : Math.random() * 0.5,
                hasHttpSource: isExploitable ? 1 : 0,
                hasSanitizer: isExploitable ? 0 : Math.random() > 0.5 ? 1 : 0,
                callDepth: Math.floor(Math.random() * 5),
                hasConditional: Math.random() > 0.5 ? 1 : 0,
                hasErrorHandler: Math.random() > 0.7 ? 1 : 0,
                isBackground: Math.random() > 0.8 ? 1 : 0,
                inMainFlow: Math.random() > 0.3 ? 1 : 0,
                afterAuth: Math.random() > 0.6 ? 1 : 0
            },
            label: isExploitable ? 1 : 0
        });
    }

    return data;
}
