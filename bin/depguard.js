#!/usr/bin/env node

/**
 * DepGuard CLI
 * Command-line interface for the DepGuard security scanner
 */

const { Command } = require('commander');
const path = require('path');
const fs = require('fs');
const chalk = require('chalk');
const DepGuardScanner = require('../src/DepGuardScanner');
const Validator = require('../src/utils/validator');
const { configureLogger } = require('../src/utils/logger');
const { ValidationError, DepGuardError } = require('../src/utils/errors');

const program = new Command();

program
  .name('depguard')
  .description('Advanced dependency vulnerability scanner with reachability analysis')
  .version('2.0.0');

// Scan command
program
  .command('scan')
  .description('Scan project for vulnerabilities')
  .option('-p, --path <path>', 'Project path', process.cwd())
  .option('-d, --depth <depth>', 'Analysis depth', '10')
  .option('--deep-analysis', 'Enable deep reachability analysis', false)
  .option('-c, --confidence <confidence>', 'Minimum confidence threshold (0-1)', '0.5')
  .option('-o, --output <format>', 'Output format (table, json, html, sarif, markdown)', 'table')
  .option('-f, --file <filepath>', 'Save report to file')
  .option('--reachable-only', 'Show only reachable vulnerabilities', false)
  .option('--severity <level>', 'Filter by severity (critical, high, medium, low)')
  .option('--disable-data-flow', 'Disable data flow analysis', false)
  .option('--disable-ml', 'Disable ML risk prediction', false)
  .option('-v, --verbose', 'Verbose output', false)
  .action(async (options) => {
    try {
      // Configure logger
      const logLevel = options.verbose ? 'DEBUG' : 'INFO';
      configureLogger({ level: logLevel });

      console.log(chalk.bold.cyan('+================================================================+'));
      console.log(chalk.bold.cyan('|                    DepGuard v2.0.0                            |'));
      console.log(chalk.bold.cyan('|     Advanced Dependency Vulnerability Scanner                 |'));
      console.log(chalk.bold.cyan('|              with Reachability Analysis                        |'));
      console.log(chalk.bold.cyan('+================================================================+\n'));

      // Validate inputs
      const projectPath = path.resolve(options.path);
      const maxDepth = Validator.validateInteger(options.depth, 'depth', 1, 100);
      const minConfidence = Validator.validateConfidence(options.confidence, 'confidence');
      const outputFormat = Validator.validateOutputFormat(options.output);

      if (options.severity) {
        Validator.validateSeverity(options.severity);
      }

      // Validate project path exists
      if (!fs.existsSync(projectPath)) {
        throw new ValidationError('Project path does not exist', 'path', projectPath);
      }

      const scanner = new DepGuardScanner({
        projectPath,
        maxDepth,
        minConfidence,
        deepAnalysis: options.deepAnalysis,
        entryPointConfidence: 0.6, // Default
        verbose: options.verbose,
        enableDataFlow: !options.disableDataFlow,
        enableML: !options.disableMl
      });

      // Run scan
      const scanResult = await scanner.scan();

      if (!scanResult.success) {
        throw new Error(scanResult.error || 'Scan failed');
      }

      const results = scanResult.results;

      // Filter by severity if specified
      let filteredResults = results;
      if (options.severity) {
        const severityLower = options.severity.toLowerCase();
        filteredResults = results.filter(r =>
          r.vulnerability && r.vulnerability.severity &&
          r.vulnerability.severity.toLowerCase() === severityLower
        );
      }

      // Filter reachable only if specified
      if (options.reachableOnly) {
        filteredResults = filteredResults.filter(r => r.isReachable);
      }

      // Generate and display report
      const reportContent = await scanner.generateReport(outputFormat);

      // If output is table or markdown, print to console, otherwise just save or print basic info
      if (['table', 'markdown'].includes(outputFormat)) {
        console.log(reportContent);
      } else {
        if (!options.file) {
          console.log(reportContent); // Print JSON/SARIF to stdout if no file specified
        }
      }

      // Save to file if specified
      if (options.file) {
        // Validate output file path
        const outputDir = path.dirname(options.file);
        if (!fs.existsSync(outputDir)) {
          fs.mkdirSync(outputDir, { recursive: true });
        }

        fs.writeFileSync(options.file, reportContent, 'utf8');
        console.log(chalk.green(`\n[OK] Report saved to: ${options.file}`));
      }

      // Exit with appropriate code
      const reachableVulns = filteredResults.filter(r => r.isReachable);

      if (reachableVulns.length > 0) {
        console.log(chalk.yellow(`\n[!] Found ${reachableVulns.length} reachable vulnerabilities.`));
        process.exit(1);
      } else if (filteredResults.length > 0) {
        console.log(chalk.white(`\n[i] Found ${filteredResults.length} vulnerabilities, but none were confirmed reachable.`));
      } else {
        console.log(chalk.green('\n[OK] No vulnerabilities found.'));
      }

    } catch (error) {
      if (error instanceof ValidationError) {
        console.error(chalk.red('Validation Error:'), error.message);
        if (error.details) {
          console.error(chalk.gray('Details:'), JSON.stringify(error.details, null, 2));
        }
      } else if (error instanceof DepGuardError) {
        console.error(chalk.red(`${error.name}:`), error.message);
        if (error.details && options.verbose) {
          console.error(chalk.gray('Details:'), JSON.stringify(error.details, null, 2));
        }
      } else {
        console.error(chalk.red('Error during scan:'), error.message);
      }

      if (options.verbose) {
        console.error(chalk.gray('\nStack trace:'));
        console.error(error.stack);
      }

      process.exit(1);
    }
  });

// Info command
program
  .command('info')
  .description('Show project dependency information')
  .option('-p, --path <path>', 'Project path', process.cwd())
  .action(async (options) => {
    try {
      const projectPath = path.resolve(options.path);
      const scanner = new DepGuardScanner({ projectPath });

      console.log(chalk.bold('\n[STATS] Project Information\n'));
      console.log(`Project Path: ${projectPath}`);

      await scanner.discoverProjectStructure();

      const stats = scanner.getStatistics();
      console.log(`\nManifests Found: ${stats.manifests}`);
      console.log(`Ecosystems: ${stats.ecosystems}`);

      // We can also trigger dependency analysis only
      await scanner.analyzeDependencies();
      const statsAfterDep = scanner.getStatistics();
      console.log(`Total Dependencies: ${statsAfterDep.dependencies}`);

    } catch (error) {
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

// Clear cache command
program
  .command('clear-cache')
  .description('Clear vulnerability database cache')
  .action(() => {
    const cacheDir = path.join(process.cwd(), '.depguard-cache');

    if (fs.existsSync(cacheDir)) {
      fs.rmSync(cacheDir, { recursive: true, force: true });
      console.log(chalk.green('[OK] Cache cleared'));
    } else {
      console.log(chalk.yellow('No cache found'));
    }
  });

// Feedback command (NEW)
program
  .command('feedback <cve-id>')
  .description('Provide feedback on a vulnerability finding')
  .requiredOption('--verdict <verdict>', 'Verdict: true-positive, false-positive, or unsure')
  .option('--reason <reason>', 'Reason for verdict')
  .option('--risk-override <risk>', 'Override risk level (critical, high, medium, low)')
  .action((cveId, options) => {
    try {
      const MLManager = require('../src/ml/MLManager');
      const mlManager = new MLManager();

      // Validate verdict
      if (!['true-positive', 'false-positive', 'unsure'].includes(options.verdict)) {
        console.log(chalk.red('Error: Verdict must be true-positive, false-positive, or unsure'));
        process.exit(1);
      }

      // For now, create a minimal finding object
      // In a real scenario, this would load from scan results
      const finding = {
        vulnerability: {
          id: cveId,
          package: 'unknown', // Would come from scan results
          version: 'unknown'
        },
        confidence: 0,
        path: []
      };

      const feedback = {
        verdict: options.verdict,
        reason: options.reason || '',
        riskOverride: options.riskOverride
      };

      mlManager.recordFeedback(finding, feedback);

      console.log(chalk.green(`[OK] Feedback recorded for ${cveId}`));
      console.log(chalk.gray(`  Verdict: ${options.verdict}`));

      if (options.reason) {
        console.log(chalk.gray(`  Reason: ${options.reason}`));
      }

      // Check if we should train
      const stats = mlManager.getFeedbackStats();
      const threshold = 50;

      if (stats.total >= threshold) {
        console.log(chalk.yellow(`\n[TIP] You have ${stats.total} feedback entries. Run 'depguard ml train' to train a custom model!`));
      } else {
        console.log(chalk.gray(`\n  Total feedback: ${stats.total}/${threshold} (need ${threshold} for auto-training)`));
      }
    } catch (error) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

// ML command group (NEW)
const mlCommand = program
  .command('ml')
  .description('Machine learning risk prediction commands');

mlCommand
  .command('status')
  .description('Show ML model and feedback status')
  .action(() => {
    try {
      const MLManager = require('../src/ml/MLManager');
      const mlManager = new MLManager();

      const status = mlManager.getStatus();

      console.log(chalk.bold.cyan('\n[STATS] ML Status\n'));

      // Feedback stats
      console.log(chalk.bold('Feedback:'));
      console.log(`  Total: ${status.feedback.total}`);
      console.log(`  True Positives: ${status.feedback.truePositives}`);
      console.log(`  False Positives: ${status.feedback.falsePositives}`);
      console.log(`  Unsure: ${status.feedback.unsure}`);

      if (status.feedback.withDataFlow > 0) {
        console.log(`  With Data Flow: ${status.feedback.withDataFlow}`);
      }

      // Model status
      console.log(chalk.bold('\nModel:'));
      if (status.model.status === 'trained') {
        console.log(chalk.green(`  Status: Trained`));
        console.log(`  Accuracy: ${(status.model.accuracy * 100).toFixed(1)}%`);
        console.log(`  Training Samples: ${status.model.samples}`);
        console.log(`  Trained At: ${status.model.trainedAt}`);
      } else {
        console.log(chalk.yellow(`  Status: Untrained (using defaults)`));
        console.log(chalk.gray(`  Collect ${status.autoTrainThreshold} feedback entries to train`));
      }

      // Recommendations
      console.log(chalk.bold('\nRecommendations:'));
      if (status.readyForTraining && status.model.status === 'untrained') {
        console.log(chalk.green(`  [OK] Ready to train! Run 'depguard ml train'`));
      } else if (!status.readyForTraining) {
        console.log(chalk.gray(`  Collect ${10 - status.feedback.total} more feedback entries to enable training`));
      }

      if (status.trainingRecommended && status.model.status === 'trained') {
        const newSamples = status.feedback.total - status.model.samples;
        console.log(chalk.yellow(`  [TIP] ${newSamples} new feedback entries. Consider retraining!`));
      }
    } catch (error) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

mlCommand
  .command('train')
  .description('Train ML model on collected feedback')
  .action(() => {
    try {
      const MLManager = require('../src/ml/MLManager');
      const mlManager = new MLManager();

      console.log(chalk.cyan('[ML] Training ML model...\n'));

      const result = mlManager.trainModel();

      if (result.success) {
        console.log(chalk.green(`[OK] Model trained successfully!`));
        console.log(`  Accuracy: ${(result.accuracy * 100).toFixed(1)}%`);
        console.log(`  Training Samples: ${result.samples}`);
        console.log(`  Trained At: ${result.trainedAt}`);
        console.log(chalk.yellow(`\n[TIP] Future scans will use this personalized model!`));
      } else {
        console.log(chalk.red(`✗ Training failed: ${result.message}`));
        if (result.currentCount) {
          console.log(chalk.gray(`  Current feedback: ${result.currentCount}/10 required`));
        }
        process.exit(1);
      }
    } catch (error) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

mlCommand
  .command('stats')
  .description('Show detailed feedback statistics')
  .action(() => {
    try {
      const MLManager = require('../src/ml/MLManager');
      const mlManager = new MLManager();

      const stats = mlManager.getFeedbackStats();

      console.log(chalk.bold.cyan('\n[DATA] Feedback Statistics\n'));

      console.log(chalk.bold('Overall:'));
      console.log(`  Total: ${stats.total}`);
      console.log(`  True Positives: ${stats.truePositives} (${(stats.truePositives/stats.total*100).toFixed(1)}%)`);
      console.log(`  False Positives: ${stats.falsePositives} (${(stats.falsePositives/stats.total*100).toFixed(1)}%)`);
      console.log(`  Unsure: ${stats.unsure} (${(stats.unsure/stats.total*100).toFixed(1)}%)`);

      if (Object.keys(stats.byPackage).length > 0) {
        console.log(chalk.bold('\nBy Package:'));
        Object.entries(stats.byPackage)
          .sort((a, b) => (b[1].tp + b[1].fp) - (a[1].tp + a[1].fp))
          .slice(0, 10)
          .forEach(([pkg, counts]) => {
            const total = counts.tp + counts.fp + counts.unsure;
            console.log(`  ${pkg}: ${total} (TP: ${counts.tp}, FP: ${counts.fp})`);
          });
      }
    } catch (error) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

mlCommand
  .command('export <file>')
  .description('Export feedback to JSON file')
  .action((file) => {
    try {
      const MLManager = require('../src/ml/MLManager');
      const mlManager = new MLManager();

      const outputPath = path.resolve(file);
      const success = mlManager.exportFeedback(outputPath);

      if (success) {
        console.log(chalk.green(`[OK] Feedback exported to ${outputPath}`));
      } else {
        console.log(chalk.red('✗ Export failed'));
        process.exit(1);
      }
    } catch (error) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

mlCommand
  .command('reset')
  .description('Reset ML model to defaults')
  .action(() => {
    try {
      const MLManager = require('../src/ml/MLManager');
      const mlManager = new MLManager();

      mlManager.resetModel();

      console.log(chalk.green('[OK] ML model reset to defaults'));
      console.log(chalk.gray('  Feedback data preserved. Model will use default weights until retrained.'));
    } catch (error) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

mlCommand
  .command('clear')
  .description('Clear all feedback data (use with caution!)')
  .option('--confirm', 'Confirm deletion')
  .action((options) => {
    try {
      if (!options.confirm) {
        console.log(chalk.yellow('[!]  This will delete ALL feedback data!'));
        console.log(chalk.gray('  Run with --confirm to proceed'));
        process.exit(1);
      }

      const MLManager = require('../src/ml/MLManager');
      const mlManager = new MLManager();

      mlManager.clearFeedback();

      console.log(chalk.green('[OK] All feedback data cleared'));
    } catch (error) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

// Parse arguments
program.parse(process.argv);

// Show help if no command specified
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
