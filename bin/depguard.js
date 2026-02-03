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
  .option('-v, --verbose', 'Verbose output', false)
  .action(async (options) => {
    try {
      // Configure logger
      const logLevel = options.verbose ? 'DEBUG' : 'INFO';
      configureLogger({ level: logLevel });

      console.log(chalk.bold.cyan('╔════════════════════════════════════════════════════════════════╗'));
      console.log(chalk.bold.cyan('║                    DepGuard v2.0.0                            ║'));
      console.log(chalk.bold.cyan('║     Advanced Dependency Vulnerability Scanner                 ║'));
      console.log(chalk.bold.cyan('║              with Reachability Analysis                        ║'));
      console.log(chalk.bold.cyan('╚════════════════════════════════════════════════════════════════╝\n'));

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
        verbose: options.verbose
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
        console.log(chalk.green(`\n✓ Report saved to: ${options.file}`));
      }

      // Exit with appropriate code
      const reachableVulns = filteredResults.filter(r => r.isReachable);

      if (reachableVulns.length > 0) {
        console.log(chalk.yellow(`\n⚠️ Found ${reachableVulns.length} reachable vulnerabilities.`));
        process.exit(1);
      } else if (filteredResults.length > 0) {
        console.log(chalk.white(`\nℹ️ Found ${filteredResults.length} vulnerabilities, but none were confirmed reachable.`));
      } else {
        console.log(chalk.green('\n✓ No vulnerabilities found.'));
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

      console.log(chalk.bold('\n📊 Project Information\n'));
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
      console.log(chalk.green('✓ Cache cleared'));
    } else {
      console.log(chalk.yellow('No cache found'));
    }
  });

// Parse arguments
program.parse(process.argv);

// Show help if no command specified
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
