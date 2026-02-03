#!/usr/bin/env node

/**
 * DepGuard v2.0 - Production CLI
 *
 * Truly generic vulnerability scanner with advanced reachability detection
 */

const { program } = require('commander');
const path = require('path');
const fs = require('fs');
const chalk = require('chalk');
const DepGuardScanner2 = require('../src/DepGuardScanner2');
const packageJSON = require('../package.json');

program
    .name('depguard')
    .description('Generic vulnerability scanner with advanced reachability analysis')
    .version(packageJSON.version);

// Scan command
program
    .command('scan')
    .description('Scan a project for reachable vulnerabilities')
    .argument('[path]', 'Path to project directory', process.cwd())
    .option('-f, --format <type>', 'Output format (table, json, html, sarif, markdown)', 'table')
    .option('-o, --output <file>', 'Output file (default: stdout)')
    .option('--min-confidence <number>', 'Minimum confidence threshold (0-1)', '0.5')
    .option('--entry-confidence <number>', 'Minimum entry point confidence (0-1)', '0.6')
    .option('--max-depth <number>', 'Maximum call graph depth', '10')
    .option('--deep', 'Enable deep analysis (slower, more thorough)')
    .option('--verbose', 'Verbose output')
    .option('--no-color', 'Disable colored output')
    .action(async (projectPath, options) => {
        try {
            console.log(chalk.bold.cyan('\n🔍 DepGuard v2.0 - Generic Vulnerability Scanner\n'));

            // Validate project path
            const absPath = path.resolve(projectPath);
            if (!fs.existsSync(absPath)) {
                console.error(chalk.red(`❌ Error: Project path does not exist: ${absPath}`));
                process.exit(1);
            }

            // Create scanner
            const scanner = new DepGuardScanner2({
                projectPath: absPath,
                minConfidence: parseFloat(options.minConfidence),
                entryPointConfidence: parseFloat(options.entryConfidence),
                maxDepth: parseInt(options.maxDepth),
                deepAnalysis: options.deep,
                verbose: options.verbose
            });

            // Run scan
            const startTime = Date.now();
            const result = await scanner.scan();
            const duration = ((Date.now() - startTime) / 1000).toFixed(2);

            if (!result.success) {
                console.error(chalk.red(`\n❌ Scan failed: ${result.error}\n`));
                process.exit(1);
            }

            // Display summary
            console.log(chalk.bold('\n📊 Scan Summary:'));
            console.log(chalk.gray('─'.repeat(60)));
            console.log(`Duration: ${duration}s`);
            console.log(`Manifests: ${result.statistics.manifests}`);
            console.log(`Dependencies: ${result.statistics.dependencies}`);
            console.log(`Vulnerabilities found: ${result.statistics.vulnerabilities}`);
            console.log(`Entry points: ${result.statistics.entryPoints}`);
            console.log(`Call graph: ${result.statistics.callGraph.totalNodes} nodes, ${result.statistics.callGraph.totalEdges} edges`);
            console.log(chalk.gray('─'.repeat(60)));

            if (result.statistics.reachableVulnerabilities > 0) {
                console.log(chalk.red.bold(`\n⚠️  ${result.statistics.reachableVulnerabilities} REACHABLE vulnerabilities found!`));
            } else {
                console.log(chalk.green.bold('\n✅ No reachable vulnerabilities found!'));
            }

            if (result.statistics.unreachableVulnerabilities > 0) {
                console.log(chalk.yellow(`ℹ️  ${result.statistics.unreachableVulnerabilities} unreachable vulnerabilities (not exploitable)`));
            }

            // Generate report
            if (options.output) {
                await scanner.generateReport(options.format, options.output);
                console.log(chalk.gray(`\n📄 Report saved to: ${options.output}`));
            } else if (options.format !== 'table') {
                const output = await scanner.generateReport(options.format);
                console.log('\n' + output);
            } else {
                await scanner.generateReport('table');
            }

            // Exit with appropriate code
            process.exit(result.statistics.reachableVulnerabilities > 0 ? 1 : 0);

        } catch (error) {
            console.error(chalk.red(`\n❌ Fatal error: ${error.message}`));
            if (options.verbose) {
                console.error(error.stack);
            }
            process.exit(1);
        }
    });

// Info command
program
    .command('info')
    .description('Show scanner capabilities and supported ecosystems')
    .action(() => {
        console.log(chalk.bold.cyan('\n🔍 DepGuard v2.0 - Scanner Information\n'));

        console.log(chalk.bold('Supported Ecosystems:'));
        console.log('  • Node.js (npm, yarn, pnpm)');
        console.log('  • Python (pip, poetry, pipenv)');
        console.log('  • Java (Maven, Gradle)');
        console.log('  • Go (go modules)');
        console.log('  • Rust (Cargo)');
        console.log('  • Ruby (Bundler)');
        console.log('  • PHP (Composer)');
        console.log('  • .NET (NuGet)');

        console.log(chalk.bold('\nSupported Frameworks (Entry Point Detection):'));
        console.log('  • Express, Next.js, Koa, Hapi, Fastify (Node.js)');
        console.log('  • Flask, FastAPI, Django (Python)');
        console.log('  • Spring Boot, JAX-RS (Java)');
        console.log('  • Gin, Echo (Go)');

        console.log(chalk.bold('\nKey Features:'));
        console.log('  ✓ Zero hardcoded assumptions about project structure');
        console.log('  ✓ Works with monorepos and microservices');
        console.log('  ✓ Advanced reachability analysis with confidence scoring');
        console.log('  ✓ Multi-signal entry point detection');
        console.log('  ✓ Real-time vulnerability data from OSV');
        console.log('  ✓ Explainable results with evidence');

        console.log(chalk.bold('\nOutput Formats:'));
        console.log('  • table - Human-readable table (default)');
        console.log('  • json - Machine-readable JSON');
        console.log('  • html - Interactive HTML report');
        console.log('  • sarif - SARIF format (GitHub integration)');
        console.log('  • markdown - Markdown report');

        console.log('');
    });

// Examples command
program
    .command('examples')
    .description('Show usage examples')
    .action(() => {
        console.log(chalk.bold.cyan('\n📚 DepGuard Usage Examples\n'));

        console.log(chalk.bold('Basic scan:'));
        console.log(chalk.gray('  depguard scan'));
        console.log(chalk.gray('  depguard scan /path/to/project\n'));

        console.log(chalk.bold('Save results to file:'));
        console.log(chalk.gray('  depguard scan --format json --output results.json'));
        console.log(chalk.gray('  depguard scan --format html --output report.html\n'));

        console.log(chalk.bold('Adjust sensitivity:'));
        console.log(chalk.gray('  depguard scan --min-confidence 0.7        # Higher confidence threshold'));
        console.log(chalk.gray('  depguard scan --entry-confidence 0.8      # Stricter entry point detection\n'));

        console.log(chalk.bold('Deep analysis (slower but more thorough):'));
        console.log(chalk.gray('  depguard scan --deep --max-depth 15\n'));

        console.log(chalk.bold('Verbose output for debugging:'));
        console.log(chalk.gray('  depguard scan --verbose\n'));

        console.log(chalk.bold('CI/CD integration:'));
        console.log(chalk.gray('  depguard scan --format sarif --output depguard.sarif'));
        console.log(chalk.gray('  # Upload to GitHub Security tab\n'));

        console.log(chalk.bold('Monorepo scanning:'));
        console.log(chalk.gray('  depguard scan /path/to/monorepo'));
        console.log(chalk.gray('  # Automatically detects and scans all services\n'));
    });

// Stats command
program
    .command('stats [path]')
    .description('Show project statistics without scanning')
    .argument('[path]', 'Path to project directory', process.cwd())
    .action(async (projectPath) => {
        try {
            const GenericManifestFinder = require('../src/core/GenericManifestFinder');
            const FileWalker = require('../src/utils/FileWalker');

            const absPath = path.resolve(projectPath);
            console.log(chalk.bold.cyan(`\n📊 Project Statistics: ${absPath}\n`));

            // Find manifests
            const manifestFinder = new GenericManifestFinder({ verbose: false });
            const manifests = manifestFinder.findManifests(absPath);
            const stats = manifestFinder.getStatistics(manifests);

            console.log(chalk.bold('Dependency Manifests:'));
            console.log(`  Total: ${stats.total}`);
            for (const [ecosystem, count] of Object.entries(stats.byEcosystem)) {
                console.log(`  • ${ecosystem}: ${count}`);
            }
            console.log(`  Workspaces: ${stats.workspaces}`);

            // Find source files
            const walker = new FileWalker({ maxDepth: 10 });
            const jsFiles = walker.findJavaScriptFiles(absPath);
            const pyFiles = walker.findPythonFiles(absPath);
            const javaFiles = walker.findJavaFiles(absPath);
            const goFiles = walker.findGoFiles(absPath);

            console.log(chalk.bold('\nSource Files:'));
            if (jsFiles.length > 0) console.log(`  • JavaScript/TypeScript: ${jsFiles.length}`);
            if (pyFiles.length > 0) console.log(`  • Python: ${pyFiles.length}`);
            if (javaFiles.length > 0) console.log(`  • Java: ${javaFiles.length}`);
            if (goFiles.length > 0) console.log(`  • Go: ${goFiles.length}`);

            console.log('');
        } catch (error) {
            console.error(chalk.red(`❌ Error: ${error.message}`));
            process.exit(1);
        }
    });

// Version with details
program
    .command('version')
    .description('Show version and build information')
    .action(() => {
        console.log(chalk.bold.cyan('\n🔍 DepGuard v2.0\n'));
        console.log(`Version: ${packageJSON.version}`);
        console.log(`Node: ${process.version}`);
        console.log(`Platform: ${process.platform} ${process.arch}`);
        console.log('');
    });

// Error handling
program.exitOverride();

try {
    program.parse(process.argv);

    // Show help if no command
    if (!process.argv.slice(2).length) {
        program.outputHelp();
    }
} catch (error) {
    if (error.code === 'commander.help' || error.code === 'commander.helpDisplayed') {
        // Help was displayed, exit normally
        process.exit(0);
    }
    console.error(chalk.red(`\n❌ Error: ${error.message}\n`));
    process.exit(1);
}
