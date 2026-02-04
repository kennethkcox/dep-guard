/**
 * Report Generator
 * Creates comprehensive security reports in various formats
 */

const chalk = require('chalk');
const fs = require('fs');
const Validator = require('../utils/validator');
const { getLogger } = require('../utils/logger');

class Reporter {
  constructor(options = {}) {
    this.options = {
      format: options.format || 'table',
      verbosity: options.verbosity || 'normal',
      onlyReachable: options.onlyReachable || false,
      ...options
    };
    this.logger = getLogger().child({ component: 'Reporter' });
  }

  /**
   * Generates a report from scan results
   */
  generate(results, metadata = {}) {
    try {
      this.logger.debug('Generating report', { format: this.options.format, resultCount: results.length });

      // Validate results
      if (!Array.isArray(results)) {
        throw new Error('Results must be an array');
      }

      switch (this.options.format) {
        case 'json':
          return this.generateJSON(results, metadata);
        case 'html':
          return this.generateHTML(results, metadata);
        case 'sarif':
          return this.generateSARIF(results, metadata);
        case 'markdown':
          return this.generateMarkdown(results, metadata);
        case 'table':
        default:
          return this.generateTable(results, metadata);
      }
    } catch (error) {
      this.logger.error('Failed to generate report', { error: error.message });
      throw error;
    }
  }

  /**
   * Generates a table format report (for CLI)
   */
  generateTable(results, metadata) {
    let output = [];

    // Header
    output.push(chalk.bold('\n+================================================================+'));
    output.push(chalk.bold('| DepGuard Security Report                                       |'));
    output.push(chalk.bold('+================================================================+'));

    // Summary statistics
    const calculatedStats = this.calculateStatistics(results);
    // Use provided metadata stats if available (richer source), otherwise calculated
    const stats = {
      ...calculatedStats,
      totalDependencies: metadata.dependencies || calculatedStats.totalDependencies,
      totalVulnerabilities: metadata.vulnerabilities || calculatedStats.totalVulnerabilities,
      reachableVulnerabilities: metadata.reachableVulnerabilities || calculatedStats.reachableVulnerabilities
    };

    output.push(chalk.bold(`| Total Dependencies: ${String(stats.totalDependencies).padEnd(42)}|`));
    output.push(chalk.bold(`| Vulnerabilities Found: ${String(stats.totalVulnerabilities).padEnd(38)}|`));
    output.push(chalk.bold(`| Reachable Vulnerabilities: ${String(stats.reachableVulnerabilities).padEnd(34)}|`));
    if (calculatedStats.taintedVulnerabilities > 0) {
      output.push(chalk.red(`| [FLOW] Tainted (User Input): ${String(calculatedStats.taintedVulnerabilities).padEnd(26)}|`));
    }
    if (calculatedStats.mlPredicted > 0) {
      output.push(chalk.cyan(`| [ML] Risk Assessed: ${String(calculatedStats.mlPredicted).padEnd(40)}|`));
      if (calculatedStats.mlCritical > 0 || calculatedStats.mlHigh > 0) {
        output.push(chalk.red(`|    ML Critical/High: ${String(calculatedStats.mlCritical + calculatedStats.mlHigh).padEnd(37)}|`));
      }
    }
    output.push(chalk.bold(`| Critical: ${String(calculatedStats.critical).padEnd(51)}|`));
    output.push(chalk.bold(`| High: ${String(calculatedStats.high).padEnd(55)}|`));
    output.push(chalk.bold(`| Medium: ${String(calculatedStats.medium).padEnd(53)}|`));
    output.push(chalk.bold('+================================================================+\n'));

    // Filter results if needed
    let filteredResults = results;
    if (this.options.onlyReachable) {
      filteredResults = results.filter(r => r.reachability && r.reachability.isReachable);
    }

    if (filteredResults.length === 0) {
      output.push(chalk.green('[OK] No vulnerabilities found!\n'));
      return output.join('\n');
    }

    // Sort by priority
    filteredResults.sort((a, b) => {
      const aPriority = this.getSeverityScore(a.vulnerability.severity);
      const bPriority = this.getSeverityScore(b.vulnerability.severity);
      if (aPriority !== bPriority) return bPriority - aPriority;

      // Then by reachability confidence
      const aConf = a.reachability ? a.reachability.confidence : 0;
      const bConf = b.reachability ? b.reachability.confidence : 0;
      return bConf - aConf;
    });

    // Vulnerability details
    filteredResults.forEach((result, index) => {
      output.push(this.formatVulnerability(result, index + 1));
    });

    return output.join('\n');
  }

  /**
   * Formats a single vulnerability for table output
   */
  formatVulnerability(result, index) {
    const vuln = result.vulnerability;
    const reach = result.reachability;

    let output = [];

    // ML Risk Score (NEW - show first if available)
    if (result.mlPrediction) {
      const score = result.mlPrediction.riskScore;
      const level = result.mlPrediction.riskLevel;
      const scoreColor = score >= 80 ? chalk.red :
                        score >= 60 ? chalk.yellow :
                        score >= 40 ? chalk.blue : chalk.gray;

      output.push(chalk.bold(`\n[*] ML Risk Score: ${scoreColor(`${score}/100 (${level})`)}`));
    }

    // Severity indicator
    const severityColor = this.getSeverityColor(vuln.severity);
    const severityIcon = this.getSeverityIcon(vuln.severity);

    // Reachability indicator
    const reachableIcon = reach && reach.isReachable
      ? chalk.red('[!] REACHABLE')
      : chalk.yellow('○ NOT REACHABLE');

    const confidence = reach && reach.isReachable
      ? ` (${Math.round(reach.confidence * 100)}% confidence)`
      : '';

    output.push(`${chalk.bold(`[${vuln.severity}]`)} ${severityIcon} ${reachableIcon}${confidence}`);
    output.push(chalk.bold(`Package: ${result.package}`));
    output.push(chalk.bold(`Vulnerability: ${vuln.id}`));
    output.push(`CVSS: ${vuln.cvss} (${vuln.severity})`);
    output.push(`Description: ${vuln.title}`);

    // Data Flow Analysis (NEW)
    if (result.dataFlow) {
      const df = result.dataFlow;
      if (df.isTainted) {
        output.push(chalk.red(`\n[FLOW] Data Flow: TAINTED (${Math.round(df.confidence * 100)}% confidence)`));
        output.push(chalk.red(`   User input reaches this vulnerability!`));

        if (df.sources && df.sources.length > 0) {
          output.push(chalk.dim(`   Sources: ${df.sources.map(s => s.source).join(', ')}`));
        }

        if (df.sanitizers && df.sanitizers.length > 0) {
          output.push(chalk.yellow(`   [!] Sanitizers: ${df.sanitizers.join(', ')} (may not be effective)`));
        }

        output.push(chalk.red(`   Risk: ${df.risk}`));
      } else {
        output.push(chalk.green(`\n[FLOW] Data Flow: Not tainted`));
        output.push(chalk.dim(`   No user input detected reaching this vulnerability`));
      }
    }

    // ML Explanation (NEW - show top factors)
    if (result.mlPrediction && result.mlPrediction.explanation && this.options.verbosity !== 'quiet') {
      const topFactors = result.mlPrediction.explanation.slice(0, 3);
      if (topFactors.length > 0) {
        output.push(chalk.cyan('\n[TIP] Top Risk Factors:'));
        topFactors.forEach((factor, idx) => {
          const sign = factor.impact === 'increases' ? '+' : '-';
          const color = factor.impact === 'increases' ? chalk.red : chalk.green;
          output.push(color(`   ${idx + 1}. ${factor.feature} (${sign}${Math.abs(parseFloat(factor.contribution) * 100).toFixed(0)} points)`));
        });
      }
    }

    // Vulnerable function location
    if (result.functionName) {
      output.push(chalk.dim(`\nLocation: ${result.modulePath}::${result.functionName}`));
    }

    // Reachability path
    if (reach && reach.isReachable && reach.paths && reach.paths.length > 0) {
      output.push(chalk.cyan('\nReachable Path:'));
      const topPath = reach.paths[0];

      topPath.nodes.forEach((node, idx) => {
        const indent = '  '.repeat(idx);
        const arrow = idx > 0 ? '->' : '';
        output.push(chalk.dim(`  ${indent}${arrow}${node}`));
      });

      if (reach.totalPathsFound > 1) {
        output.push(chalk.dim(`  ... and ${reach.totalPathsFound - 1} more path(s)`));
      }
    }

    // Fix recommendation
    if (vuln.fixedVersion) {
      output.push(chalk.green(`\nRecommendation: Update to ${result.package}@${vuln.fixedVersion} or higher`));
    } else if (result.mlPrediction) {
      const rec = result.mlPrediction.recommendation;
      if (rec) {
        output.push(chalk.yellow(`\nRecommendation: ${rec.action}`));
        output.push(chalk.dim(`Timeline: ${rec.timeline}`));
      }
    }

    // References
    if (this.options.verbosity === 'detailed' && vuln.references) {
      output.push(chalk.dim('\nReferences:'));
      vuln.references.forEach(ref => {
        output.push(chalk.dim(`  - ${ref}`));
      });
    }

    output.push(chalk.gray('-'.repeat(64)));

    return output.join('\n');
  }

  /**
   * Generates JSON format report
   */
  generateJSON(results, metadata) {
    const stats = this.calculateStatistics(results);

    const report = {
      metadata: {
        tool: 'DepGuard',
        version: '1.0.0',
        scanDate: new Date().toISOString(),
        ...metadata
      },
      statistics: stats,
      vulnerabilities: results.map(r => ({
        package: r.package,
        vulnerability: {
          id: r.vulnerability.id,
          title: r.vulnerability.title,
          description: r.vulnerability.description,
          severity: r.vulnerability.severity,
          cvss: r.vulnerability.cvss,
          affectedVersions: r.vulnerability.affectedVersions,
          fixedVersion: r.vulnerability.fixedVersion,
          exploitMaturity: r.vulnerability.exploitMaturity,
          references: r.vulnerability.references
        },
        location: {
          modulePath: r.modulePath,
          functionName: r.functionName
        },
        reachability: r.reachability
      }))
    };

    return JSON.stringify(report, null, 2);
  }

  /**
   * Generates HTML format report
   */
  generateHTML(results, metadata) {
    const stats = this.calculateStatistics(results);

    let html = `
<!DOCTYPE html>
<html>
<head>
  <title>DepGuard Security Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    h1 { color: #333; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }
    .summary { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }
    .stat-box { background: #ecf0f1; padding: 20px; border-radius: 5px; text-align: center; }
    .stat-number { font-size: 32px; font-weight: bold; color: #2c3e50; }
    .stat-label { color: #7f8c8d; margin-top: 5px; }
    .vulnerability { border: 1px solid #ddd; margin: 20px 0; padding: 20px; border-radius: 5px; }
    .critical { border-left: 5px solid #c0392b; }
    .high { border-left: 5px solid #e74c3c; }
    .medium { border-left: 5px solid #f39c12; }
    .low { border-left: 5px solid #f1c40f; }
    .reachable { background: #fee; }
    .badge { display: inline-block; padding: 5px 10px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-right: 10px; }
    .badge-critical { background: #c0392b; color: white; }
    .badge-high { background: #e74c3c; color: white; }
    .badge-medium { background: #f39c12; color: white; }
    .badge-low { background: #f1c40f; color: #333; }
    .badge-reachable { background: #e74c3c; color: white; }
    .path { font-family: monospace; font-size: 12px; background: #f8f9fa; padding: 10px; border-left: 3px solid #3498db; margin: 10px 0; }
    .path-node { margin: 5px 0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>DepGuard Security Report</h1>
    <p>Generated: ${new Date().toISOString()}</p>

    <div class="summary">
      <div class="stat-box">
        <div class="stat-number">${stats.totalVulnerabilities}</div>
        <div class="stat-label">Total Vulnerabilities</div>
      </div>
      <div class="stat-box">
        <div class="stat-number">${stats.reachableVulnerabilities}</div>
        <div class="stat-label">Reachable</div>
      </div>
      <div class="stat-box">
        <div class="stat-number">${stats.critical}</div>
        <div class="stat-label">Critical</div>
      </div>
    </div>

    ${results.map(r => this.formatVulnerabilityHTML(r)).join('\n')}
  </div>
</body>
</html>
`;

    return html;
  }

  /**
   * Formats a vulnerability for HTML output
   */
  formatVulnerabilityHTML(result) {
    const vuln = result.vulnerability;
    const reach = result.reachability;
    const isReachable = reach && reach.isReachable;

    const severityClass = vuln.severity.toLowerCase();
    const reachableClass = isReachable ? 'reachable' : '';

    let html = `
    <div class="vulnerability ${severityClass} ${reachableClass}">
      <div>
        <span class="badge badge-${severityClass}">${vuln.severity}</span>
        ${isReachable ? '<span class="badge badge-reachable">REACHABLE</span>' : ''}
      </div>
      <h3>${vuln.id}: ${vuln.title}</h3>
      <p><strong>Package:</strong> ${result.package}</p>
      <p><strong>CVSS:</strong> ${vuln.cvss}</p>
      <p>${vuln.description}</p>
    `;

    if (isReachable && reach.paths && reach.paths.length > 0) {
      html += '<div class="path"><strong>Reachable Path:</strong>';
      reach.paths[0].nodes.forEach((node, idx) => {
        const arrow = idx > 0 ? '->' : '';
        html += `<div class="path-node">${'  '.repeat(idx)}${arrow}${node}</div>`;
      });
      html += '</div>';
    }

    if (vuln.fixedVersion) {
      html += `<p><strong>Fix:</strong> Update to version ${vuln.fixedVersion} or higher</p>`;
    }

    html += '</div>';

    return html;
  }

  /**
   * Generates SARIF format (for CI/CD integration)
   */
  generateSARIF(results, metadata) {
    const sarif = {
      version: '2.1.0',
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs: [{
        tool: {
          driver: {
            name: 'DepGuard',
            version: '1.0.0',
            informationUri: 'https://github.com/owasp/depguard'
          }
        },
        results: results.map(r => ({
          ruleId: r.vulnerability.id,
          level: this.getSARIFLevel(r.vulnerability.severity),
          message: {
            text: `${r.vulnerability.title}: ${r.vulnerability.description}`
          },
          locations: [{
            physicalLocation: {
              artifactLocation: {
                uri: r.modulePath
              }
            }
          }],
          properties: {
            package: r.package,
            cvss: r.vulnerability.cvss,
            reachable: r.reachability && r.reachability.isReachable,
            reachabilityConfidence: r.reachability ? r.reachability.confidence : 0
          }
        }))
      }]
    };

    return JSON.stringify(sarif, null, 2);
  }

  /**
   * Generates Markdown format report
   */
  generateMarkdown(results, metadata) {
    const stats = this.calculateStatistics(results);

    let md = `# DepGuard Security Report\n\n`;
    md += `**Generated:** ${new Date().toISOString()}\n\n`;

    md += `## Summary\n\n`;
    md += `- **Total Vulnerabilities:** ${stats.totalVulnerabilities}\n`;
    md += `- **Reachable Vulnerabilities:** ${stats.reachableVulnerabilities}\n`;
    md += `- **Critical:** ${stats.critical}\n`;
    md += `- **High:** ${stats.high}\n`;
    md += `- **Medium:** ${stats.medium}\n`;
    md += `- **Low:** ${stats.low}\n\n`;

    md += `## Vulnerabilities\n\n`;

    results.forEach((r, idx) => {
      const vuln = r.vulnerability;
      const reach = r.reachability;

      md += `### ${idx + 1}. ${vuln.id}: ${vuln.title}\n\n`;
      md += `- **Package:** ${r.package}\n`;
      md += `- **Severity:** ${vuln.severity} (CVSS: ${vuln.cvss})\n`;
      md += `- **Reachable:** ${reach && reach.isReachable ? '[!] YES' : '[ ] NO'}\n`;

      if (reach && reach.isReachable) {
        md += `- **Confidence:** ${Math.round(reach.confidence * 100)}%\n`;
      }

      md += `\n${vuln.description}\n\n`;

      if (vuln.fixedVersion) {
        md += `**Fix:** Update to version ${vuln.fixedVersion} or higher\n\n`;
      }
    });

    return md;
  }

  /**
   * Calculates statistics from results
   */
  calculateStatistics(results) {
    return {
      totalDependencies: new Set(results.map(r => r.package)).size,
      totalVulnerabilities: results.length,
      reachableVulnerabilities: results.filter(r => r.reachability && r.reachability.isReachable).length,
      taintedVulnerabilities: results.filter(r => r.dataFlow && r.dataFlow.isTainted).length,
      mlPredicted: results.filter(r => r.mlPrediction).length,
      mlCritical: results.filter(r => r.mlPrediction && r.mlPrediction.riskLevel === 'CRITICAL').length,
      mlHigh: results.filter(r => r.mlPrediction && r.mlPrediction.riskLevel === 'HIGH').length,
      critical: results.filter(r => r.vulnerability.severity === 'CRITICAL').length,
      high: results.filter(r => r.vulnerability.severity === 'HIGH').length,
      medium: results.filter(r => r.vulnerability.severity === 'MEDIUM').length,
      low: results.filter(r => r.vulnerability.severity === 'LOW').length
    };
  }

  /**
   * Gets severity score for sorting
   */
  getSeverityScore(severity) {
    const scores = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    return scores[severity] || 0;
  }

  /**
   * Gets color for severity
   */
  getSeverityColor(severity) {
    const colors = {
      CRITICAL: chalk.red.bold,
      HIGH: chalk.red,
      MEDIUM: chalk.yellow,
      LOW: chalk.blue
    };
    return colors[severity] || chalk.white;
  }

  /**
   * Gets icon for severity
   */
  getSeverityIcon(severity) {
    const icons = {
      CRITICAL: '[CRIT]',
      HIGH: '[HIGH]',
      MEDIUM: '[MED]',
      LOW: '[LOW]'
    };
    return icons[severity] || '[ ]';
  }

  /**
   * Gets SARIF severity level
   */
  getSARIFLevel(severity) {
    const levels = {
      CRITICAL: 'error',
      HIGH: 'error',
      MEDIUM: 'warning',
      LOW: 'note'
    };
    return levels[severity] || 'warning';
  }

  /**
   * Saves report to file
   */
  saveToFile(content, filepath) {
    fs.writeFileSync(filepath, content, 'utf-8');
    console.log(chalk.green(`\n[OK] Report saved to: ${filepath}`));
  }
}

module.exports = Reporter;
