/**
 * DepGuard - Main Export
 * Advanced dependency vulnerability scanner with reachability analysis
 */

const DepGuardScanner = require('./DepGuardScanner');
const ReachabilityAnalyzer = require('./core/ReachabilityAnalyzer');
const VulnerabilityDatabase = require('./vulnerabilities/VulnerabilityDatabase');
const Reporter = require('./reporting/Reporter');

// Analyzers
const JavaScriptAnalyzer = require('./analyzers/JavaScriptAnalyzer');
const PythonAnalyzer = require('./analyzers/PythonAnalyzer');
const JavaAnalyzer = require('./analyzers/JavaAnalyzer');

module.exports = {
  DepGuardScanner,
  ReachabilityAnalyzer,
  VulnerabilityDatabase,
  Reporter,
  JavaScriptAnalyzer,
  PythonAnalyzer,
  JavaAnalyzer
};
