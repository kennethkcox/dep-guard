/**
 * Generic Entry Point Detector
 * Works with ANY framework, ANY structure
 * Uses heuristics and pattern matching, not hardcoded paths
 */

const fs = require('fs');
const path = require('path');
const { getLogger } = require('../utils/logger');
const Validator = require('../utils/validator');

class GenericEntryPointDetector {
  constructor(options = {}) {
    this.options = options;
    this.entryPoints = [];
    this.confidenceThreshold = options.confidenceThreshold || 0.6;
    this.logger = getLogger().child({ component: 'GenericEntryPointDetector' });
  }

  /**
   * Detect entry points across entire project
   * No assumptions about structure
   */
  detectEntryPoints(files, callGraph) {
    console.log(`\nDetecting entry points in ${files.length} files...`);

    files.forEach(file => {
      const signals = this.analyzeFile(file, callGraph);
      const confidence = this.calculateConfidence(signals);

      if (confidence >= this.confidenceThreshold) {
        this.entryPoints.push({
          file,
          signals,
          confidence,
          type: this.determineType(signals)
        });

        console.log(`  [OK] Entry point: ${path.basename(file)} (${Math.round(confidence * 100)}%)`);
        signals.forEach(s => console.log(`    - ${s.type}: ${s.reason}`));
      }
    });

    console.log(`\nFound ${this.entryPoints.length} entry points\n`);
    return this.entryPoints;
  }

  /**
   * Analyze a single file for entry point signals
   */
  analyzeFile(file, callGraph) {
    const signals = [];

    try {
      // Check if file exists
      if (!fs.existsSync(file)) {
        this.logger.debug('File does not exist, skipping', { file });
        return signals;
      }

      // Validate file size before reading (max 10MB for entry point analysis)
      Validator.validateFileSize(file, 10 * 1024 * 1024);

      const content = fs.readFileSync(file, 'utf-8');
      const basename = path.basename(file);
      const extension = path.extname(file);

    // Signal 1: HTTP Handler Signatures
    const httpSignal = this.detectHttpHandler(content, file);
    if (httpSignal) signals.push(httpSignal);

    // Signal 2: Main Function
    const mainSignal = this.detectMainFunction(content, file, basename);
    if (mainSignal) signals.push(mainSignal);

    // Signal 3: CLI Command Registration
    const cliSignal = this.detectCliCommand(content, file);
    if (cliSignal) signals.push(cliSignal);

    // Signal 4: Event/Message Handler
    const eventSignal = this.detectEventHandler(content, file);
    if (eventSignal) signals.push(eventSignal);

    // Signal 5: Exported from Package Entry
    const exportSignal = this.detectPackageExport(file, callGraph);
    if (exportSignal) signals.push(exportSignal);

    // Signal 6: Server/Application Initialization
    const serverSignal = this.detectServerInit(content, file);
    if (serverSignal) signals.push(serverSignal);

    // Signal 7: Test/Mock files (NEGATIVE signal)
    if (this.isTestFile(file, basename)) {
      signals.push({
        type: 'TEST_FILE',
        confidence: -0.8,
        reason: 'Test/spec file (not production entry point)'
      });
    }

      // Signal 8: No incoming calls (potential entry point)
      if (callGraph && callGraph.getIncomingCalls) {
        const incomingCalls = callGraph.getIncomingCalls(file);
        if (incomingCalls.length === 0 && signals.length > 0) {
          signals.push({
            type: 'NO_CALLERS',
            confidence: 0.3,
            reason: 'No internal callers (might be entry point)'
          });
        }
      }

      return signals;
    } catch (error) {
      this.logger.warn('Error analyzing file for entry points', {
        file,
        error: error.message
      });
      // Return empty signals array on error
      return signals;
    }
  }

  /**
   * Detect HTTP handler patterns (framework-agnostic)
   */
  detectHttpHandler(content, file) {
    const patterns = [
      // Express.js
      { regex: /app\.(get|post|put|delete|patch|all)\s*\(['"]/i, framework: 'Express', confidence: 0.95 },
      { regex: /router\.(get|post|put|delete|patch|all)\s*\(['"]/i, framework: 'Express Router', confidence: 0.95 },

      // Next.js App Router
      { regex: /export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(/i, framework: 'Next.js App Router', confidence: 0.98 },

      // Next.js Pages API
      { regex: /export\s+default\s+(async\s+)?function\s+handler\s*\(/i, framework: 'Next.js Pages', confidence: 0.90 },

      // Flask
      { regex: /@app\.route\s*\(/i, framework: 'Flask', confidence: 0.98 },
      { regex: /@blueprint\.route\s*\(/i, framework: 'Flask Blueprint', confidence: 0.95 },

      // FastAPI
      { regex: /@app\.(get|post|put|delete|patch)\s*\(/i, framework: 'FastAPI', confidence: 0.98 },
      { regex: /@router\.(get|post|put|delete|patch)\s*\(/i, framework: 'FastAPI Router', confidence: 0.95 },

      // Django
      { regex: /def\s+(get|post|put|delete|patch)\s*\([^)]*request/i, framework: 'Django CBV', confidence: 0.85 },

      // Spring Boot
      { regex: /@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)/i, framework: 'Spring Boot', confidence: 0.98 },
      { regex: /@RestController/i, framework: 'Spring Boot', confidence: 0.90 },

      // Gin (Go)
      { regex: /r\.(GET|POST|PUT|DELETE|PATCH)\s*\(/i, framework: 'Gin', confidence: 0.95 },

      // Echo (Go)
      { regex: /e\.(GET|POST|PUT|DELETE|PATCH)\s*\(/i, framework: 'Echo', confidence: 0.95 },

      // Koa
      { regex: /router\.(get|post|put|del|delete|patch)\s*\(/i, framework: 'Koa', confidence: 0.95 },

      // Hapi
      { regex: /server\.route\s*\(\s*\{[^}]*method\s*:\s*['"](GET|POST|PUT|DELETE|PATCH)/i, framework: 'Hapi', confidence: 0.95 },

      // Fastify
      { regex: /fastify\.(get|post|put|delete|patch)\s*\(/i, framework: 'Fastify', confidence: 0.95 },

      // Generic patterns (lower confidence)
      { regex: /function\s+handle(Request|Get|Post|Put|Delete|Patch)/i, framework: 'Generic HTTP Handler', confidence: 0.70 },
      { regex: /def\s+handle_(request|get|post|put|delete|patch)/i, framework: 'Generic HTTP Handler', confidence: 0.70 },
      { regex: /(Request|Response)Handler/i, framework: 'Generic Handler', confidence: 0.60 }
    ];

    for (const pattern of patterns) {
      if (pattern.regex.test(content)) {
        return {
          type: 'HTTP_HANDLER',
          confidence: pattern.confidence,
          reason: `${pattern.framework} HTTP handler detected`,
          framework: pattern.framework,
          evidence: content.match(pattern.regex)?.[0]
        };
      }
    }

    return null;
  }

  /**
   * Detect main function patterns (language-agnostic)
   */
  detectMainFunction(content, file, basename) {
    const patterns = [
      // JavaScript/TypeScript
      { regex: /if\s*\(\s*require\.main\s*===\s*module\s*\)/i, lang: 'JavaScript', confidence: 1.0 },
      { regex: /if\s*\(\s*import\.meta\.url\s*===.*\)/i, lang: 'JavaScript ESM', confidence: 1.0 },

      // Python
      { regex: /if\s+__name__\s*==\s*['"]__main__['"]/i, lang: 'Python', confidence: 1.0 },

      // Java
      { regex: /public\s+static\s+void\s+main\s*\(\s*String\s*\[\s*\]\s*args\s*\)/i, lang: 'Java', confidence: 1.0 },

      // Go
      { regex: /func\s+main\s*\(\s*\)\s*\{/i, lang: 'Go', confidence: 1.0 },

      // Rust
      { regex: /fn\s+main\s*\(\s*\)\s*(->\s*\w+\s*)?\{/i, lang: 'Rust', confidence: 1.0 },

      // C/C++
      { regex: /int\s+main\s*\(/i, lang: 'C/C++', confidence: 1.0 },

      // Ruby
      { regex: /if\s+__FILE__\s*==\s*\$0/i, lang: 'Ruby', confidence: 1.0 },

      // PHP
      { regex: /if\s*\(\s*__FILE__\s*==\s*realpath\(\$_SERVER\['SCRIPT_FILENAME'\]\)\s*\)/i, lang: 'PHP', confidence: 1.0 }
    ];

    for (const pattern of patterns) {
      if (pattern.regex.test(content)) {
        return {
          type: 'MAIN_FUNCTION',
          confidence: pattern.confidence,
          reason: `${pattern.lang} main entry point detected`,
          language: pattern.lang
        };
      }
    }

    // Also check filename
    if (['main.js', 'main.ts', 'main.py', 'main.go', 'main.rs', 'Main.java'].includes(basename)) {
      return {
        type: 'MAIN_FUNCTION',
        confidence: 0.8,
        reason: 'Main entry point file (by filename)',
        evidence: `Filename: ${basename}`
      };
    }

    return null;
  }

  /**
   * Detect CLI command registration (framework-agnostic)
   */
  detectCliCommand(content, file) {
    const patterns = [
      // Commander.js
      { regex: /program\.(command|action)\s*\(/i, framework: 'Commander.js', confidence: 0.95 },

      // Yargs
      { regex: /yargs\.(command|builder)\s*\(/i, framework: 'Yargs', confidence: 0.95 },

      // Click (Python)
      { regex: /@click\.(command|group)\s*\(/i, framework: 'Click', confidence: 0.98 },

      // Argparse (Python)
      { regex: /ArgumentParser\s*\(\s*\)/i, framework: 'Argparse', confidence: 0.85 },

      // Cobra (Go)
      { regex: /cobra\.Command\s*\{/i, framework: 'Cobra', confidence: 0.95 },

      // Clap (Rust)
      { regex: /Command::new\s*\(/i, framework: 'Clap', confidence: 0.95 }
    ];

    for (const pattern of patterns) {
      if (pattern.regex.test(content)) {
        return {
          type: 'CLI_COMMAND',
          confidence: pattern.confidence,
          reason: `${pattern.framework} CLI command detected`,
          framework: pattern.framework
        };
      }
    }

    return null;
  }

  /**
   * Detect event/message handlers
   */
  detectEventHandler(content, file) {
    const patterns = [
      // EventEmitter
      { regex: /\.(on|addListener)\s*\(\s*['"`][\w-]+['"`]/i, framework: 'EventEmitter', confidence: 0.75 },

      // WebSocket
      { regex: /ws\.(on|onmessage)\s*\(/i, framework: 'WebSocket', confidence: 0.85 },
      { regex: /socket\.on\s*\(\s*['"`](message|data)['"`]/i, framework: 'WebSocket', confidence: 0.85 },

      // Message Queues
      { regex: /@RabbitListener/i, framework: 'RabbitMQ', confidence: 0.95 },
      { regex: /@KafkaListener/i, framework: 'Kafka', confidence: 0.95 },
      { regex: /@SqsListener/i, framework: 'AWS SQS', confidence: 0.95 },
      { regex: /\.subscribe\s*\(\s*['"`][\w-]+['"`]/i, framework: 'PubSub', confidence: 0.80 },
      { regex: /\.consume\s*\(/i, framework: 'Message Queue', confidence: 0.80 },

      // GraphQL
      { regex: /@Resolver\s*\(/i, framework: 'GraphQL', confidence: 0.90 },
      { regex: /@Query\s*\(/i, framework: 'GraphQL', confidence: 0.90 },
      { regex: /@Mutation\s*\(/i, framework: 'GraphQL', confidence: 0.90 }
    ];

    for (const pattern of patterns) {
      if (pattern.regex.test(content)) {
        return {
          type: 'EVENT_HANDLER',
          confidence: pattern.confidence,
          reason: `${pattern.framework} event handler detected`,
          framework: pattern.framework
        };
      }
    }

    return null;
  }

  /**
   * Detect server/application initialization
   */
  detectServerInit(content, file) {
    const patterns = [
      { regex: /app\.listen\s*\(/i, framework: 'Express/Node.js Server', confidence: 0.90 },
      { regex: /server\.listen\s*\(/i, framework: 'Node.js Server', confidence: 0.90 },
      { regex: /\.run\s*\(\s*host\s*=/i, framework: 'Flask/FastAPI Server', confidence: 0.90 },
      { regex: /@SpringBootApplication/i, framework: 'Spring Boot', confidence: 0.95 },
      { regex: /http\.ListenAndServe\s*\(/i, framework: 'Go HTTP Server', confidence: 0.95 }
    ];

    for (const pattern of patterns) {
      if (pattern.regex.test(content)) {
        return {
          type: 'SERVER_INIT',
          confidence: pattern.confidence,
          reason: `${pattern.framework} initialization detected`,
          framework: pattern.framework
        };
      }
    }

    return null;
  }

  /**
   * Detect if file is exported from package entry
   */
  detectPackageExport(file, callGraph) {
    // Check if this file is reachable from package.json "main" or "exports"
    if (!callGraph || !callGraph.isReachableFromPackageEntry) {
      return null;
    }

    if (callGraph.isReachableFromPackageEntry(file)) {
      return {
        type: 'PACKAGE_EXPORT',
        confidence: 0.85,
        reason: 'Exported from package entry point'
      };
    }

    return null;
  }

  /**
   * Check if file is a test/spec file (negative signal)
   */
  isTestFile(file, basename) {
    const testPatterns = [
      /\.test\.(js|ts|jsx|tsx|py|java|go|rs)$/i,
      /\.spec\.(js|ts|jsx|tsx|py|java|go|rs)$/i,
      /_test\.(js|ts|jsx|tsx|py|java|go|rs)$/i,
      /test_.*\.(py|rb)$/i,
      /.*Test\.java$/i,
      /__tests__/i,
      /\/test\//i,
      /\/tests\//i,
      /\/spec\//i
    ];

    return testPatterns.some(pattern => pattern.test(file));
  }

  /**
   * Calculate overall confidence from signals
   */
  calculateConfidence(signals) {
    if (signals.length === 0) return 0;

    // Start with average
    let confidence = signals.reduce((sum, s) => sum + s.confidence, 0) / signals.length;

    // Boost for multiple strong signals
    const strongSignals = signals.filter(s => s.confidence > 0.8);
    if (strongSignals.length >= 2) {
      confidence = Math.min(1.0, confidence + 0.1);
    }

    // Penalize for negative signals
    const negativeSignals = signals.filter(s => s.confidence < 0);
    if (negativeSignals.length > 0) {
      confidence = Math.max(0, confidence + negativeSignals[0].confidence);
    }

    return confidence;
  }

  /**
   * Determine primary type from signals
   */
  determineType(signals) {
    if (signals.length === 0) return 'UNKNOWN';

    // Return the signal type with highest confidence
    const sorted = signals.sort((a, b) => b.confidence - a.confidence);
    return sorted[0].type;
  }

  /**
   * Get all detected entry points
   */
  getEntryPoints() {
    return this.entryPoints;
  }

  /**
   * Get entry points by type
   */
  getEntryPointsByType(type) {
    return this.entryPoints.filter(ep => ep.type === type);
  }

  /**
   * Get high-confidence entry points only
   */
  getHighConfidenceEntryPoints(threshold = 0.8) {
    return this.entryPoints.filter(ep => ep.confidence >= threshold);
  }
}

module.exports = GenericEntryPointDetector;
