/**
 * Configuration Constants
 * Central location for all configurable constants used throughout DepGuard
 */

module.exports = {
  // File processing limits
  FILE: {
    MAX_SIZE: 50 * 1024 * 1024,       // 50MB - Maximum file size to process
    MAX_JSON_SIZE: 10 * 1024 * 1024,  // 10MB - Maximum JSON content size
    MAX_DEPENDENCIES: 10000,           // Maximum dependencies per manifest
  },

  // Analysis configuration
  ANALYSIS: {
    MAX_DEPTH_DEFAULT: 10,            // Default call graph traversal depth
    MAX_TRAVERSAL_DEPTH: 100,         // Maximum graph traversal (prevent infinite loops)
    MIN_CONFIDENCE_DEFAULT: 0.5,      // Default minimum confidence threshold
    ENTRY_POINT_CONFIDENCE: 0.6,      // Default entry point confidence threshold
  },

  // Reachability analysis confidence scores
  CONFIDENCE: {
    IMPORT_BASE: 0.6,                 // Base confidence for import-based detection
    IMPORT_MULTIPLE_BOOST: 0.05,      // Boost per additional import
    IMPORT_MAX: 0.85,                 // Maximum confidence for import-based detection
    DIRECT_CALL: 1.0,                 // Direct function call confidence
    DYNAMIC_CALL: 0.7,                // Dynamic call confidence
    BACKWARD_ANALYSIS: 0.8,           // Backward analysis confidence penalty
    LENGTH_PENALTY_FACTOR: 0.95,      // Path length confidence penalty per hop
    SHORT_PATH_BOOST: 1.1,            // Boost for paths <= 3 hops
  },

  // Data flow analysis
  DATA_FLOW: {
    TAINT_CONFIDENCE_THRESHOLD: 0.6,  // Minimum confidence to consider tainted
    CONFIDENCE_BOOST: 0.3,            // Boost to add when taint path found
    MAX_ENHANCED_CONFIDENCE: 0.98,    // Maximum final confidence score
  },

  // API configuration
  API: {
    TIMEOUT_MS: 30000,                // Default API timeout (30 seconds)
    OSV_BATCH_SIZE: 20,               // OSV API batch size
    MAX_RETRIES: 3,                   // Maximum retry attempts
    RETRY_DELAY_MS: 1000,             // Initial retry delay
    RETRY_BACKOFF_MULTIPLIER: 2,      // Exponential backoff multiplier
  },

  // Performance tuning
  PERFORMANCE: {
    CACHE_SIZE_LIMIT: 1000,           // Maximum cache entries
    PROGRESS_UPDATE_INTERVAL: 10,     // Update progress every N files
    PARALLEL_ANALYSIS_LIMIT: 4,       // Maximum parallel analyzers
  },

  // Path constants
  PATHS: {
    NODE_MODULES: 'node_modules',
    CACHE_DIR: '.depguard-cache',
    FEEDBACK_DIR: '.depguard-feedback',
  },

  // Ecosystem identifiers
  ECOSYSTEMS: {
    NPM: 'npm',
    PYPI: 'pypi',
    MAVEN: 'maven',
    GO: 'go',
    CARGO: 'cargo',
    RUBYGEMS: 'rubygems',
    PACKAGIST: 'packagist',
    NUGET: 'nuget',
    PUB: 'pub',
  },

  // Call types
  CALL_TYPES: {
    DIRECT: 'direct',
    DYNAMIC: 'dynamic',
    DIRECT_METHOD: 'direct-method',
  },

  // Output formats
  OUTPUT_FORMATS: ['table', 'json', 'html', 'sarif', 'markdown'],

  // Severity levels
  SEVERITY_LEVELS: ['critical', 'high', 'medium', 'low'],

  // Exclude patterns for file scanning
  EXCLUDE_PATTERNS: [
    'node_modules',
    '.git',
    '.svn',
    '.hg',
    'dist',
    'build',
    'target',
    'out',
    'bin',
    'obj',
    '.next',
    '.nuxt',
    'coverage',
    '__pycache__',
    '.pytest_cache',
    '.tox',
    'venv',
    'env',
    '.env',
    '.venv',
  ],

  // Supported file extensions by language
  EXTENSIONS: {
    JAVASCRIPT: ['.js', '.jsx', '.mjs', '.cjs'],
    TYPESCRIPT: ['.ts', '.tsx'],
    PYTHON: ['.py'],
    JAVA: ['.java'],
    GO: ['.go'],
    RUST: ['.rs'],
    RUBY: ['.rb'],
    PHP: ['.php'],
    CSHARP: ['.cs'],
  },

  // Manifest file names
  MANIFESTS: {
    NPM: ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
    PYTHON: ['requirements.txt', 'Pipfile', 'Pipfile.lock', 'pyproject.toml', 'setup.py'],
    JAVA: ['pom.xml', 'build.gradle', 'build.gradle.kts', 'gradle.properties'],
    GO: ['go.mod', 'go.sum'],
    RUST: ['Cargo.toml', 'Cargo.lock'],
    RUBY: ['Gemfile', 'Gemfile.lock'],
    PHP: ['composer.json', 'composer.lock'],
    NUGET: ['*.csproj', 'packages.config', '*.nuspec'],
    DART: ['pubspec.yaml', 'pubspec.lock'],
  },
};
