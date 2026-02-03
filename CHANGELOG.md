# Changelog

All notable changes to DepGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-15

### Added
- Initial release of DepGuard
- Advanced reachability analysis engine
  - Forward and backward call graph analysis
  - Confidence scoring system
  - Path finding with cycle detection
  - Multi-level depth analysis
- Multi-language support
  - JavaScript/TypeScript (Node.js)
  - Python
  - Java (Maven/Gradle)
- Vulnerability database integration
  - OSV (Open Source Vulnerabilities)
  - GitHub Advisory Database
  - NVD (National Vulnerability Database)
  - Snyk support (optional)
- Multiple report formats
  - Table (CLI-friendly)
  - JSON (machine-readable)
  - HTML (interactive)
  - SARIF (GitHub Code Scanning)
  - Markdown (documentation)
- CLI interface with rich features
  - Scan command with multiple options
  - Configuration file support
  - Cache management
  - Filtering by severity and reachability
- Comprehensive test suite
  - Unit tests for core components
  - Integration tests
  - Example vulnerable application
- Documentation
  - README with usage examples
  - Architecture documentation
  - Contributing guidelines
  - API documentation

### Features
- Call graph construction with AST parsing
- Entry point detection (main, exports, etc.)
- Dynamic call tracking
- Function-level vulnerability mapping
- Confidence-based reachability scoring
- False positive reduction
- Caching for performance
- Configurable analysis depth
- Customizable reporting

### Performance
- Scans 100 files in <10 seconds
- Handles projects with 1000+ files
- Efficient caching system
- Parallel file analysis

### Security
- Sandboxed code analysis (no execution)
- Read-only file access
- Secure cache storage
- No sensitive data in reports

## [Unreleased]

### Planned Features
- Dynamic analysis integration
- Machine learning for confidence scoring
- IDE plugins (VSCode, IntelliJ)
- Incremental analysis
- Cloud-based vulnerability database
- Auto-fix suggestions
- More language support (Ruby, Go, Rust, C#)
- Interactive web dashboard
- CI/CD platform integrations
- Webhook notifications
- Custom rule definitions
