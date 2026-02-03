# Contributing to DepGuard

Thank you for your interest in contributing to DepGuard! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/depguard.git`
3. Install dependencies: `npm install`
4. Create a branch: `git checkout -b feature/your-feature-name`

## Development Setup

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run linter
npm run lint

# Test CLI locally
node bin/depguard.js scan
```

## Code Style

- Use 2 spaces for indentation
- Use meaningful variable and function names
- Add JSDoc comments for public APIs
- Keep functions focused and small
- Write tests for new features

## Adding New Language Support

To add support for a new language:

1. Create a new analyzer in `src/analyzers/YourLanguageAnalyzer.js`
2. Implement the following methods:
   - `analyzeFile(filePath)` - Parse and analyze a single file
   - `analyzeProject(projectDir)` - Analyze entire project
   - `analyzeDependencies(projectDir)` - Extract dependency list
3. Register the analyzer in `src/DepGuardScanner.js`
4. Add tests in `tests/analyzers/`

## Adding New Vulnerability Sources

To integrate a new vulnerability database:

1. Add fetching logic to `src/vulnerabilities/VulnerabilityDatabase.js`
2. Implement `fetchFromYourSource(packageName, version)` method
3. Process and normalize vulnerability data
4. Add tests for the integration

## Improving Reachability Analysis

The reachability analyzer is the core of DepGuard. Improvements could include:

- Better handling of dynamic calls
- Support for reflection and eval
- Improved control flow analysis
- Inter-procedural analysis enhancements
- Context-sensitive analysis

## Testing

- Write unit tests for new features
- Ensure all tests pass before submitting PR
- Add integration tests for major features
- Test with real-world projects

## Documentation

- Update README.md if adding user-facing features
- Add JSDoc comments for new APIs
- Include examples in documentation
- Update CHANGELOG.md

## Pull Request Process

1. Update documentation
2. Add tests for new features
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Submit PR with clear description
6. Respond to review feedback

## Security

If you discover a security vulnerability, please email security@depguard.org instead of opening a public issue.

## License

By contributing to DepGuard, you agree that your contributions will be licensed under the Apache-2.0 License.

## Questions?

Open an issue or discussion on GitHub if you have questions!
