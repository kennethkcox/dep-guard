# Security Policy

## Supported Versions

We actively support the following versions of DepGuard:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 2.0.x   | :white_check_mark: | Active development |
| < 2.0   | :x:                | No longer supported |

## Security in DepGuard

DepGuard is a security tool designed to help you find vulnerabilities in your dependencies. We take the security of DepGuard itself very seriously.

### Our Security Practices

1. **Dependency Management**
   - All production dependencies are regularly updated via Dependabot
   - We run DepGuard on itself to catch vulnerabilities early
   - Weekly automated security audits via GitHub Actions
   - Zero reachable vulnerabilities in production code

2. **Code Security**
   - Input validation on all user-provided data
   - Path traversal protection for file operations
   - Depth limiting to prevent infinite loops
   - HMAC verification for cache integrity
   - No execution of untrusted code

3. **Test Coverage**
   - 98 comprehensive tests covering security-critical paths
   - Automated testing on all pull requests
   - Security-focused test cases for edge conditions

### Intentionally Vulnerable Code

**Important:** The following directories contain *intentionally vulnerable* code for testing purposes:

- `examples/vulnerable-app/` - Simple vulnerable Node.js app
- `examples/vulnerable-test-app/` - Complex vulnerable test application

These are NOT part of the production DepGuard tool and should NEVER be deployed to production. They exist solely to demonstrate DepGuard's capabilities.

**Do not report vulnerabilities in these test applications** - they are vulnerable by design.

## Reporting a Vulnerability

If you discover a security vulnerability in DepGuard's *production code* (excluding test apps), please report it responsibly:

### Where to Report

**Email:** [cczine@gmail.com](mailto:cczine@gmail.com)

**Subject:** `[SECURITY] DepGuard Vulnerability Report`

### What to Include

Please include the following information:

1. **Description** - Clear description of the vulnerability
2. **Location** - Affected file(s) and line numbers
3. **Impact** - Potential security impact and severity
4. **Reproduction** - Steps to reproduce the issue
5. **Proof of Concept** - Example code or commands (if applicable)
6. **Suggested Fix** - Proposed solution (if you have one)
7. **Disclosure Timeline** - Your expectations for disclosure

### What to Expect

1. **Acknowledgment** - We'll acknowledge receipt within 48 hours
2. **Initial Assessment** - We'll assess severity and validity within 5 business days
3. **Updates** - We'll provide regular updates on progress
4. **Fix Timeline** - Critical issues will be fixed within 7 days, others within 30 days
5. **Credit** - We'll credit you in release notes (unless you prefer anonymity)
6. **Disclosure** - We'll coordinate disclosure timing with you

### Security Update Process

When we release security updates:

1. We'll publish a security advisory on GitHub
2. Release notes will include CVE numbers (if applicable)
3. Affected versions and remediation steps will be clearly documented
4. We'll notify users via GitHub release notes

## Dependency Vulnerabilities

DepGuard scans for vulnerabilities in dependencies. Here's our approach:

### Main Production Code

- **Target:** Zero reachable vulnerabilities
- **Policy:** All dependencies kept up-to-date
- **Updates:** Automated via Dependabot (weekly)
- **Testing:** All updates verified with 98-test suite

### Test Applications

- **Intentionally Vulnerable** - Test apps contain known vulnerabilities
- **Purpose:** Demonstrate DepGuard's detection capabilities
- **Policy:** These are NOT updated to remain vulnerable
- **Isolation:** Never used in production code paths

## Security-Related Configuration

### Secure Defaults

DepGuard ships with secure defaults:

```yaml
# Default security settings
security:
  maxFileSize: 50MB          # Prevent DoS via large files
  maxJsonSize: 10MB          # Limit JSON parsing memory
  maxDepth: 10               # Prevent infinite recursion
  maxTraversalDepth: 100     # Limit call graph traversal
  cacheIntegrity: true       # HMAC verification enabled
  pathValidation: true       # Path traversal protection
```

### Running Securely

Best practices when running DepGuard:

1. **Run in a isolated environment** for untrusted code
2. **Use read-only file access** when possible
3. **Limit network access** if scanning offline
4. **Review configuration** before scanning sensitive codebases
5. **Keep DepGuard updated** to latest version

## Known Limitations

### Static Analysis Limitations

DepGuard uses static analysis which has inherent limitations:

1. **Dynamic behavior** - Cannot detect runtime-only vulnerabilities
2. **Code generation** - May miss dynamically generated code
3. **External calls** - Cannot analyze code outside the scanned project
4. **False positives** - May report unreachable code paths

These are not security vulnerabilities in DepGuard itself, but limitations of the approach.

### API Rate Limits

DepGuard queries external vulnerability databases:

- **OSV API** - May be rate-limited
- **NVD API** - Requires API key for high volume
- **GitHub API** - Rate limited for unauthenticated requests

Rate limiting is not a security vulnerability.

## Compliance

### Data Privacy

DepGuard respects your privacy:

- **No telemetry** - We don't collect usage data
- **Local processing** - All analysis happens on your machine
- **No cloud uploads** - Your code never leaves your environment
- **Optional ML** - Machine learning is local and opt-in

### License Compliance

DepGuard is licensed under Apache-2.0:

- Free for commercial use
- No warranty provided
- See [LICENSE](./LICENSE) for full terms

## Questions?

For security questions or concerns:

- **Security issues:** [cczine@gmail.com](mailto:cczine@gmail.com)
- **General questions:** [GitHub Discussions](https://github.com/kennethkcox/dep-guard/discussions)
- **Bug reports:** [GitHub Issues](https://github.com/kennethkcox/dep-guard/issues)

---

**Last Updated:** February 4, 2026
**Version:** 2.0.0
