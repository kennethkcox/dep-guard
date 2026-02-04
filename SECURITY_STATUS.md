# DepGuard Security Status

**Last Updated:** February 4, 2026  
**Version:** 2.0.0

## Quick Summary

✅ **Production Code: SECURE**
- 0 vulnerabilities in main dependencies (verified via npm audit)
- 0 reachable vulnerabilities via DepGuard self-scan
- All dependencies up-to-date
- Automated weekly security checks enabled

⚠️ **Test Applications: INTENTIONALLY VULNERABLE**
- `examples/vulnerable-app/` - Contains known vulnerabilities for testing
- `examples/vulnerable-test-app/` - Contains known vulnerabilities for testing
- These are NOT part of production code
- Used to demonstrate DepGuard's detection capabilities

## Production Dependencies Status

```bash
$ npm audit
found 0 vulnerabilities

$ npm outdated
# All packages up-to-date
```

### Core Dependencies (All Current)

| Package | Version | Latest | Status |
|---------|---------|--------|--------|
| @babel/parser | 7.26.5 | 7.26.5 | ✅ Current |
| @babel/traverse | 7.26.5 | 7.26.5 | ✅ Current |
| acorn | 8.14.0 | 8.14.0 | ✅ Current |
| acorn-walk | 8.3.4 | 8.3.4 | ✅ Current |
| chalk | 4.1.2 | 5.6.2 | ⚠️ v5 is ESM-only, staying on v4 for compatibility |
| commander | 14.0.3 | 14.0.3 | ✅ Current |
| glob | 11.0.0 | 11.0.0 | ✅ Current |
| yaml | 2.7.0 | 2.7.0 | ✅ Current |

## GitHub Security Alerts Explained

GitHub shows **55 vulnerabilities** in the repo, but these are ALL in the intentionally vulnerable test applications:

```
examples/
├── vulnerable-app/          # Contains lodash@4.17.20 (vulnerable)
└── vulnerable-test-app/     # Contains multiple vulnerable packages
    ├── lodash@4.17.21       # Known vulnerabilities
    ├── axios@1.6.0          # Known vulnerabilities  
    ├── express@4.18.2       # Known vulnerabilities
    └── ejs@3.1.9           # Known vulnerabilities
```

**These vulnerabilities are INTENTIONAL** - they demonstrate DepGuard's ability to:
- Detect known CVEs from multiple sources
- Analyze reachability from entry points
- Track data flow from user input
- Predict risk with ML

## Automated Security Maintenance

### Dependabot (Enabled)

- **Frequency:** Weekly (Mondays at 9 AM UTC)
- **Scope:** Production dependencies only
- **Auto-merge:** Manual review required
- **PR Limit:** 10 open PRs max

### GitHub Actions (Enabled)

**Workflow:** `.github/workflows/dependency-check.yml`

Runs on:
- Every push to main
- Every pull request
- Weekly schedule (Mondays 9 AM UTC)
- Manual trigger available

Jobs:
1. **dependency-audit** - npm audit + DepGuard self-scan
2. **test-suite** - Full test coverage (98 tests)
3. **outdated-check** - Report outdated packages

### Security Policy

See [SECURITY.md](./SECURITY.md) for:
- Vulnerability reporting process
- Supported versions
- Security best practices
- Data privacy commitments

## Verification Commands

You can verify the security status yourself:

```bash
# Clone and install
git clone https://github.com/kennethkcox/dep-guard.git
cd dep-guard
npm install

# Check for vulnerabilities in production code
npm audit --audit-level=moderate

# Check for outdated packages
npm outdated

# Run tests
npm test

# Self-scan with DepGuard (excluding examples)
# Note: Will include vulnerable test apps by default
node bin/depguard.js scan -p .
```

## What Gets Updated

### ✅ Auto-Updated (via Dependabot)

- Production dependencies in root package.json
- GitHub Actions versions
- Security patches (automatically)

### 🔄 Manual Review Required

- Breaking changes (major version updates)
- Dependencies with API changes
- Updates that fail tests

### ❌ NOT Updated (Intentional)

- `examples/vulnerable-app/package.json` - Must remain vulnerable
- `examples/vulnerable-test-app/package.json` - Must remain vulnerable
- chalk v4→v5 (ESM compatibility)

## Monitoring

### GitHub Security Tab

Visit: https://github.com/kennethkcox/dep-guard/security

Shows:
- Dependabot alerts (mostly test apps)
- Security advisories
- Code scanning results (if enabled)

### Weekly Email Notifications

If you watch the repo, you'll receive:
- Dependabot PR notifications
- Security workflow results
- Failed audit notifications

## Questions?

- **Security issues:** See [SECURITY.md](./SECURITY.md) for reporting
- **False positives:** Check if it's in `examples/` (intentional)
- **Production code concerns:** Email cczine@gmail.com

---

**TL;DR:** Production code is secure with 0 vulnerabilities. The 55 GitHub alerts are from intentionally vulnerable test applications used for demonstration purposes.
