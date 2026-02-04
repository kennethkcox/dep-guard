# Automated Security & Maintenance

## Overview

DepGuard implements comprehensive automated security checks to ensure the production codebase remains vulnerability-free while demonstrating its own scanning capabilities.

## Current Status

### Production Code: ✅ SECURE
- **Vulnerabilities:** 0 (verified via npm audit + DepGuard self-scan)
- **Dependencies:** All up-to-date
- **Tests:** 98 passing on Node 18, 20, 22
- **Last Updated:** February 4, 2026

### Test Applications: ⚠️ INTENTIONALLY VULNERABLE
- Contains known CVEs for demonstration
- Excluded from production security scans
- Used to prove DepGuard's detection capabilities

## Automated Workflows

### 1. Security Check Workflow (`.github/workflows/security.yml`)

Comprehensive 6-job pipeline that runs on:
- Every push to `main` branch
- Every pull request
- Weekly schedule (Mondays 9 AM UTC)
- Manual trigger via GitHub UI

#### Job Breakdown:

**Job 1: Production Security Audit**
```bash
# What it does:
- npm audit --production
- DepGuard scan excluding examples/
- Filter results to production code only
- Report 0 reachable vulnerabilities
- Upload 90-day artifact reports
- Comment on PRs with results
```

**Job 2: Test Suite (Matrix)**
```bash
# What it does:
- Run 98 tests on Node 18, 20, 22
- Generate coverage reports
- Verify >70% coverage target
- Ensure cross-version compatibility
```

**Job 3: Dependency Health**
```bash
# What it does:
- Check for outdated packages
- Analyze licenses
- Report bundle sizes
- Provide update recommendations
```

**Job 4: Code Quality**
```bash
# What it does:
- Run ESLint checks
- Scan for TODO/FIXME comments
- Report code statistics
- Enforce quality standards
```

**Job 5: Full Repository Scan**
```bash
# What it does:
- Scan entire repo (including test apps)
- Demonstrate DepGuard's capabilities
- Label as including intentional vulnerabilities
- Provide comparison baseline
```

**Job 6: Security Summary**
```bash
# What it does:
- Aggregate all job results
- Generate final pass/fail status
- Create GitHub summary
- Link to detailed reports
```

### 2. Dependency Updates (`.github/dependabot.yml`)

Automated dependency updates:

**Schedule:** Weekly (Mondays 9 AM UTC)

**Scope:**
- ✅ Production dependencies in root `package.json`
- ✅ GitHub Actions versions
- ✅ Security patches (automatic)
- ❌ Test app dependencies (intentionally vulnerable)

**Configuration:**
```yaml
- Grouped updates (Babel packages together)
- Max 10 open PRs
- Labeled: dependencies, automated
- Excludes chalk v4→v5 (ESM compatibility)
```

## How It Works

### Production Code Isolation

The workflow uses filtering to separate production from test code:

```javascript
// Filter production vulnerabilities only
const prodVulns = results.filter(r => 
  !r.vulnerability.package.startsWith('examples/')
);
```

This ensures test app vulnerabilities don't pollute production security metrics.

### Automated PR Comments

When you open a PR, the workflow automatically:

1. Scans changed code
2. Runs full test suite
3. Checks for new vulnerabilities
4. Posts results as PR comment:

```markdown
## 🛡️ DepGuard Security Scan Results

**Production Code Analysis:**
- Total vulnerabilities found: 0
- Reachable vulnerabilities: 0
- Status: ✅ Secure

📊 View detailed report in artifacts
```

### GitHub Summaries

Each workflow run generates a rich markdown summary showing:

- Vulnerability counts by severity
- Test results and coverage
- Outdated package recommendations
- Final security status

Accessible at: Actions → Select Run → Summary tab

## Trust & Verification

### Public Transparency

All workflow results are publicly visible:

**View Live Results:**
1. Visit https://github.com/kennethkcox/dep-guard/actions
2. Click "Security & Quality Checks"
3. View latest run
4. Download artifacts for detailed reports

### Artifacts Available

Each run uploads:

| Artifact | Retention | Content |
|----------|-----------|---------|
| `depguard-production-report` | 90 days | Production code scan (JSON) |
| `depguard-full-report` | 30 days | Full repo scan (JSON) |
| `test-coverage` | 30 days | Code coverage reports |

### Verification Commands

Anyone can verify the results:

```bash
# Clone and scan
git clone https://github.com/kennethkcox/dep-guard.git
cd dep-guard
npm install

# Verify no vulnerabilities in production
npm audit --production

# Run DepGuard self-scan
node bin/depguard.js scan -p .

# Run tests
npm test

# Check outdated
npm outdated
```

## Maintenance Schedule

### Automated (No Manual Intervention)

- **Weekly:** Dependency security checks
- **Weekly:** Outdated package reports
- **On PR:** Full security scan + tests
- **On Push:** Security validation

### Manual Review Required

- **Dependabot PRs:** Review and merge updates
- **Failed Checks:** Investigate and fix issues
- **Coverage Drops:** Add tests if coverage falls

## What Gets Updated

### ✅ Automatically Updated

Production dependencies:
- `@babel/parser`, `@babel/traverse`
- `acorn`, `acorn-walk`
- `commander`
- `glob`
- `yaml`

DevDependencies:
- `eslint`
- `jest`

GitHub Actions:
- `actions/checkout`
- `actions/setup-node`
- `actions/upload-artifact`

### 🔄 Manual Review

- Breaking changes (major versions)
- Dependencies with API changes
- Updates that fail tests
- `chalk` v4→v5 (ESM compatibility)

### ❌ Never Updated

- `examples/vulnerable-app/package.json`
- `examples/vulnerable-test-app/package.json`

These MUST remain vulnerable for testing.

## Security Guarantees

### What We Promise

1. **Zero Production Vulnerabilities**
   - Automated weekly audits
   - DepGuard self-scanning
   - npm audit validation
   - All checks must pass

2. **Test Coverage >70%**
   - 98 comprehensive tests
   - Critical paths covered
   - Edge cases validated
   - Security-focused tests

3. **Multi-Version Support**
   - Node 18, 20, 22 tested
   - Backward compatibility
   - Forward compatibility
   - LTS version support

4. **Weekly Security Audits**
   - Scheduled Monday 9 AM UTC
   - Dependabot updates
   - Automated scanning
   - Email notifications

### What We DON'T Promise

1. **Zero Vulnerabilities in Test Apps**
   - They're intentionally vulnerable
   - Used for demonstration
   - Never deployed to production
   - Clearly documented

2. **Instant Updates**
   - Weekly schedule (not daily)
   - Manual review for breaking changes
   - Test validation required
   - Measured approach

3. **100% Test Coverage**
   - Target is >70%
   - Critical paths prioritized
   - Diminishing returns above 70%
   - Quality over quantity

## Monitoring & Alerts

### GitHub Notifications

You'll be notified of:
- Dependabot PRs (weekly)
- Failed security checks (immediate)
- Weekly audit results (Monday)
- PR scan results (on PR)

### Where to Check

1. **Actions Tab:** Live workflow results
2. **Security Tab:** Dependabot alerts
3. **PR Comments:** Automated scan results
4. **Email:** Workflow failures

## Questions?

### Common Questions

**Q: Why does GitHub show 55 vulnerabilities?**
A: Those are in intentionally vulnerable test apps (`examples/`). Production code has 0 vulnerabilities.

**Q: How do I run the same checks locally?**
A: `npm audit --production && npm test && node bin/depguard.js scan -p .`

**Q: What if a check fails?**
A: The PR will be blocked until fixed. Check the workflow logs for details.

**Q: Can I trigger checks manually?**
A: Yes! Go to Actions → Security & Quality Checks → Run workflow

**Q: How often are dependencies updated?**
A: Weekly via Dependabot (Mondays 9 AM UTC)

### Need Help?

- **Security issues:** See [SECURITY.md](./SECURITY.md)
- **CI/CD questions:** Open a GitHub Discussion
- **Bug reports:** Open a GitHub Issue
- **Urgent security:** Email cczine@gmail.com

---

**Last Updated:** February 4, 2026  
**Workflow Version:** 1.0  
**Status:** ✅ All systems operational
