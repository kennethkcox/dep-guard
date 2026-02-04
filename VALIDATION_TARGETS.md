# DepGuard Validation Targets

## Interesting Open Source Projects to Scan

### Tier 1: High-Value Validation (Known Vulnerable Versions)

1. **express@4.17.1** (Web Framework)
   ```bash
   mkdir -p validation/express && cd validation/express
   npm init -y
   npm install express@4.17.1
   node ../../scripts/validate-against-npm-audit.js .
   ```
   - **Why:** Known CVEs in qs dependency (CVE-2022-24999)
   - **Tests:** Prototype pollution detection, middleware analysis
   - **Expected:** Should detect but mark as unreachable if not used

2. **axios@0.21.1** (HTTP Client)
   ```bash
   mkdir -p validation/axios && cd validation/axios
   npm init -y
   npm install axios@0.21.1
   node ../../scripts/validate-against-npm-audit.js .
   ```
   - **Why:** CVE-2021-3749 (SSRF vulnerability)
   - **Tests:** Data flow tracking for user input → HTTP requests
   - **Expected:** High confidence if user input flows to axios calls

3. **lodash@4.17.19** (Utility Library)
   ```bash
   mkdir -p validation/lodash && cd validation/lodash
   npm init -y
   npm install lodash@4.17.19
   node ../../scripts/validate-against-npm-audit.js .
   ```
   - **Why:** Multiple prototype pollution CVEs
   - **Tests:** Reachability of vulnerable functions (setWith, merge, etc.)
   - **Expected:** Should detect which lodash functions are actually called

4. **minimist@1.2.5** (Argument Parser)
   ```bash
   mkdir -p validation/minimist && cd validation/minimist
   npm init -y
   npm install minimist@1.2.5
   node ../../scripts/validate-against-npm-audit.js .
   ```
   - **Why:** CVE-2021-44906 (Prototype pollution)
   - **Tests:** Entry point detection, CLI argument flow
   - **Expected:** High risk if used in CLI tools

5. **moment@2.29.1** (Date Library)
   ```bash
   mkdir -p validation/moment && cd validation/moment
   npm init -y
   npm install moment@2.29.1
   node ../../scripts/validate-against-npm-audit.js .
   ```
   - **Why:** ReDoS vulnerabilities (CVE-2022-24785)
   - **Tests:** Regular expression analysis
   - **Expected:** Should detect regex issues

### Tier 2: Real-World Popular Projects

6. **next.js** (React Framework)
   ```bash
   git clone --depth 1 https://github.com/vercel/next.js.git validation/nextjs
   cd validation/nextjs
   npm install
   node ../../scripts/validate-against-npm-audit.js .
   ```
   - **Why:** Large dependency tree, production-grade
   - **Tests:** Scalability, performance with 1000+ dependencies
   - **Expected:** Long scan time, many transitive deps

7. **create-react-app** (Bootstrapping Tool)
   ```bash
   npx create-react-app validation/cra-test
   cd validation/cra-test
   node ../../scripts/validate-against-npm-audit.js .
   ```
   - **Why:** Common starting point for React apps
   - **Tests:** Bundler analysis (webpack), build tool deps
   - **Expected:** Many dev dependencies, few runtime vulns

8. **gatsby** (Static Site Generator)
   ```bash
   git clone --depth 1 https://github.com/gatsbyjs/gatsby.git validation/gatsby
   cd validation/gatsby
   npm install
   node ../../scripts/validate-against-npm-audit.js .
   ```
   - **Why:** GraphQL integration, complex build pipeline
   - **Tests:** Multi-package monorepo handling
   - **Expected:** Stress test for performance

### Tier 3: Security-Critical Applications

9. **passport** (Authentication Middleware)
   ```bash
   git clone --depth 1 https://github.com/jaredhanson/passport.git validation/passport
   cd validation/passport
   npm install
   node ../../scripts/validate-against-npm-audit.js .
   ```
   - **Why:** Security-critical authentication library
   - **Tests:** Crypto usage, session management
   - **Expected:** High-confidence needed for security issues

10. **jsonwebtoken** (JWT Implementation)
    ```bash
    git clone --depth 1 https://github.com/auth0/node-jsonwebtoken.git validation/jwt
    cd validation/jwt
    npm install
    node ../../scripts/validate-against-npm-audit.js .
    ```
    - **Why:** Critical for authentication security
    - **Tests:** Crypto vulnerabilities, algorithm confusion
    - **Expected:** Must catch security-critical issues

### Tier 4: Known Vulnerable Test Cases

11. **juice-shop** (OWASP Intentionally Vulnerable App)
    ```bash
    git clone --depth 1 https://github.com/juice-shop/juice-shop.git validation/juice-shop
    cd validation/juice-shop
    npm install
    node ../../scripts/validate-against-npm-audit.js .
    ```
    - **Why:** Intentionally vulnerable for security training
    - **Tests:** Should find MANY vulnerabilities
    - **Expected:** 100+ vulnerabilities, high reachability

12. **dvna** (Damn Vulnerable NodeJS Application)
    ```bash
    git clone --depth 1 https://github.com/appsecco/dvna.git validation/dvna
    cd validation/dvna
    npm install
    node ../../scripts/validate-against-npm-audit.js .
    ```
    - **Why:** Educational vulnerable app
    - **Tests:** SQL injection, XSS, command injection deps
    - **Expected:** High confidence for reachable vulns

## Validation Workflow

### Automated Testing Script

Create `scripts/run-all-validations.sh`:

```bash
#!/bin/bash

PROJECTS=(
  "express@4.17.1"
  "axios@0.21.1"
  "lodash@4.17.19"
  "minimist@1.2.5"
  "moment@2.29.1"
)

mkdir -p validation/results

for project in "${PROJECTS[@]}"; do
  name=$(echo $project | cut -d@ -f1)
  version=$(echo $project | cut -d@ -f2)

  echo "=================================================="
  echo "Testing: $project"
  echo "=================================================="

  mkdir -p validation/$name
  cd validation/$name

  # Create minimal package.json
  echo '{"name":"test","version":"1.0.0"}' > package.json
  npm install $project --save

  # Run validation
  node ../../scripts/validate-against-npm-audit.js . | tee ../../validation/results/$name.txt

  cd ../..
done

echo "=================================================="
echo "All validations complete!"
echo "Results saved in validation/results/"
echo "=================================================="
```

### Expected Outcomes

| Project | npm audit vulns | DepGuard vulns | Reachable | Reduction |
|---------|----------------|----------------|-----------|-----------|
| express@4.17.1 | 5-10 | 5-10 | 0-2 | 60-80% |
| axios@0.21.1 | 2-3 | 2-3 | 1-2 | 30-50% |
| lodash@4.17.19 | 3-5 | 3-5 | 0-1 | 70-90% |
| minimist@1.2.5 | 1-2 | 1-2 | 1-2 | 0-20% |
| moment@2.29.1 | 1-2 | 1-2 | 1-2 | 10-30% |

### Success Criteria

✅ **Precision:** >90% (minimal false positives)
✅ **Recall:** >85% (catch most vulnerabilities)
✅ **F1 Score:** >85% (balanced accuracy)
✅ **Reachability Reduction:** >40% (significant noise reduction)

### Failure Modes to Watch For

❌ **False Negatives:** Missing known CVEs
- Root cause: Vulnerability database incomplete
- Fix: Add more data sources (NVD, Snyk, etc.)

❌ **False Positives:** Flagging non-vulnerable code
- Root cause: Over-sensitive pattern matching
- Fix: Improve confidence scoring

❌ **Low Reachability Detection:** Not finding call chains
- Root cause: Static analysis limitations
- Fix: Enhance call graph construction

❌ **Performance Issues:** Scan taking >5 min on small projects
- Root cause: Inefficient algorithms
- Fix: Optimize hot paths, add caching

## How to Run Validation

### Quick Test (Single Project)
```bash
# Test on express
mkdir -p validation/express && cd validation/express
npm init -y
npm install express@4.17.1
node ../../scripts/validate-against-npm-audit.js .
```

### Full Validation Suite
```bash
# Run all Tier 1 validations
bash scripts/run-all-validations.sh

# View results
cat validation/results/*.txt
```

### Continuous Validation
Add to CI workflow to run validation on every push:

```yaml
- name: Validate against known vulnerable packages
  run: |
    bash scripts/run-all-validations.sh
    # Check if any validation failed
    if grep -r "FALSE NEGATIVES.*[1-9]" validation/results/; then
      echo "Warning: DepGuard missed some vulnerabilities"
    fi
```

## Real-World Case Studies

### Case Study 1: log4js (RCE Vulnerability)
- **CVE:** CVE-2022-21704
- **Package:** log4js@6.4.0
- **Test:** Does DepGuard detect deserialization RCE?
- **Expected:** High confidence if user input reaches log functions

### Case Study 2: node-serialize (RCE)
- **CVE:** CVE-2017-5941
- **Package:** node-serialize@0.0.4
- **Test:** Detect unserialize() with user input
- **Expected:** Data flow from tainted source to unserialize

### Case Study 3: marked (XSS)
- **CVE:** CVE-2022-21680
- **Package:** marked@4.0.10
- **Test:** Markdown parsing with user input
- **Expected:** Reachable if rendering user-provided markdown

## Next Steps

1. ✅ Create validation script (DONE)
2. ⏳ Run Tier 1 validations
3. ⏳ Analyze results and tune confidence thresholds
4. ⏳ Document findings in validation report
5. ⏳ Add continuous validation to CI
6. ⏳ Publish results as DepGuard accuracy benchmark

---

**Ready to validate?** Run:
```bash
chmod +x scripts/run-all-validations.sh
bash scripts/run-all-validations.sh
```
