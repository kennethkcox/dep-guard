## Comprehensive Threat Intelligence Integration

DepGuard now integrates **5 major threat intelligence sources** to provide the most comprehensive vulnerability detection and prioritization available in open-source scanners.

## Threat Intelligence Sources

### 1. OSV (Open Source Vulnerabilities) - PRIMARY
**Status**: ✅ Enabled by default
**API**: https://osv.dev
**Coverage**: Comprehensive open-source vulnerability database

**What It Provides**:
- Vulnerabilities for npm, PyPI, Maven, Go, and more
- Affected versions and version ranges
- Affected functions (when available)
- CVE and GHSA mappings

**Reliability**: ⭐⭐⭐⭐ Good
**Strengths**: Fast, free, comprehensive, actively maintained
**Limitations**: May miss some vendor-specific advisories

### 2. NVD (National Vulnerability Database)
**Status**: ⚠️ Optional (disabled by default due to rate limits)
**API**: https://nvd.nist.gov
**Coverage**: Official US government vulnerability database

**What It Provides**:
- Official CVE data with CVSS scores
- CPE (Common Platform Enumeration) matching
- CWE (Common Weakness Enumeration)
- Detailed vulnerability descriptions
- CVSS v2, v3.0, and v3.1 metrics

**Reliability**: ⭐⭐⭐⭐⭐ Excellent (authoritative source)
**Strengths**: Authoritative, detailed CVSS metrics, comprehensive
**Limitations**: Rate limited (5 req/30s without key), may lag on new CVEs

**Configuration**:
```bash
# Get API key from https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="your-api-key-here"

# Enable in scan
depguard scan --enable-nvd
```

### 3. GitHub Security Advisory Database
**Status**: ⚠️ Optional (requires GitHub token)
**API**: https://github.com/advisories
**Coverage**: GitHub's curated security advisories

**What It Provides**:
- GHSA (GitHub Security Advisory) IDs
- Package-specific advisories
- CVSS scores and severity ratings
- Vulnerable version ranges
- First patched versions
- CWE classifications

**Reliability**: ⭐⭐⭐⭐⭐ Excellent
**Strengths**: Fast updates, package ecosystem focus, well-maintained
**Limitations**: Requires GitHub token for reasonable rate limits

**Configuration**:
```bash
# Create token at https://github.com/settings/tokens
# Needs: public_repo, read:packages scopes
export GITHUB_TOKEN="your-token-here"

# Enable in scan
depguard scan --enable-github
```

### 4. EPSS (Exploit Prediction Scoring System) - ENRICHMENT
**Status**: ✅ Enabled by default
**API**: https://api.first.org/data/v1/epss
**Provider**: FIRST.org

**What It Provides**:
- **Probability** (0-1) that a CVE will be exploited in next 30 days
- **Percentile** (0-100) compared to all CVEs
- Predictions based on real-world exploitation data

**How It Helps**:
```
Without EPSS:
CVE-2023-1234: CVSS 9.8 (CRITICAL)
CVE-2023-5678: CVSS 9.8 (CRITICAL)
→ Which to patch first? Both look equally critical!

With EPSS:
CVE-2023-1234: CVSS 9.8, EPSS 0.85 (85% exploit probability)
CVE-2023-5678: CVSS 9.8, EPSS 0.02 (2% exploit probability)
→ Clear: Fix CVE-2023-1234 first!
```

**Reliability**: ⭐⭐⭐⭐ Very Good
**Strengths**: Data-driven prioritization, daily updates, free
**Limitations**: CVE-only (no GHSA support)

**EPSS Interpretation**:
| EPSS Score | Risk Level | Recommendation |
|------------|------------|----------------|
| 0.75+ | CRITICAL | Patch immediately - very high exploit probability |
| 0.50-0.74 | HIGH | Patch within 7 days - high exploit probability |
| 0.25-0.49 | MEDIUM | Patch within 30 days - moderate probability |
| 0.10-0.24 | LOW | Standard patching schedule |
| <0.10 | VERY LOW | Monitor, standard schedule |

### 5. CISA KEV (Known Exploited Vulnerabilities) - CRITICAL INDICATOR
**Status**: ✅ Enabled by default
**Source**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
**Provider**: US CISA (Cybersecurity & Infrastructure Security Agency)

**What It Provides**:
- **Confirmed** real-world exploitation
- Due dates for federal agency remediation
- Known ransomware campaign usage
- Required remediation actions

**How It Helps**:
```
Regular Vulnerability:
CVE-2021-12345: Found in package, CVSS 7.5

KEV-Listed Vulnerability:
CVE-2021-44228 (Log4Shell): CONFIRMED EXPLOITATION IN THE WILD
- Added to KEV: 2021-12-10
- Due Date: 2021-12-24
- Known Ransomware Use: YES
- Required Action: Apply updates per vendor instructions
→ IMMEDIATE ACTION REQUIRED!
```

**Reliability**: ⭐⭐⭐⭐⭐ Excellent (authoritative)
**Strengths**: Confirmed exploitation, actionable, authoritative
**Limitations**: Only includes actively exploited CVEs (smaller catalog)

**KEV Statistics**:
- ~1,000 actively exploited vulnerabilities tracked
- Updated regularly as new exploits emerge
- Includes ransomware campaign indicators

## Multi-Source Architecture

### Query Strategy

```
┌─────────────────────────────────────────────────┐
│         Package: lodash@4.17.20                │
└─────────────────┬───────────────────────────────┘
                  │
       ┌──────────┼──────────┬──────────┐
       │          │          │          │
   ┌───▼───┐  ┌──▼───┐  ┌───▼────┐  ┌─▼──┐
   │  OSV  │  │ NVD  │  │ GitHub │  │... │
   │       │  │(opt) │  │ (opt)  │  │    │
   └───┬───┘  └──┬───┘  └───┬────┘  └─┬──┘
       │         │          │          │
       └─────────┼──────────┴──────────┘
                 │
          ┌──────▼────────┐
          │ Merge & Dedupe│
          │  (by CVE ID)  │
          └──────┬────────┘
                 │
       ┌─────────┼─────────┐
       │                   │
   ┌───▼────┐       ┌──────▼─────┐
   │  EPSS  │       │  CISA KEV  │
   │Enrich  │       │   Check    │
   └───┬────┘       └──────┬─────┘
       │                   │
       └─────────┬─────────┘
                 │
        ┌────────▼─────────┐
        │  Enriched Result │
        │  - Vulnerability │
        │  - EPSS Score    │
        │  - KEV Status    │
        │  - Prioritization│
        └──────────────────┘
```

### Deduplication

When multiple sources report the same vulnerability:
1. Merge by CVE/GHSA ID
2. Prefer more detailed descriptions
3. Keep all unique references
4. Use highest severity rating
5. Track all sources for transparency

**Example**:
```json
{
  "id": "CVE-2021-23337",
  "sources": ["OSV", "GitHub", "NVD"],
  "package": "lodash",
  "severity": "HIGH",
  "cvss": {
    "score": 7.2,
    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
  },
  "epss": {
    "score": 0.12,
    "percentile": 85.3,
    "risk": "LOW"
  },
  "kev": {
    "isKnownExploited": false
  }
}
```

## Enriched Output Format

### Complete Vulnerability Report

```
[CRITICAL] 🔴 CVE-2021-44228 - Remote Code Execution in log4j

Package: org.apache.logging.log4j:log4j-core@2.14.1
Severity: CRITICAL (CVSS 10.0)
Sources: OSV, NVD, GitHub Advisory

🎯 EPSS Score: 0.97 (97th percentile)
   → CRITICAL: Very high probability of exploitation
   → Recommendation: URGENT - Patch immediately

⚠️  CISA KEV: CONFIRMED EXPLOITATION IN THE WILD
   → Added to KEV: 2021-12-10
   → Due Date: 2021-12-24
   → Ransomware Use: YES
   → Required Action: Apply updates per vendor instructions

Reachable Path:
  src/server.js:createLogger
  → logger/LogManager.js:getLogger
  → log4j-core.jar:LogManager.getLogger()

Fix: Upgrade to log4j-core@2.17.1

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
  - https://www.lunasec.io/docs/blog/log4j-zero-day/
  - https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
```

## Configuration Options

### Environment Variables

```bash
# NVD API (optional, for rate limit increase)
export NVD_API_KEY="your-key"

# GitHub token (optional, for GitHub Advisory access)
export GITHUB_TOKEN="your-token"
```

### CLI Flags

```bash
# Enable all sources
depguard scan --enable-nvd --enable-github

# Disable EPSS enrichment
depguard scan --disable-epss

# Disable KEV checking
depguard scan --disable-kev

# Disable OSV (not recommended)
depguard scan --disable-osv
```

### Configuration File (`.depguard.yml`)

```yaml
vulnerability:
  sources:
    osv: true              # Primary source
    nvd: true              # Enable NVD (requires API key)
    github: true           # Enable GitHub (requires token)

  enrichment:
    epss: true             # Enable EPSS scoring
    kev: true              # Enable KEV checking

  priority:
    # Prioritize vulnerabilities in KEV
    kevFirst: true
    # Then by EPSS score
    epssThreshold: 0.10    # Only show EPSS > 10%
    # Then by CVSS
    cvssThreshold: 7.0
```

## Prioritization Logic

### How DepGuard Prioritizes Findings

```
Priority 1: KEV-Listed (Confirmed Exploitation)
  ├─ In CISA KEV catalog
  ├─ Due date approaching
  └─ Ransomware campaign usage

Priority 2: High EPSS + High CVSS
  ├─ EPSS > 0.50 AND CVSS >= 7.0
  └─ Very likely to be exploited

Priority 3: High EPSS or High CVSS
  ├─ EPSS > 0.25 OR CVSS >= 9.0
  └─ Significant risk

Priority 4: KEV + ANY reachability
  ├─ In KEV catalog with ANY confidence
  └─ Known exploitation risk

Priority 5: EPSS > threshold
  ├─ EPSS > 0.10
  └─ Above-average exploitation risk

Priority 6: Standard CVSS-based
  ├─ CVSS-based severity
  └─ No additional context
```

### Example Prioritization

```
Your scan found 47 vulnerabilities. Here's the priority order:

🔴 URGENT (3):
  1. CVE-2021-44228 in log4j - KEV + EPSS 0.97 + CVSS 10.0
  2. CVE-2022-12345 in spring - KEV + EPSS 0.75 + CVSS 9.8
  3. CVE-2023-67890 in jackson - EPSS 0.82 + CVSS 9.1

🟠 HIGH PRIORITY (8):
  4-11. Various CVEs with EPSS 0.30-0.60 + CVSS 7.5-8.9

🟡 MEDIUM PRIORITY (15):
  12-26. CVEs with EPSS 0.10-0.30 or CVSS 7.0-7.4

🟢 LOW PRIORITY (21):
  27-47. CVEs with EPSS < 0.10 and CVSS < 7.0
```

## Performance Characteristics

### Query Times

| Source | Single Query | Batch 100 |
|--------|--------------|-----------|
| OSV | ~200ms | ~2-3s |
| NVD | ~1-2s (with key) | ~2-3min (rate limited) |
| GitHub | ~500ms (with token) | ~50s |
| EPSS | ~300ms | ~1-2s (batch API) |
| KEV | <10ms (local catalog) | <100ms |

### Rate Limits

| Source | Without Auth | With Auth | Notes |
|--------|--------------|-----------|-------|
| OSV | Unlimited | N/A | Free, no key needed |
| NVD | 5 req/30s | 20 req/s | API key highly recommended |
| GitHub | 60 req/hour | 5,000 req/hour | Token required |
| EPSS | Unlimited | N/A | Free, no key needed |
| KEV | Unlimited | N/A | Downloaded once, cached 24h |

### Caching Strategy

- **OSV**: 24 hour file cache
- **NVD**: 24 hour in-memory cache
- **GitHub**: No cache (fast enough)
- **EPSS**: 24 hour in-memory cache
- **KEV**: 24 hour file cache (catalog downloaded once daily)

## Best Practices

### For Maximum Coverage

```bash
# 1. Get API keys
export NVD_API_KEY="..."
export GITHUB_TOKEN="..."

# 2. Enable all sources
depguard scan --enable-nvd --enable-github

# 3. Use deep analysis
depguard scan --deep-analysis

# Result: Maximum vulnerability detection + enrichment
```

### For Speed (CI/CD)

```bash
# Use OSV only (default, fastest)
depguard scan

# With EPSS and KEV enrichment (small overhead)
depguard scan  # Already enabled by default

# Result: Fast scanning with good prioritization
```

### For Security-Critical Apps

```bash
# 1. Enable everything
export NVD_API_KEY="..."
export GITHUB_TOKEN="..."

# 2. Show only KEV or high EPSS
depguard scan \
  --enable-nvd \
  --enable-github \
  --kev-only          # Or --epss-threshold 0.25

# Result: Focus on actively exploited or likely-to-be-exploited CVEs
```

## Validation & Testing

### Health Check

```bash
# Check if all sources are accessible
depguard health-check

# Output:
✓ OSV: Available
✓ NVD: Available (with API key)
✓ GitHub: Available (with token)
✓ EPSS: Available
✓ CISA KEV: Catalog loaded (1,234 entries)
```

### Test Against Known Vulnerabilities

```bash
# Scan a known vulnerable app
cd examples/vulnerable-test-app
depguard scan --enable-nvd --enable-github

# Should detect:
# - Log4Shell (CVE-2021-44228) - KEV listed
# - Prototype pollution in lodash - High EPSS
# - etc.
```

## Comparison with Other Scanners

| Feature | DepGuard | Snyk | npm audit | OWASP Dep-Check |
|---------|----------|------|-----------|-----------------|
| **Sources** |
| OSV | ✅ | ✅ | ❌ | ✅ |
| NVD | ✅ | ✅ | ❌ | ✅ |
| GitHub Advisory | ✅ | ✅ | ✅ | ❌ |
| EPSS Enrichment | ✅ | ✅ ($) | ❌ | ❌ |
| CISA KEV | ✅ | ✅ ($) | ❌ | ❌ |
| **Analysis** |
| Reachability | ✅ | ✅ ($) | ❌ | ❌ |
| Function-level | ✅ | ✅ ($) | ❌ | ❌ |
| **Cost** | Free | $$ | Free | Free |

✅ = Supported
❌ = Not supported
($) = Paid tier only

## FAQs

### Q: Why is OSV the primary source?
**A**: OSV is comprehensive, fast, free, and covers all major ecosystems. It aggregates data from multiple sources including GitHub Security Advisory.

### Q: Should I enable NVD?
**A**: If you have an API key, yes. NVD provides authoritative CVSS scores and detailed CVE data. Without a key, rate limits make it impractical for large scans.

### Q: Is EPSS reliable?
**A**: Yes. EPSS is developed by FIRST.org and based on machine learning trained on real exploitation data. It's widely used for vulnerability prioritization.

### Q: What if a vulnerability isn't in KEV?
**A**: KEV only lists actively exploited CVEs. Not being in KEV doesn't mean it's safe - use EPSS and CVSS for prioritization.

### Q: Can I use this offline?
**A**: Partially. KEV can be cached. OSV has an offline export. NVD and GitHub require online access. EPSS needs online API.

### Q: How often is data updated?
**A**: OSV (continuous), NVD (daily), GitHub (continuous), EPSS (daily), KEV (as exploits emerge, checked daily by scanner).

---

**Bottom Line**: DepGuard provides the most comprehensive free vulnerability intelligence by combining 5 authoritative sources with smart prioritization based on real-world exploitation risk.
