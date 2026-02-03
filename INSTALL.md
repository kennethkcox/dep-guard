# DepGuard Installation Guide

## Prerequisites

- **Node.js**: Version 16.0.0 or higher
- **npm**: Version 7.0.0 or higher (comes with Node.js)
- **Operating System**: Windows, macOS, or Linux

Check your versions:
```bash
node --version  # Should be >= 16.0.0
npm --version   # Should be >= 7.0.0
```

## Installation Methods

### Method 1: Global Installation (Recommended)

Install DepGuard globally to use it from anywhere:

```bash
npm install -g depguard
```

Verify installation:
```bash
depguard version
```

### Method 2: Local Project Installation

Install as a dev dependency in your project:

```bash
npm install --save-dev depguard
```

Add to package.json scripts:
```json
{
  "scripts": {
    "security": "depguard scan",
    "security:reachable": "depguard scan --reachable-only"
  }
}
```

Run with:
```bash
npm run security
```

### Method 3: Direct from Source

Clone and install from source:

```bash
git clone https://github.com/owasp/depguard.git
cd depguard
npm install
npm link
```

This creates a global symlink to your local copy.

## First Run

After installation, try scanning the example project:

```bash
cd examples/vulnerable-app
depguard scan
```

You should see output showing vulnerabilities with reachability analysis.

## Configuration

### Create Configuration File

Generate a default configuration:

```bash
depguard config
```

This creates `.depguard.yml` in your project root.

### Customize Configuration

Edit `.depguard.yml` to customize behavior:

```yaml
scan:
  depth: 10
  excludePaths:
    - test/**
    - dist/**

reachability:
  minConfidence: 0.7

reporting:
  onlyReachable: true
```

## Troubleshooting

### Issue: Command not found

**Problem**: `depguard: command not found`

**Solution**:
```bash
# Ensure npm global bin is in PATH
npm config get prefix

# Add to PATH (Linux/Mac)
export PATH="$PATH:$(npm config get prefix)/bin"

# Or reinstall globally
npm install -g depguard
```

### Issue: Permission denied

**Problem**: `EACCES: permission denied`

**Solution**:
```bash
# Use sudo (Linux/Mac)
sudo npm install -g depguard

# Or configure npm to use a different directory
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
export PATH=~/.npm-global/bin:$PATH
npm install -g depguard
```

### Issue: Module not found

**Problem**: `Cannot find module '@babel/parser'`

**Solution**:
```bash
# Reinstall dependencies
npm install -g depguard --force
```

### Issue: Scan fails on Windows

**Problem**: Path issues on Windows

**Solution**: Use forward slashes in paths or double backslashes:
```bash
depguard scan --path "C:/projects/myapp"
# or
depguard scan --path "C:\\projects\\myapp"
```

## Updating

### Update Global Installation

```bash
npm update -g depguard
```

### Update Local Installation

```bash
npm update depguard
```

### Check for Updates

```bash
npm outdated -g depguard
```

## Uninstallation

### Remove Global Installation

```bash
npm uninstall -g depguard
```

### Remove Local Installation

```bash
npm uninstall depguard
```

### Clean Cache

```bash
# Remove vulnerability cache
rm -rf .depguard-cache

# Clear npm cache
npm cache clean --force
```

## Platform-Specific Notes

### Windows

- Use PowerShell or Command Prompt
- May need to run as Administrator for global install
- Use double backslashes or forward slashes in paths

### macOS

- May need sudo for global install
- Ensure Xcode Command Line Tools are installed
- Use Terminal or iTerm2

### Linux

- May need sudo for global install
- Ensure build-essential is installed (for native modules)
- Works on all major distributions

## Docker Installation

Use DepGuard in a Docker container:

```dockerfile
FROM node:16-alpine

RUN npm install -g depguard

WORKDIR /app

CMD ["depguard", "scan"]
```

Build and run:
```bash
docker build -t depguard .
docker run -v $(pwd):/app depguard
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '16'
      - run: npm install -g depguard
      - run: depguard scan --output sarif --file report.sarif
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: report.sarif
```

### GitLab CI

```yaml
security_scan:
  image: node:16
  script:
    - npm install -g depguard
    - depguard scan --output json --file report.json
  artifacts:
    reports:
      security: report.json
```

### Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('Security Scan') {
      steps {
        sh 'npm install -g depguard'
        sh 'depguard scan --output json --file report.json'
      }
    }
  }
}
```

## Verification

After installation, verify everything works:

```bash
# Check version
depguard version

# Check help
depguard --help

# Try scanning the example
cd examples/vulnerable-app
depguard scan

# Generate config
depguard config

# Check info
depguard info
```

## Next Steps

1. Read the [Quick Start Guide](QUICKSTART.md)
2. Scan your first project
3. Review the [Architecture Documentation](ARCHITECTURE.md)
4. Explore [Examples](examples/README.md)
5. Check out [Contributing Guidelines](CONTRIBUTING.md)

## Getting Help

- **Documentation**: See README.md
- **Issues**: https://github.com/owasp/depguard/issues
- **Discussions**: https://github.com/owasp/depguard/discussions
- **OWASP**: https://owasp.org

## License

DepGuard is licensed under Apache-2.0. See [LICENSE](LICENSE) for details.
