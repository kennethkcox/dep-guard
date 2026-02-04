# Vulnerable Test Application

This is an intentionally vulnerable test application designed to evaluate the effectiveness of DepGuard scanner.

## Purpose

This application contains **hard-to-detect vulnerabilities** that challenge static analysis tools:

1. **Deep call chains** - Vulnerable functions are called through multiple layers
2. **Dynamic imports** - Modules loaded conditionally at runtime
3. **Callback/Promise chains** - Vulnerabilities in async code paths
4. **Object property lookups** - Dynamic handler selection
5. **Array iterations** - Vulnerabilities in processing pipelines
6. **Error paths** - Vulnerabilities only in error handling
7. **Conditional loading** - Environment-based module selection
8. **Middleware chains** - Vulnerabilities in authentication flow
9. **External integrations** - Third-party service dependencies
10. **Background jobs** - Scheduled tasks not in HTTP flow

## Known Vulnerabilities

This app intentionally uses vulnerable versions of:

- **lodash@4.17.20** - Prototype pollution in _.template, _.merge, etc.
- **semver@7.3.5** - ReDoS vulnerability
- **minimist@1.2.5** - Prototype pollution
- **axios@0.21.1** - SSRF vulnerability
- **jsonwebtoken@8.5.1** - Algorithm confusion
- **ejs@3.1.6** - Template injection
- **xml2js@0.4.23** - XXE vulnerability
- **handlebars@4.7.7** - Prototype pollution
- **node-notifier@8.0.1** - Command injection

## Test Scenarios

### Scenario 1: Template Injection (Deep Chain)
```
POST /api/render
Body: { "template": "malicious template" }

Flow: server.js -> sanitizer.js -> template-processor.js -> lodash.template()
```

### Scenario 2: XML External Entity (Dynamic Import)
```
GET /api/parse-xml?format=xml&data=<xml>...</xml>

Flow: server.js -> xml-parser.js (dynamically loaded) -> xml2js.Parser()
```

### Scenario 3: ReDoS (Promise Chain)
```
GET /api/user/123

Flow: server.js -> user-service.js -> version-checker.js -> semver.satisfies()
```

### Scenario 4: Prototype Pollution (Object Lookup)
```
POST /api/process
Body: { "type": "json", "data": {...} }

Flow: server.js -> handlers[type] -> json-handler.js -> _.merge()
```

### Scenario 5: Multiple Vulnerabilities (Pipeline)
```
POST /api/pipeline
Body: { "data": "..." }

Flow: server.js -> processors[] -> validator/transformer/encoder -> various vulnerabilities
```

## Running the Scanner

Test DepGuard against this application:

```bash
cd examples/vulnerable-test-app
npm install
cd ../..
node bin/depguard.js scan -p examples/vulnerable-test-app --deep-analysis -v
```

## Expected Results

A good scanner should detect:

- **10 vulnerable packages**
- **Multiple reachability paths** for each vulnerability
- **Different confidence levels** based on call chain complexity
- **Entry points** for all 10 HTTP routes

## Analysis Challenges

This application tests the scanner's ability to:

1. Follow deep call chains (5+ levels)
2. Handle dynamic require() statements
3. Trace through callbacks and promises
4. Analyze object property/method lookups
5. Track vulnerabilities in loops
6. Detect error-path vulnerabilities
7. Handle conditional module loading
8. Analyze middleware chains
9. Track external service dependencies
10. Identify background job vulnerabilities

**Note**: This is for testing purposes only. Never deploy this code in production!
