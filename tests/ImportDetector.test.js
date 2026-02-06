/**
 * Tests for ImportDetector
 * Language-specific import detection and dangerous pattern scanning
 */

const ImportDetector = require('../src/utils/ImportDetector');

describe('ImportDetector', () => {
    let detector;

    beforeEach(() => {
        detector = new ImportDetector();
    });

    // ─── JavaScript/TypeScript Import Detection ──────────────────────

    describe('detectImportsInContent - JavaScript', () => {
        test('should detect require() calls', () => {
            const content = `const express = require('express');`;
            const imports = detector.detectImportsInContent(content, 'express', 'app.js');
            expect(imports.length).toBeGreaterThan(0);
            expect(imports[0].packageName).toBe('express');
            expect(imports[0].language).toBe('javascript');
        });

        test('should detect require() with subpath', () => {
            const content = `const merge = require('lodash/merge');`;
            const imports = detector.detectImportsInContent(content, 'lodash', 'app.js');
            expect(imports.length).toBeGreaterThan(0);
        });

        test('should detect import from statements', () => {
            const content = `import React from 'react';`;
            const imports = detector.detectImportsInContent(content, 'react', 'app.js');
            expect(imports.length).toBeGreaterThan(0);
        });

        test('should detect side-effect imports', () => {
            const content = `import 'dotenv';`;
            const imports = detector.detectImportsInContent(content, 'dotenv', 'app.js');
            expect(imports.length).toBeGreaterThan(0);
        });

        test('should detect dynamic imports', () => {
            const content = `const mod = import('lodash');`;
            const imports = detector.detectImportsInContent(content, 'lodash', 'app.js');
            expect(imports.length).toBeGreaterThan(0);
        });

        test('should not match wrong package', () => {
            const content = `const express = require('express');`;
            const imports = detector.detectImportsInContent(content, 'lodash', 'app.js');
            expect(imports).toHaveLength(0);
        });
    });

    // ─── Python Import Detection ─────────────────────────────────────

    describe('detectImportsInContent - Python', () => {
        test('should detect import statements', () => {
            const content = `import requests`;
            const imports = detector.detectImportsInContent(content, 'requests', 'app.py');
            expect(imports.length).toBeGreaterThan(0);
            const pythonImport = imports.find(i => i.language === 'python');
            expect(pythonImport).toBeDefined();
        });

        test('should detect from...import statements', () => {
            const content = `from flask import Flask`;
            const imports = detector.detectImportsInContent(content, 'flask', 'app.py');
            expect(imports.length).toBeGreaterThan(0);
        });

        test('should detect import as alias', () => {
            const content = `import numpy as np`;
            const imports = detector.detectImportsInContent(content, 'numpy', 'app.py');
            expect(imports.length).toBeGreaterThan(0);
        });
    });

    // ─── Java Import Detection ───────────────────────────────────────

    describe('detectImportsInContent - Java', () => {
        test('should detect import statements', () => {
            const content = `import org.apache.commons.lang3.StringUtils;`;
            const imports = detector.detectImportsInContent(content, 'org.apache.commons', 'App.java');
            expect(imports.length).toBeGreaterThan(0);
            const javaImport = imports.find(i => i.language === 'java');
            expect(javaImport).toBeDefined();
        });

        test('should detect static imports', () => {
            const content = `import static org.junit.Assert.assertEquals;`;
            const imports = detector.detectImportsInContent(content, 'org.junit', 'Test.java');
            expect(imports.length).toBeGreaterThan(0);
        });
    });

    // ─── C# Import Detection ────────────────────────────────────────

    describe('detectImportsInContent - C#', () => {
        test('should detect using statements', () => {
            const content = `using Newtonsoft.Json;`;
            const imports = detector.detectImportsInContent(content, 'Newtonsoft', 'App.cs');
            expect(imports.length).toBeGreaterThan(0);
            expect(imports[0].language).toBe('csharp');
        });

        test('should detect using static', () => {
            const content = `using static System.Math;`;
            const imports = detector.detectImportsInContent(content, 'System', 'App.cs');
            expect(imports.length).toBeGreaterThan(0);
        });

        test('should detect using alias', () => {
            const content = `using Json = Newtonsoft.Json;`;
            const imports = detector.detectImportsInContent(content, 'Newtonsoft', 'App.cs');
            expect(imports.length).toBeGreaterThan(0);
        });
    });

    // ─── Rust Import Detection ───────────────────────────────────────

    describe('detectImportsInContent - Rust', () => {
        test('should detect use statements', () => {
            const content = `use serde::Deserialize;`;
            const imports = detector.detectImportsInContent(content, 'serde', 'main.rs');
            expect(imports.length).toBeGreaterThan(0);
            expect(imports[0].language).toBe('rust');
        });

        test('should detect extern crate', () => {
            const content = `extern crate serde;`;
            const imports = detector.detectImportsInContent(content, 'serde', 'lib.rs');
            expect(imports.length).toBeGreaterThan(0);
        });
    });

    // ─── Ruby Import Detection ───────────────────────────────────────

    describe('detectImportsInContent - Ruby', () => {
        test('should detect require statements', () => {
            const content = `require 'nokogiri'`;
            const imports = detector.detectImportsInContent(content, 'nokogiri', 'app.rb');
            expect(imports.length).toBeGreaterThan(0);
            const rubyImport = imports.find(i => i.language === 'ruby');
            expect(rubyImport).toBeDefined();
        });

        test('should detect gem declarations', () => {
            const content = `gem 'rails'`;
            const imports = detector.detectImportsInContent(content, 'rails', 'Gemfile');
            expect(imports.length).toBeGreaterThan(0);
        });
    });

    // ─── Dart Import Detection ───────────────────────────────────────

    describe('detectImportsInContent - Dart', () => {
        test('should detect package imports', () => {
            const content = `import 'package:flutter/material.dart';`;
            const imports = detector.detectImportsInContent(content, 'flutter', 'main.dart');
            expect(imports.length).toBeGreaterThan(0);
            expect(imports[0].language).toBe('dart');
        });
    });

    // ─── Confidence Calculation ──────────────────────────────────────

    describe('calculateImportConfidence', () => {
        test('should give high confidence to require()', () => {
            const confidence = detector.calculateImportConfidence("require('express')", 'javascript');
            expect(confidence).toBe(0.9);
        });

        test('should give high confidence to ES import', () => {
            const confidence = detector.calculateImportConfidence("import React from 'react'", 'javascript');
            expect(confidence).toBe(0.95);
        });

        test('should give high confidence to Python from...import', () => {
            const confidence = detector.calculateImportConfidence('from flask import Flask', 'python');
            expect(confidence).toBe(0.95);
        });

        test('should give high confidence to C# using', () => {
            const confidence = detector.calculateImportConfidence('using Newtonsoft.Json;', 'csharp');
            expect(confidence).toBe(0.95);
        });

        test('should give high confidence to Rust extern crate', () => {
            const confidence = detector.calculateImportConfidence('extern crate serde;', 'rust');
            expect(confidence).toBe(0.98);
        });

        test('should give low confidence to commented imports', () => {
            const confidence = detector.calculateImportConfidence("// require('express')", 'javascript');
            expect(confidence).toBe(0.2);
        });
    });

    // ─── Source File Detection ────────────────────────────────────────

    describe('isSourceFile', () => {
        test('should detect JavaScript files', () => {
            expect(detector.isSourceFile('app.js')).toBe(true);
            expect(detector.isSourceFile('index.tsx')).toBe(true);
            expect(detector.isSourceFile('utils.mjs')).toBe(true);
        });

        test('should detect Python files', () => {
            expect(detector.isSourceFile('app.py')).toBe(true);
            expect(detector.isSourceFile('types.pyi')).toBe(true);
        });

        test('should detect various language files', () => {
            expect(detector.isSourceFile('App.java')).toBe(true);
            expect(detector.isSourceFile('main.go')).toBe(true);
            expect(detector.isSourceFile('lib.rs')).toBe(true);
            expect(detector.isSourceFile('app.rb')).toBe(true);
            expect(detector.isSourceFile('index.php')).toBe(true);
            expect(detector.isSourceFile('Program.cs')).toBe(true);
            expect(detector.isSourceFile('main.dart')).toBe(true);
            expect(detector.isSourceFile('main.swift')).toBe(true);
            expect(detector.isSourceFile('app.ex')).toBe(true);
            expect(detector.isSourceFile('Main.hs')).toBe(true);
        });

        test('should reject non-source files', () => {
            expect(detector.isSourceFile('readme.md')).toBe(false);
            expect(detector.isSourceFile('data.json')).toBe(false);
            expect(detector.isSourceFile('image.png')).toBe(false);
            expect(detector.isSourceFile('style.css')).toBe(false);
        });
    });

    // ─── Skip Logic ──────────────────────────────────────────────────

    describe('shouldSkip', () => {
        test('should skip node_modules', () => {
            expect(detector.shouldSkip('node_modules')).toBe(true);
        });

        test('should skip .git', () => {
            expect(detector.shouldSkip('.git')).toBe(true);
        });

        test('should skip hidden directories', () => {
            expect(detector.shouldSkip('.cache')).toBe(true);
            expect(detector.shouldSkip('.next')).toBe(true);
        });

        test('should skip build directories', () => {
            expect(detector.shouldSkip('dist')).toBe(true);
            expect(detector.shouldSkip('build')).toBe(true);
        });

        test('should not skip regular directories', () => {
            expect(detector.shouldSkip('src')).toBe(false);
            expect(detector.shouldSkip('lib')).toBe(false);
        });
    });

    // ─── Conditional Import Detection ────────────────────────────────

    describe('detectConditionalImports', () => {
        test('should detect try/catch requires', () => {
            const content = `
try {
    const pkg = require('optional-pkg');
} catch (e) {
    // fallback
}`;
            const imports = detector.detectConditionalImports(content, 'optional-pkg');
            expect(imports.length).toBeGreaterThan(0);
            expect(imports[0].conditionalType).toBe('try-catch');
            expect(imports[0].confidence).toBeLessThan(0.8);
        });

        test('should detect conditional requires', () => {
            const content = `
if (process.env.USE_PKG) {
    const pkg = require('conditional-pkg');
}`;
            const imports = detector.detectConditionalImports(content, 'conditional-pkg');
            expect(imports.length).toBeGreaterThan(0);
            expect(imports[0].conditionalType).toBe('conditional');
        });

        test('should not detect regular requires', () => {
            const content = `const pkg = require('regular-pkg');`;
            const imports = detector.detectConditionalImports(content, 'regular-pkg');
            expect(imports).toHaveLength(0);
        });
    });

    // ─── Dangerous Pattern Detection ─────────────────────────────────

    describe('detectDangerousPatterns', () => {
        test('should detect command injection', () => {
            const content = `exec('rm -rf ' + req.body.path)`;
            const patterns = detector.detectDangerousPatterns(content, 'server.js');
            const cmdInjection = patterns.find(p => p.category === 'command-injection');
            expect(cmdInjection).toBeDefined();
            expect(cmdInjection.severity).toBe('CRITICAL');
        });

        test('should detect SQL injection', () => {
            const content = `db.query("SELECT * FROM users WHERE id = " + userId)`;
            const patterns = detector.detectDangerousPatterns(content, 'db.js');
            const sqlInjection = patterns.find(p => p.category === 'sql-injection');
            expect(sqlInjection).toBeDefined();
            expect(sqlInjection.severity).toBe('CRITICAL');
        });

        test('should detect path traversal', () => {
            const content = `fs.readFileSync(req.query.file)`;
            const patterns = detector.detectDangerousPatterns(content, 'file.js');
            const pathTraversal = patterns.find(p => p.category === 'path-traversal');
            expect(pathTraversal).toBeDefined();
        });

        test('should detect unsafe deserialization', () => {
            const content = `eval(userInput)`;
            const patterns = detector.detectDangerousPatterns(content, 'handler.js');
            const deser = patterns.find(p => p.category === 'unsafe-deserialization');
            expect(deser).toBeDefined();
            expect(deser.severity).toBe('CRITICAL');
        });

        test('should detect hardcoded secrets', () => {
            const content = `const api_key = "sk-1234567890abcdef"`;
            const patterns = detector.detectDangerousPatterns(content, 'config.js');
            const secret = patterns.find(p => p.category === 'hardcoded-secret');
            expect(secret).toBeDefined();
        });

        test('should detect weak crypto', () => {
            const content = `crypto.createHash('md5')`;
            const patterns = detector.detectDangerousPatterns(content, 'auth.js');
            const weakCrypto = patterns.find(p => p.category === 'weak-crypto');
            expect(weakCrypto).toBeDefined();
        });

        test('should detect XSS via innerHTML', () => {
            const content = `element.innerHTML = userInput;`;
            const patterns = detector.detectDangerousPatterns(content, 'ui.js');
            const xss = patterns.find(p => p.category === 'xss');
            expect(xss).toBeDefined();
        });

        test('should detect insecure TLS', () => {
            const content = `{ rejectUnauthorized: false }`;
            const patterns = detector.detectDangerousPatterns(content, 'client.js');
            const tls = patterns.find(p => p.category === 'insecure-tls');
            expect(tls).toBeDefined();
        });

        test('should detect prototype pollution', () => {
            const content = `_.merge(target, req.body)`;
            const patterns = detector.detectDangerousPatterns(content, 'handler.js');
            const proto = patterns.find(p => p.category === 'prototype-pollution');
            expect(proto).toBeDefined();
        });

        test('should include line numbers', () => {
            const content = `line1\nline2\neval(input)`;
            const patterns = detector.detectDangerousPatterns(content, 'file.js');
            expect(patterns[0].lineNumber).toBe(3);
        });

        test('should return empty for safe code', () => {
            const content = `
const x = 1 + 2;
console.log(x);
            `;
            const patterns = detector.detectDangerousPatterns(content, 'safe.js');
            expect(patterns).toHaveLength(0);
        });
    });

    // ─── Regex Escaping ──────────────────────────────────────────────

    describe('escapeRegex', () => {
        test('should escape special regex characters', () => {
            expect(detector.escapeRegex('a.b')).toBe('a\\.b');
            expect(detector.escapeRegex('a*b')).toBe('a\\*b');
            expect(detector.escapeRegex('a[b]')).toBe('a\\[b\\]');
        });

        test('should not modify plain strings', () => {
            expect(detector.escapeRegex('lodash')).toBe('lodash');
        });
    });
});
