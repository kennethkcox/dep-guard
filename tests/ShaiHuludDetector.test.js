/**
 * Tests for ShaiHuludDetector
 * Shadow dependency detection, typosquatting, and dependency confusion
 */

const ShaiHuludDetector = require('../src/analysis/ShaiHuludDetector');

describe('ShaiHuludDetector', () => {
    let detector;

    beforeEach(() => {
        detector = new ShaiHuludDetector();
    });

    // ─── Levenshtein Distance ────────────────────────────────────────

    describe('levenshteinDistance', () => {
        test('should return 0 for identical strings', () => {
            expect(detector.levenshteinDistance('lodash', 'lodash')).toBe(0);
        });

        test('should return correct distance for single character difference', () => {
            expect(detector.levenshteinDistance('lodash', 'lodahs')).toBe(2);
            expect(detector.levenshteinDistance('react', 'recat')).toBe(2);
        });

        test('should return correct distance for insertion', () => {
            expect(detector.levenshteinDistance('lodash', 'lodashs')).toBe(1);
        });

        test('should return correct distance for deletion', () => {
            expect(detector.levenshteinDistance('lodash', 'lodas')).toBe(1);
        });

        test('should handle empty strings', () => {
            expect(detector.levenshteinDistance('', 'abc')).toBe(3);
            expect(detector.levenshteinDistance('abc', '')).toBe(3);
            expect(detector.levenshteinDistance('', '')).toBe(0);
        });

        test('should handle completely different strings', () => {
            expect(detector.levenshteinDistance('abc', 'xyz')).toBe(3);
        });
    });

    // ─── Malicious Pattern Detection ─────────────────────────────────

    describe('checkMaliciousPattern', () => {
        test('should detect hyphen-underscore swap', () => {
            expect(detector.checkMaliciousPattern('lodash_utils', 'lodash-utils'))
                .toBe('hyphen-underscore-swap');
        });

        test('should detect suffix attacks', () => {
            expect(detector.checkMaliciousPattern('express-js', 'express'))
                .toBe('suffix-attack (-js)');
        });

        test('should detect prefix attacks', () => {
            expect(detector.checkMaliciousPattern('node-express', 'express'))
                .toBe('prefix-attack (node-)');
        });

        test('should detect character insertion', () => {
            expect(detector.checkMaliciousPattern('expresss', 'express'))
                .toBe('character-insertion');
        });

        test('should return null for unrelated packages', () => {
            expect(detector.checkMaliciousPattern('totally-different', 'express'))
                .toBeNull();
        });

        test('should return null for identical packages', () => {
            expect(detector.checkMaliciousPattern('lodash', 'lodash'))
                .toBeNull();
        });
    });

    // ─── Built-in Module Detection ───────────────────────────────────

    describe('isBuiltinModule', () => {
        test('should identify Node.js builtins', () => {
            expect(detector.isBuiltinModule('fs')).toBe(true);
            expect(detector.isBuiltinModule('path')).toBe(true);
            expect(detector.isBuiltinModule('crypto')).toBe(true);
            expect(detector.isBuiltinModule('node:fs')).toBe(true);
        });

        test('should identify Python builtins', () => {
            expect(detector.isBuiltinModule('os')).toBe(true);
            expect(detector.isBuiltinModule('sys')).toBe(true);
            expect(detector.isBuiltinModule('json')).toBe(true);
            expect(detector.isBuiltinModule('asyncio')).toBe(true);
        });

        test('should identify Ruby builtins', () => {
            expect(detector.isBuiltinModule('json')).toBe(true);
            expect(detector.isBuiltinModule('yaml')).toBe(true);
        });

        test('should not flag external packages', () => {
            expect(detector.isBuiltinModule('express')).toBe(false);
            expect(detector.isBuiltinModule('lodash')).toBe(false);
            expect(detector.isBuiltinModule('react')).toBe(false);
        });
    });

    // ─── JS Import Extraction ────────────────────────────────────────

    describe('extractJSImportedPackages', () => {
        test('should extract require() calls', () => {
            const content = `
                const express = require('express');
                const lodash = require('lodash');
            `;
            const packages = detector.extractJSImportedPackages(content);
            expect(packages).toContain('express');
            expect(packages).toContain('lodash');
        });

        test('should extract import from statements', () => {
            const content = `
                import React from 'react';
                import { useState } from 'react';
            `;
            const packages = detector.extractJSImportedPackages(content);
            expect(packages).toContain('react');
        });

        test('should extract dynamic imports', () => {
            const content = `const mod = import('lodash');`;
            const packages = detector.extractJSImportedPackages(content);
            expect(packages).toContain('lodash');
        });

        test('should extract side-effect imports', () => {
            const content = `import 'dotenv/config';`;
            const packages = detector.extractJSImportedPackages(content);
            expect(packages).toContain('dotenv');
        });

        test('should handle scoped packages', () => {
            const content = `
                const sdk = require('@aws-sdk/client-s3');
                import { Component } from '@angular/core';
            `;
            const packages = detector.extractJSImportedPackages(content);
            expect(packages).toContain('@aws-sdk/client-s3');
            expect(packages).toContain('@angular/core');
        });

        test('should normalize subpath imports', () => {
            const content = `const merge = require('lodash/merge');`;
            const packages = detector.extractJSImportedPackages(content);
            expect(packages).toContain('lodash');
            expect(packages).not.toContain('lodash/merge');
        });

        test('should not extract relative imports', () => {
            const content = `
                const util = require('./utils');
                import helper from '../helpers';
            `;
            const packages = detector.extractJSImportedPackages(content);
            expect(packages).toHaveLength(0);
        });
    });

    // ─── Python Import Extraction ────────────────────────────────────

    describe('extractPythonImportedPackages', () => {
        test('should extract import statements', () => {
            const content = `
import requests
import flask
            `;
            const packages = detector.extractPythonImportedPackages(content);
            expect(packages).toContain('requests');
            expect(packages).toContain('flask');
        });

        test('should extract from...import statements', () => {
            const content = `from django.db import models`;
            const packages = detector.extractPythonImportedPackages(content);
            expect(packages).toContain('django');
        });

        test('should skip comments', () => {
            const content = `# import malware`;
            const packages = detector.extractPythonImportedPackages(content);
            expect(packages).toHaveLength(0);
        });
    });

    // ─── Go Import Extraction ────────────────────────────────────────

    describe('extractGoImportedPackages', () => {
        test('should extract single imports', () => {
            const content = `import "github.com/gin-gonic/gin"`;
            const packages = detector.extractGoImportedPackages(content);
            expect(packages).toContain('github.com/gin-gonic/gin');
        });

        test('should extract block imports', () => {
            const content = `
import (
    "fmt"
    "github.com/gorilla/mux"
    "github.com/sirupsen/logrus"
)`;
            const packages = detector.extractGoImportedPackages(content);
            expect(packages).toContain('github.com/gorilla/mux');
            expect(packages).toContain('github.com/sirupsen/logrus');
        });

        test('should skip standard library packages', () => {
            const content = `import "fmt"`;
            const packages = detector.extractGoImportedPackages(content);
            expect(packages).toHaveLength(0);
        });
    });

    // ─── Ruby Import Extraction ──────────────────────────────────────

    describe('extractRubyImportedPackages', () => {
        test('should extract require statements', () => {
            const content = `
require 'nokogiri'
require 'httparty'
            `;
            const packages = detector.extractRubyImportedPackages(content);
            expect(packages).toContain('nokogiri');
            expect(packages).toContain('httparty');
        });

        test('should handle subpath requires', () => {
            const content = `require 'active_support/core_ext'`;
            const packages = detector.extractRubyImportedPackages(content);
            expect(packages).toContain('active_support');
        });
    });

    // ─── Rust Import Extraction ──────────────────────────────────────

    describe('extractRustImportedPackages', () => {
        test('should extract extern crate', () => {
            const content = `extern crate serde;`;
            const packages = detector.extractRustImportedPackages(content);
            expect(packages).toContain('serde');
        });

        test('should extract use statements', () => {
            const content = `
use tokio::runtime;
use serde_json::Value;
            `;
            const packages = detector.extractRustImportedPackages(content);
            expect(packages).toContain('tokio');
            expect(packages).toContain('serde-json');
        });

        test('should skip std library crates', () => {
            const content = `
use std::io;
use core::fmt;
            `;
            const packages = detector.extractRustImportedPackages(content);
            expect(packages).toHaveLength(0);
        });
    });

    // ─── Internal Package Name Detection ─────────────────────────────

    describe('looksInternal', () => {
        test('should flag internal-looking names', () => {
            expect(detector.looksInternal('internal-auth')).toBe(true);
            expect(detector.looksInternal('corp-utils')).toBe(true);
            expect(detector.looksInternal('company-core')).toBe(true);
            expect(detector.looksInternal('my-logger')).toBe(true);
            expect(detector.looksInternal('auth-service')).toBe(true);
            expect(detector.looksInternal('platform-sdk')).toBe(true);
        });

        test('should not flag regular package names', () => {
            expect(detector.looksInternal('express')).toBe(false);
            expect(detector.looksInternal('lodash')).toBe(false);
            expect(detector.looksInternal('react')).toBe(false);
        });
    });

    // ─── Generic Scope Detection ─────────────────────────────────────

    describe('isGenericScope', () => {
        test('should identify well-known scopes', () => {
            expect(detector.isGenericScope('@types')).toBe(false);
            expect(detector.isGenericScope('@babel')).toBe(false);
            expect(detector.isGenericScope('@angular')).toBe(false);
            expect(detector.isGenericScope('@aws-sdk')).toBe(false);
        });

        test('should flag generic/unknown scopes', () => {
            expect(detector.isGenericScope('@mycompany')).toBe(true);
            expect(detector.isGenericScope('@random-org')).toBe(true);
            expect(detector.isGenericScope('@internal')).toBe(true);
        });
    });

    // ─── Typosquatting Detection ─────────────────────────────────────

    describe('detectTyposquatting', () => {
        test('should detect typosquatting candidates', () => {
            const depsByEcosystem = new Map([
                ['npm', new Set(['lodashs', 'expresss', 'react'])]
            ]);

            detector.detectTyposquatting(depsByEcosystem);

            const findings = detector.findings.filter(f => f.type === 'typosquatting-risk');
            expect(findings.length).toBeGreaterThan(0);

            const lodashFinding = findings.find(f => f.package === 'lodashs');
            expect(lodashFinding).toBeDefined();
            expect(lodashFinding.severity).toBe('HIGH');
        });

        test('should not flag exact matches of popular packages', () => {
            const depsByEcosystem = new Map([
                ['npm', new Set(['lodash', 'express', 'react'])]
            ]);

            detector.detectTyposquatting(depsByEcosystem);

            const findings = detector.findings.filter(f => f.type === 'typosquatting-risk');
            expect(findings).toHaveLength(0);
        });

        test('should not flag packages far from any popular package', () => {
            const depsByEcosystem = new Map([
                ['npm', new Set(['completely-unique-package-name'])]
            ]);

            detector.detectTyposquatting(depsByEcosystem);

            const findings = detector.findings.filter(f => f.type === 'typosquatting-risk');
            expect(findings).toHaveLength(0);
        });

        test('should detect naming pattern attacks', () => {
            const depsByEcosystem = new Map([
                ['npm', new Set(['express-js'])]
            ]);

            detector.detectTyposquatting(depsByEcosystem);

            const findings = detector.findings.filter(f => f.type === 'typosquatting-risk');
            expect(findings.length).toBeGreaterThan(0);
        });
    });

    // ─── Dependency Confusion Detection ──────────────────────────────

    describe('detectDependencyConfusion', () => {
        test('should flag unscoped internal-looking npm packages', () => {
            const depsByEcosystem = new Map([
                ['npm', new Set(['internal-auth', 'corp-utils'])]
            ]);

            detector.detectDependencyConfusion(depsByEcosystem, []);

            const findings = detector.findings.filter(f => f.type === 'dependency-confusion-risk');
            expect(findings.length).toBe(2);
            expect(findings[0].severity).toBe('HIGH');
        });

        test('should flag generic scoped packages', () => {
            const depsByEcosystem = new Map([
                ['npm', new Set(['@mycompany/utils'])]
            ]);

            detector.detectDependencyConfusion(depsByEcosystem, []);

            const findings = detector.findings.filter(f => f.type === 'dependency-confusion-risk');
            expect(findings.length).toBe(1);
            expect(findings[0].severity).toBe('MEDIUM');
        });

        test('should not flag well-known scoped packages', () => {
            const depsByEcosystem = new Map([
                ['npm', new Set(['@types/node', '@babel/core'])]
            ]);

            detector.detectDependencyConfusion(depsByEcosystem, []);

            const findings = detector.findings.filter(f => f.type === 'dependency-confusion-risk');
            expect(findings).toHaveLength(0);
        });

        test('should detect Python hyphen/underscore ambiguity', () => {
            const depsByEcosystem = new Map([
                ['pypi', new Set(['my-package', 'my_package'])]
            ]);

            detector.detectDependencyConfusion(depsByEcosystem, []);

            const findings = detector.findings.filter(f => f.type === 'dependency-confusion-risk');
            expect(findings.length).toBeGreaterThan(0);
        });

        test('should skip unsupported ecosystems', () => {
            const depsByEcosystem = new Map([
                ['cargo', new Set(['internal-auth'])]
            ]);

            detector.detectDependencyConfusion(depsByEcosystem, []);

            const findings = detector.findings.filter(f => f.type === 'dependency-confusion-risk');
            expect(findings).toHaveLength(0);
        });
    });

    // ─── Summary ─────────────────────────────────────────────────────

    describe('getSummary', () => {
        test('should return correct summary', () => {
            detector.findings = [
                { type: 'shadow-dependency', severity: 'MEDIUM' },
                { type: 'shadow-dependency', severity: 'MEDIUM' },
                { type: 'typosquatting-risk', severity: 'HIGH' },
                { type: 'dependency-confusion-risk', severity: 'HIGH' }
            ];

            const summary = detector.getSummary();
            expect(summary.total).toBe(4);
            expect(summary.byType['shadow-dependency']).toBe(2);
            expect(summary.byType['typosquatting-risk']).toBe(1);
            expect(summary.highSeverity).toBe(2);
        });

        test('should return zeros for empty findings', () => {
            const summary = detector.getSummary();
            expect(summary.total).toBe(0);
            expect(summary.highSeverity).toBe(0);
        });
    });

    // ─── JS Package Name Normalization ───────────────────────────────

    describe('normalizeJSPackageName', () => {
        test('should extract base package from subpath', () => {
            expect(detector.normalizeJSPackageName('lodash/merge')).toBe('lodash');
        });

        test('should handle scoped packages with subpaths', () => {
            expect(detector.normalizeJSPackageName('@scope/pkg/sub')).toBe('@scope/pkg');
        });

        test('should return plain package names unchanged', () => {
            expect(detector.normalizeJSPackageName('express')).toBe('express');
        });

        test('should handle scoped packages without subpath', () => {
            expect(detector.normalizeJSPackageName('@types/node')).toBe('@types/node');
        });
    });
});
