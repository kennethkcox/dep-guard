/**
 * Tests for DependencyResolver
 * Parser tests for lockfile formats (no external tool dependencies)
 */

const fs = require('fs');
const path = require('path');
const DependencyResolver = require('../src/utils/DependencyResolver');

describe('DependencyResolver', () => {
    let resolver;
    const fixtureDir = path.join(__dirname, 'fixtures', 'resolver-test');

    beforeEach(() => {
        resolver = new DependencyResolver({ timeout: 5000 });
        fs.mkdirSync(fixtureDir, { recursive: true });
    });

    afterEach(() => {
        fs.rmSync(fixtureDir, { recursive: true, force: true });
    });

    function createFile(relativePath, content) {
        const fullPath = path.join(fixtureDir, relativePath);
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, content);
        return fullPath;
    }

    // ─── Maven Dependency Tree Parser ────────────────────────────────

    describe('parseMavenDependencyTree', () => {
        test('should parse standard Maven dependency tree output', () => {
            // The parser regex matches [INFO] followed by a pipe/plus/dash char then whitespace
            const content = '[INFO] --- maven-dependency-plugin:3.6.0:tree ---\n' +
                '[INFO] com.example:myapp:jar:1.0\n' +
                '[INFO] | org.apache.shiro:shiro-core:jar:1.2.3:compile\n' +
                '[INFO] | com.google.guava:guava:jar:31.0:compile\n' +
                '[INFO] - junit:junit:jar:4.13:test\n';
            const deps = resolver.parseMavenDependencyTree(content);
            expect(deps.length).toBe(3);
            expect(deps[0].name).toBe('org.apache.shiro:shiro-core');
            expect(deps[0].version).toBe('1.2.3');
            expect(deps[0].ecosystem).toBe('maven');
            expect(deps[0].scope).toBe('compile');
        });

        test('should handle empty output', () => {
            const deps = resolver.parseMavenDependencyTree('');
            expect(deps).toHaveLength(0);
        });
    });

    // ─── npm Lockfile v1 Parser ──────────────────────────────────────

    describe('parseNpmLockfileV1', () => {
        test('should parse direct dependencies', () => {
            const result = [];
            resolver.parseNpmLockfileV1({
                'express': { version: '4.18.2' },
                'lodash': { version: '4.17.21' }
            }, result, false);

            expect(result.length).toBe(2);
            expect(result[0].name).toBe('express');
            expect(result[0].transitive).toBe(false);
        });

        test('should parse nested transitive dependencies', () => {
            const result = [];
            resolver.parseNpmLockfileV1({
                'express': {
                    version: '4.18.2',
                    dependencies: {
                        'accepts': { version: '1.3.8' },
                        'body-parser': { version: '1.20.1' }
                    }
                }
            }, result, false);

            expect(result.length).toBe(3);
            const transitive = result.filter(d => d.transitive);
            expect(transitive.length).toBe(2);
        });

        test('should mark dev dependencies', () => {
            const result = [];
            resolver.parseNpmLockfileV1({
                'jest': { version: '29.0.0', dev: true }
            }, result, false);

            expect(result[0].dev).toBe(true);
        });
    });

    // ─── npm Lockfile v2 Parser ──────────────────────────────────────

    describe('parseNpmLockfileV2', () => {
        test('should parse packages and skip root', () => {
            const result = [];
            resolver.parseNpmLockfileV2({
                '': { name: 'my-project', version: '1.0.0' },
                'node_modules/express': { version: '4.18.2' },
                'node_modules/lodash': { version: '4.17.21' }
            }, result);

            expect(result.length).toBe(2);
            expect(result[0].name).toBe('express');
            expect(result[0].transitive).toBe(false);
        });

        test('should detect transitive dependencies', () => {
            const result = [];
            resolver.parseNpmLockfileV2({
                '': { name: 'root' },
                'node_modules/express': { version: '4.18.2' },
                'node_modules/express/node_modules/accepts': { version: '1.3.8' }
            }, result);

            const transitive = result.filter(d => d.transitive);
            expect(transitive.length).toBe(1);
            expect(transitive[0].name).toBe('express');
        });

        test('should mark dev dependencies', () => {
            const result = [];
            resolver.parseNpmLockfileV2({
                '': { name: 'root' },
                'node_modules/jest': { version: '29.0.0', dev: true }
            }, result);

            expect(result[0].dev).toBe(true);
        });
    });

    // ─── npm ls Output Parser ────────────────────────────────────────

    describe('parseNpmLsOutput', () => {
        test('should parse npm ls JSON output', () => {
            const result = [];
            resolver.parseNpmLsOutput({
                'express': {
                    version: '4.18.2',
                    dependencies: {
                        'body-parser': { version: '1.20.1' }
                    }
                },
                'lodash': { version: '4.17.21' }
            }, result, false);

            expect(result.length).toBe(3);
            expect(result[0].name).toBe('express');
            expect(result[0].transitive).toBe(false);
            expect(result[1].name).toBe('body-parser');
            expect(result[1].transitive).toBe(true);
        });

        test('should skip entries without version', () => {
            const result = [];
            resolver.parseNpmLsOutput({
                'broken': {},
                'valid': { version: '1.0.0' }
            }, result, false);

            expect(result.length).toBe(1);
            expect(result[0].name).toBe('valid');
        });
    });

    // ─── Pipfile.lock Parser ─────────────────────────────────────────

    describe('parsePipfileLock', () => {
        test('should parse Pipfile.lock', () => {
            const lockfilePath = createFile('Pipfile.lock', JSON.stringify({
                default: {
                    'flask': { version: '==2.0.0' },
                    'requests': { version: '==2.28.0' }
                },
                develop: {
                    'pytest': { version: '==7.0.0' }
                }
            }));

            const deps = resolver.parsePipfileLock(lockfilePath);
            expect(deps.length).toBe(3);
            expect(deps[0].name).toBe('flask');
            expect(deps[0].version).toBe('2.0.0');
            expect(deps[0].ecosystem).toBe('pypi');
            expect(deps[2].dev).toBe(true);
        });

        test('should handle missing sections', () => {
            const lockfilePath = createFile('Pipfile.lock', JSON.stringify({
                default: {
                    'flask': { version: '==2.0.0' }
                }
            }));

            const deps = resolver.parsePipfileLock(lockfilePath);
            expect(deps.length).toBe(1);
        });
    });

    // ─── Poetry.lock Parser ──────────────────────────────────────────

    describe('parsePoetryLock', () => {
        test('should parse poetry.lock', () => {
            const lockfilePath = createFile('poetry.lock', `
[[package]]
name = "flask"
version = "2.0.0"

[[package]]
name = "requests"
version = "2.28.0"
`);

            const deps = resolver.parsePoetryLock(lockfilePath);
            expect(deps.length).toBe(2);
            expect(deps[0].name).toBe('flask');
            expect(deps[0].version).toBe('2.0.0');
            expect(deps[1].name).toBe('requests');
        });

        test('should handle empty lock file', () => {
            const lockfilePath = createFile('poetry.lock', '');
            const deps = resolver.parsePoetryLock(lockfilePath);
            expect(deps).toHaveLength(0);
        });
    });

    // ─── NuGet Parsers ───────────────────────────────────────────────

    describe('parseDotnetListOutput', () => {
        test('should parse JSON output with top-level and transitive', () => {
            const output = JSON.stringify({
                projects: [{
                    frameworks: [{
                        topLevelPackages: [
                            { id: 'Newtonsoft.Json', resolvedVersion: '13.0.1' }
                        ],
                        transitivePackages: [
                            { id: 'System.Text.Json', resolvedVersion: '6.0.0' }
                        ]
                    }]
                }]
            });

            const deps = resolver.parseDotnetListOutput(output);
            expect(deps.length).toBe(2);
            expect(deps[0].name).toBe('Newtonsoft.Json');
            expect(deps[0].transitive).toBe(false);
            expect(deps[1].name).toBe('System.Text.Json');
            expect(deps[1].transitive).toBe(true);
        });

        test('should handle empty projects', () => {
            const deps = resolver.parseDotnetListOutput(JSON.stringify({ projects: [] }));
            expect(deps).toHaveLength(0);
        });
    });

    describe('parseDotnetListTextOutput', () => {
        test('should parse text format output', () => {
            const output = `
Top-level Package               Requested         Resolved
> Newtonsoft.Json                13.0.1            13.0.1

Transitive Package              Resolved
> System.Text.Json               6.0.0
`;
            const deps = resolver.parseDotnetListTextOutput(output);
            expect(deps.length).toBe(2);
            expect(deps[0].name).toBe('Newtonsoft.Json');
            expect(deps[0].transitive).toBe(false);
            expect(deps[1].name).toBe('System.Text.Json');
            expect(deps[1].transitive).toBe(true);
        });
    });

    describe('resolveNuGetFromLockfile', () => {
        test('should parse packages.lock.json', () => {
            createFile('packages.lock.json', JSON.stringify({
                version: 1,
                dependencies: {
                    'net6.0': {
                        'Newtonsoft.Json': { type: 'Direct', resolved: '13.0.1' },
                        'System.Text.Json': { type: 'Transitive', resolved: '6.0.0' }
                    }
                }
            }));

            const deps = resolver.resolveNuGetFromLockfile(fixtureDir);
            expect(deps.length).toBe(2);
            expect(deps[0].transitive).toBe(false);
            expect(deps[1].transitive).toBe(true);
        });

        test('should return empty when no lockfile exists', () => {
            const deps = resolver.resolveNuGetFromLockfile('/nonexistent/path');
            expect(deps).toHaveLength(0);
        });
    });

    // ─── Rust (Cargo.lock) Parser ────────────────────────────────────

    describe('resolveRustDependencies', () => {
        test('should parse Cargo.lock', () => {
            createFile('Cargo.toml', '[package]\nname = "test"');
            createFile('Cargo.lock', `
[[package]]
name = "serde"
version = "1.0.188"

[[package]]
name = "tokio"
version = "1.32.0"
`);

            const manifestPath = path.join(fixtureDir, 'Cargo.toml');
            const deps = resolver.resolveRustDependencies(manifestPath);
            expect(deps.length).toBe(2);
            expect(deps[0].name).toBe('serde');
            expect(deps[0].version).toBe('1.0.188');
            expect(deps[0].ecosystem).toBe('cargo');
        });

        test('should return empty when no Cargo.lock', () => {
            createFile('Cargo.toml', '[package]\nname = "test"');
            const manifestPath = path.join(fixtureDir, 'Cargo.toml');
            const deps = resolver.resolveRustDependencies(manifestPath);
            expect(deps).toHaveLength(0);
        });
    });

    // ─── Ruby (Gemfile.lock) Parser ──────────────────────────────────

    describe('resolveRubyDependencies', () => {
        test('should parse Gemfile.lock', () => {
            createFile('Gemfile', "gem 'rails'");
            createFile('Gemfile.lock', `
GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.0.6)
    actionmailbox (7.0.6)
    rails (7.0.6)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.0)
`);

            const manifestPath = path.join(fixtureDir, 'Gemfile');
            const deps = resolver.resolveRubyDependencies(manifestPath);
            expect(deps.length).toBe(3);
            expect(deps[0].name).toBe('actioncable');
            expect(deps[0].version).toBe('7.0.6');
            expect(deps[0].ecosystem).toBe('rubygems');
        });

        test('should return empty when no Gemfile.lock', () => {
            createFile('Gemfile', "gem 'rails'");
            const manifestPath = path.join(fixtureDir, 'Gemfile');
            const deps = resolver.resolveRubyDependencies(manifestPath);
            expect(deps).toHaveLength(0);
        });
    });

    // ─── npm Dependencies from Lockfile ──────────────────────────────

    describe('resolveNpmDependencies', () => {
        test('should parse package-lock.json v1 format', () => {
            createFile('package.json', JSON.stringify({ name: 'test' }));
            createFile('package-lock.json', JSON.stringify({
                lockfileVersion: 1,
                dependencies: {
                    'express': { version: '4.18.2' },
                    'lodash': { version: '4.17.21' }
                }
            }));

            const manifestPath = path.join(fixtureDir, 'package.json');
            const deps = resolver.resolveNpmDependencies(manifestPath);
            expect(deps.length).toBe(2);
        });

        test('should parse package-lock.json v2 format', () => {
            createFile('package.json', JSON.stringify({ name: 'test' }));
            createFile('package-lock.json', JSON.stringify({
                lockfileVersion: 2,
                packages: {
                    '': { name: 'test', version: '1.0.0' },
                    'node_modules/express': { version: '4.18.2' }
                }
            }));

            const manifestPath = path.join(fixtureDir, 'package.json');
            const deps = resolver.resolveNpmDependencies(manifestPath);
            expect(deps.length).toBe(1);
            expect(deps[0].name).toBe('express');
        });
    });
});
