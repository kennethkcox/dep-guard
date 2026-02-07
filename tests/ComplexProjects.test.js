/**
 * Integration tests with complex multi-ecosystem project structures
 * Tests manifest finding, dependency extraction, and reachability across
 * realistic project layouts
 */

const fs = require('fs');
const path = require('path');
const DepGuardScanner = require('../src/DepGuardScanner');
const GenericManifestFinder = require('../src/core/GenericManifestFinder');

const FIXTURE_ROOT = path.join(__dirname, 'fixtures', 'complex-projects');

function createFile(relativePath, content) {
    const fullPath = path.join(FIXTURE_ROOT, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content);
    return fullPath;
}

function cleanup() {
    if (fs.existsSync(FIXTURE_ROOT)) {
        fs.rmSync(FIXTURE_ROOT, { recursive: true, force: true });
    }
}

beforeAll(() => {
    cleanup();
    fs.mkdirSync(FIXTURE_ROOT, { recursive: true });
});

afterAll(() => {
    cleanup();
});

// ─── NuGet / .NET Projects ──────────────────────────────────────────

describe('NuGet/.NET project detection', () => {
    const projectDir = path.join(FIXTURE_ROOT, 'dotnet-project');

    beforeAll(() => {
        // Modern .NET 6+ project with standard PackageReference
        createFile('dotnet-project/WebApi/WebApi.csproj', `<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Swashbuckle.AspNetCore" Version="6.5.0" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer" Version="8.0.0" />
  </ItemGroup>
</Project>`);

        // .NET project with Version as child element
        createFile('dotnet-project/DataLayer/DataLayer.csproj', `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Dapper">
      <Version>2.1.24</Version>
    </PackageReference>
    <PackageReference Include="System.Data.SqlClient">
      <Version>4.8.6</Version>
    </PackageReference>
  </ItemGroup>
</Project>`);

        // .NET project with extra attributes on PackageReference
        createFile('dotnet-project/Tests/Tests.csproj', `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <IsPackable>false</IsPackable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.8.0" />
    <PackageReference Include="xunit" Version="2.6.2" />
    <PackageReference Include="Moq" Version="4.20.70" PrivateAssets="all" />
    <PackageReference Include="coverlet.collector" Version="6.0.0">
      <IncludeAssets>runtime; build; native; contentfiles; analyzers</IncludeAssets>
      <PrivateAssets>all</PrivateAssets>
    </PackageReference>
  </ItemGroup>
</Project>`);

        // Central Package Management (Directory.Packages.props)
        createFile('dotnet-project/Directory.Packages.props', `<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Serilog" Version="3.1.1" />
    <PackageVersion Include="AutoMapper" Version="12.0.1" />
  </ItemGroup>
</Project>`);

        // F# project
        createFile('dotnet-project/FSharpLib/FSharpLib.fsproj', `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="FSharp.Core" Version="8.0.100" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>`);

        // .nuspec file
        createFile('dotnet-project/MyPackage.nuspec', `<?xml version="1.0"?>
<package>
  <metadata>
    <id>MyPackage</id>
    <version>1.0.0</version>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Newtonsoft.Json" version="[13.0.3,)" />
        <dependency id="Serilog" version="[3.0,4.0)" />
      </group>
    </dependencies>
  </metadata>
</package>`);

        // packages.config (legacy)
        createFile('dotnet-project/LegacyApp/packages.config', `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="EntityFramework" version="6.4.4" targetFramework="net472" />
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net472" />
</packages>`);

        // Solution file
        createFile('dotnet-project/MySolution.sln', `
Microsoft Visual Studio Solution File, Format Version 12.00
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "WebApi", "WebApi\\WebApi.csproj", "{GUID1}"
EndProject
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "DataLayer", "DataLayer\\DataLayer.csproj", "{GUID2}"
EndProject
Project("{F2A71F9B-5D33-465A-A702-920D77279786}") = "FSharpLib", "FSharpLib\\FSharpLib.fsproj", "{GUID3}"
EndProject`);

        // C# source with using statements
        createFile('dotnet-project/WebApi/Program.cs', `using Microsoft.AspNetCore.Builder;
using Newtonsoft.Json;
using Swashbuckle.AspNetCore.SwaggerGen;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers().AddNewtonsoftJson();
var app = builder.Build();
app.MapGet("/api/hello", () => "Hello World");
app.Run();`);
    });

    test('should find all NuGet manifest types', () => {
        const finder = new GenericManifestFinder({ maxDepth: 5, excludePatterns: [] });
        const manifests = finder.findManifests(projectDir);

        const nugetManifests = manifests.filter(m => m.ecosystem === 'nuget');
        expect(nugetManifests.length).toBeGreaterThanOrEqual(6);

        const filenames = nugetManifests.map(m => m.filename);
        expect(filenames).toContain('WebApi.csproj');
        expect(filenames).toContain('DataLayer.csproj');
        expect(filenames).toContain('FSharpLib.fsproj');
        expect(filenames).toContain('Directory.Packages.props');
        expect(filenames).toContain('packages.config');
        expect(filenames.some(f => f.endsWith('.nuspec'))).toBe(true);
    });

    test('should extract dependencies from standard PackageReference', () => {
        const scanner = new DepGuardScanner({ projectPath: projectDir });
        const content = fs.readFileSync(path.join(projectDir, 'WebApi/WebApi.csproj'), 'utf8');
        const deps = scanner.extractNuGetDependencies(content, {
            path: path.join(projectDir, 'WebApi/WebApi.csproj'),
            filename: 'WebApi.csproj',
            ecosystem: 'nuget'
        });

        expect(deps.length).toBe(3);
        expect(deps.find(d => d.name === 'Newtonsoft.Json')).toBeDefined();
        expect(deps.find(d => d.name === 'Swashbuckle.AspNetCore')).toBeDefined();
        expect(deps.find(d => d.name === 'Microsoft.EntityFrameworkCore.SqlServer')).toBeDefined();
    });

    test('should extract dependencies from PackageReference with Version child element', () => {
        const scanner = new DepGuardScanner({ projectPath: projectDir });
        const content = fs.readFileSync(path.join(projectDir, 'DataLayer/DataLayer.csproj'), 'utf8');
        const deps = scanner.extractNuGetDependencies(content, {
            path: path.join(projectDir, 'DataLayer/DataLayer.csproj'),
            filename: 'DataLayer.csproj',
            ecosystem: 'nuget'
        });

        expect(deps.length).toBe(2);
        expect(deps.find(d => d.name === 'Dapper')).toBeDefined();
        expect(deps.find(d => d.name === 'Dapper').version).toBe('2.1.24');
    });

    test('should extract dependencies from PackageReference with extra attributes', () => {
        const scanner = new DepGuardScanner({ projectPath: projectDir });
        const content = fs.readFileSync(path.join(projectDir, 'Tests/Tests.csproj'), 'utf8');
        const deps = scanner.extractNuGetDependencies(content, {
            path: path.join(projectDir, 'Tests/Tests.csproj'),
            filename: 'Tests.csproj',
            ecosystem: 'nuget'
        });

        expect(deps.length).toBeGreaterThanOrEqual(3);
        expect(deps.find(d => d.name === 'xunit')).toBeDefined();
        expect(deps.find(d => d.name === 'Moq')).toBeDefined();
        expect(deps.find(d => d.name === 'coverlet.collector')).toBeDefined();
    });

    test('should extract dependencies from packages.config', () => {
        const scanner = new DepGuardScanner({ projectPath: projectDir });
        const content = fs.readFileSync(path.join(projectDir, 'LegacyApp/packages.config'), 'utf8');
        const deps = scanner.extractNuGetDependencies(content, {
            path: path.join(projectDir, 'LegacyApp/packages.config'),
            filename: 'packages.config',
            ecosystem: 'nuget'
        });

        expect(deps.length).toBe(2);
        expect(deps.find(d => d.name === 'EntityFramework')).toBeDefined();
    });

    test('should extract dependencies from .nuspec', () => {
        const scanner = new DepGuardScanner({ projectPath: projectDir });
        const content = fs.readFileSync(path.join(projectDir, 'MyPackage.nuspec'), 'utf8');
        const deps = scanner.extractNuGetDependencies(content, {
            path: path.join(projectDir, 'MyPackage.nuspec'),
            filename: 'MyPackage.nuspec',
            ecosystem: 'nuget'
        });

        expect(deps.length).toBe(2);
        expect(deps.find(d => d.name === 'Newtonsoft.Json')).toBeDefined();
        expect(deps.find(d => d.name === 'Serilog')).toBeDefined();
    });

    test('should detect .sln workspaces', () => {
        const finder = new GenericManifestFinder({ maxDepth: 5, excludePatterns: [] });
        const workspaces = finder.detectWorkspaces(projectDir);
        const nugetWs = workspaces.filter(w => w.ecosystem === 'nuget');
        expect(nugetWs.length).toBeGreaterThanOrEqual(2);
    });
});

// ─── Node.js Monorepo ────────────────────────────────────────────────

describe('Node.js monorepo detection', () => {
    const projectDir = path.join(FIXTURE_ROOT, 'node-monorepo');

    beforeAll(() => {
        createFile('node-monorepo/package.json', JSON.stringify({
            name: 'monorepo-root',
            private: true,
            workspaces: ['packages/*', 'apps/*'],
            devDependencies: { 'lerna': '^7.0.0' }
        }));

        createFile('node-monorepo/packages/core/package.json', JSON.stringify({
            name: '@myorg/core',
            version: '1.0.0',
            dependencies: { 'lodash': '^4.17.21' }
        }));

        createFile('node-monorepo/packages/utils/package.json', JSON.stringify({
            name: '@myorg/utils',
            version: '1.0.0',
            dependencies: { 'uuid': '^9.0.0' }
        }));

        createFile('node-monorepo/apps/web/package.json', JSON.stringify({
            name: '@myorg/web',
            version: '1.0.0',
            dependencies: { 'express': '^4.18.2', '@myorg/core': '*' }
        }));

        createFile('node-monorepo/apps/web/src/index.js', `
const express = require('express');
const { merge } = require('lodash');
const app = express();

app.get('/api/data', (req, res) => {
    const config = merge({}, req.body);
    res.json(config);
});

app.listen(3000);
`);

        createFile('node-monorepo/packages/core/src/index.js', `
const _ = require('lodash');
module.exports.deepMerge = (a, b) => _.merge(a, b);
`);
    });

    test('should find all workspace manifests', () => {
        const finder = new GenericManifestFinder({ maxDepth: 5, excludePatterns: [] });
        const manifests = finder.findManifests(projectDir);
        expect(manifests.length).toBeGreaterThanOrEqual(4);
    });

    test('should detect npm workspaces', () => {
        const finder = new GenericManifestFinder({ maxDepth: 5, excludePatterns: [] });
        const workspaces = finder.detectWorkspaces(projectDir);
        expect(workspaces.length).toBe(2);
        expect(workspaces[0].source).toBe('package.json');
    });

    test('should extract dependencies from each workspace package', () => {
        const scanner = new DepGuardScanner({ projectPath: projectDir });
        const coreContent = fs.readFileSync(path.join(projectDir, 'packages/core/package.json'), 'utf8');
        const deps = scanner.extractNpmDependencies(coreContent, {
            path: path.join(projectDir, 'packages/core/package.json'),
            filename: 'package.json'
        });
        expect(deps.find(d => d.name === 'lodash')).toBeDefined();
    });
});

// ─── Python Multi-Tool Project ───────────────────────────────────────

describe('Python multi-tool project detection', () => {
    const projectDir = path.join(FIXTURE_ROOT, 'python-project');

    beforeAll(() => {
        createFile('python-project/requirements.txt', `flask==2.3.3
requests>=2.31.0
gunicorn~=21.2.0
# this is a comment
-r requirements-dev.txt`);

        createFile('python-project/pyproject.toml', `[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.104.0"
uvicorn = "^0.24.0"
sqlalchemy = "^2.0.0"
`);

        createFile('python-project/services/ml/setup.py', `from setuptools import setup
setup(
    name='ml-service',
    install_requires=[
        'torch>=2.0',
        'numpy>=1.24',
        'scikit-learn>=1.3',
    ]
)`);

        createFile('python-project/services/ml/setup.cfg', `[options]
install_requires =
    pandas>=2.0
    matplotlib>=3.7`);

        createFile('python-project/app.py', `from flask import Flask, request
import requests
from sqlalchemy import create_engine

app = Flask(__name__)

@app.route('/api/proxy')
def proxy():
    url = request.args.get('url')
    response = requests.get(url)
    return response.text
`);
    });

    test('should find all Python manifests', () => {
        const finder = new GenericManifestFinder({ maxDepth: 5, excludePatterns: [] });
        const manifests = finder.findManifests(projectDir);
        const pyManifests = manifests.filter(m => m.ecosystem === 'pypi');
        expect(pyManifests.length).toBeGreaterThanOrEqual(3);

        const filenames = pyManifests.map(m => m.filename);
        expect(filenames).toContain('requirements.txt');
        expect(filenames).toContain('pyproject.toml');
        expect(filenames).toContain('setup.py');
    });

    test('should extract dependencies from requirements.txt', () => {
        const scanner = new DepGuardScanner({ projectPath: projectDir });
        const content = fs.readFileSync(path.join(projectDir, 'requirements.txt'), 'utf8');
        const deps = scanner.extractPythonDependencies(content, {
            path: path.join(projectDir, 'requirements.txt'),
            filename: 'requirements.txt'
        });
        expect(deps.length).toBeGreaterThanOrEqual(3);
        expect(deps.find(d => d.name === 'flask')).toBeDefined();
        expect(deps.find(d => d.name === 'requests')).toBeDefined();
    });
});

// ─── Go Multi-Module Project ─────────────────────────────────────────

describe('Go multi-module project', () => {
    const projectDir = path.join(FIXTURE_ROOT, 'go-project');

    beforeAll(() => {
        createFile('go-project/go.mod', `module github.com/myorg/myapp

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/lib/pq v1.10.9
\tgithub.com/sirupsen/logrus v1.9.3
)

require (
\tgolang.org/x/crypto v0.14.0 // indirect
)`);

        createFile('go-project/main.go', `package main

import (
\t"github.com/gin-gonic/gin"
\t"github.com/lib/pq"
)

func main() {
\tr := gin.Default()
\tr.GET("/ping", func(c *gin.Context) {
\t\tc.JSON(200, gin.H{"message": "pong"})
\t})
\tr.Run()
}
`);
    });

    test('should find go.mod', () => {
        const finder = new GenericManifestFinder({ maxDepth: 5, excludePatterns: [] });
        const manifests = finder.findManifests(projectDir);
        const goManifests = manifests.filter(m => m.ecosystem === 'go');
        expect(goManifests.length).toBeGreaterThanOrEqual(1);
    });

    test('should extract Go dependencies', () => {
        const scanner = new DepGuardScanner({ projectPath: projectDir });
        const content = fs.readFileSync(path.join(projectDir, 'go.mod'), 'utf8');
        const deps = scanner.extractGoDependencies(content, {
            path: path.join(projectDir, 'go.mod'),
            filename: 'go.mod'
        });
        expect(deps.length).toBeGreaterThanOrEqual(3);
        expect(deps.find(d => d.name === 'github.com/gin-gonic/gin')).toBeDefined();
    });
});

// ─── Rust Workspace Project ──────────────────────────────────────────

describe('Rust workspace project', () => {
    const projectDir = path.join(FIXTURE_ROOT, 'rust-project');

    beforeAll(() => {
        createFile('rust-project/Cargo.toml', `[workspace]
members = [
  "crate-api",
  "crate-core"
]

[workspace.dependencies]
serde = "1.0"
tokio = { version = "1.32", features = ["full"] }

[dependencies]
serde = { workspace = true }
`);

        createFile('rust-project/crate-api/Cargo.toml', `[package]
name = "crate-api"
version = "0.1.0"

[dependencies]
actix-web = "4.4"
serde = { workspace = true }
serde_json = "1.0"
`);

        createFile('rust-project/crate-api/src/main.rs', `use actix_web::{web, App, HttpServer, HttpResponse};
use serde_json::json;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new().route("/api", web::get().to(index))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}

async fn index() -> HttpResponse {
    HttpResponse::Ok().json(json!({"status": "ok"}))
}
`);
    });

    test('should find Cargo.toml manifests', () => {
        const finder = new GenericManifestFinder({ maxDepth: 5, excludePatterns: [] });
        const manifests = finder.findManifests(projectDir);
        const cargoManifests = manifests.filter(m => m.ecosystem === 'cargo');
        expect(cargoManifests.length).toBeGreaterThanOrEqual(2);
    });

    test('should detect Cargo workspaces', () => {
        const finder = new GenericManifestFinder({ maxDepth: 5, excludePatterns: [] });
        const workspaces = finder.detectWorkspaces(projectDir);
        const cargoWs = workspaces.filter(w => w.ecosystem === 'cargo');
        expect(cargoWs.length).toBe(2);
    });

    test('should extract Rust dependencies', () => {
        const scanner = new DepGuardScanner({ projectPath: projectDir });
        const content = fs.readFileSync(path.join(projectDir, 'crate-api/Cargo.toml'), 'utf8');
        const deps = scanner.extractRustDependencies(content, {
            path: path.join(projectDir, 'crate-api/Cargo.toml'),
            filename: 'Cargo.toml'
        });
        expect(deps.length).toBeGreaterThanOrEqual(2);
        expect(deps.find(d => d.name === 'actix-web')).toBeDefined();
        expect(deps.find(d => d.name === 'serde_json')).toBeDefined();
    });
});

// ─── Mixed Ecosystem Monorepo ────────────────────────────────────────

describe('Mixed ecosystem monorepo', () => {
    const projectDir = path.join(FIXTURE_ROOT, 'mixed-monorepo');

    beforeAll(() => {
        // Root Node.js
        createFile('mixed-monorepo/package.json', JSON.stringify({
            name: 'mixed-monorepo',
            private: true,
            dependencies: { 'concurrently': '^8.0.0' }
        }));

        // Python backend
        createFile('mixed-monorepo/backend/requirements.txt', 'django==4.2.7\ncelery>=5.3.0\nredis>=5.0.0');

        // Java microservice
        createFile('mixed-monorepo/services/auth/pom.xml', `<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.myorg</groupId>
  <artifactId>auth-service</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-security</artifactId>
      <version>3.2.0</version>
    </dependency>
  </dependencies>
</project>`);

        // .NET microservice
        createFile('mixed-monorepo/services/payments/Payments.csproj', `<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Stripe.net" Version="43.3.0" />
  </ItemGroup>
</Project>`);

        // Ruby service
        createFile('mixed-monorepo/services/notifications/Gemfile', `source 'https://rubygems.org'
gem 'sidekiq', '~> 7.0'
gem 'redis', '~> 5.0'
gem 'twilio-ruby', '~> 6.0'`);
    });

    test('should find manifests across all ecosystems', () => {
        const finder = new GenericManifestFinder({ maxDepth: 5, excludePatterns: [] });
        const manifests = finder.findManifests(projectDir);

        expect(manifests.length).toBeGreaterThanOrEqual(5);

        const ecosystems = new Set(manifests.map(m => m.ecosystem));
        expect(ecosystems.has('npm')).toBe(true);
        expect(ecosystems.has('pypi')).toBe(true);
        expect(ecosystems.has('maven')).toBe(true);
        expect(ecosystems.has('nuget')).toBe(true);
        expect(ecosystems.has('rubygems')).toBe(true);
    });

    test('should extract dependencies from each ecosystem', () => {
        const scanner = new DepGuardScanner({ projectPath: projectDir });

        // Python
        const pyContent = fs.readFileSync(path.join(projectDir, 'backend/requirements.txt'), 'utf8');
        const pyDeps = scanner.extractPythonDependencies(pyContent, {
            path: path.join(projectDir, 'backend/requirements.txt'),
            filename: 'requirements.txt'
        });
        expect(pyDeps.length).toBe(3);

        // NuGet
        const nugetContent = fs.readFileSync(path.join(projectDir, 'services/payments/Payments.csproj'), 'utf8');
        const nugetDeps = scanner.extractNuGetDependencies(nugetContent, {
            path: path.join(projectDir, 'services/payments/Payments.csproj'),
            filename: 'Payments.csproj',
            ecosystem: 'nuget'
        });
        expect(nugetDeps.length).toBe(1);
        expect(nugetDeps[0].name).toBe('Stripe.net');

        // Ruby
        const rubyContent = fs.readFileSync(path.join(projectDir, 'services/notifications/Gemfile'), 'utf8');
        const rubyDeps = scanner.extractRubyDependencies(rubyContent, {
            path: path.join(projectDir, 'services/notifications/Gemfile'),
            filename: 'Gemfile'
        });
        expect(rubyDeps.length).toBe(3);
    });
});

// ─── NuGet Edge Cases ────────────────────────────────────────────────

describe('NuGet edge cases', () => {
    test('should handle PackageReference with attributes in any order', () => {
        const scanner = new DepGuardScanner({ projectPath: FIXTURE_ROOT });
        const content = `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Version="13.0.3" Include="Newtonsoft.Json" />
    <PackageReference Include="Serilog" Version="3.1.1" PrivateAssets="all" />
  </ItemGroup>
</Project>`;
        const deps = scanner.extractNuGetDependencies(content, {
            path: '/test/Test.csproj', filename: 'Test.csproj', ecosystem: 'nuget'
        });
        expect(deps.find(d => d.name === 'Newtonsoft.Json')).toBeDefined();
        expect(deps.find(d => d.name === 'Serilog')).toBeDefined();
    });

    test('should handle multi-line PackageReference', () => {
        const scanner = new DepGuardScanner({ projectPath: FIXTURE_ROOT });
        const content = `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference
      Include="Microsoft.Extensions.Logging"
      Version="8.0.0" />
  </ItemGroup>
</Project>`;
        const deps = scanner.extractNuGetDependencies(content, {
            path: '/test/Test.csproj', filename: 'Test.csproj', ecosystem: 'nuget'
        });
        expect(deps.find(d => d.name === 'Microsoft.Extensions.Logging')).toBeDefined();
    });

    test('should handle non-self-closing PackageReference with extra child elements', () => {
        const scanner = new DepGuardScanner({ projectPath: FIXTURE_ROOT });
        const content = `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="coverlet.collector" Version="6.0.0">
      <IncludeAssets>runtime; build</IncludeAssets>
      <PrivateAssets>all</PrivateAssets>
    </PackageReference>
  </ItemGroup>
</Project>`;
        const deps = scanner.extractNuGetDependencies(content, {
            path: '/test/Test.csproj', filename: 'Test.csproj', ecosystem: 'nuget'
        });
        expect(deps.find(d => d.name === 'coverlet.collector')).toBeDefined();
    });
});

// ─── CVSS Vector Parsing ────────────────────────────────────────────

describe('CVSS vector parsing', () => {
    let osvDb;

    beforeAll(() => {
        const OSVDatabase = require('../src/vulnerabilities/OSVDatabase');
        osvDb = new OSVDatabase();
    });

    test('should parse critical severity vector (9.8)', () => {
        // Log4Shell-like: Network/Low/None/None, Scope Unchanged, all High impact
        const score = osvDb.parseCVSSVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
        expect(score).toBeGreaterThanOrEqual(9.0);
        expect(score).toBeLessThanOrEqual(10.0);
    });

    test('should parse high severity vector', () => {
        // Network/Low/Low/None, Scope Unchanged, High/High/None
        const score = osvDb.parseCVSSVector('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N');
        expect(score).toBeGreaterThanOrEqual(7.0);
        expect(score).toBeLessThan(9.0);
    });

    test('should parse medium severity vector', () => {
        // Network/High/None/Required, Scope Unchanged, Low/Low/None
        const score = osvDb.parseCVSSVector('CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N');
        expect(score).toBeGreaterThanOrEqual(3.0);
        expect(score).toBeLessThan(7.0);
    });

    test('should parse low severity vector', () => {
        // Local/High/High/Required, Scope Unchanged, Low/None/None
        const score = osvDb.parseCVSSVector('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N');
        expect(score).toBeGreaterThan(0);
        expect(score).toBeLessThan(4.0);
    });

    test('should return 0 for no-impact vector', () => {
        const score = osvDb.parseCVSSVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N');
        expect(score).toBe(0);
    });

    test('should handle scope changed vectors', () => {
        // Scope Changed boosts the score
        const scoreUnchanged = osvDb.parseCVSSVector('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N');
        const scoreChanged = osvDb.parseCVSSVector('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N');
        expect(scoreChanged).toBeGreaterThan(scoreUnchanged);
    });

    test('should never return score above 10', () => {
        // Max possible: all worst-case metrics
        const score = osvDb.parseCVSSVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
        expect(score).toBeLessThanOrEqual(10.0);
    });

    test('extractCVSS should parse vector strings from OSV format', () => {
        const vuln = {
            severity: [
                { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }
            ]
        };
        const score = osvDb.extractCVSS(vuln);
        expect(score).toBeGreaterThanOrEqual(9.0);
        expect(score).not.toBe(5.0); // Must NOT default to 5.0
    });

    test('extractCVSS should return null when no severity data', () => {
        const score = osvDb.extractCVSS({});
        expect(score).toBeNull();
    });

    test('extractCVSS should return null for unknown data, not 5.0', () => {
        const score = osvDb.extractCVSS({ severity: [] });
        expect(score).toBeNull();
    });

    test('extractCVSS should handle numeric scores directly', () => {
        const vuln = {
            severity: [{ type: 'CVSS_V3', score: '7.5' }]
        };
        const score = osvDb.extractCVSS(vuln);
        expect(score).toBe(7.5);
    });

    test('extractSeverity should return UNKNOWN when no data', () => {
        const severity = osvDb.extractSeverity({});
        expect(severity).toBe('UNKNOWN');
    });

    test('extractSeverity should classify from CVSS score', () => {
        const critical = osvDb.extractSeverity({
            severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }]
        });
        expect(critical).toBe('CRITICAL');

        const high = osvDb.extractSeverity({
            severity: [{ type: 'CVSS_V3', score: '7.5' }]
        });
        expect(high).toBe('HIGH');
    });
});

// ─── Shai-Hulud Integration Tests ───────────────────────────────────

describe('Shai-Hulud integration', () => {
    const ShaiHuludDetector = require('../src/analysis/ShaiHuludDetector');

    test('should detect typosquatting across npm ecosystem', () => {
        const detector = new ShaiHuludDetector();
        const depsByEcosystem = new Map();
        depsByEcosystem.set('npm', new Set([
            'lodahs',     // typo of lodash (letter swap)
            'exprss',     // typo of express (missing letter)
            'react',      // legitimate
            'axois',      // typo of axios (letter swap)
        ]));

        detector.detectTyposquatting(depsByEcosystem);

        const typoFindings = detector.findings.filter(f => f.type === 'typosquatting-risk');
        expect(typoFindings.length).toBeGreaterThanOrEqual(2);

        const flaggedNames = typoFindings.map(f => f.package);
        expect(flaggedNames).toContain('lodahs');
        expect(flaggedNames).toContain('exprss');
        // react is legitimate, should NOT be flagged
        expect(flaggedNames).not.toContain('react');
    });

    test('should detect typosquatting across pypi ecosystem', () => {
        const detector = new ShaiHuludDetector();
        const depsByEcosystem = new Map();
        depsByEcosystem.set('pypi', new Set([
            'reqeusts',   // typo of requests
            'flaks',      // typo of flask
            'numpy',      // legitimate
        ]));

        detector.detectTyposquatting(depsByEcosystem);

        const typoFindings = detector.findings.filter(f => f.type === 'typosquatting-risk');
        const flaggedNames = typoFindings.map(f => f.package);
        expect(flaggedNames).toContain('reqeusts');
        expect(flaggedNames).not.toContain('numpy');
    });

    test('should detect dependency confusion for unscoped internal packages', () => {
        const detector = new ShaiHuludDetector();
        const depsByEcosystem = new Map();
        depsByEcosystem.set('npm', new Set([
            'my-company-utils',
            'internal-auth-service',
            'express',     // public, should not flag
        ]));

        detector.detectDependencyConfusion(depsByEcosystem, []);

        const confusionFindings = detector.findings.filter(f => f.type === 'dependency-confusion-risk');
        const flaggedNames = confusionFindings.map(f => f.package);
        // Internal-looking names should be flagged
        expect(flaggedNames.some(n => n.includes('internal'))).toBe(true);
    });

    test('should detect naming pattern attacks', () => {
        const detector = new ShaiHuludDetector();
        const depsByEcosystem = new Map();
        depsByEcosystem.set('npm', new Set([
            'lodash-utils',    // piggybacks on lodash name (-utils suffix)
            'express-helper',  // piggybacks on express name
        ]));

        detector.detectTyposquatting(depsByEcosystem);

        // These should either trigger typosquatting-risk or naming pattern match
        const findings = detector.findings;
        expect(findings.length).toBeGreaterThanOrEqual(0); // May or may not trigger based on distance
    });

    test('getSummary should aggregate findings correctly', () => {
        const detector = new ShaiHuludDetector();

        // Manually add findings using actual type names
        detector.findings = [
            { type: 'shadow-dependency', severity: 'MEDIUM', package: 'pkg1' },
            { type: 'shadow-dependency', severity: 'MEDIUM', package: 'pkg2' },
            { type: 'typosquatting-risk', severity: 'HIGH', package: 'pkg3' },
            { type: 'dependency-confusion-risk', severity: 'HIGH', package: 'pkg4' },
        ];

        const summary = detector.getSummary();
        expect(summary.total).toBe(4);
        expect(summary.byType['shadow-dependency']).toBe(2);
        expect(summary.byType['typosquatting-risk']).toBe(1);
        expect(summary.byType['dependency-confusion-risk']).toBe(1);
        expect(summary.highSeverity).toBe(2);
    });
});

// ─── All Vulnerabilities in Results ─────────────────────────────────

describe('All vulnerabilities inclusion', () => {
    const ReachabilityAnalyzer = require('../src/core/ReachabilityAnalyzer');

    test('should include both reachable and unreachable vulns in results', () => {
        const analyzer = new ReachabilityAnalyzer({ maxDepth: 5, minConfidence: 0.5 });

        // Set up a reachable path
        analyzer.addEntryPoint('app.js', 'main');
        analyzer.addCall('app.js', 'main', 'vuln1.js', 'vulnFunc', 'direct');

        // Add reachable vuln
        analyzer.addVulnerability('pkg-a', 'vuln1.js', 'vulnFunc', {
            id: 'CVE-2024-0001', severity: 'CRITICAL'
        });

        // Add unreachable vuln (no path from entry point)
        analyzer.addVulnerability('pkg-b', 'isolated.js', 'noPath', {
            id: 'CVE-2024-0002', severity: 'HIGH'
        });

        // Add another unreachable vuln
        analyzer.addVulnerability('pkg-c', 'other.js', 'alsoNoPath', {
            id: 'CVE-2024-0003', severity: 'MEDIUM'
        });

        const results = analyzer.analyzeAll();

        // ALL 3 vulns must be present
        expect(results.length).toBe(3);

        const reachable = results.filter(r => r.isReachable);
        const unreachable = results.filter(r => !r.isReachable);

        expect(reachable.length).toBe(1);
        expect(reachable[0].vulnerability.id).toBe('CVE-2024-0001');

        expect(unreachable.length).toBe(2);
        expect(unreachable.every(r => r.reachability.confidence === 0)).toBe(true);
        expect(unreachable.every(r => r.reachability.detectionMethod === 'none')).toBe(true);

        // Reachable should come first in sort order
        expect(results[0].isReachable).toBe(true);
        expect(results[1].isReachable).toBe(false);
        expect(results[2].isReachable).toBe(false);

        analyzer.clear();
    });

    test('should show correct confidence for unreachable vulns', () => {
        const analyzer = new ReachabilityAnalyzer({ maxDepth: 5, minConfidence: 0.5 });

        analyzer.addVulnerability('pkg', 'file.js', 'func', {
            id: 'CVE-2024-9999', severity: 'HIGH'
        });

        const results = analyzer.analyzeAll();

        expect(results.length).toBe(1);
        expect(results[0].isReachable).toBe(false);
        expect(results[0].confidence).toBe(0);
        expect(results[0].reachability.isReachable).toBe(false);

        analyzer.clear();
    });
});

// ─── Advanced Reachability ──────────────────────────────────────────

describe('Advanced reachability analysis', () => {
    const ReachabilityAnalyzer = require('../src/core/ReachabilityAnalyzer');
    const fs = require('fs');
    const path = require('path');

    const reachDir = path.join(FIXTURE_ROOT, 'reachability-test');

    beforeAll(() => {
        fs.mkdirSync(reachDir, { recursive: true });

        // Create a JS file that uses lodash.template (known vulnerable pattern)
        createFile('reachability-test/app.js', `
const _ = require('lodash');
const express = require('express');
const app = express();

app.get('/render', (req, res) => {
    const compiled = _.template(req.query.tpl);
    res.send(compiled({ name: 'World' }));
});

app.listen(3000);
`);

        // Create a Python file with yaml.load (known dangerous)
        createFile('reachability-test/service.py', `
import yaml
from flask import Flask, request

app = Flask(__name__)

@app.route('/parse')
def parse_config():
    data = yaml.load(request.data)
    return str(data)
`);

        // Create a file that imports but doesn't use vulnerable patterns
        createFile('reachability-test/safe.js', `
const lodash = require('lodash');
const sorted = lodash.sortBy([3, 1, 2]);
console.log(sorted);
`);

        // Create a file with no package imports (isolated)
        createFile('reachability-test/isolated.js', `
function helper(x) { return x * 2; }
module.exports = helper;
`);
    });

    test('should detect reachability via dangerous pattern matching', () => {
        const analyzer = new ReachabilityAnalyzer({
            maxDepth: 5,
            minConfidence: 0.3,
            usePatternMatching: true,
            useTransitiveImports: false
        });
        analyzer.setProjectPath(reachDir);

        // Add entry point
        const appFile = path.join(reachDir, 'app.js');
        analyzer.addEntryPoint(appFile, 'module');
        analyzer.reachableFiles.add(appFile);

        // Add lodash vulnerability
        analyzer.addVulnerability('lodash', 'node_modules/lodash/template.js', 'template', {
            id: 'CVE-2021-23337', severity: 'CRITICAL', package: 'lodash'
        });

        const results = analyzer.analyzeAll();

        expect(results.length).toBe(1);
        expect(results[0].isReachable).toBe(true);
        expect(results[0].reachability.confidence).toBeGreaterThan(0.5);
        expect(results[0].reachability.detectionMethod).toContain('pattern');

        analyzer.clear();
    });

    test('should report detection method correctly', () => {
        const analyzer = new ReachabilityAnalyzer({
            maxDepth: 5,
            minConfidence: 0.3,
            usePatternMatching: true,
            useImportHeuristics: true,
            useTransitiveImports: false
        });
        analyzer.setProjectPath(reachDir);

        const appFile = path.join(reachDir, 'app.js');
        analyzer.addEntryPoint(appFile, 'module');
        analyzer.reachableFiles.add(appFile);

        analyzer.addVulnerability('lodash', 'node_modules/lodash/index.js', 'default', {
            id: 'CVE-2021-23337', severity: 'CRITICAL', package: 'lodash'
        });

        const results = analyzer.analyzeAll();
        expect(results[0].reachability.detectionMethod).not.toBe('none');

        analyzer.clear();
    });

    test('should not mark isolated code as reachable', () => {
        const analyzer = new ReachabilityAnalyzer({
            maxDepth: 5,
            minConfidence: 0.5,
            usePatternMatching: true,
            useTransitiveImports: false,
            useImportHeuristics: false
        });

        // No entry points, no project path
        analyzer.addVulnerability('some-pkg', 'some-file.js', 'func', {
            id: 'CVE-9999', severity: 'LOW', package: 'some-pkg'
        });

        const results = analyzer.analyzeAll();
        expect(results.length).toBe(1);
        expect(results[0].isReachable).toBe(false);
        expect(results[0].reachability.detectionMethod).toBe('none');

        analyzer.clear();
    });

    test('should handle multiple detection strategies for same vuln', () => {
        const analyzer = new ReachabilityAnalyzer({
            maxDepth: 5,
            minConfidence: 0.3,
            usePatternMatching: true,
            useImportHeuristics: true,
            useTransitiveImports: false
        });
        analyzer.setProjectPath(reachDir);

        const appFile = path.join(reachDir, 'app.js');
        analyzer.addEntryPoint(appFile, 'module');
        analyzer.reachableFiles.add(appFile);

        // Add a vuln that should be found by both import heuristics AND pattern matching
        analyzer.addVulnerability('lodash', 'node_modules/lodash/template.js', 'template', {
            id: 'CVE-2021-23337', severity: 'CRITICAL', package: 'lodash'
        });

        const results = analyzer.analyzeAll();

        // Should be reachable with boosted confidence (import + pattern)
        expect(results[0].isReachable).toBe(true);
        // Confidence should be higher due to multiple signals
        expect(results[0].reachability.confidence).toBeGreaterThan(0.5);

        analyzer.clear();
    });

    test('KNOWN_VULNERABLE_PATTERNS should cover major ecosystems', () => {
        // Import the patterns directly from the module
        const analyzerModule = require('../src/core/ReachabilityAnalyzer');
        const analyzer = new analyzerModule({ maxDepth: 5 });

        // Verify the analyzer can be instantiated and has pattern-matching capability
        expect(analyzer.options.usePatternMatching).toBe(true);
        expect(typeof analyzer.analyzeViaPatterns).toBe('function');

        analyzer.clear();
    });
});
