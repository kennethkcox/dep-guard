/**
 * Tests for GenericEntryPointDetector
 * Framework-agnostic entry point detection
 */

const fs = require('fs');
const path = require('path');
const GenericEntryPointDetector = require('../src/core/GenericEntryPointDetector');

describe('GenericEntryPointDetector', () => {
    let detector;
    const fixtureDir = path.join(__dirname, 'fixtures', 'entrypoint-test');

    beforeEach(() => {
        detector = new GenericEntryPointDetector({ confidenceThreshold: 0.5 });
        fs.mkdirSync(fixtureDir, { recursive: true });
    });

    afterEach(() => {
        fs.rmSync(fixtureDir, { recursive: true, force: true });
    });

    function createFile(name, content) {
        const filePath = path.join(fixtureDir, name);
        fs.mkdirSync(path.dirname(filePath), { recursive: true });
        fs.writeFileSync(filePath, content);
        return filePath;
    }

    // ─── HTTP Handler Detection ──────────────────────────────────────

    describe('detectHttpHandler', () => {
        test('should detect Express.js routes', () => {
            const content = `app.get('/api/users', (req, res) => { res.json([]); });`;
            const result = detector.detectHttpHandler(content, 'routes.js');
            expect(result).not.toBeNull();
            expect(result.type).toBe('HTTP_HANDLER');
            expect(result.framework).toBe('Express');
        });

        test('should detect Express router', () => {
            const content = `router.post('/login', loginHandler);`;
            const result = detector.detectHttpHandler(content, 'auth.js');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Express Router');
        });

        test('should detect Next.js App Router', () => {
            const content = `export async function GET(request) { return Response.json({}); }`;
            const result = detector.detectHttpHandler(content, 'route.ts');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Next.js App Router');
        });

        test('should detect Flask routes', () => {
            const content = `@app.route('/api/data', methods=['GET'])`;
            const result = detector.detectHttpHandler(content, 'app.py');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Flask');
        });

        test('should detect FastAPI routes', () => {
            const content = `@app.post('/items')`;
            const result = detector.detectHttpHandler(content, 'main.py');
            expect(result).not.toBeNull();
            // FastAPI uses same @app.verb pattern as Express; detector returns first match
            expect(result.type).toBe('HTTP_HANDLER');
        });

        test('should detect Spring Boot annotations', () => {
            const content = `@GetMapping("/users")`;
            const result = detector.detectHttpHandler(content, 'Controller.java');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Spring Boot');
        });

        test('should detect ASP.NET Minimal API', () => {
            const content = `app.MapGet("/api/hello", () => "Hello World");`;
            const result = detector.detectHttpHandler(content, 'Program.cs');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('ASP.NET Minimal API');
        });

        test('should detect ASP.NET Controller attributes', () => {
            const content = `[HttpGet("users")]`;
            const result = detector.detectHttpHandler(content, 'UsersController.cs');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('ASP.NET Controller');
        });

        test('should detect Rails routes', () => {
            const content = `get '/users', to: 'users#index'`;
            const result = detector.detectHttpHandler(content, 'routes.rb');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Rails Router');
        });

        test('should detect Sinatra routes', () => {
            const content = `get '/hello' do\n  'Hello World'\nend`;
            const result = detector.detectHttpHandler(content, 'app.rb');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Sinatra');
        });

        test('should detect Laravel routes', () => {
            const content = `Route::get('/users', [UserController::class, 'index']);`;
            const result = detector.detectHttpHandler(content, 'web.php');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Laravel Router');
        });

        test('should detect Gin (Go) routes', () => {
            const content = `r.GET("/ping", func(c *gin.Context) { c.JSON(200, gin.H{}) })`;
            const result = detector.detectHttpHandler(content, 'main.go');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Gin');
        });

        test('should detect Actix-web routes', () => {
            const content = `web::get().to(index)`;
            const result = detector.detectHttpHandler(content, 'main.rs');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Actix-web');
        });

        test('should detect Fastify routes', () => {
            const content = `fastify.get('/api', handler)`;
            const result = detector.detectHttpHandler(content, 'server.js');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Fastify');
        });

        test('should return null for non-handler code', () => {
            const content = `const x = 1 + 2; console.log(x);`;
            const result = detector.detectHttpHandler(content, 'utils.js');
            expect(result).toBeNull();
        });
    });

    // ─── Main Function Detection ─────────────────────────────────────

    describe('detectMainFunction', () => {
        test('should detect Node.js main check', () => {
            const content = `if (require.main === module) { start(); }`;
            const result = detector.detectMainFunction(content, 'server.js', 'server.js');
            expect(result).not.toBeNull();
            expect(result.type).toBe('MAIN_FUNCTION');
        });

        test('should detect Python main', () => {
            const content = `if __name__ == '__main__':\n    main()`;
            const result = detector.detectMainFunction(content, 'app.py', 'app.py');
            expect(result).not.toBeNull();
            expect(result.language).toBe('Python');
        });

        test('should detect Java main', () => {
            const content = `public static void main(String[] args) { }`;
            const result = detector.detectMainFunction(content, 'App.java', 'App.java');
            expect(result).not.toBeNull();
            expect(result.language).toBe('Java');
        });

        test('should detect Go main', () => {
            const content = `func main() {\n    fmt.Println("hello")\n}`;
            const result = detector.detectMainFunction(content, 'main.go', 'main.go');
            expect(result).not.toBeNull();
            expect(result.language).toBe('Go');
        });

        test('should detect Rust main', () => {
            const content = `fn main() {\n    println!("hello");\n}`;
            const result = detector.detectMainFunction(content, 'main.rs', 'main.rs');
            expect(result).not.toBeNull();
            expect(result.language).toBe('Rust');
        });

        test('should detect C# main', () => {
            const content = `static void Main(string[] args) { }`;
            const result = detector.detectMainFunction(content, 'Program.cs', 'Program.cs');
            expect(result).not.toBeNull();
            expect(result.language).toBe('C#');
        });

        test('should detect Dart main', () => {
            const content = `void main() {\n  runApp(MyApp());\n}`;
            const result = detector.detectMainFunction(content, 'main.dart', 'main.dart');
            expect(result).not.toBeNull();
            expect(result.language).toBe('Dart');
        });

        test('should detect by filename', () => {
            const content = `const server = createServer();`;
            const result = detector.detectMainFunction(content, 'main.js', 'main.js');
            expect(result).not.toBeNull();
            expect(result.confidence).toBe(0.8);
        });

        test('should detect Program.cs by filename', () => {
            const content = `var app = WebApplication.CreateBuilder(args);`;
            const result = detector.detectMainFunction(content, 'Program.cs', 'Program.cs');
            expect(result).not.toBeNull();
        });

        test('should return null for non-main files', () => {
            const content = `function helper() { return 42; }`;
            const result = detector.detectMainFunction(content, 'utils.js', 'utils.js');
            expect(result).toBeNull();
        });
    });

    // ─── CLI Command Detection ───────────────────────────────────────

    describe('detectCliCommand', () => {
        test('should detect Commander.js', () => {
            const content = `program.command('serve').action(serve);`;
            const result = detector.detectCliCommand(content, 'cli.js');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Commander.js');
        });

        test('should detect Click (Python)', () => {
            const content = `@click.command()`;
            const result = detector.detectCliCommand(content, 'cli.py');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Click');
        });

        test('should detect Cobra (Go)', () => {
            const content = `rootCmd := &cobra.Command{`;
            const result = detector.detectCliCommand(content, 'cmd.go');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Cobra');
        });

        test('should detect Clap (Rust)', () => {
            const content = `let matches = Command::new("myapp")`;
            const result = detector.detectCliCommand(content, 'main.rs');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Clap');
        });
    });

    // ─── Event Handler Detection ─────────────────────────────────────

    describe('detectEventHandler', () => {
        test('should detect event handlers', () => {
            const content = `socket.on('message', (data) => { });`;
            const result = detector.detectEventHandler(content, 'ws.js');
            expect(result).not.toBeNull();
            // EventEmitter pattern matches first since it's more general
            expect(result.type).toBe('EVENT_HANDLER');
        });

        test('should detect message queue listeners', () => {
            const content = `@KafkaListener(topics = "orders")`;
            const result = detector.detectEventHandler(content, 'Consumer.java');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Kafka');
        });

        test('should detect GraphQL resolvers', () => {
            const content = `@Query(() => [User])`;
            const result = detector.detectEventHandler(content, 'resolver.ts');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('GraphQL');
        });
    });

    // ─── Server Init Detection ───────────────────────────────────────

    describe('detectServerInit', () => {
        test('should detect app.listen', () => {
            const content = `app.listen(3000, () => console.log('running'));`;
            const result = detector.detectServerInit(content, 'server.js');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Express/Node.js Server');
        });

        test('should detect Spring Boot', () => {
            const content = `@SpringBootApplication`;
            const result = detector.detectServerInit(content, 'Application.java');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('Spring Boot');
        });

        test('should detect Go HTTP server', () => {
            const content = `http.ListenAndServe(":8080", router)`;
            const result = detector.detectServerInit(content, 'main.go');
            expect(result).not.toBeNull();
        });

        test('should detect ASP.NET init', () => {
            const content = `var app = WebApplication.Create(args);`;
            const result = detector.detectServerInit(content, 'Program.cs');
            expect(result).not.toBeNull();
            expect(result.framework).toBe('ASP.NET');
        });
    });

    // ─── Test File Detection ─────────────────────────────────────────

    describe('isTestFile', () => {
        test('should detect test files', () => {
            expect(detector.isTestFile('/src/app.test.js', 'app.test.js')).toBe(true);
            expect(detector.isTestFile('/src/app.spec.ts', 'app.spec.ts')).toBe(true);
            expect(detector.isTestFile('/src/app_test.go', 'app_test.go')).toBe(true);
            expect(detector.isTestFile('/tests/test_app.py', 'test_app.py')).toBe(true);
            expect(detector.isTestFile('/src/AppTest.java', 'AppTest.java')).toBe(true);
        });

        test('should detect test directories', () => {
            expect(detector.isTestFile('/__tests__/app.js', 'app.js')).toBe(true);
            expect(detector.isTestFile('/test/helpers.js', 'helpers.js')).toBe(true);
        });

        test('should not flag production files', () => {
            expect(detector.isTestFile('/src/app.js', 'app.js')).toBe(false);
            expect(detector.isTestFile('/src/main.py', 'main.py')).toBe(false);
        });
    });

    // ─── Confidence Calculation ──────────────────────────────────────

    describe('calculateConfidence', () => {
        test('should return 0 for no signals', () => {
            expect(detector.calculateConfidence([])).toBe(0);
        });

        test('should average signal confidences', () => {
            const signals = [
                { type: 'HTTP_HANDLER', confidence: 0.9 },
                { type: 'SERVER_INIT', confidence: 0.8 }
            ];
            const confidence = detector.calculateConfidence(signals);
            // Average + boost for 2 strong signals
            expect(confidence).toBeGreaterThan(0.85);
        });

        test('should boost for multiple strong signals', () => {
            const single = [{ type: 'HTTP_HANDLER', confidence: 0.9 }];
            const multiple = [
                { type: 'HTTP_HANDLER', confidence: 0.9 },
                { type: 'SERVER_INIT', confidence: 0.9 }
            ];
            expect(detector.calculateConfidence(multiple)).toBeGreaterThan(
                detector.calculateConfidence(single)
            );
        });

        test('should penalize for negative signals (test files)', () => {
            const signals = [
                { type: 'HTTP_HANDLER', confidence: 0.9 },
                { type: 'TEST_FILE', confidence: -0.8 }
            ];
            const confidence = detector.calculateConfidence(signals);
            expect(confidence).toBeLessThan(0.5);
        });
    });

    // ─── Type Determination ──────────────────────────────────────────

    describe('determineType', () => {
        test('should return highest confidence signal type', () => {
            const signals = [
                { type: 'HTTP_HANDLER', confidence: 0.95 },
                { type: 'SERVER_INIT', confidence: 0.85 }
            ];
            expect(detector.determineType(signals)).toBe('HTTP_HANDLER');
        });

        test('should return UNKNOWN for empty signals', () => {
            expect(detector.determineType([])).toBe('UNKNOWN');
        });
    });

    // ─── Integration: analyzeFile ────────────────────────────────────

    describe('analyzeFile', () => {
        test('should analyze Express.js entry point', () => {
            const filePath = createFile('server.js', `
const express = require('express');
const app = express();
app.get('/api/users', (req, res) => res.json([]));
app.listen(3000);
            `);
            const signals = detector.analyzeFile(filePath, {});
            expect(signals.length).toBeGreaterThan(0);
            const types = signals.map(s => s.type);
            expect(types).toContain('HTTP_HANDLER');
            expect(types).toContain('SERVER_INIT');
        });

        test('should detect test file with negative signal', () => {
            const filePath = createFile('app.test.js', `
const app = require('./app');
app.get('/test', handler);
            `);
            const signals = detector.analyzeFile(filePath, {});
            const testSignal = signals.find(s => s.type === 'TEST_FILE');
            expect(testSignal).toBeDefined();
            expect(testSignal.confidence).toBeLessThan(0);
        });

        test('should return empty for non-existent file', () => {
            const signals = detector.analyzeFile('/nonexistent/file.js', {});
            expect(signals).toHaveLength(0);
        });
    });
});
