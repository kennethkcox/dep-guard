const js = require('@eslint/js');

module.exports = [
  js.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: 'commonjs',
      globals: {
        require: 'readonly',
        module: 'readonly',
        exports: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        process: 'readonly',
        console: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        setInterval: 'readonly',
        clearTimeout: 'readonly',
        clearInterval: 'readonly',
        setImmediate: 'readonly',
        clearImmediate: 'readonly',
        URL: 'readonly',
        global: 'readonly',
        // Jest globals
        describe: 'readonly',
        it: 'readonly',
        test: 'readonly',
        expect: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        beforeAll: 'readonly',
        afterAll: 'readonly',
        jest: 'readonly'
      }
    },
    rules: {
      'indent': 'off', // Turn off indentation checking - codebase uses mixed 2/4 spaces
      'linebreak-style': 'off', // Disable for Windows compatibility
      'quotes': ['warn', 'single', { 'avoidEscape': true }],
      'semi': ['error', 'always'],
      'no-unused-vars': ['warn', {
        'argsIgnorePattern': '^_',
        'varsIgnorePattern': '^_'
      }],
      'no-console': 'off',
      'no-constant-condition': 'warn',
      'no-empty': 'warn',
      'no-undef': 'error',
      'no-redeclare': 'error'
    }
  },
  {
    ignores: [
      'node_modules/**',
      '.depguard-cache/**',
      'coverage/**',
      'dist/**',
      'build/**',
      '*.test.js',
      'test-*.js'
    ]
  }
];
