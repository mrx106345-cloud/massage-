#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

console.log('🔍 Production Readiness Check\n');

const checks = [];

// Check package.json
try {
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  checks.push({ name: 'package.json exists', passed: true });
  checks.push({ name: 'Has build script', passed: !!pkg.scripts.build });
  checks.push({ name: 'Has start script', passed: !!pkg.scripts.start });
} catch (e) {
  checks.push({ name: 'package.json exists', passed: false, error: e.message });
}

// Check Docker files
checks.push({ name: 'Dockerfile exists', passed: fs.existsSync('Dockerfile') });
checks.push({ name: 'docker-compose.yml exists', passed: fs.existsSync('docker-compose.yml') });
checks.push({
  name: 'docker-compose.prod.yml exists',
  passed: fs.existsSync('docker-compose.prod.yml'),
});

// Check env example
checks.push({ name: '.env.example exists', passed: fs.existsSync('.env.example') });

// Check documentation
checks.push({ name: 'README.md exists', passed: fs.existsSync('README.md') });
checks.push({ name: 'DEPLOYMENT.md exists', passed: fs.existsSync('DEPLOYMENT.md') });
checks.push({ name: 'SECURITY.md exists', passed: fs.existsSync('SECURITY.md') });

// Check build output
checks.push({ name: 'dist/ exists', passed: fs.existsSync('dist') });

// Check critical files
const criticalFiles = [
  'src/index.ts',
  'src/app.ts',
  'src/config/index.ts',
  'src/middleware/security.ts',
];
for (const file of criticalFiles) {
  checks.push({ name: `${file} exists`, passed: fs.existsSync(file) });
}

let passed = 0;
let failed = 0;

for (const check of checks) {
  if (check.passed) {
    console.log(`✅ ${check.name}`);
    passed++;
  } else {
    console.log(`❌ ${check.name}${check.error ? ': ' + check.error : ''}`);
    failed++;
  }
}

console.log(`\n📊 Results: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
