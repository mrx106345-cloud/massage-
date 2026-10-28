#!/usr/bin/env node
/**
 * Standalone audit recorder.
 *
 * Usage:
 *   node scripts/audit.cjs          # runtime deps only
 *   node scripts/audit.cjs --all    # runtime + dev deps
 *
 * This records the audit result and exits with 0 when the relevant tree is
 * clean, and exits with 1 when advisories are present for the requested tree.
 *
 * The point is to make audit status explicit and repeatable, not to hide
 * advisories. For production releases, only the runtime tree should be treated
 * as a release blocker; dev/build advisories should still be tracked.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const AUDIT_LOG = path.resolve(ROOT, 'AUDIT.md');

const args = process.argv.slice(2);
const all = args.includes('--all');
const omitDev = !all;

function runAudit() {
  const cmd = `npm audit --json ${omitDev ? '--omit=dev' : ''}`;
  let output;
  try {
    output = execSync(cmd, {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    output = (err.stdout || '') + (err.stderr || '');
  }
  return output;
}

function parseAudit(output) {
  const jsonStart = output.indexOf('{');
  const jsonText = jsonStart !== -1 ? output.slice(jsonStart) : output;
  let parsed;
  try {
    parsed = JSON.parse(jsonText);
  } catch (err) {
    const hint = output.slice(0, 300).replace(/\n/g, ' ');
    return { error: true, raw: output, hint };
  }
  return parsed;
}

function advisoryCount(parsed) {
  const vulns = parsed.vulnerabilities;
  if (!vulns || typeof vulns !== 'object' || Array.isArray(vulns)) {
    return 0;
  }
  return Object.values(vulns).filter((p) => {
    if (p.hasOwnProperty('severity')) {
      if (typeof p.severity === 'string') {
        return p.severity !== 'info';
      }
      return true;
    }
    return true;
  }).length;
}

function summaryLines(parsed) {
  const lines = [];
  const vulns = parsed.vulnerabilities || {};
  lines.push(`- Audit date: ${new Date().toISOString()}`);
  lines.push(`- Mode: ${omitDev ? 'runtime deps only (--omit=dev)' : 'all deps'}`);
  lines.push(`- Total advisories in tree: ${Object.keys(vulns).length}`);
  const bySeverity = { critical: 0, high: 0, moderate: 0, low: 0, info: 0 };
  for (const p of Object.values(vulns)) {
    const sev = typeof p.severity === 'string' ? p.severity : 'unknown';
    bySeverity[sev] = (bySeverity[sev] || 0) + 1;
  }
  for (const [sev, count] of Object.entries(bySeverity)) {
    if (count > 0) {
      lines.push(`- ${sev}: ${count}`);
    }
  }
  const runtimeClean = advisoryCount(parsed) === 0;
  lines.push(`- Runtime tree clean: ${runtimeClean}`);
  return lines;
}

function main() {
  const output = runAudit();
  const parsed = parseAudit(output);

  console.log(`
=== npm audit ===
${output.split('\n').slice(0, 20).join('\n')}
`);

  const lines = summaryLines(parsed);
  console.log(lines.join('\n'));

  const runtimeClean = advisoryCount(parsed) === 0;
  if (omitDev && !runtimeClean) {
    console.error('Runtime dependency audit found advisories.');
    process.exit(1);
  }
  if (!omitDev && Object.keys(parsed.vulnerabilities || {}).length > 0) {
    console.error('Full dependency audit found advisories.');
    process.exit(1);
  }

  // Keep AUDIT.md current so the audit conclusion is visible in the repo.
  try {
    let existing = '';
    if (fs.existsSync(AUDIT_MD)) {
      existing = fs.readFileSync(AUDIT_MD, 'utf8');
    }
    const marker = '## Dependency security\n';
    const idx = existing.indexOf(marker);
    if (idx !== -1) {
      const after = existing.indexOf('\n## ', idx + marker.length);
      const prefix = existing.slice(0, idx);
      const suffix = after !== -1 ? existing.slice(after) : existing.slice(idx);
      const updated = prefix + '## Dependency security\n\n' + lines.join('\n') + '\n\n' + suffix;
      fs.writeFileSync(AUDIT_MD, updated, 'utf8');
    }
  } catch {
    // best-effort: if we cannot write AUDIT.md, still exit with the audit result
  }
}

main();
