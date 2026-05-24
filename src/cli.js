#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) {
  console.log(`secret-leak-local

Usage:
  secret-leak-local [paths...] [--json]`);
  process.exit(0);
}
const json = args.includes('--json');
const roots = args.filter((a) => !a.startsWith('-'));
if (!roots.length) roots.push('.');
const ignore = new Set(['.git', 'node_modules', 'dist', 'build', 'coverage', '.next']);
const patterns = [
  ['private-key', /-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['aws-access-key', /AKIA[0-9A-Z]{16}/],
  ['github-token', /gh[pousr]_[A-Za-z0-9_]{20,}/],
  ['jwt', /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/],
  ['env-secret', /\b(API_KEY|TOKEN|SECRET|PASSWORD|PRIVATE_KEY)\s*=\s*['\"]?[^'\"\s]{8,}/i]
];
function walk(p, files = []) {
  if (!fs.existsSync(p)) return files;
  const stat = fs.statSync(p);
  if (stat.isDirectory()) {
    if (ignore.has(path.basename(p))) return files;
    for (const child of fs.readdirSync(p)) walk(path.join(p, child), files);
  } else if (stat.isFile() && stat.size < 1024 * 1024) {
    files.push(p);
  }
  return files;
}
const findings = [];
for (const root of roots) {
  for (const file of walk(root)) {
    let text = '';
    try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    const lines = text.split(/\r?\n/);
    lines.forEach((line, index) => {
      for (const [type, regex] of patterns) {
        if (regex.test(line)) findings.push({ type, file, line: index + 1 });
      }
    });
  }
}
const result = { findings, count: findings.length };
if (json) { console.log(JSON.stringify(result, null, 2)); process.exit(findings.length ? 2 : 0); }
console.log(`# Secret Leak Local

${findings.length ? findings.map((f) => `- [${f.type}] ${f.file}:${f.line}`).join('\n') : '- No obvious secret patterns found.'}

${findings.length ? 'Review these files before committing. Rotate any credential that was already shared.' : 'Keep scanning before commits and releases.'}
`);
process.exit(findings.length ? 2 : 0);
