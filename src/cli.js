#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
const VERSION = '0.1.0';
const args = process.argv.slice(2);
function has(flag) { return args.includes(flag); }
function value(flag, fallback) { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : fallback; }
if (has('--help') || has('-h')) {
  console.log(`secret-leak-local v${VERSION}

Usage:
  secret-leak-local [paths...] [--staged] [--json] [--allow-file .secretignore]`);
  process.exit(0);
}
if (has('--version')) { console.log(VERSION); process.exit(0); }
const json = has('--json');
const staged = has('--staged');
const allowFile = value('--allow-file', '.secretignore');
const roots = args.filter((a, i) => !a.startsWith('-') && args[i - 1] !== '--allow-file');
if (!roots.length && !staged) roots.push('.');
const ignoreDirs = new Set(['.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.turbo']);
const allowPatterns = fs.existsSync(allowFile) ? fs.readFileSync(allowFile, 'utf8').split(/\r?\n/).map((x) => x.trim()).filter(Boolean).map((x) => new RegExp(x)) : [];
const patterns = [
  ['private-key', /-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['aws-access-key', /AKIA[0-9A-Z]{16}/],
  ['github-token', /gh[pousr]_[A-Za-z0-9_]{20,}/],
  ['slack-token', /xox[baprs]-[A-Za-z0-9-]{10,}/],
  ['jwt', /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/],
  ['env-secret', /\b(API_KEY|TOKEN|SECRET|PASSWORD|PRIVATE_KEY)\s*=\s*['\"]?[^'\"\s]{8,}/i]
];
function mask(line) {
  return line.replace(/([=:]\s*['"]?)([^'"]{4})[^'"]{4,}/, '$1$2***');
}
function allowed(file, line) {
  return allowPatterns.some((regex) => regex.test(file) || regex.test(line));
}
function walk(p, files = []) {
  if (!fs.existsSync(p)) return files;
  const stat = fs.statSync(p);
  if (stat.isDirectory()) {
    if (ignoreDirs.has(path.basename(p))) return files;
    for (const child of fs.readdirSync(p)) walk(path.join(p, child), files);
  } else if (stat.isFile() && stat.size < 1024 * 1024) files.push(p);
  return files;
}
function stagedFiles() {
  try { return execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACMR'], { encoding: 'utf8' }).trim().split('\n').filter(Boolean); } catch { return []; }
}
const files = staged ? stagedFiles() : roots.flatMap((root) => walk(root));
const findings = [];
for (const file of files) {
  let text = '';
  try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
  if (text.includes('\u0000')) continue;
  text.split(/\r?\n/).forEach((line, index) => {
    if (allowed(file, line)) return;
    for (const [type, regex] of patterns) {
      if (regex.test(line)) findings.push({ type, file, line: index + 1, preview: mask(line.trim()).slice(0, 200) });
    }
  });
}
const result = { findings, count: findings.length, staged };
if (json) console.log(JSON.stringify(result, null, 2));
else console.log(`# Secret Leak Local

${findings.length ? findings.map((f) => `- [${f.type}] ${f.file}:${f.line} ${f.preview}`).join('\n') : '- No obvious secret patterns found.'}

${findings.length ? 'Review these files before committing. Rotate any credential that was already shared.' : 'Keep scanning before commits and releases.'}
`);
process.exit(findings.length ? 2 : 0);
