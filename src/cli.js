#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const VERSION = '0.1.0';
const args = process.argv.slice(2);

function has(flag) {
  return args.includes(flag);
}

function value(flag, fallback) {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : fallback;
}

if (has('--help') || has('-h')) {
  console.log(`secret-leak-local v${VERSION}

Usage:
  secret-leak-local [paths...] [--staged] [--json|--sarif] [--baseline .secrets.baseline]

Options:
  --config <file>       Read JSON config. Default: .secret-leak-local.json when present.
  --staged              Scan staged files only.
  --allow-file <file>   Regex allow-list file. Default: .secretignore.
  --baseline <file>     Ignore findings already captured in a baseline JSON file.
  --write-baseline <f>  Write current findings as a baseline file.
  --sarif               Print SARIF for GitHub code scanning.
  --json                Print JSON.
  --version             Print version.
  -h, --help            Show help.`);
  process.exit(0);
}
if (has('--version')) {
  console.log(VERSION);
  process.exit(0);
}

function readJson(file, fallback = {}) {
  if (!file || !fs.existsSync(file)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    console.error(`Unable to read ${file}: ${error.message}`);
    process.exit(1);
  }
}

const configFile = value('--config', fs.existsSync('.secret-leak-local.json') ? '.secret-leak-local.json' : '');
const config = readJson(configFile);
const json = has('--json');
const sarif = has('--sarif');
const staged = has('--staged');
const allowFile = value('--allow-file', config.allowFile || '.secretignore');
const baselineFile = value('--baseline', config.baseline || '');
const writeBaseline = value('--write-baseline', '');
const roots = args.filter((a, i) => !a.startsWith('-') && !['--allow-file', '--baseline', '--write-baseline', '--config'].includes(args[i - 1]));
if (!roots.length && !staged) roots.push('.');

const ignoreDirs = new Set([...(config.ignoreDirs || []), '.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.turbo']);
const maxFileSize = Number(config.maxFileSize || 1024 * 1024);
const allowPatterns = [
  ...(fs.existsSync(allowFile) ? fs.readFileSync(allowFile, 'utf8').split(/\r?\n/).map((x) => x.trim()).filter(Boolean) : []),
  ...(config.allow || [])
].map((x) => new RegExp(x));
const baseline = new Set((readJson(baselineFile, { findings: [] }).findings || []).map((f) => f.fingerprint));

const patterns = [
  ['private-key', /-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['aws-access-key', /AKIA[0-9A-Z]{16}/],
  ['github-token', /gh[pousr]_[A-Za-z0-9_]{20,}/],
  ['slack-token', /xox[baprs]-[A-Za-z0-9-]{10,}/],
  ['jwt', /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/],
  ['env-secret', /\b(API_KEY|TOKEN|SECRET|PASSWORD|PRIVATE_KEY)\s*=\s*['"]?[^'"\s]{8,}/i],
  ...(config.patterns || []).map((p) => [p.type, new RegExp(p.pattern, p.flags || '')])
];

function entropy(value) {
  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) || 0) + 1);
  let score = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    score -= p * Math.log2(p);
  }
  return score;
}

function highEntropyTokens(line) {
  if (config.entropy === false) return [];
  const threshold = Number(config.entropyThreshold || 4.2);
  return (line.match(/[A-Za-z0-9+/=_-]{24,}/g) || []).filter((token) => entropy(token) >= threshold);
}

function fingerprint(file, line, type, preview) {
  return crypto.createHash('sha256').update(`${file}:${line}:${type}:${preview}`).digest('hex');
}

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
  } else if (stat.isFile() && stat.size <= maxFileSize) files.push(p);
  return files;
}

function stagedFiles() {
  try {
    return execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACMR'], { encoding: 'utf8' }).trim().split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

const files = staged ? stagedFiles() : roots.flatMap((root) => walk(root));
const findings = [];
for (const file of files) {
  let text = '';
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    continue;
  }
  if (text.includes('\u0000')) continue;
  text.split(/\r?\n/).forEach((line, index) => {
    if (allowed(file, line)) return;
    for (const [type, regex] of patterns) {
      if (regex.test(line)) {
        const preview = mask(line.trim()).slice(0, 200);
        const fp = fingerprint(file, index + 1, type, preview);
        if (!baseline.has(fp)) findings.push({ type, file, line: index + 1, preview, fingerprint: fp });
      }
    }
    for (const token of highEntropyTokens(line)) {
      const preview = line.replace(token, `${token.slice(0, 4)}***`).trim().slice(0, 200);
      const fp = fingerprint(file, index + 1, 'high-entropy', preview);
      if (!baseline.has(fp)) findings.push({ type: 'high-entropy', file, line: index + 1, preview, fingerprint: fp });
    }
  });
}

const result = { findings, count: findings.length, staged, scannedFiles: files.length };
if (writeBaseline) fs.writeFileSync(writeBaseline, JSON.stringify({ findings }, null, 2));

function toSarif(data) {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'secret-leak-local', informationUri: 'https://github.com/niuxinhuai/secret-leak-local', rules: [] } },
      results: data.findings.map((finding) => ({
        ruleId: finding.type,
        level: 'error',
        message: { text: `${finding.type} at ${finding.file}:${finding.line}` },
        partialFingerprints: { primaryLocationLineHash: finding.fingerprint },
        locations: [{ physicalLocation: { artifactLocation: { uri: finding.file }, region: { startLine: finding.line } } }]
      }))
    }]
  };
}

if (sarif) console.log(JSON.stringify(toSarif(result), null, 2));
else if (json) console.log(JSON.stringify(result, null, 2));
else {
  console.log(`# Secret Leak Local

Scanned files: ${files.length}

${findings.length ? findings.map((f) => `- [${f.type}] ${f.file}:${f.line} ${f.preview}`).join('\n') : '- No obvious secret patterns found.'}

${findings.length ? 'Review these files before committing. Rotate any credential that was already shared.' : 'Keep scanning before commits and releases.'}
`);
}
process.exit(findings.length ? 2 : 0);
