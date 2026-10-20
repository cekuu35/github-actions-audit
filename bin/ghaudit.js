#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

const SECRET_VALUE_PATTERNS = [
  /sk-(ant-)?[A-Za-z0-9_-]{20,}/,
  /ghp_[A-Za-z0-9]{30,}/,
  /github_pat_[A-Za-z0-9_]{20,}/,
  /AKIA[0-9A-Z]{16}/,
  /AIza[0-9A-Za-z_-]{30,}/,
  /xox[baprs]-[A-Za-z0-9-]{10,}/,
  /glpat-[A-Za-z0-9_-]{15,}/,
  /npm_[A-Za-z0-9]{30,}/,
];
const PLACEHOLDER_RE = /^(\$\{|%|\{|<|your|my[-_]?|change|example|placeholder|xxx|\*|0+|test[-_]?|dummy|fake)/i;
const SHA_RE = /^[0-9a-f]{40}$/i;
const INJECTION_CONTEXT_RE = /\$\{\{[^}]*github\.event\.(pull_request|issue|discussion|head_commit)\.[^}]*(body|title|message|ref|label\.name|comment\.body)[^}]*\}\}/i;
const PR_HEAD_REF_RE = /ref:\s*\$\{\{[^}]*github\.event\.pull_request\.head/i;

function redact(value) {
  const v = String(value);
  if (v.length <= 8) return v.slice(0, 2) + '***';
  return v.slice(0, 6) + '***(' + v.length + ' chars)';
}

function isRealSecretValue(value) {
  if (typeof value !== 'string' || value.length < 16) return false;
  if (PLACEHOLDER_RE.test(value)) return false;
  return SECRET_VALUE_PATTERNS.some((re) => re.test(value));
}

function stripCommentsAndStringsLine(line) {
  let s = line;
  const hash = s.indexOf('#');
  if (hash >= 0 && !s.slice(0, hash).includes("'")) s = s.slice(0, hash);
  return s;
}

function parseWorkflow(src) {
  const lines = src.split(/\r?\n/);
  const wf = { triggers: [], uses: [], runs: [], hasPermissions: false, secretUses: [], envs: [], allLines: [] };
  let i = 0;
  let onIndent = -1;
  while (i < lines.length) {
    const raw = lines[i];
    const line = stripCommentsAndStringsLine(raw);
    const indent = line.match(/^\s*/)[0].length;
    if (line.trim().length === 0) { i++; continue; }
    if (/^\s*on\s*:/.test(line)) {
      onIndent = indent;
      const rest = line.replace(/^\s*on\s*:\s*/, '');
      if (rest.trim().length > 0) {
        for (const t of rest.split(/[\[\],]/)) {
          const t2 = t.trim().replace(/['"]/g, '');
          if (t2) wf.triggers.push(t2);
        }
      } else {
        let j = i + 1;
        while (j < lines.length) {
          const l2 = stripCommentsAndStringsLine(lines[j]);
          const i2 = l2.match(/^\s*/)[0].length;
          if (l2.trim().length === 0) { j++; continue; }
          if (i2 <= onIndent) break;
          const tm = l2.match(/^\s*([A-Za-z_]+)\s*:\s*.*$/);
          const lm = l2.match(/^\s*-\s+([A-Za-z_]+)\s*$/);
          if (tm) wf.triggers.push(tm[1].replace(/['"]/g, ''));
          else if (lm) wf.triggers.push(lm[1].replace(/['"]/g, ''));
          j++;
        }
        i = j - 1;
      }
    } else if (/^\s*permissions\s*:/.test(line) || /^\s*permissions\s*:\s*\S/.test(line)) {
      wf.hasPermissions = true;
    } else if (/^\s*-\s+uses\s*:/.test(line) || /^\s*uses\s*:/.test(line)) {
      wf.uses.push({ line: i + 1, value: line.replace(/^\s*-\s+/, '').replace(/^\s*uses\s*:\s*/, '').trim().replace(/['"]/g, '') });
    } else if (/^\s*-\s+run\s*:/.test(line) || /^\s*run\s*:/.test(line)) {
      const runIndent = indent;
      const rest = line.replace(/^\s*-\s+/, '').replace(/^\s*run\s*:\s*/, '').trim();
      const parts = [];
      if (rest && rest !== '|' && rest !== '>' && rest !== '|-' && rest !== '>-') {
        parts.push(rest);
      } else {
        let j = i + 1;
        while (j < lines.length) {
          const l2 = lines[j];
          const i2 = l2.match(/^\s*/)[0].length;
          if (l2.trim().length === 0) { j++; continue; }
          if (i2 <= runIndent) break;
          parts.push(stripCommentsAndStringsLine(l2));
          j++;
        }
        i = j - 1;
      }
      wf.runs.push({ line: i + 1, text: parts.join('\n') });
    } else if (/\bsecrets\.[A-Za-z_]/.test(line)) {
      wf.secretUses.push({ line: i + 1, text: line.trim() });
    }
    wf.allLines.push(line);
    i++;
  }
  return wf;
}

function auditWorkflow(filePath, wf) {
  const findings = [];
  const hasPRT = wf.triggers.includes('pull_request_target');

  if (hasPRT) {
    const headCheckout = wf.allLines.some((l) => PR_HEAD_REF_RE.test(l)) || wf.runs.some((r) => PR_HEAD_REF_RE.test(r.text));
    if (headCheckout) {
      findings.push({
        rule: 'PWN_REQUEST', severity: 'critical',
        detail: 'pull_request_target checks out untrusted PR code with access to base-repo secrets — a malicious PR gets full secret access ("pwn request")',
        evidence: 'on: pull_request_target + checkout of github.event.pull_request.head',
      });
    } else if (wf.secretUses.length > 0) {
      findings.push({
        rule: 'PR_TARGET_WITH_SECRETS', severity: 'high',
        detail: 'pull_request_target workflow uses secrets while running code influenced by a PR — verify every step only processes trusted refs',
        evidence: wf.secretUses[0].text.slice(0, 100),
      });
    }
  }

  for (const run of wf.runs) {
    if (INJECTION_CONTEXT_RE.test(run.text)) {
      findings.push({
        rule: 'SCRIPT_INJECTION', severity: 'critical',
        detail: 'run block interpolates attacker-controllable GitHub context (PR/issue body, title, commit message) into a shell script',
        evidence: run.text.split('\n').find((l) => INJECTION_CONTEXT_RE.test(l)).trim().slice(0, 120),
      });
    }
  }

  for (const l of wf.allLines) {
    if (isRealSecretValue(l.trim())) {
      findings.push({
        rule: 'HARDCODED_SECRET', severity: 'high',
        detail: 'real-looking secret literal in the workflow file — use secrets context, not literals',
        evidence: redact(l.trim()),
      });
    }
  }

  for (const u of wf.uses) {
    const m = /^([^@\s]+)@(.+)$/.exec(u.value);
    if (!m) {
      findings.push({
        rule: 'MALFORMED_USES', severity: 'medium',
        detail: 'uses value has no @ref: ' + u.value,
        evidence: u.value,
      });
      continue;
    }
    if (!SHA_RE.test(m[2])) {
      findings.push({
        rule: 'UNPINNED_ACTION', severity: 'medium',
        detail: 'action pinned to mutable ref "' + m[2] + '" — pin to a full commit SHA for supply-chain safety',
        evidence: u.value,
      });
    }
  }

  if (!wf.hasPermissions && wf.triggers.length > 0) {
    findings.push({
      rule: 'NO_PERMISSIONS_BLOCK', severity: 'medium',
      detail: 'no top-level permissions: block — GITHUB_TOKEN scope is the repo default instead of least privilege',
      evidence: '(missing permissions)',
    });
  }

  return { file: filePath, findings };
}

function scanFile(filePath, raw) {
  try {
    return auditWorkflow(filePath, parseWorkflow(raw));
  } catch (e) {
    return { file: filePath, findings: [], error: 'parse failure: ' + e.message };
  }
}

function defaultPaths() {
  const dir = path.join(process.cwd(), '.github', 'workflows');
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml')).map((f) => path.join(dir, f));
}

function printReport(results) {
  const lines = [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const res of results) {
    lines.push('');
    lines.push('== ' + res.file);
    if (res.error) lines.push('   skipped: ' + res.error);
    for (const f of res.findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
      lines.push('   [' + f.severity.toUpperCase() + '] ' + f.rule);
      lines.push('       ' + f.detail);
      lines.push('       evidence: ' + f.evidence);
    }
  }
  return { text: lines.join('\n'), counts };
}

function main(argv) {
  const json = argv.includes('--json');
  const paths = argv.filter((a) => !a.startsWith('--'));
  const targets = paths.length > 0 ? paths : defaultPaths();
  if (targets.length === 0) {
    console.error('No workflow files found. Pass paths explicitly, e.g.: github-actions-audit .github/workflows/ci.yml');
    return 2;
  }
  const results = [];
  for (const file of targets) {
    try {
      results.push(scanFile(file, fs.readFileSync(file, 'utf8')));
    } catch (e) {
      results.push({ file, findings: [], error: 'unreadable: ' + e.message });
    }
  }
  if (json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    const { text, counts } = printReport(results);
    console.log(text);
    console.log('');
    console.log('Summary: ' + counts.critical + ' critical, ' + counts.high + ' high, ' + counts.medium + ' medium, ' + counts.low + ' low');
  }
  const blocking = results.some((r) => r.findings.some((f) => f.severity === 'critical' || f.severity === 'high'));
  return blocking ? 1 : 0;
}

if (require.main === module) {
  process.exit(main(process.argv.slice(2)));
}

module.exports = { scanFile, parseWorkflow, auditWorkflow, isRealSecretValue, redact, main };
