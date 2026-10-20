'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { scanFile, parseWorkflow, auditWorkflow } = require('../bin/ghaudit.js');

const ROOT = path.join(__dirname, '..');
const broken = fs.readFileSync(path.join(ROOT, 'examples', 'broken', 'preview.yml'), 'utf8');
const clean = fs.readFileSync(path.join(ROOT, 'examples', 'clean', 'ci.yml'), 'utf8');

test('broken workflow triggers PWN_REQUEST, SCRIPT_INJECTION, HARDCODED_SECRET and UNPINNED_ACTION', () => {
  const res = scanFile('preview.yml', broken);
  const rules = res.findings.map((f) => f.rule);
  for (const expected of ['PWN_REQUEST', 'SCRIPT_INJECTION', 'HARDCODED_SECRET', 'UNPINNED_ACTION']) {
    assert.ok(rules.includes(expected), 'missing: ' + expected);
  }
});

test('clean workflow produces zero findings', () => {
  const res = scanFile('ci.yml', clean);
  assert.strictEqual(res.findings.length, 0);
});

test('pull_request_target without head checkout but with secrets is PR_TARGET_WITH_SECRETS', () => {
  const wf = parseWorkflow("on: [pull_request_target]\njobs:\n  x:\n    steps:\n      - run: echo hi\n        env:\n          T: ${{ secrets.A }}");
  const res = auditWorkflow('w', wf);
  assert.ok(res.findings.some((f) => f.rule === 'PR_TARGET_WITH_SECRETS' && f.severity === 'high'));
  assert.ok(!res.findings.some((f) => f.rule === 'PWN_REQUEST'));
});

test('missing permissions block is flagged medium', () => {
  const wf = parseWorkflow("on: push\njobs:\n  x:\n    steps:\n      - run: echo hi");
  const res = auditWorkflow('w', wf);
  assert.ok(res.findings.some((f) => f.rule === 'NO_PERMISSIONS_BLOCK' && f.severity === 'medium'));
});

test('run interpolation of issue title is caught as injection', () => {
  const wf = parseWorkflow("on: issues\njobs:\n  x:\n    steps:\n      - run: |\n          echo \"${{ github.event.issue.title }}\"");
  const res = auditWorkflow('w', wf);
  assert.ok(res.findings.some((f) => f.rule === 'SCRIPT_INJECTION'));
});

test('dashed list items parse for uses and triggers', () => {
  const wf = parseWorkflow("on:\n  - push\n  - pull_request\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4");
  assert.ok(wf.triggers.includes('push'));
  assert.ok(wf.triggers.includes('pull_request'));
  assert.strictEqual(wf.uses.length, 1);
});

test('pwn request evidence never contains secret values', () => {
  const res = scanFile('preview.yml', broken);
  for (const f of res.findings) {
    assert.ok(!String(f.evidence).includes('FAKE0000FAKE0000'), 'leaked secret in evidence');
  }
});
