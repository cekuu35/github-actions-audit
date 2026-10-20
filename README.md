# github-actions-audit

[![CI](https://github.com/cekuu35/github-actions-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/cekuu35/github-actions-audit/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/github-actions-audit.svg)](https://www.npmjs.com/package/github-actions-audit)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Static audit of **GitHub Actions workflow files** for the failure modes that
actually burn repositories: pwn requests, script injection, hardcoded
secrets, and unpinned actions.

The most dangerous line in many repos is a well-intentioned
`pull_request_target` that checks out the PR's code with access to base-repo
secrets — a "pwn request". A malicious fork PR gets the token. The second
is `run:` blocks interpolating `${{ github.event.pull_request.body }}` —
whoever opens the PR executes whatever they want in your shell. Both survive
review because the YAML looks normal.

Zero dependencies. No YAML parser, no network. **Free, forever.**

## Quick start

```bash
npx github-actions-audit                     # scans .github/workflows/*.yml
npx github-actions-audit path/to/workflow.yml --json
```

Exit codes are CI-friendly: `0` clean, `1` any critical/high finding, `2` no
workflow files found.

## What it detects

| Rule | Severity | What it catches |
|---|---|---|
| `PWN_REQUEST` | critical | `pull_request_target` + checkout of `github.event.pull_request.head` — untrusted PR code runs with base-repo secret access |
| `SCRIPT_INJECTION` | critical | `run:` blocks interpolating attacker-controllable context (PR/issue body, title, commit message) into a shell |
| `PR_TARGET_WITH_SECRETS` | high | `pull_request_target` workflow using `secrets.*` — verify every step only processes trusted refs |
| `HARDCODED_SECRET` | high | real-looking token literals (`sk-`, `ghp_`, `AKIA`, `AIza`, `xox`, `glpat`, `npm_`) anywhere in the file |
| `UNPINNED_ACTION` | medium | `uses:` pinned to a mutable tag/branch instead of a full commit SHA |
| `NO_PERMISSIONS_BLOCK` | medium | no top-level `permissions:` — GITHUB_TOKEN gets the repo default instead of least privilege |
| `MALFORMED_USES` | medium | `uses:` without an `@ref` |

Dashed list forms (`- uses:`, `- run:`) and block triggers (`on:` with
`- push` items) parse correctly. Evidence is redacted — reports are safe to
paste into issues.

## Example output

Scanning the [broken example](examples/broken/preview.yml):

```
== examples/broken/preview.yml
   [CRITICAL] PWN_REQUEST
       pull_request_target checks out untrusted PR code with access to base-repo secrets — a malicious PR gets full secret access ("pwn request")
       evidence: on: pull_request_target + checkout of github.event.pull_request.head
   [CRITICAL] SCRIPT_INJECTION
       run block interpolates attacker-controllable GitHub context (PR/issue body, title, commit message) into a shell script
       evidence: echo "Deploying PR title: ${{ github.event.pull_request.title }}"
   [HIGH] HARDCODED_SECRET
       real-looking secret literal in the workflow file — use secrets context, not literals
       evidence: api_ke***(40 chars)
   ...

Summary: 2 critical, 1 high, 2 medium, 0 low
```

## Tests

```bash
npm test
```

7 tests, zero dependencies: every rule fires on the broken fixture, the
SHA-pinned clean fixture stays clean, `pull_request_target`+secrets without
a head checkout maps to `PR_TARGET_WITH_SECRETS` (not PWN), dashed list
items parse, missing `permissions:` is flagged.

## Honest scope

This is a static linter, not a security audit of your CI. It does not
resolve composite actions, evaluate expression logic, check runner
isolation, or know which secrets are actually sensitive. A workflow can
pass this scan and still be misconfigured. Pin actions to SHAs and read the
[pull_request_target docs](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target)
before using that trigger at all.

## The audit family

Free, zero-dependency security auditors in the same shape:

- [mcp-config-security](https://github.com/cekuu35/mcp-config-security) — scan MCP client configs (Claude, Cursor, Windsurf) for leaked tokens
- [firebase-rules-audit](https://github.com/cekuu35/firebase-rules-audit) — static audit of Firebase Firestore & Storage security rules
- [n8n-workflow-audit](https://github.com/cekuu35/n8n-workflow-audit) — scan exported n8n workflow JSON for hardcoded credentials
- [stripe-webhook-audit](https://github.com/cekuu35/stripe-webhook-audit) — Stripe webhook handlers that trust events without signature verification
- [supabase-rls-leak-demo](https://github.com/cekuu35/supabase-rls-leak-demo) — red/green fixture proving a Supabase RLS leak, and its one-file fix

## Support

If this tool caught a pwn request before someone else did, you can
[buy me a coffee](https://www.buymeacoffee.com/cenkkurtoglu) — completely
optional. The tool is free, no features are locked, and no email is asked.

## License

MIT
