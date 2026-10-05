#!/usr/bin/env node

// `npm audit` with an explicit, expiring exception list.
//
// npm audit is all-or-nothing: it cannot waive one advisory, so the only ways
// past an unfixable finding are lowering the threshold for everything or
// dropping the gate. Both are worse than naming the one advisory accepted, why,
// and until when. An exception here is a decision with an owner and a date, not
// a silence.
//
// It fails on: any high/critical advisory that is not listed; a listed advisory
// whose date has passed; and a listed advisory that no longer appears at all —
// because an exception nobody needs is one nobody is reviewing either.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const BLOCKING = new Set(['high', 'critical']);
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const frontendDir = join(repositoryRoot, 'frontend');
// --allowlist and --input exist so the contract test can drive this with
// fixtures instead of the repository's own state; CI passes neither.
const allowlistFlag = process.argv.indexOf('--allowlist');
const allowlistPath = allowlistFlag === -1
    ? join(frontendDir, 'npm-audit-allowlist.json')
    : resolve(process.argv[allowlistFlag + 1]);

function runNpmAudit() {
    const options = { cwd: frontendDir, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 };
    try {
        return execFileSync('npm', ['audit', '--json'], options);
    } catch (error) {
        // npm audit exits non-zero whenever it finds anything, which is most of
        // the time here: the report is still on stdout and is what we came for.
        if (typeof error.stdout === 'string' && error.stdout.trimStart().startsWith('{')) return error.stdout;
        throw error;
    }
}

const inputFlag = process.argv.indexOf('--input');
const report = JSON.parse(inputFlag === -1
    ? runNpmAudit()
    : readFileSync(process.argv[inputFlag + 1], 'utf8'));

const allowlist = JSON.parse(readFileSync(allowlistPath, 'utf8'));
const today = (process.env.AUDIT_TODAY ?? new Date().toISOString()).slice(0, 10);

const found = new Map();
for (const [name, entry] of Object.entries(report.vulnerabilities ?? {})) {
    for (const via of entry.via ?? []) {
        // A string `via` means "depends on something vulnerable" — the advisory
        // itself is recorded against the package it was filed for.
        if (typeof via !== 'object' || !BLOCKING.has(via.severity)) continue;
        const id = /GHSA-[0-9a-z-]+/.exec(via.url ?? '')?.[0] ?? String(via.source);
        if (!found.has(id)) found.set(id, { id, severity: via.severity, packages: new Set() });
        found.get(id).packages.add(via.name ?? name);
    }
}

const problems = [];
const accepted = [];
for (const advisory of found.values()) {
    const exception = allowlist.find(item => item.id === advisory.id);
    if (!exception) {
        problems.push(`${advisory.severity}: ${advisory.id} (${[...advisory.packages].join(', ')}) is not in `
            + `${allowlistPath.replace(repositoryRoot + '/', '')}. Fix it, or add it with a reason and a date.`);
    } else if (exception.until < today) {
        problems.push(`${advisory.id} was accepted until ${exception.until}; that date has passed. `
            + `Re-check whether a fix exists, then move the date or fix it.`);
    } else {
        accepted.push(`${advisory.id} (${[...advisory.packages].join(', ')}) accepted until ${exception.until}: ${exception.reason}`);
    }
}
for (const exception of allowlist) {
    if (!found.has(exception.id)) {
        problems.push(`${exception.id} is listed as accepted but no longer reported. Remove it from the allowlist.`);
    }
}

for (const line of accepted) console.log(`audit-frontend: ${line}`);
if (problems.length === 0) {
    const counts = report.metadata?.vulnerabilities ?? {};
    console.log(`audit-frontend: no unaccounted high or critical advisories `
        + `(npm reports ${counts.high ?? 0} high, ${counts.critical ?? 0} critical).`);
    process.exit(0);
}
console.error(`audit-frontend: ${problems.length} problem(s).`);
for (const problem of problems) console.error(`  - ${problem}`);
process.exit(1);
