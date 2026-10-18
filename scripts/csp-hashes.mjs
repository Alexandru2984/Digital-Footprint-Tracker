#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

const directories = process.argv.slice(2);
if (directories.length < 1 || directories.length > 2) {
    throw new Error('usage: csp-hashes.mjs FRONTEND [TRANSITION_FRONTEND]');
}

const hashes = new Set();
for (const input of directories) {
    const frontend = resolve(input);
    if (!lstatSync(frontend).isDirectory()) {
        throw new Error(`not a frontend directory: ${frontend}`);
    }
    // Derived from the tree being scanned, so a new page's inline script cannot
    // be missing from the CSP the same deploy installs.
    // Top-level pages and each content directory's index.html, as
    // frontend/pages.mjs lists them (kept in step by the CSP drift check).
    const pages = readdirSync(frontend).filter(name => name.endsWith('.html'));
    for (const name of readdirSync(frontend)) {
        if (['node_modules', 'tests', 'docs', 'playwright-report', 'test-results'].includes(name)) continue;
        if (statSync(join(frontend, name)).isDirectory() && existsSync(join(frontend, name, 'index.html'))) {
            pages.push(join(name, 'index.html'));
        }
    }
    for (const page of pages.sort()) {
        const html = readFileSync(join(frontend, page), 'utf8');
        const inlineScript = /<script(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/gi;
        let match;
        while ((match = inlineScript.exec(html))) {
            // JSON-LD is data; script-src does not govern it.
            if (/\btype=["']application\/ld\+json["']/i.test(match[1])) continue;
            hashes.add(`sha256-${createHash('sha256').update(match[2]).digest('base64')}`);
        }
    }
}

if (hashes.size === 0) throw new Error('no inline scripts found');
for (const hash of [...hashes].sort()) console.log(hash);
