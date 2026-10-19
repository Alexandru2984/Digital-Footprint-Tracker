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
    const walk = (relative, depth) => {
        for (const name of readdirSync(join(frontend, relative))) {
            if (name.startsWith('.')) continue;
            if (depth === 0 && ['node_modules', 'tests', 'docs', 'playwright-report', 'test-results'].includes(name)) continue;
            const child = relative ? join(relative, name) : name;
            if (!statSync(join(frontend, child)).isDirectory()) continue;
            if (existsSync(join(frontend, child, 'index.html'))) pages.push(join(child, 'index.html'));
            if (depth < 1) walk(child, depth + 1);
        }
    };
    walk('', 0);
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
