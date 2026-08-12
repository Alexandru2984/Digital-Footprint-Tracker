#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const directories = process.argv.slice(2);
const pages = ['index.html', 'login.html', 'register.html', 'admin.html'];
if (directories.length < 1 || directories.length > 2) {
    throw new Error('usage: csp-hashes.mjs FRONTEND [TRANSITION_FRONTEND]');
}

const hashes = new Set();
for (const input of directories) {
    const frontend = resolve(input);
    if (!lstatSync(frontend).isDirectory()) {
        throw new Error(`not a frontend directory: ${frontend}`);
    }
    for (const page of pages) {
        const html = readFileSync(join(frontend, page), 'utf8');
        const inlineScript = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
        let match;
        while ((match = inlineScript.exec(html))) {
            hashes.add(`sha256-${createHash('sha256').update(match[1]).digest('base64')}`);
        }
    }
}

if (hashes.size === 0) throw new Error('no inline scripts found');
for (const hash of [...hashes].sort()) console.log(hash);
