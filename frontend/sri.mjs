#!/usr/bin/env node

// Derives every subresource-integrity attribute from the bytes it protects.
//
// The hash was hand-copied into the page, so regenerating tailwind.css moved
// the file and left the attribute describing the previous one. A browser that
// honours SRI then refuses the stylesheet outright — the page loads unstyled —
// and the only thing standing between that and production was someone
// remembering to paste a new digest. This removes the remembering.
//
// Run by `npm run build:css`, so the digest cannot survive a rebuild of the
// asset. `check.mjs` still verifies independently: this writes, that one reads.

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const frontendDir = dirname(fileURLToPath(import.meta.url));
const pages = readdirSync(frontendDir).filter(name => name.endsWith('.html')).sort();

// Twelve hex characters of the file's sha256: long enough that two builds never
// collide, short enough to read in a URL.
const VERSION_LENGTH = 12;

function contentVersion(assetPath) {
    return createHash('sha256')
        .update(readFileSync(join(frontendDir, assetPath.slice(1))))
        .digest('hex')
        .slice(0, VERSION_LENGTH);
}

let rewritten = 0;
let attributes = 0;
let versions = 0;

for (const page of pages) {
    const file = join(frontendDir, page);
    const original = readFileSync(file, 'utf8');

    // The cache-busting query comes from the file, not from someone remembering
    // to bump it. On 2026-10-05 Cloudflare held the previous tailwind.css for
    // four hours against pages declaring the new integrity hash, and a browser
    // that honours SRI refuses a stylesheet whose hash does not match — so the
    // admin page rendered unstyled. When the bytes change, the URL changes.
    const versioned = /\b(href|src)=(["'])(\/[^"'?#]+)\?v=[^"'#]*\2/gi;
    const rebusted = original.replace(versioned, (whole, attr, quote, assetPath) => {
        versions += 1;
        return `${attr}=${quote}${assetPath}?v=${contentVersion(assetPath)}${quote}`;
    });

    // A negated character class spans newlines, which the multi-line link tag
    // in admin.html needs.
    const element = /<(?:script|link)\b[^>]*\bintegrity=["']sha384-[^"']*["'][^>]*>/gi;
    const updated = rebusted.replace(element, (tag) => {
        attributes += 1;
        const asset = /\b(?:src|href)=["']([^"']+)["']/i.exec(tag);
        if (!asset) throw new Error(`${page}: integrity attribute with no asset`);
        const assetPath = asset[1].split(/[?#]/, 1)[0];
        if (!assetPath.startsWith('/')) {
            throw new Error(`${page}: integrity asset must be origin-relative`);
        }
        const digest = createHash('sha384')
            .update(readFileSync(join(frontendDir, assetPath.slice(1))))
            .digest('base64');
        return tag.replace(/\bintegrity=["']sha384-[^"']*["']/i, `integrity="sha384-${digest}"`);
    });

    if (updated !== original) {
        writeFileSync(file, updated);
        rewritten += 1;
        console.log(`sri: refreshed ${page}`);
    }
}

console.log(`sri: ${attributes} integrity attribute(s) and ${versions} versioned URL(s) across ${pages.length} page(s), ${rewritten} rewritten.`);
