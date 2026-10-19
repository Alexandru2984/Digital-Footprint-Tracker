// The pages this site ships: every top-level .html file, and the index.html
// of each content directory (/email-lookup/ and the like, served at a clean
// URL). One list, so integrity, versioning and CSP checks see the same set.
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const notContent = new Set(['node_modules', 'tests', 'docs', 'playwright-report', 'test-results']);

export function listPages(frontendDir) {
    const pages = readdirSync(frontendDir).filter(name => name.endsWith('.html'));
    // Content directories, two levels deep at most (/ro/cautare-email/).
    const walk = (relative, depth) => {
        for (const name of readdirSync(join(frontendDir, relative))) {
            if (name.startsWith('.') || (depth === 0 && notContent.has(name))) continue;
            const child = relative ? `${relative}/${name}` : name;
            if (!statSync(join(frontendDir, child)).isDirectory()) continue;
            if (existsSync(join(frontendDir, child, 'index.html'))) pages.push(`${child}/index.html`);
            if (depth < 1) walk(child, depth + 1);
        }
    };
    walk('', 0);
    return pages.sort();
}

// JSON-LD is data, not script: CSP's script-src does not govern it, so it
// needs no hash, and its wording can change without touching the CSP.
export function isDataBlock(attributes) {
    return /\btype=["']application\/ld\+json["']/i.test(attributes);
}
