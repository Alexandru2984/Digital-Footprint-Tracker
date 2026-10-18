// The pages this site ships: every top-level .html file, and the index.html
// of each content directory (/email-lookup/ and the like, served at a clean
// URL). One list, so integrity, versioning and CSP checks see the same set.
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const notContent = new Set(['node_modules', 'tests', 'docs', 'playwright-report', 'test-results']);

export function listPages(frontendDir) {
    const pages = readdirSync(frontendDir).filter(name => name.endsWith('.html'));
    for (const name of readdirSync(frontendDir)) {
        if (notContent.has(name) || name.startsWith('.')) continue;
        const dir = join(frontendDir, name);
        if (statSync(dir).isDirectory() && existsSync(join(dir, 'index.html'))) pages.push(`${name}/index.html`);
    }
    return pages.sort();
}

// JSON-LD is data, not script: CSP's script-src does not govern it, so it
// needs no hash, and its wording can change without touching the CSP.
export function isDataBlock(attributes) {
    return /\btype=["']application\/ld\+json["']/i.test(attributes);
}
