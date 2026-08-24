import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const frontendDir = dirname(fileURLToPath(import.meta.url));
const repositoryDir = resolve(frontendDir, '..');
const pages = ['index.html', 'login.html', 'register.html', 'admin.html'];
const inlineHashes = [];

function fail(message) {
    throw new Error(message);
}

for (const page of pages) {
    const html = readFileSync(join(frontendDir, page), 'utf8');

    const inlineHandler = html.match(/<[a-z][^>]*\son[a-z]+\s*=/i);
    if (inlineHandler) fail(`${page}: inline event handler violates script-src CSP`);

    if (/<script\b[^>]*\bsrc=["']https?:\/\//i.test(html)) {
        fail(`${page}: scripts must be served first-party`);
    }
    const linkTag = /<link\b([^>]*)>/gi;
    let linkMatch;
    while ((linkMatch = linkTag.exec(html))) {
        if (/\brel=["']stylesheet["']/i.test(linkMatch[1])
            && /\bhref=["']https?:\/\//i.test(linkMatch[1])) {
            fail(`${page}: stylesheets must be served first-party`);
        }
    }

    const localScript = /<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi;
    let scriptMatch;
    while ((scriptMatch = localScript.exec(html))) {
        const assetPath = scriptMatch[1].split(/[?#]/, 1)[0];
        if (!assetPath.startsWith('/')) fail(`${page}: script path must be origin-relative`);
        if (!existsSync(join(frontendDir, assetPath.slice(1)))) {
            fail(`${page}: missing script ${assetPath}`);
        }
    }

    const integrityTag = /<(?:script|link)\b([^>]*\bintegrity=["']sha384-([^"']+)["'][^>]*)>/gi;
    let integrityMatch;
    while ((integrityMatch = integrityTag.exec(html))) {
        const assetMatch = /\b(?:src|href)=["']([^"']+)["']/i.exec(integrityMatch[1]);
        if (!assetMatch) fail(`${page}: integrity attribute has no local asset`);
        const assetPath = assetMatch[1].split(/[?#]/, 1)[0];
        if (!assetPath.startsWith('/')) fail(`${page}: integrity asset must be origin-relative`);
        const asset = readFileSync(join(frontendDir, assetPath.slice(1)));
        const actual = createHash('sha384').update(asset).digest('base64');
        if (actual !== integrityMatch[2]) fail(`${page}: stale SRI for ${assetPath}`);
    }

    const inlineScript = /<script(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/gi;
    while ((scriptMatch = inlineScript.exec(html))) {
        const attributes = scriptMatch[1];
        const source = scriptMatch[2];
        if (/\btype=["']application\/ld\+json["']/i.test(attributes)) {
            JSON.parse(source);
        } else {
            // Parse without executing browser code.
            new Function(source);
        }
        inlineHashes.push(createHash('sha256').update(source).digest('base64'));
    }
}

for (const script of ['admin.js', 'investigation.js', 'dark-web.js']) {
    new Function(readFileSync(join(frontendDir, script), 'utf8'));
}

const firstPartySource = pages.concat(['admin.js', 'investigation.js', 'dark-web.js'])
    .map(file => readFileSync(join(frontendDir, file), 'utf8'))
    .join('\n');
if (/localStorage\.(?:getItem|setItem)\(\s*["']authToken["']/i.test(firstPartySource)) {
    fail('Bearer credentials must not be persisted in localStorage');
}
if (/document\.write\s*\(/.test(firstPartySource)) {
    fail('First-party code must not use the document.write HTML parser sink');
}
if (!readFileSync(join(frontendDir, 'investigation.js'), 'utf8').includes("default-src \\'none\\'")) {
    fail('Generated investigation reports require a deny-by-default embedded CSP');
}
const darkWebSource = readFileSync(join(frontendDir, 'dark-web.js'), 'utf8');
if (/\.innerHTML\s*=/.test(darkWebSource)) {
    fail('dark-web.js must render untrusted worker data without innerHTML');
}
for (const required of ['dark-web-overlay', 'dark-web-form', 'dark-web-jobs', 'dark-web-findings']) {
    if (!readFileSync(join(frontendDir, 'index.html'), 'utf8').includes(`id="${required}"`)) {
        fail(`index.html: missing dark-web UI element #${required}`);
    }
}

const csp = readFileSync(join(repositoryDir, 'ops/nginx/snippets/swift-csp.conf'), 'utf8');
const scriptDirective = /script-src ([^;]+);/.exec(csp)?.[1];
if (!scriptDirective) fail('CSP script-src directive is missing');
if (!scriptDirective.includes("'nonce-$request_id'")) {
    fail('CSP must expose a per-request nginx nonce for Cloudflare JSD');
}
if (scriptDirective.includes("'unsafe-inline'")) {
    fail('CSP script-src must not permit unsafe-inline');
}
const configuredHashes = [...csp.matchAll(/'sha256-([^']+)'/g)].map(match => match[1]);
const expected = new Set(inlineHashes);
const configured = new Set(configuredHashes);
if (configuredHashes.length !== configured.size) fail('CSP contains duplicate script hashes');
if (expected.size !== configured.size || [...expected].some(hash => !configured.has(hash))) {
    fail(`CSP hash drift: expected ${[...expected].join(' ')}, found ${[...configured].join(' ')}`);
}

console.log(`Frontend integrity checks passed (${pages.length} pages, ${inlineHashes.length} inline scripts).`);
