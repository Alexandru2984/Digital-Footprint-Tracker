#!/usr/bin/env node

// Checks, before any browser test runs, that the pinned Playwright image carries
// the browser build the locked @playwright/test will look for.
//
// The image ships browsers for exactly one Playwright release, and the lockfile
// decides which build the runner expects. Move one without the other and every
// test dies with "Executable doesn't exist" and nothing that says why — which is
// how a routine dependabot bump turned the browser gate red. This names both
// sides and what to change. Both are read from their sources, nothing is copied.

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const [frontendDir, browsersPath] = process.argv.slice(2);
if (!frontendDir || !browsersPath) {
    console.error('usage: playwright-image-preflight.mjs FRONTEND_DIR BROWSERS_PATH');
    process.exit(64);
}

const core = join(frontendDir, 'node_modules', 'playwright-core');
const { version } = JSON.parse(readFileSync(join(core, 'package.json'), 'utf8'));
const { browsers } = JSON.parse(readFileSync(join(core, 'browsers.json'), 'utf8'));
const shell = browsers.find(browser => browser.name === 'chromium-headless-shell');
if (!shell) {
    console.error(`playwright-image-preflight: playwright-core ${version} declares no chromium-headless-shell build.`);
    process.exit(1);
}

const wanted = `chromium_headless_shell-${shell.revision}`;
if (!existsSync(join(browsersPath, wanted))) {
    const present = existsSync(browsersPath)
        ? readdirSync(browsersPath).filter(name => name.startsWith('chromium_headless_shell-'))
        : [];
    console.error(`playwright-image-preflight: @playwright/test ${version} needs ${wanted}, `
        + `but the pinned image carries ${present.join(', ') || 'no headless shell'}.`);
    console.error('Pin PLAYWRIGHT_IMAGE in scripts/run-browser-tests.sh to the digest of '
        + `mcr.microsoft.com/playwright:v${version}-noble — the package and the image move together.`);
    process.exit(1);
}
console.log(`playwright-image-preflight: image carries ${wanted} for @playwright/test ${version}.`);
