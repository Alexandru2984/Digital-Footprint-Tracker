import { expect, test } from '@playwright/test';
import { mockAPI } from './fixtures.mjs';

test('skip navigation and keyboard-help dialog preserve keyboard focus', async ({ page }) => {
    await mockAPI(page);
    await page.goto('/', { waitUntil: 'networkidle' });

    await page.keyboard.press('Tab');
    const skipLink = page.getByRole('link', { name: 'Skip to main content' });
    await expect(skipLink).toBeFocused();
    await expect(skipLink).toBeVisible();
    await page.keyboard.press('Enter');
    await expect(page.locator('#main-content')).toBeFocused();

    const trigger = page.locator('#kbd-help-trigger');
    await trigger.focus();
    await page.keyboard.press('Enter');
    const dialog = page.getByRole('dialog', { name: 'Keyboard Shortcuts' });
    await expect(dialog).toBeVisible();
    await expect(page.locator('#kbd-help-close')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#kbd-help-close')).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(trigger).toBeFocused();
});

test('mobile menu has accurate expanded state and Escape behavior', async ({ page }, testInfo) => {
    test.skip((testInfo.project.use.viewport?.width || 1000) >= 768, 'mobile menu only');
    await mockAPI(page);
    await page.goto('/', { waitUntil: 'networkidle' });

    const button = page.locator('#hamburger-btn');
    await expect(button).toBeVisible();
    await expect(button).toHaveAttribute('aria-expanded', 'false');
    await button.focus();
    await page.keyboard.press('Enter');
    await expect(button).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('#auth-widget')).toHaveClass(/mobile-open/);
    await page.keyboard.press('Escape');
    await expect(button).toHaveAttribute('aria-expanded', 'false');
});

test('production CSP permits tracked scripts and blocks injected inline code', async ({ page }) => {
    await page.addInitScript(() => {
        window.__cspViolations = [];
        document.addEventListener('securitypolicyviolation', event => {
            window.__cspViolations.push({ directive: event.effectiveDirective, blockedURI: event.blockedURI });
        });
    });
    await mockAPI(page);
    const response = await page.goto('/', { waitUntil: 'networkidle' });
    const csp = (await response.allHeaders())['content-security-policy'];
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain("script-src 'self' 'unsafe-inline'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(await page.evaluate(() => window.__cspViolations)).toEqual([]);

    const executed = await page.evaluate(() => {
        const script = document.createElement('script');
        script.textContent = 'window.__unapprovedInlineScript = true';
        document.head.appendChild(script);
        return Boolean(window.__unapprovedInlineScript);
    });
    expect(executed).toBe(false);
    await expect.poll(() => page.evaluate(() => window.__cspViolations.length)).toBeGreaterThan(0);
    expect(await page.evaluate(() => window.__cspViolations.some(item => item.directive.startsWith('script-src')))).toBe(true);
});

test('reduced-motion users receive effectively static transitions and animations', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await mockAPI(page);
    await page.goto('/', { waitUntil: 'networkidle' });

    const motion = await page.evaluate(() => {
        const body = getComputedStyle(document.body);
        const scanLine = getComputedStyle(document.querySelector('.scan-line'));
        return {
            bodyTransitionMs: parseFloat(body.transitionDuration) * 1000,
            scanAnimationMs: parseFloat(scanLine.animationDuration) * 1000,
            scrollBehavior: getComputedStyle(document.documentElement).scrollBehavior,
        };
    });
    expect(motion.bodyTransitionMs).toBeLessThanOrEqual(1);
    expect(motion.scanAnimationMs).toBeLessThanOrEqual(1);
    expect(motion.scrollBehavior).toBe('auto');
});

test('admin audit and notification payloads render as text, never markup', async ({ page }) => {
    const fixture = await mockAPI(page, { authenticated: true, admin: true });
    await page.goto('/admin.html', { waitUntil: 'networkidle' });
    await page.locator('#load-audit-btn').click();
    await expect(page.locator('#audit-log-container')).toContainText(fixture.malicious);
    expect(await page.locator('[data-browser-xss]').count()).toBe(0);
    expect(await page.evaluate(() => Boolean(window.__browserXSS))).toBe(false);

    await page.goto('/', { waitUntil: 'networkidle' });
    await expect(page.locator('#notif-list')).toContainText(fixture.malicious);
    expect(await page.locator('[data-browser-xss]').count()).toBe(0);
    expect(await page.evaluate(() => Boolean(window.__browserXSS))).toBe(false);
});

test('admin exposes signed audit verification without leaking ledger payloads', async ({ page }) => {
    await mockAPI(page, { authenticated: true, admin: true });
    await page.goto('/admin.html', { waitUntil: 'networkidle' });
    const status = page.locator('#audit-integrity-status');
    await expect(status).toContainText('Valid signed ledger');
    await expect(status).toContainText('12 events');
    await expect(status).toContainText('browser-test');
    await expect(status).not.toContainText('headHash');
});

test('admin shows plugin health and top plugins as text, and a populated chart does not stop the page', async ({ page }) => {
    const fixture = await mockAPI(page, { authenticated: true, admin: true });
    const errors = [];
    page.on('pageerror', error => errors.push(String(error)));
    await page.goto('/admin.html', { waitUntil: 'networkidle' });

    await expect(page.locator('#plugin-health-summary')).toHaveText('1 failing · 0 degraded · 1 healthy · 1 not run since restart · 1 canary failing · 1 not configured (missing API key)');
    const rows = page.locator('#plugin-health-container tbody tr');
    await expect(rows).toHaveCount(3);
    await expect(rows.nth(0)).toContainText(fixture.malicious);
    await expect(rows.nth(0)).toContainText('3 / 3');
    await expect(rows.nth(0)).toContainText('failing · 2 skipped · next probe');
    await expect(rows.nth(1)).not.toContainText('skipped');
    await expect(rows.nth(0)).toContainText('FAILED (');
    await expect(rows.nth(1)).toContainText('passed ·');
    await expect(rows.nth(2)).toContainText('not configured');
    await expect(rows.nth(1)).toContainText('healthy');
    await expect(page.locator('#top-plugins-chart svg text').first()).toHaveText(/^<img data-browser-/);
    await expect(page.locator('#audit-integrity-status')).toContainText('Valid signed ledger');

    expect(errors).toEqual([]);
    expect(await page.locator('[data-browser-xss]').count()).toBe(0);
    expect(await page.evaluate(() => Boolean(window.__browserXSS))).toBe(false);
});

test('a shared report shows its results and names the sources that were not checked', async ({ page }) => {
    const fixture = await mockAPI(page);
    const requested = [];
    page.on('request', request => requested.push(new URL(request.url()).pathname));
    await page.goto('/share#' + 'A'.repeat(32), { waitUntil: 'networkidle' });

    await expect(page.locator('#results-grid > *')).toHaveCount(2);
    await expect(page.locator('#results-grid')).toContainText('GitHub account found.');
    const note = page.locator('#unavailable-sources-note');
    await expect(note).toBeVisible();
    await expect(note).toContainText('Not checked — source temporarily unavailable: Reddit');
    await expect(note).toContainText(fixture.malicious);

    expect(requested.some(path => path.includes('undefined')), requested.join('\n')).toBe(false);
    const history = await page.evaluate(() => localStorage.getItem('dft_history'));
    expect(history || '').not.toContain('00000000-0000-4000-8000-0000000000aa');
    expect(await page.locator('[data-browser-xss]').count()).toBe(0);
    expect(await page.evaluate(() => Boolean(window.__browserXSS))).toBe(false);
});

test('the graph tab draws how identifiers connect, coloured by strength', async ({ page }) => {
    const fixture = await mockAPI(page);
    await page.goto('/?scan=00000000-0000-4000-8000-0000000000bb', { waitUntil: 'networkidle' });
    await page.locator('#tab-graph').click();

    const svg = page.locator('#social-graph-svg');
    await expect(svg.locator('.js-node')).toHaveCount(6);
    await expect(svg.locator('.js-link-verified')).toHaveCount(2);
    await expect(svg.locator('.js-link-inferred')).toHaveCount(1);
    await expect(svg.locator('.js-link-declared')).toHaveCount(1);
    await expect(page.locator('#graph-legend')).toContainText('verified');

    await svg.locator('.js-node', { hasText: 'github: alice' }).click();
    const detail = page.locator('#graph-detail-body');
    await expect(detail).toContainText('Belongs to the target: 98%');
    await expect(detail).toContainText('Via: alice@example.com → github: alice');
    await expect(detail).toContainText('VERIFIED · alice@example.com');
    await expect(detail).toContainText('signs in through GitHub (crates.io)');

    const chips = page.locator('#identity-panel .js-attributions');
    await expect(chips).toContainText('github: alice 98%');
    await expect(chips).toContainText('steam: alice 22%');
    await expect(chips).toContainText(`twitter: ${fixture.malicious} 90%`);

    await page.locator('#graph-mode [data-graph-mode="sources"]').click();
    await expect(page.locator('#graph-legend')).toContainText('Source');
    await expect(svg.locator('.js-node')).toHaveCount(0);
    await page.locator('#graph-mode [data-graph-mode="connections"]').click();
    await expect(svg.locator('.js-node')).toHaveCount(6);

    expect(await page.locator('[data-browser-xss]').count()).toBe(0);
    expect(await page.evaluate(() => Boolean(window.__browserXSS))).toBe(false);
});

test('timeline evidence is responsive, filterable and rendered only as text', async ({ page }) => {
    const fixture = await mockAPI(page);
    await page.goto('/', { waitUntil: 'networkidle' });
    await page.evaluate(({ malicious }) => {
        document.querySelector('#results-panel').classList.remove('hidden');
        const events = Array.from({ length: 13 }, (_, index) => ({
            date: `20${String(index + 10).padStart(2, '0')}`,
            label: `${malicious} event ${index}`,
            category: index % 2 ? 'account' : 'breach',
            precision: 'year',
            sources: [malicious, 'fixture-source'],
            confidence: 0.85,
            evidenceCount: 2,
            conflicting: index === 0,
            conflictDates: index === 0 ? ['2010', malicious] : [],
        }));
        window.renderIdentity(document.querySelector('#identity-panel'), {
            likelyName: null,
            emails: [], handles: [], confirmedAccounts: [], breaches: [], phones: [],
            exposedIPs: [], exposedServices: [], vulnerabilities: [], exposedDataClasses: [],
            timeline: events,
            timelineSummary: {
                totalEventCount: 13,
                breachRecurrenceCount: 6,
                conflictGroups: 1,
            },
            riskScore: 25,
            riskLevel: 'Low',
            riskFactors: [
                { category: 'breach', label: malicious, points: 20, findings: 1 },
                { category: 'account', label: 'Online accounts', points: 5, findings: 3 },
            ],
            links: [
                { from: 'alice@example.com', to: 'github: alice', kind: 'verified', source: 'GitHub', reason: 'verified email' },
                { from: malicious, to: 'steam: alice', kind: 'inferred', source: malicious, reason: malicious },
            ],
            dossier: {
                headline: `${malicious} — 1 confirmed account; in 215 breaches`,
                confirmed: [{ label: 'github: alice', score: 98 }],
                probable: [{ label: malicious, score: 60 }],
                unconfirmedCount: 4, sites: [], breachCount: 215, latestBreach: '2026',
                sensitiveData: ['Passwords', malicious],
            },
        });
    }, fixture);

    const panel = page.locator('#identity-panel');
    await expect(panel).toBeVisible();
    await expect(panel).toContainText(fixture.malicious);
    const connections = panel.locator('.js-identity-links');
    await expect(connections).toContainText('How these are connected · 1 confirmed, 1 unconfirmed');
    await expect(connections).toContainText('alice@example.com → github: alice verified');
    await expect(connections).toContainText(`${fixture.malicious} → steam: alice inferred`);
    await expect(panel.locator('.js-risk-factors')).toHaveText(
        `Risk made of: ${fixture.malicious} 20 (1 finding) · Online accounts 5 (3 findings)`);
    const dossier = panel.locator('.js-dossier');
    await expect(dossier).toContainText(`${fixture.malicious} — 1 confirmed account; in 215 breaches`);
    await expect(dossier.locator('.js-dossier-tier').first()).toContainText('Confirmed (80%+)github: alice · 98%');
    await expect(dossier).toContainText(`${fixture.malicious} · 60%`);
    await expect(dossier).toContainText('4 more found by name alone (unconfirmed)');
    await expect(dossier).toContainText(`215 breaches, latest 2026; leaked: Passwords, ${fixture.malicious}`);
    expect(await page.locator('[data-browser-xss]').count()).toBe(0);
    expect(await page.evaluate(() => Boolean(window.__browserXSS))).toBe(false);

    const years = panel.locator('.js-timeline-year');
    await expect(years).toHaveCount(13);
    await expect(panel.locator('.js-timeline-year[data-year="2010"]')).toHaveAttribute('aria-label', '2010: 1 event, 1 breach');
    await panel.locator('.js-timeline-year[data-year="2011"]').click();
    await expect(panel).toContainText('Showing 1 of 1 from 2011');
    await expect(panel.locator('.js-timeline-year[data-year="2011"]')).toHaveAttribute('aria-pressed', 'true');
    await panel.locator('.js-timeline-year[data-year="2011"]').click();
    await expect(panel).toContainText('Showing 12 of 13');

    const filter = page.getByLabel('Filter timeline by category');
    await filter.selectOption('account');
    await expect(panel).toContainText('Showing 6 of 6');
    // Years with no account event stay as empty, disabled columns.
    await expect(years).toHaveCount(11);
    await expect(panel.locator('.js-timeline-year[data-year="2012"]')).toBeDisabled();
    await filter.selectOption('all');
    const expand = page.getByRole('button', { name: 'Show all loaded' });
    await expand.click();
    await expect(panel).toContainText('Showing 13 of 13');

    const overflow = await page.evaluate(() => {
        const viewportWidth = document.documentElement.clientWidth;
        const rect = document.querySelector('#identity-panel').getBoundingClientRect();
        return rect.left < -1 || rect.right > viewportWidth + 1;
    });
    expect(overflow).toBe(false);
});

test('the surface tab warns about a subdomain that can be taken over, as text', async ({ page }) => {
    const fixture = await mockAPI(page);
    await page.goto('/?scan=00000000-0000-4000-8000-0000000000bb', { waitUntil: 'networkidle' });
    await page.locator('#tab-surface').click();
    const warning = page.locator('#surface-tab-content .js-takeover');
    await expect(warning).toHaveCount(1);
    await expect(warning).toContainText('old.example.com');
    await expect(warning).toContainText('(Azure)');
    await expect(warning).toContainText(fixture.malicious);
    const history = page.locator('#surface-tab-content .js-dns-history');
    await expect(history).toContainText('POSSIBLE ORIGIN BEHIND THE CDN: 203.0.113.9');
    expect(await page.locator('[data-browser-xss]').count()).toBe(0);
    expect(await page.evaluate(() => Boolean(window.__browserXSS))).toBe(false);
});

test('d3 and qrcode load only when their feature opens, within the CSP', async ({ page }) => {
    await page.addInitScript(() => {
        window.__cspViolations = [];
        document.addEventListener('securitypolicyviolation', event => {
            window.__cspViolations.push({ directive: event.effectiveDirective, blockedURI: event.blockedURI });
        });
    });
    const requested = [];
    page.on('request', request => requested.push(new URL(request.url()).pathname));
    await mockAPI(page, { authenticated: true });
    await page.route('**/api/auth/2fa/setup', route => route.fulfill({
        status: 200,
        contentType: 'application/json; charset=utf-8',
        body: JSON.stringify({
            secret: 'JBSWY3DPEHPK3PXP',
            otpauthURI: 'otpauth://totp/Browser:browser-tester?secret=JBSWY3DPEHPK3PXP&issuer=Browser',
        }),
    }));

    await page.goto('/', { waitUntil: 'networkidle' });
    expect(requested).not.toContain('/d3.min.js');
    expect(requested).not.toContain('/qrcode.js');
    expect(await page.evaluate(() => typeof window.d3)).toBe('undefined');

    // The real setup handler: it has to fetch qrcode.js before it can draw.
    await page.evaluate(() => document.getElementById('twofa-start-btn').click());
    await expect(page.locator('#twofa-qr svg')).toBeAttached();
    expect(requested.filter(path => path === '/qrcode.js')).toHaveLength(1);

    await page.evaluate(() => loadScriptOnce('/d3.min.js'));
    expect(await page.evaluate(() => typeof window.d3.forceSimulation)).toBe('function');
    expect(await page.evaluate(() => window.__cspViolations)).toEqual([]);
});

test('a board seeded from a scan loads d3 with it and draws the graph', async ({ page }) => {
    const requested = [];
    page.on('request', request => requested.push(new URL(request.url()).pathname));
    await mockAPI(page, { authenticated: true });
    await page.route('**/api/investigations**', route => route.fulfill({
        status: 200, contentType: 'application/json; charset=utf-8', body: '[]',
    }));

    await page.goto('/', { waitUntil: 'networkidle' });
    expect(requested).not.toContain('/investigation.js');
    expect(requested).not.toContain('/d3.min.js');

    // Straight to the board, never through the graph tab: boards must not rely
    // on something else having loaded d3 first.
    await page.evaluate(() => {
        lastScanData = { input: 'browser-tester', results: [] };
        document.getElementById('seed-board-btn').click();
    });
    await expect(page.locator('#board-overlay')).toBeVisible();
    await expect(page.locator('#board-svg circle').first()).toBeAttached();
    expect(requested.indexOf('/d3.min.js')).toBeLessThan(requested.indexOf('/investigation.js'));
});
