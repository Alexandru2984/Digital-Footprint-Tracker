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
        });
    }, fixture);

    const panel = page.locator('#identity-panel');
    await expect(panel).toBeVisible();
    await expect(panel).toContainText(fixture.malicious);
    expect(await page.locator('[data-browser-xss]').count()).toBe(0);
    expect(await page.evaluate(() => Boolean(window.__browserXSS))).toBe(false);

    const filter = page.getByLabel('Filter timeline by category');
    await filter.selectOption('account');
    await expect(panel).toContainText('Showing 6 of 6');
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
