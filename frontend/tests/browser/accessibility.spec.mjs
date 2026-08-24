import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { formatViolations, mockAPI } from './fixtures.mjs';

const pages = [
    { path: '/', heading: /OSINT.*FOOTPRINT TRACKER/i, authenticated: false },
    { path: '/login.html', heading: /OSINT.*TRACKER/i, authenticated: false },
    { path: '/register.html', heading: /OSINT.*TRACKER/i, authenticated: false },
    { path: '/admin.html', heading: /ADMIN.*DASHBOARD/i, authenticated: true, admin: true },
];

for (const pageCase of pages) {
    test(`${pageCase.path} is WCAG 2.2 AA and viewport safe`, async ({ page }) => {
        const pageErrors = [];
        page.on('pageerror', error => pageErrors.push(error.message));
        await mockAPI(page, pageCase);

        await page.goto(pageCase.path, { waitUntil: 'networkidle' });
        await expect(page.getByRole('heading', { name: pageCase.heading }).first()).toBeVisible();

        const results = await new AxeBuilder({ page })
            .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
            .analyze();
        const violations = formatViolations(results.violations);
        expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);

        const layout = await page.evaluate(() => {
            const viewportWidth = document.documentElement.clientWidth;
            const offenders = [...document.body.querySelectorAll('*')]
                .filter(element => {
                    const style = getComputedStyle(element);
                    if (style.display === 'none' || style.visibility === 'hidden') return false;
                    const rect = element.getBoundingClientRect();
                    return rect.width > 0 && (rect.left < -1 || rect.right > viewportWidth + 1);
                })
                .slice(0, 10)
                .map(element => ({
                    tag: element.tagName,
                    id: element.id,
                    className: String(element.className).slice(0, 120),
                    rect: element.getBoundingClientRect().toJSON(),
                }));
            return {
                viewportWidth,
                scrollWidth: document.documentElement.scrollWidth,
                offenders,
            };
        });
        expect(layout.scrollWidth, JSON.stringify(layout, null, 2)).toBeLessThanOrEqual(layout.viewportWidth + 1);
        expect(layout.offenders, JSON.stringify(layout, null, 2)).toEqual([]);
        expect(pageErrors).toEqual([]);
    });
}

test('mobile interactive targets meet the WCAG 2.2 minimum size', async ({ page }, testInfo) => {
    test.skip((testInfo.project.use.viewport?.width || 1000) > 375, 'mobile viewport only');
    await mockAPI(page);
    await page.goto('/', { waitUntil: 'networkidle' });

    const undersized = await page.evaluate(() => [...document.querySelectorAll('a[href], button, input, select, textarea')]
        .filter(element => {
            const style = getComputedStyle(element);
            if (style.display === 'none' || style.visibility === 'hidden' || element.disabled) return false;
            const rect = element.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0 && (rect.width < 24 || rect.height < 24);
        })
        .map(element => ({
            tag: element.tagName,
            id: element.id,
            text: (element.textContent || element.getAttribute('aria-label') || '').trim().slice(0, 80),
            rect: element.getBoundingClientRect().toJSON(),
        })));
    expect(undersized, JSON.stringify(undersized, null, 2)).toEqual([]);
});
