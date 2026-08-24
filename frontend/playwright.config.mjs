import { defineConfig } from '@playwright/test';

const outputRoot = process.env.PLAYWRIGHT_OUTPUT_DIR || 'test-results';
const reportRoot = process.env.PLAYWRIGHT_REPORT_DIR || 'playwright-report';

export default defineConfig({
    testDir: './tests/browser',
    outputDir: outputRoot,
    timeout: 30_000,
    expect: { timeout: 5_000 },
    fullyParallel: true,
    forbidOnly: Boolean(process.env.CI),
    retries: process.env.CI ? 1 : 0,
    workers: process.env.CI ? 1 : 2,
    reporter: [
        ['line'],
        ['html', { outputFolder: reportRoot, open: 'never' }],
    ],
    use: {
        baseURL: 'http://127.0.0.1:4173',
        colorScheme: 'dark',
        locale: 'en-US',
        screenshot: 'only-on-failure',
        trace: 'retain-on-failure',
        video: 'retain-on-failure',
    },
    webServer: {
        command: 'node ./tests/browser-server.mjs',
        url: 'http://127.0.0.1:4173/healthz',
        reuseExistingServer: false,
        timeout: 15_000,
    },
    projects: [
        {
            name: 'mobile-320',
            use: { viewport: { width: 320, height: 800 }, isMobile: true, hasTouch: true },
        },
        {
            name: 'mobile-375',
            use: { viewport: { width: 375, height: 812 }, isMobile: true, hasTouch: true },
        },
        {
            name: 'tablet-768',
            use: { viewport: { width: 768, height: 1024 }, hasTouch: true },
        },
        {
            name: 'desktop-1440',
            use: { viewport: { width: 1440, height: 1000 } },
        },
    ],
});
