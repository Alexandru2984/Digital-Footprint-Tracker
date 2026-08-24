export async function mockAPI(page, options = {}) {
    const authenticated = Boolean(options.authenticated);
    const admin = Boolean(options.admin);
    const malicious = '<img data-browser-xss src=x onerror="window.__browserXSS=true">';

    await page.route('**/api/**', async route => {
        const pathname = new URL(route.request().url()).pathname;
        let status = 200;
        let body = {};

        if (pathname === '/api/auth/me') {
            if (!authenticated) {
                status = 401;
                body = { reason: 'not_authenticated' };
            } else {
                body = {
                    id: '00000000-0000-4000-8000-000000000001',
                    username: 'browser-tester',
                    isAdmin: admin,
                    emailVerified: true,
                    twoFactorEnabled: false,
                };
            }
        } else if (pathname === '/api/stats') {
            body = { totalScans: 0, scansLast24h: 0, scansLast7d: 0, totalResults: 0, topSources: [] };
        } else if (pathname === '/api/plugins') {
            body = [];
        } else if (pathname === '/api/admin/dashboard') {
            body = { totalScans: 0, totalUsers: 1, totalResults: 0, scansPerDay: [], topPlugins: [] };
        } else if (pathname === '/api/admin/audit/integrity') {
            body = {
                status: 'valid',
                failureCode: null,
                verifiedEvents: 12,
                legacyUntrackedLogs: 0,
                lastSequence: 12,
                headHash: 'a'.repeat(64),
                activeSigningKeyID: 'browser-test',
                checkedAt: '2026-08-24T00:00:00Z',
            };
        } else if (pathname === '/api/admin/audit') {
            body = {
                items: [{
                    createdAt: '2026-08-24T00:00:00Z',
                    userID: malicious,
                    action: malicious,
                    target: malicious,
                    ip: malicious,
                }],
                metadata: { total: 1 },
            };
        } else if (pathname === '/api/notifications') {
            body = [{
                id: malicious,
                scanID: malicious,
                message: malicious,
                isRead: false,
                createdAt: '2026-08-24T00:00:00Z',
            }];
        } else if (pathname === '/api/tags' || pathname === '/api/scheduled-scans' || pathname === '/api/auth/api-keys') {
            body = [];
        } else if (pathname === '/api/auth/2fa/status') {
            body = { enabled: false };
        } else {
            status = 404;
            body = { error: 'browser_fixture_not_mocked' };
        }

        await route.fulfill({
            status,
            contentType: 'application/json; charset=utf-8',
            body: JSON.stringify(body),
        });
    });

    return { malicious };
}

export function formatViolations(violations) {
    return violations.map(violation => ({
        id: violation.id,
        impact: violation.impact,
        help: violation.help,
        nodes: violation.nodes.map(node => node.target),
    }));
}
