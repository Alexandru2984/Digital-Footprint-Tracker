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
        } else if (pathname === '/api/share') {
            body = {
                scan: {
                    id: '00000000-0000-4000-8000-0000000000aa',
                    input: 'shared-target',
                    status: 'completed',
                    completedAt: 1787000000,
                    scannedAt: 1787000000,
                    unavailableSources: ['Reddit', malicious],
                },
                results: [
                    { id: null, source: 'GitHubAccountCheck', type: 'account_presence', confidenceScore: 0.9,
                      rawData: 'GitHub account found.', metadata: null },
                    { id: null, source: malicious, type: 'account_presence', confidenceScore: 0.8,
                      rawData: malicious, metadata: null },
                ],
            };
        } else if (pathname === '/api/results/00000000-0000-4000-8000-0000000000bb') {
            body = {
                scanID: '00000000-0000-4000-8000-0000000000bb', input: 'alice@example.com', status: 'completed',
                completedAt: 1787000000, scannedAt: 1787000000, unavailableSources: [],
                results: [
                    { id: null, source: 'GitHub', type: 'developer_identity', confidenceScore: 1, rawData: 'verified', metadata: null },
                    { id: null, source: 'Steam', type: 'account_presence', confidenceScore: 0.75, rawData: 'same name', metadata: null },
                    { id: null, source: 'AttackSurface', type: 'subdomain_takeover', confidenceScore: 0.9, rawData: 'takeover',
                      metadata: { subdomain: 'old.example.com', service: 'Azure', cname: malicious, domain: 'example.com' } },
                    { id: null, source: 'PassiveDNS', type: 'dns_history', confidenceScore: 0.8, rawData: 'history',
                      metadata: { domain: 'example.com', addresses: '104.21.25.147, 203.0.113.9', possibleOrigins: '203.0.113.9' } },
                ],
            };
        } else if (pathname === '/api/identity/00000000-0000-4000-8000-0000000000bb') {
            body = {
                likelyName: null, emails: ['alice@example.com'], handles: [], confirmedAccounts: [], breaches: [], phones: [],
                exposedIPs: [], exposedServices: [], vulnerabilities: [], exposedDataClasses: [], timeline: [],
                riskScore: 10, riskLevel: 'Low', riskFactors: [],
                links: [
                    { from: 'alice@example.com', to: 'github: alice', kind: 'verified', source: 'GitHub', reason: 'verified email' },
                    { from: 'crates.io: alice', to: 'github: alice', kind: 'verified', source: 'crates.io', reason: 'signs in through GitHub' },
                    { from: 'alice', to: 'steam: alice', kind: 'inferred', source: 'Steam', reason: malicious },
                    { from: 'alice@example.com', to: malicious, kind: 'declared', source: malicious, reason: 'profile link' },
                ],
                attributions: [
                    { node: 'github: alice', score: 98, path: ['alice@example.com', 'github: alice'] },
                    { node: 'steam: alice', score: 22, path: ['alice@example.com', 'alice', 'steam: alice'] },
                    { node: 'twitter: ' + malicious, score: 90, path: ['alice@example.com', 'twitter: ' + malicious] },
                ],
                resultCount: 2,
            };
        } else if (pathname === '/api/stats') {
            body = { totalScans: 0, scansLast24h: 0, scansLast7d: 0, totalResults: 0, topSources: [] };
        } else if (pathname === '/api/plugins') {
            body = [];
        } else if (pathname === '/api/admin/dashboard') {
            body = {
                totalScans: 3, totalUsers: 1, totalResults: 7, scansPerDay: [],
                topPlugins: [{ source: malicious, hitCount: 5 }, { source: 'Reddit', hitCount: 2 }],
            };
        } else if (pathname === '/api/admin/plugin-health') {
            body = [
                {
                    plugin: malicious, status: 'failing', runs: 3, failures: 3, averageMilliseconds: 1200,
                    lastRunAt: '2026-08-24T00:00:00Z', lastSuccessAt: null,
                    lastFailureAt: '2026-08-24T00:00:00Z', lastFailure: malicious,
                    skipped: 2, nextProbeAt: '2026-08-24T00:05:00Z',
                    canary: { plugin: 'x', input: 'x', passed: false, results: 0, detail: malicious, checkedAt: '2026-08-24T00:00:00Z' },
                },
                { plugin: 'Reddit', status: 'healthy', runs: 4, failures: 0, averageMilliseconds: 800,
                  lastRunAt: '2026-08-24T00:00:00Z', lastSuccessAt: '2026-08-24T00:00:00Z',
                  lastFailureAt: null, lastFailure: null, skipped: 0, nextProbeAt: null,
                  canary: { plugin: 'Reddit', input: 'spez', passed: true, results: 1, detail: null, checkedAt: '2026-08-24T00:00:00Z' } },
                { plugin: 'Shodan', status: 'idle', runs: 0, failures: 0, averageMilliseconds: null,
                  lastRunAt: null, lastSuccessAt: null, lastFailureAt: null, lastFailure: null, skipped: 0, nextProbeAt: null,
                  configured: false, note: `Site audit: 1 of 400 sites cannot find their known account, left out of the sweep: ${malicious}` },
            ];
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
