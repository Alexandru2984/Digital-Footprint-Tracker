import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { dirname, extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const frontendRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = resolve(frontendRoot, '..');
const cspSource = await readFile(resolve(repositoryRoot, 'ops/nginx/snippets/swift-csp.conf'), 'utf8');
const cspMatch = cspSource.match(/add_header Content-Security-Policy "([^"]+)" always;/);
if (!cspMatch) throw new Error('Unable to load the production CSP fixture');

const mimeTypes = new Map([
    ['.css', 'text/css; charset=utf-8'],
    ['.html', 'text/html; charset=utf-8'],
    ['.js', 'text/javascript; charset=utf-8'],
    ['.json', 'application/json; charset=utf-8'],
    ['.mjs', 'text/javascript; charset=utf-8'],
    ['.png', 'image/png'],
    ['.svg', 'image/svg+xml'],
    ['.txt', 'text/plain; charset=utf-8'],
    ['.yaml', 'application/yaml; charset=utf-8'],
]);

function securityHeaders(contentType) {
    return {
        'Cache-Control': 'no-store',
        'Content-Security-Policy': cspMatch[1].replace('$request_id', randomBytes(16).toString('hex')),
        'Content-Type': contentType,
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
    };
}

const server = createServer(async (request, response) => {
    try {
        const requestURL = new URL(request.url || '/', 'http://127.0.0.1');
        if (requestURL.pathname === '/healthz') {
            response.writeHead(204, securityHeaders('text/plain; charset=utf-8'));
            response.end();
            return;
        }
        if (!['GET', 'HEAD'].includes(request.method || 'GET')) {
            response.writeHead(405, securityHeaders('application/json; charset=utf-8'));
            response.end('{"error":"method_not_allowed"}');
            return;
        }
        if (requestURL.pathname.startsWith('/api/')) {
            response.writeHead(404, securityHeaders('application/json; charset=utf-8'));
            response.end('{"error":"browser_fixture_not_mocked"}');
            return;
        }

        const pathname = decodeURIComponent(requestURL.pathname === '/' ? '/index.html' : requestURL.pathname);
        const filePath = resolve(frontendRoot, `.${pathname}`);
        if (filePath !== frontendRoot && !filePath.startsWith(`${frontendRoot}${sep}`)) {
            response.writeHead(403, securityHeaders('text/plain; charset=utf-8'));
            response.end('Forbidden');
            return;
        }
        const fileStat = await stat(filePath);
        if (!fileStat.isFile()) throw new Error('not_file');
        const body = await readFile(filePath);
        response.writeHead(200, {
            ...securityHeaders(mimeTypes.get(extname(filePath)) || 'application/octet-stream'),
            'Content-Length': String(body.length),
        });
        if (request.method !== 'HEAD') response.end(body);
        else response.end();
    } catch {
        response.writeHead(404, securityHeaders('text/plain; charset=utf-8'));
        response.end('Not found');
    }
});

server.listen(4173, '127.0.0.1');
for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => server.close(() => process.exit(0)));
}
