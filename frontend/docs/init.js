// Initialize Swagger UI. Kept in a separate file (rather than inline) so the
// project's existing CSP `script-src 'self'` covers it without needing a fresh
// SHA-256 hash whenever the init logic changes.
window.addEventListener('load', function () {
  window.ui = SwaggerUIBundle({
    // Served by the Vapor app at /openapi.yaml (see routes.swift). nginx
    // proxies / to the app for non-static paths; the spec itself is a static
    // file in this same `frontend` directory, so the request stays local.
    url: '/openapi.yaml',
    dom_id: '#swagger-ui',

    // Allow operator-style features useful for an API explorer without making
    // the UI noisy for casual visitors.
    deepLinking: true,
    displayRequestDuration: true,
    filter: true,
    tryItOutEnabled: true,
    persistAuthorization: true,

    // Default operations open by tag so the page is scannable on first load.
    docExpansion: 'list',

    // Standalone preset isn't bundled — the bundle ships SwaggerUI + Apis +
    // standalone-layout-less core. This is the minimum config to render.
    presets: [SwaggerUIBundle.presets.apis],
    layout: 'BaseLayout',
  });
});
