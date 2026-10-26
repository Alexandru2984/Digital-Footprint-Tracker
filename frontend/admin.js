(async function () {
    'use strict';

    // Guard: must be logged in and admin
    async function checkAuth() {
        try {
            const res = await fetch('/api/auth/me', { credentials: 'include' });
            if (!res.ok) { window.location.href = '/'; return null; }
            const user = await res.json();
            if (!user.isAdmin) { window.location.href = '/'; return null; }
            return user;
        } catch (_) {
            window.location.href = '/';
            return null;
        }
    }

    const user = await checkAuth();
    if (!user) return;

    // Logout
    document.getElementById('logout-btn').addEventListener('click', async () => {
        await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
        window.location.href = '/';
    });

    // Fetch dashboard data
    const loadingEl = document.getElementById('loading-state');
    const errorEl = document.getElementById('error-state');
    const contentEl = document.getElementById('dashboard-content');

    let data;
    try {
        const res = await fetch('/api/admin/dashboard', { credentials: 'include' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        data = await res.json();
    } catch (e) {
        loadingEl.classList.add('hidden');
        errorEl.classList.remove('hidden');
        errorEl.textContent = 'Failed to load dashboard: ' + e.message;
        return;
    }

    loadingEl.classList.add('hidden');
    contentEl.classList.remove('hidden');

    // Populate stat cards
    document.getElementById('stat-total-scans').textContent = (data.totalScans || 0).toLocaleString();
    document.getElementById('stat-total-users').textContent = (data.totalUsers || 0).toLocaleString();
    document.getElementById('stat-total-results').textContent = (data.totalResults || 0).toLocaleString();

    // Scans per day bar chart using D3
    function renderScansPerDay(chartData) {
        const container = document.getElementById('scans-per-day-chart');
        const width = container.getBoundingClientRect().width || 700;
        const height = 200;
        const margin = { top: 10, right: 20, bottom: 40, left: 40 };
        const innerW = width - margin.left - margin.right;
        const innerH = height - margin.top - margin.bottom;

        const svg = d3.select(container).append('svg')
            .attr('width', width)
            .attr('height', height)
            .style('overflow', 'visible');

        const g = svg.append('g')
            .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

        const x = d3.scaleBand()
            .domain(chartData.map(d => d.date))
            .range([0, innerW])
            .padding(0.3);

        const maxCount = d3.max(chartData, d => d.count) || 1;
        const y = d3.scaleLinear()
            .domain([0, maxCount])
            .nice()
            .range([innerH, 0]);

        // Bars
        g.selectAll('.bar')
            .data(chartData)
            .enter().append('rect')
            .attr('class', 'bar')
            .attr('x', d => x(d.date))
            .attr('y', d => y(d.count))
            .attr('width', x.bandwidth())
            .attr('height', d => innerH - y(d.count))
            .attr('fill', '#10b981')
            .attr('rx', 3);

        // X-axis — show only first, middle, and last labels to avoid crowding
        const xAxis = d3.axisBottom(x)
            .tickSize(0)
            .tickFormat((d, i) => {
                if (i === 0 || i === chartData.length - 1 || i === Math.floor(chartData.length / 2)) return d;
                return '';
            });
        g.append('g')
            .attr('transform', 'translate(0,' + innerH + ')')
            .call(xAxis)
            .select('.domain').attr('stroke', '#334155');
        g.selectAll('.tick text')
            .attr('fill', '#94a3b8')
            .attr('font-size', '10px');

        // Y-axis
        const yAxis = d3.axisLeft(y)
            .ticks(4)
            .tickSize(-innerW);
        g.append('g')
            .call(yAxis)
            .call(g2 => {
                g2.select('.domain').remove();
                g2.selectAll('.tick line').attr('stroke', '#1e293b').attr('stroke-dasharray', '2,2');
                g2.selectAll('.tick text').attr('fill', '#94a3b8').attr('font-size', '10px');
            });
    }

    if (Array.isArray(data.scansPerDay) && data.scansPerDay.length) {
        renderScansPerDay(data.scansPerDay);
    } else {
        document.getElementById('scans-per-day-chart').textContent = 'No data available.';
    }

    // Top plugins horizontal bar chart
    function renderTopPlugins(plugins) {
        const container = document.getElementById('top-plugins-chart');
        const width = container.getBoundingClientRect().width || 700;
        const barH = 24;
        const gap = 6;
        const labelW = 160;
        const margin = { top: 4, right: 40, bottom: 4, left: labelW };
        const innerW = width - margin.left - margin.right;
        const height = plugins.length * (barH + gap) + margin.top + margin.bottom;

        const svg = d3.select(container).append('svg')
            .attr('width', width)
            .attr('height', height);

        const g = svg.append('g')
            .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

        const maxCount = d3.max(plugins, d => d.count) || 1;
        const x = d3.scaleLinear()
            .domain([0, maxCount])
            .range([0, innerW]);

        const rows = g.selectAll('.row')
            .data(plugins)
            .enter().append('g')
            .attr('class', 'row')
            .attr('transform', (d, i) => 'translate(0,' + (i * (barH + gap)) + ')');

        // Plugin name label
        rows.append('text')
            .attr('x', -8)
            .attr('y', barH / 2)
            .attr('dy', '0.35em')
            .attr('text-anchor', 'end')
            .attr('fill', '#94a3b8')
            .attr('font-size', '11px')
            .attr('font-family', 'monospace')
            .text(d => d.plugin.length > 20 ? d.plugin.slice(0, 18) + '…' : d.plugin);

        // Bar
        rows.append('rect')
            .attr('x', 0)
            .attr('y', 0)
            .attr('width', d => x(d.count))
            .attr('height', barH)
            .attr('fill', '#0ea5e9')
            .attr('rx', 3);

        // Count label
        rows.append('text')
            .attr('x', d => x(d.count) + 6)
            .attr('y', barH / 2)
            .attr('dy', '0.35em')
            .attr('fill', '#e2e8f0')
            .attr('font-size', '10px')
            .attr('font-family', 'monospace')
            .text(d => d.count.toLocaleString());
    }

    if (Array.isArray(data.topPlugins) && data.topPlugins.length) {
        renderTopPlugins(data.topPlugins.map(p => ({ plugin: String(p.source ?? ''), count: Number(p.hitCount) || 0 })));
    } else {
        document.getElementById('top-plugins-chart').textContent = 'No plugin data available.';
    }

    // Plugin health
    document.getElementById('refresh-plugin-health-btn')?.addEventListener('click', loadPluginHealth);

    async function loadPluginHealth() {
        const summary = document.getElementById('plugin-health-summary');
        const container = document.getElementById('plugin-health-container');
        try {
            const res = await fetch('/api/admin/plugin-health', { credentials: 'include' });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const reports = await res.json();
            const count = status => reports.filter(r => r.status === status).length;
            const failing = count('failing');
            const degraded = count('degraded');
            const canaryFailing = reports.filter(r => r.canary && r.canary.passed === false && r.canary.alerts !== false).length;
            summary.className = 'mb-3 text-[11px] ' + (failing || canaryFailing ? 'text-red-400' : degraded ? 'text-yellow-400' : 'text-green-400');
            const unconfigured = reports.filter(r => r.configured === false).length;
            summary.textContent = `${failing} failing · ${degraded} degraded · ${count('healthy')} healthy · ${count('idle')} not run since restart`
                + ` · ${canaryFailing} canar${canaryFailing === 1 ? 'y' : 'ies'} failing`
                + (unconfigured ? ` · ${unconfigured} not configured (missing API key)` : '');

            const statusClass = {
                failing: 'text-red-400', degraded: 'text-yellow-400', healthy: 'text-green-400', idle: 'text-slate-500',
            };
            const when = value => value ? new Date(value).toLocaleString() : '—';
            const table = document.createElement('table');
            table.className = 'w-full text-[10px] border-collapse';
            // Avg and last success are secondary; on a phone the table keeps
            // the four columns that say what is broken and why, and wraps.
            const secondary = ' hidden sm:table-cell';
            const columns = [
                ['Plugin', ''], ['Status', ''], ['Failed / runs', ''],
                ['Avg', secondary], ['Last success', secondary], ['Last failure', ''], ['Canary', ''],
            ];
            const head = table.createTHead().insertRow();
            head.className = 'border-b border-dark-700 text-slate-400';
            for (const [label, extra] of columns) {
                const th = document.createElement('th');
                th.className = 'text-left align-bottom py-1 pr-2' + extra;
                th.textContent = label;
                head.appendChild(th);
            }
            const body = table.createTBody();
            for (const r of reports) {
                const row = body.insertRow();
                row.className = 'border-b border-dark-800 hover:bg-dark-700';
                const cells = [
                    [r.plugin, 'text-slate-200'],
                    [
                        [
                            r.configured === false ? 'not configured' : r.status,
                            Number(r.skipped) ? `${Number(r.skipped)} skipped` : '',
                            r.nextProbeAt ? `next probe ${new Date(r.nextProbeAt).toLocaleTimeString()}` : '',
                        ].filter(Boolean).join(' · '),
                        statusClass[r.status] || 'text-slate-400',
                    ],
                    [`${Number(r.failures) || 0} / ${Number(r.runs) || 0}`, 'text-slate-400'],
                    [r.averageMilliseconds == null ? '—' : `${(r.averageMilliseconds / 1000).toFixed(1)}s`, 'text-slate-400'],
                    [when(r.lastSuccessAt), 'text-slate-500'],
                    [r.lastFailureAt ? `${when(r.lastFailureAt)} · ${r.lastFailure ?? ''}` : '—', 'text-slate-500'],
                    r.canary
                        ? (r.canary.passed
                            ? [`passed · ${when(r.canary.checkedAt)}`, 'text-green-400']
                            : r.canary.alerts === false
                                ? [`failed, flaky upstream, no alert (${r.canary.detail ?? 'no result'}) · ${when(r.canary.checkedAt)}`, 'text-yellow-400']
                                : [`FAILED (${r.canary.detail ?? 'no result'}) · ${when(r.canary.checkedAt)}`, 'text-red-400'])
                        : ['—', 'text-slate-500'],
                ];
                cells.forEach(([text, cls], index) => {
                    const td = row.insertCell();
                    td.className = 'align-top py-1 pr-2 wrap-anywhere ' + cls + columns[index][1];
                    td.textContent = String(text ?? '');
                });
                if (r.note) {
                    const noteRow = body.insertRow();
                    noteRow.className = 'border-b border-dark-800 js-plugin-note';
                    const td = noteRow.insertCell();
                    td.colSpan = columns.length;
                    td.className = 'py-1 pr-2 wrap-anywhere text-slate-400';
                    td.textContent = String(r.note);
                }
            }
            container.replaceChildren(table);
        } catch (error) {
            summary.className = 'mb-3 text-[11px] text-red-400';
            summary.textContent = 'Plugin health unavailable: ' + String(error && error.message || error);
        }
    }

    // Audit log
    document.getElementById('load-audit-btn')?.addEventListener('click', loadAuditLog);
    document.getElementById('verify-audit-btn')?.addEventListener('click', loadAuditIntegrity);

    async function loadAuditIntegrity() {
        const button = document.getElementById('verify-audit-btn');
        const status = document.getElementById('audit-integrity-status');
        button.disabled = true;
        button.setAttribute('aria-busy', 'true');
        status.className = 'mb-4 rounded-lg border border-dark-700 bg-dark-900/60 px-3 py-2 text-[11px] text-slate-400';
        status.textContent = 'Verifying every signed audit event…';
        try {
            const res = await fetch('/api/admin/audit/integrity', { credentials: 'include' });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const result = await res.json();
            const checked = result.checkedAt ? new Date(result.checkedAt).toLocaleString() : 'unknown time';
            if (result.status === 'valid') {
                const legacy = Number(result.legacyUntrackedLogs || 0);
                status.className = 'mb-4 rounded-lg border border-green-700/60 bg-green-950/30 px-3 py-2 text-[11px] text-green-300';
                status.textContent = `Valid signed ledger · ${Number(result.verifiedEvents || 0).toLocaleString()} events · sequence ${Number(result.lastSequence || 0).toLocaleString()} · key ${String(result.activeSigningKeyID || 'unknown')} · checked ${checked}${legacy ? ` · ${legacy.toLocaleString()} legacy rows are not cryptographically covered` : ''}`;
            } else {
                status.className = 'mb-4 rounded-lg border border-red-700/60 bg-red-950/30 px-3 py-2 text-[11px] text-red-300';
                status.textContent = `Integrity failure · ${String(result.failureCode || 'unknown')} · checked ${checked}`;
            }
        } catch (error) {
            status.className = 'mb-4 rounded-lg border border-red-700/60 bg-red-950/30 px-3 py-2 text-[11px] text-red-300';
            status.textContent = 'Integrity verification unavailable: ' + String(error && error.message || error);
        } finally {
            button.disabled = false;
            button.removeAttribute('aria-busy');
        }
    }

    async function loadAuditLog(page = 1) {
        const container = document.getElementById('audit-log-container');
        container.innerHTML = '<p class="text-[11px] text-slate-400">Loading…</p>';
        try {
            const res = await fetch(`/api/admin/audit?page=${page}&per=50`, { credentials: 'include' });
            if (!res.ok) { container.innerHTML = '<p class="text-[11px] text-red-400">Failed to load audit log.</p>'; return; }
            const body = await res.json();
            const items = body.items || [];
            if (!items.length) { container.innerHTML = '<p class="text-[11px] text-slate-500">No audit entries found.</p>'; return; }
            const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
            container.innerHTML = `
                <div class="overflow-x-auto"><table class="w-full min-w-[640px] text-[10px] border-collapse">
                    <thead><tr class="border-b border-dark-700 text-slate-400">
                        <th class="text-left py-1 pr-2">Time</th>
                        <th class="text-left py-1 pr-2">User</th>
                        <th class="text-left py-1 pr-2">Action</th>
                        <th class="text-left py-1 pr-2">Target</th>
                        <th class="text-left py-1">IP</th>
                    </tr></thead>
                    <tbody>
                    ${items.map(e => `<tr class="border-b border-dark-800 hover:bg-dark-700">
                        <td class="py-1 pr-2 text-slate-500">${esc(e.createdAt ? new Date(e.createdAt).toLocaleString() : '')}</td>
                        <td class="py-1 pr-2">${esc(e.userID ?? '—')}</td>
                        <td class="py-1 pr-2 text-brand-400">${esc(e.action)}</td>
                        <td class="py-1 pr-2 font-mono truncate max-w-[200px]">${esc(e.target ?? '')}</td>
                        <td class="py-1 text-slate-500">${esc(e.ip ?? '')}</td>
                    </tr>`).join('')}
                    </tbody>
                </table></div>
                ${body.metadata && body.metadata.total > 50 ? `<p class="text-[10px] text-slate-500 mt-2">Showing first 50 of ${body.metadata.total}. Use pagination for more.</p>` : ''}`;
        } catch (err) {
            const msg = String(err && err.message || err).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
            container.innerHTML = `<p class="text-[11px] text-red-400">Error: ${msg}</p>`;
        }
    }

    await Promise.all([loadAuditIntegrity(), loadPluginHealth()]);
})();
