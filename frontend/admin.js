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
        renderTopPlugins(data.topPlugins);
    } else {
        document.getElementById('top-plugins-chart').textContent = 'No plugin data available.';
    }
})();
