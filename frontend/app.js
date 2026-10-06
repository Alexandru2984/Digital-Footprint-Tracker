        const form = document.getElementById('scan-form');
        const input = document.getElementById('target-input');
        const scanBtn = document.getElementById('scan-btn');
        const btnText = document.getElementById('btn-text');
        const btnIcon = document.getElementById('btn-icon');
        const loadingIcon = document.getElementById('loading-icon');
        const searchPanel = document.getElementById('search-panel');
        const statusTerminal = document.getElementById('status-terminal');
        const resultsPanel = document.getElementById('results-panel');
        const resultsGrid = document.getElementById('results-grid');
        const emptyState = document.getElementById('empty-state');
        const scanIdDisplay = document.getElementById('scan-id-display');
        const copyScanIdBtn = document.getElementById('copy-scan-id');
        const inputTypeBadge = document.getElementById('input-type-badge');
        const inputTypeLabel = document.getElementById('input-type-label');

        const POLL_INTERVAL_MS = 3000;
        const MAX_POLLS = 40;

        // Stores the most recently displayed scan data for export/share.
        let lastScanData = null;
        // Symbol token — each new scan/load gets a fresh token; stale poll callbacks check
        // this and abort if they no longer own the UI.
        let activeScanToken = null;
        let activeEventSource = null;
        // When true, only results with confidenceScore >= 0.7 are shown.
        let confidenceFilterActive = false;
        // When non-null, only results of this type are shown.
        let activeTypeFilter = null;
        // Current sort mode for results grid.
        let activeSortMode = 'default';
        // Active results tab: 'results' | 'graph' | 'map'
        let activeResultsTab = 'results';
        // Compare/diff state: null or { scanID, input }
        let diffSelectA = null;

        // Populates and shows/hides the type filter dropdown.
        function buildTypeFilterDropdown() {
            if (!lastScanData) return;
            const types = [...new Set((lastScanData.results || []).map(r => r.type))].sort();
            const container = document.getElementById('type-filter-options');
            container.innerHTML = '';

            const allEl = document.createElement('button');
            allEl.className = 'w-full text-left text-xs px-3 py-1.5 hover:bg-dark-700 transition-colors ' + (!activeTypeFilter ? 'text-purple-400 font-bold' : 'text-slate-300');
            allEl.textContent = 'All Types';
            allEl.addEventListener('click', () => { activeTypeFilter = null; applyTypeFilter(); });
            container.appendChild(allEl);

            types.forEach(t => {
                const el = document.createElement('button');
                el.className = 'w-full text-left text-xs px-3 py-1.5 hover:bg-dark-700 transition-colors ' + (activeTypeFilter === t ? 'text-purple-400 font-bold' : 'text-slate-300');
                el.textContent = t.replace(/_/g, ' ').toUpperCase();
                el.dataset.type = t;
                el.addEventListener('click', () => { activeTypeFilter = t; applyTypeFilter(); });
                container.appendChild(el);
            });
        }

        function applyTypeFilter() {
            document.getElementById('type-filter-dropdown').classList.add('hidden');
            const btn = document.getElementById('type-filter-btn');
            const label = document.getElementById('type-filter-label');
            if (activeTypeFilter) {
                label.textContent = activeTypeFilter.replace(/_/g, ' ').toUpperCase();
                btn.classList.add('text-purple-400', 'border-purple-500/50');
                btn.classList.remove('text-slate-400');
            } else {
                label.textContent = 'FILTER TYPE';
                btn.classList.remove('text-purple-400', 'border-purple-500/50');
                btn.classList.add('text-slate-400');
            }
            reRenderGrid();
        }

        document.getElementById('type-filter-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            buildTypeFilterDropdown();
            document.getElementById('type-filter-dropdown').classList.toggle('hidden');
        });

        document.addEventListener('click', () => {
            document.getElementById('type-filter-dropdown').classList.add('hidden');
            document.getElementById('sort-dropdown').classList.add('hidden');
        });

        // Sort logic
        const sortLabels = {
            'default': 'SORT',
            'confidence-desc': 'CONF ↓',
            'confidence-asc': 'CONF ↑',
            'source-asc': 'SOURCE A-Z',
            'type-asc': 'TYPE A-Z'
        };

        function sortResults(results) {
            const arr = [...results];
            switch (activeSortMode) {
                case 'confidence-desc': return arr.sort((a, b) => b.confidenceScore - a.confidenceScore);
                case 'confidence-asc':  return arr.sort((a, b) => a.confidenceScore - b.confidenceScore);
                case 'source-asc':      return arr.sort((a, b) => a.source.localeCompare(b.source));
                case 'type-asc':        return arr.sort((a, b) => a.type.localeCompare(b.type));
                default:                return arr;
            }
        }

        document.getElementById('sort-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            document.getElementById('sort-dropdown').classList.toggle('hidden');
        });

        document.querySelectorAll('.sort-opt').forEach(btn => {
            btn.addEventListener('click', () => {
                activeSortMode = btn.dataset.sort;
                const sortBtnLabel = document.getElementById('sort-label');
                sortBtnLabel.textContent = sortLabels[activeSortMode] || 'SORT';
                const sortBtn = document.getElementById('sort-btn');
                if (activeSortMode !== 'default') {
                    sortBtn.classList.add('text-orange-400', 'border-orange-500/50');
                    sortBtn.classList.remove('text-slate-400');
                } else {
                    sortBtn.classList.remove('text-orange-400', 'border-orange-500/50');
                    sortBtn.classList.add('text-slate-400');
                }
                document.getElementById('sort-dropdown').classList.add('hidden');
                reRenderGrid();
            });
        });

        // CSV export
        document.getElementById('export-csv-btn').addEventListener('click', () => {
            if (!lastScanData) return;
            const results = lastScanData.results || [];
            const header = ['source', 'type', 'confidenceScore', 'rawData'];
            // Findings carry text lifted from third-party pages — a title, a
            // WHOIS record, a paste excerpt. RFC 4180 quoting makes that parse
            // correctly but does nothing about formula injection: a spreadsheet
            // evaluates a cell whose value begins with =, +, - or @ (and the
            // whitespace variants), and the surrounding quotes are stripped
            // before it looks. Prefixing an apostrophe is what marks the cell as
            // literal text in Excel, LibreOffice and Sheets alike; it costs one
            // visible character in the rare cell that needed it.
            const neutralise = v => /^[=+\-@\t\r]/.test(v) ? "'" + v : v;
            const escape = v => '"' + neutralise(String(v ?? '')).replace(/"/g, '""') + '"';
            const rows = [header.join(',')].concat(
                results.map(r => [r.source, r.type, r.confidenceScore, r.rawData].map(escape).join(','))
            );
            const blob = new Blob([rows.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            // Same allowlist discipline the server applies to Content-Disposition.
            const safeName = String(lastScanData.input || lastScanData.scanID || 'scan')
                .replace(/@/g, '_at_').replace(/[^A-Za-z0-9_-]/g, '');
            a.download = 'footprint-' + safeName + '.csv';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        });

        // Live input-type badge: shows EMAIL, USERNAME, DOMAIN, or PHONE as the user types.
        input.addEventListener('input', () => {
            const val = input.value.trim();
            if (!val) { inputTypeBadge.classList.add('hidden'); return; }
            inputTypeBadge.classList.remove('hidden');
            if (val.includes('@')) {
                inputTypeLabel.textContent = 'EMAIL';
                inputTypeLabel.className = 'text-xs px-2 py-0.5 rounded font-bold uppercase tracking-wide bg-blue-900/60 text-blue-300 border border-blue-700';
            } else if (/^\+?[0-9]{7,15}$/.test(val)) {
                inputTypeLabel.textContent = 'PHONE';
                inputTypeLabel.className = 'text-xs px-2 py-0.5 rounded font-bold uppercase tracking-wide bg-purple-900/60 text-purple-300 border border-purple-700';
            } else if (/^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(val) || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) {
                inputTypeLabel.textContent = 'DOMAIN';
                inputTypeLabel.className = 'text-xs px-2 py-0.5 rounded font-bold uppercase tracking-wide bg-yellow-900/60 text-yellow-300 border border-yellow-700';
            } else {
                inputTypeLabel.textContent = 'USERNAME';
                inputTypeLabel.className = 'text-xs px-2 py-0.5 rounded font-bold uppercase tracking-wide bg-brand-900/60 text-brand-400 border border-brand-700';
            }
        });

        function logStatus(text, cssClass = null) {
            statusTerminal.classList.remove('hidden');
            const time = new Date().toISOString().split('T')[1].split('.')[0];
            const line = document.createElement('div');
            const timeSpan = document.createElement('span');
            timeSpan.className = 'text-slate-500';
            timeSpan.textContent = `[${time}]`;
            line.appendChild(timeSpan);
            line.appendChild(document.createTextNode(' '));
            if (cssClass) {
                const msgSpan = document.createElement('span');
                msgSpan.className = cssClass;
                msgSpan.textContent = text;
                line.appendChild(msgSpan);
            } else {
                line.appendChild(document.createTextNode(text));
            }
            statusTerminal.appendChild(line);
            statusTerminal.scrollTop = statusTerminal.scrollHeight;
        }

        // Copy text to clipboard with visual feedback on the trigger element.
        function copyToClipboard(text, triggerEl) {
            navigator.clipboard.writeText(text).then(() => {
                const prev = triggerEl.innerHTML;
                triggerEl.innerHTML = '&#10003;';
                triggerEl.style.color = '#10b981';
                setTimeout(() => { triggerEl.innerHTML = prev; triggerEl.style.color = ''; }, 1500);
            }).catch(() => {});
        }

        copyScanIdBtn.addEventListener('click', () => copyToClipboard(scanIdDisplay.textContent, copyScanIdBtn));

        function setScanningState(isScanning) {
            if (isScanning) {
                scanBtn.disabled = true;
                input.disabled = true;
                btnText.textContent = 'SCANNING...';
                btnIcon.classList.add('hidden');
                loadingIcon.classList.remove('hidden');
                searchPanel.classList.add('is-scanning');
            } else {
                scanBtn.disabled = false;
                input.disabled = false;
                btnText.textContent = 'INITIATE SCAN';
                loadingIcon.classList.add('hidden');
                btnIcon.classList.remove('hidden');
                searchPanel.classList.remove('is-scanning');
                document.getElementById('scan-progress').classList.add('hidden');
            }
        }

        function resetResultsView() {
            if (activeEventSource) {
                activeEventSource.close();
                activeEventSource = null;
            }
            lastScanData = null;
            activeTypeFilter = null;
            activeSortMode = 'default';
            const label = document.getElementById('type-filter-label');
            if (label) label.textContent = 'FILTER TYPE';
            const tfBtn = document.getElementById('type-filter-btn');
            if (tfBtn) { tfBtn.classList.remove('text-purple-400', 'border-purple-500/50'); tfBtn.classList.add('text-slate-400'); }
            const sortLabel = document.getElementById('sort-label');
            if (sortLabel) sortLabel.textContent = 'SORT';
            const sortBtn = document.getElementById('sort-btn');
            if (sortBtn) { sortBtn.classList.remove('text-orange-400', 'border-orange-500/50'); sortBtn.classList.add('text-slate-400'); }
            statusTerminal.innerHTML = '';
            resultsPanel.classList.add('hidden');
            resultsGrid.innerHTML = '';
            emptyState.classList.add('hidden');
            switchResultsTab('results');
        }

        // Returns a DOM element; all API values set via textContent/classList — never innerHTML.
        function createResultCard(result) {
            const card = document.createElement('div');
            card.className = 'bg-dark-800 border border-dark-700 rounded-xl overflow-hidden shadow-lg transition-transform hover:scale-[1.01] hover:border-brand-500/50';

            card.innerHTML = `
                <div class="px-4 py-3 bg-dark-900 border-b border-dark-700 flex justify-between items-center">
                    <div class="flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-brand-500 animate-pulse"></span>
                        <span class="js-source font-bold text-slate-200"></span>
                    </div>
                    <span class="js-type text-xs px-2 py-0.5 rounded-sm bg-dark-700 text-slate-300 border border-dark-600"></span>
                </div>
                <div class="p-4">
                    <div class="flex justify-between items-end mb-4">
                        <div>
                            <p class="text-xs text-slate-500 mb-1">CONFIDENCE SCORE</p>
                            <p class="js-score text-xl font-bold"></p>
                        </div>
                        <div class="text-right">
                            <p class="text-xs text-slate-500 mb-1">MATCH DATA</p>
                            <p class="js-raw-data text-sm text-white break-all"></p>
                        </div>
                    </div>
                    <div class="mt-4">
                        <div class="flex items-center justify-between mb-2">
                            <p class="text-xs text-slate-500">RAW JSON OUTPUT</p>
                            <button class="js-copy-json text-xs text-slate-500 hover:text-brand-500 transition-colors" title="Copy JSON">
                                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
                            </button>
                        </div>
                        <div class="bg-[#0b1120] rounded-sm p-3 text-xs text-brand-500 overflow-x-auto border border-dark-900">
                            <pre><code class="js-json"></code></pre>
                        </div>
                    </div>
                </div>
            `;

            // Set all user-controlled values via DOM APIs — never via innerHTML interpolation.
            card.querySelector('.js-source').textContent = result.source;
            card.querySelector('.js-type').textContent = result.type;

            const scoreEl = card.querySelector('.js-score');
            const score = typeof result.confidenceScore === 'number' ? result.confidenceScore : 0;
            scoreEl.textContent = (score * 100).toFixed(0) + '%';
            scoreEl.classList.add(score < 0.5 ? 'text-red-500' : score < 0.8 ? 'text-yellow-500' : 'text-green-500');

            renderRawData(card.querySelector('.js-raw-data'), result.rawData);
            const jsonStr = JSON.stringify(result, null, 2);
            card.querySelector('.js-json').textContent = jsonStr;
            card.querySelector('.js-copy-json').addEventListener('click', function() {
                copyToClipboard(jsonStr, this);
            });

            // Structured metadata: a JSON string from the Result model, or an
            // object from the share/export DTOs. Parse defensively.
            let meta = result.metadata;
            if (typeof meta === 'string') { try { meta = JSON.parse(meta); } catch (e) { meta = null; } }
            meta = (meta && typeof meta === 'object') ? meta : {};

            // "Inferred" badge: a derived candidate (e.g. a username pivoted from
            // an email local-part) carries a provenance marker.
            const derived = !!meta.derivedFrom || /^\[via /.test(result.rawData || '');
            if (derived) {
                const badge = document.createElement('span');
                // Inline styles: the compiled tailwind.css is purged, so new
                // utility classes (amber, arbitrary sizes) would not exist.
                badge.style.cssText = 'margin-left:8px;font-size:10px;text-transform:uppercase;letter-spacing:.05em;padding:1px 6px;border-radius:4px;background:rgba(245,158,11,.15);color:#fbbf24;border:1px solid rgba(245,158,11,.35);';
                badge.textContent = 'inferred';
                badge.title = (typeof meta.derivedFrom === 'string') ? meta.derivedFrom : 'Derived from another identifier';
                card.querySelector('.js-source').insertAdjacentElement('afterend', badge);
            }

            // Metadata chips for the salient structured fields (XSS-safe: values
            // set via text nodes only).
            const chipKeys = Object.keys(meta).filter(k => k !== 'derivedFrom');
            if (chipKeys.length) {
                const chips = document.createElement('div');
                chips.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;';
                chipKeys.slice(0, 8).forEach(k => {
                    const v = meta[k];
                    if (v === null || v === undefined || v === '') return;
                    const chip = document.createElement('span');
                    chip.style.cssText = 'font-size:11px;padding:1px 8px;border-radius:4px;background:#1f2937;border:1px solid #374151;color:#cbd5e1;';
                    const key = document.createElement('span');
                    key.style.color = '#64748b';
                    key.textContent = k + ': ';
                    chip.appendChild(key);
                    chip.appendChild(document.createTextNode(String(v).slice(0, 60)));
                    chips.appendChild(chip);
                });
                const body = card.querySelector('.p-4');
                if (body && chips.childNodes.length) body.insertBefore(chips, body.firstChild);
            }

            return card;
        }

        // Splits rawData text on URLs and renders them as safe <a> elements.
        function renderRawData(container, text) {
            const urlRegex = /(https?:\/\/[^\s]+)/g;
            let lastIndex = 0;
            let match;
            while ((match = urlRegex.exec(text)) !== null) {
                if (match.index > lastIndex) {
                    container.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
                }
                const href = match[1];
                if (/^https?:\/\//i.test(href)) {
                    const a = document.createElement('a');
                    a.setAttribute('href', href);
                    a.setAttribute('target', '_blank');
                    a.setAttribute('rel', 'noopener noreferrer');
                    a.className = 'text-brand-400 underline hover:text-brand-300';
                    a.textContent = href;
                    container.appendChild(a);
                } else {
                    container.appendChild(document.createTextNode(href));
                }
                lastIndex = urlRegex.lastIndex;
            }
            if (lastIndex < text.length) {
                container.appendChild(document.createTextNode(text.slice(lastIndex)));
            }
        }

        // Returns a relative date string ("today", "2 days ago", "Apr 20").
        function formatRelativeDate(date) {
            const diffDays = Math.floor((Date.now() - date) / 86400000);
            if (diffDays === 0) return 'today';
            if (diffDays === 1) return 'yesterday';
            if (diffDays < 30) return diffDays + ' days ago';
            return date.toLocaleDateString();
        }

        // Returns results filtered by the current confidence threshold and type filter.
        function filterResults(results) {
            let out = results;
            if (confidenceFilterActive) out = out.filter(r => r.confidenceScore >= 0.7);
            if (activeTypeFilter) out = out.filter(r => r.type === activeTypeFilter);
            return out;
        }

        // Re-renders the results grid from lastScanData using the current filter and sort.
        function reRenderGrid() {
            if (!lastScanData) return;
            const filtered = sortResults(filterResults(lastScanData.results || []));
            resultsGrid.innerHTML = '';
            if (filtered.length === 0) {
                emptyState.classList.remove('hidden');
                resultsGrid.classList.add('hidden');
            } else {
                emptyState.classList.add('hidden');
                resultsGrid.classList.remove('hidden');
                filtered.forEach(r => resultsGrid.appendChild(createResultCard(r)));
            }
        }

        // Fetches the attack-surface delta vs the previous scan of this target and
        // renders a banner. Owner-only endpoint: 401/404 (anonymous or shared view)
        // just leaves the banner hidden.
        function loadExposureDiff(scanID) {
            const banner = document.getElementById('exposure-diff-banner');
            if (!banner || !scanID) return;
            banner.classList.add('hidden');
            fetch('/api/scans/' + encodeURIComponent(scanID) + '/exposure-diff', { credentials: 'include' })
                .then(r => r.ok ? r.json() : null)
                .then(d => { if (d && d.previous) renderExposureDiff(banner, d); })
                .catch(() => {});
        }

        function renderExposureDiff(banner, d) {
            const delta = d.delta || {};
            const portCount = (delta.newPorts || []).reduce((n, h) => n + (h.ports || []).length, 0);
            const worse = (delta.gradeChanges || []).filter(g => g.from && g.to > g.from);
            const better = (delta.gradeChanges || []).filter(g => !g.from || g.to <= g.from);
            const additions = portCount + (delta.newCVEs || []).length + (delta.newSubdomains || []).length + worse.length;
            const removals = (delta.closedPorts || []).reduce((n, h) => n + (h.ports || []).length, 0)
                + (delta.resolvedCVEs || []).length + (delta.removedSubdomains || []).length + better.length;

            banner.innerHTML = '';
            // Worsening = red/amber accent; only improvements/none = green.
            const accent = additions > 0 ? '#f59e0b' : '#10b981';
            banner.style.cssText = 'background:' + accent + '14;border:1px solid ' + accent + '55;border-radius:12px;padding:12px 14px;';

            const head = document.createElement('div');
            head.style.cssText = 'font-weight:700;color:#e2e8f0;display:flex;align-items:center;gap:8px;flex-wrap:wrap;';
            const when = d.previous && d.previous.scannedAt ? formatRelativeDate(new Date(d.previous.scannedAt * 1000)) : 'previous scan';
            head.textContent = additions > 0
                ? '⚠ Attack-surface changes since ' + when
                : (removals > 0 ? '✓ Surface reduced since ' + when : '✓ No exposure changes since ' + when);
            banner.appendChild(head);

            const list = document.createElement('div');
            list.style.cssText = 'display:flex;flex-direction:column;gap:3px;margin-top:8px;font-size:13px;';
            const line = (text, color) => {
                const el = document.createElement('div'); el.style.cssText = 'color:' + (color || '#cbd5e1') + ';word-break:break-word;'; el.textContent = text; list.appendChild(el);
            };
            (delta.newPorts || []).forEach(h => line('🔓 New ports — ' + h.ip + ': ' + (h.ports || []).join(', '), '#fca5a5'));
            if ((delta.newCVEs || []).length) line('🐛 New CVEs — ' + delta.newCVEs.slice(0, 6).join(', ') + (delta.newCVEs.length > 6 ? ' +' + (delta.newCVEs.length - 6) : ''), '#fca5a5');
            if ((delta.newSubdomains || []).length) line('🌐 New subdomains — ' + delta.newSubdomains.slice(0, 8).join(', ') + (delta.newSubdomains.length > 8 ? ' +' + (delta.newSubdomains.length - 8) : ''), '#fcd34d');
            worse.forEach(g => line('📉 ' + g.domain + ' posture ' + g.from + '→' + g.to, '#fca5a5'));
            // Improvements, secondary.
            (delta.closedPorts || []).forEach(h => line('✓ Closed ports — ' + h.ip + ': ' + (h.ports || []).join(', '), '#86efac'));
            if ((delta.resolvedCVEs || []).length) line('✓ Resolved CVEs — ' + delta.resolvedCVEs.slice(0, 6).join(', '), '#86efac');
            if ((delta.removedSubdomains || []).length) line('✓ Removed subdomains — ' + delta.removedSubdomains.slice(0, 8).join(', '), '#86efac');
            better.forEach(g => line('📈 ' + g.domain + ' posture ' + (g.from || '?') + '→' + g.to, '#86efac'));

            if (list.children.length) banner.appendChild(list);
            banner.classList.remove('hidden');
        }

        // Fetches and renders the synthesized identity profile for a scan.
        function loadIdentity(scanID) {
            const panel = document.getElementById('identity-panel');
            if (!panel || !scanID) return;
            const encodedID = encodeURIComponent(scanID);
            const identityRequest = fetch('/api/identity/' + encodedID, { credentials: 'include' })
                .then(r => r.ok ? r.json() : null);
            const timelineRequest = fetch('/api/scans/' + encodedID + '/timeline', { credentials: 'include' })
                .then(r => r.ok ? r.json() : null)
                .catch(() => null);
            Promise.all([identityRequest, timelineRequest])
                .then(([p, timeline]) => {
                    if (!p) { panel.classList.add('hidden'); return; }
                    if (timeline && Array.isArray(timeline.events)) {
                        p.timeline = timeline.events;
                        p.timelineSummary = timeline.summary || null;
                    }
                    renderIdentity(panel, p);
                })
                .catch(() => panel.classList.add('hidden'));
        }

        // All colours are inline: the compiled tailwind.css is purged and would
        // not contain any new utility classes used here.
        function renderIdentity(panel, p) {
            const hasData = p.likelyName || (p.emails || []).length || (p.handles || []).length ||
                            (p.confirmedAccounts || []).length || (p.breaches || []).length || (p.phones || []).length ||
                            (p.exposedIPs || []).length || (p.exposedServices || []).length || (p.vulnerabilities || []).length ||
                            (p.exposedDataClasses || []).length || (p.timeline || []).length;
            if (!hasData) { panel.classList.add('hidden'); return; }
            panel.innerHTML = '';
            panel.style.cssText = 'background:#111827;border:1px solid rgba(99,102,241,.3);border-radius:12px;padding:16px;';

            const head = document.createElement('div');
            head.style.cssText = 'display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;';
            const title = document.createElement('span');
            title.style.cssText = 'font-weight:700;color:#e2e8f0;';
            title.textContent = '🧬 Synthesized Identity';
            head.appendChild(title);
            if (typeof p.riskScore === 'number') {
                const riskColors = { critical: '#f87171', high: '#fb923c', medium: '#facc15', low: '#4ade80' };
                const c = riskColors[(p.riskLevel || '').toLowerCase()] || '#94a3b8';
                const risk = document.createElement('span');
                risk.style.cssText = 'font-size:12px;padding:2px 8px;border-radius:6px;border:1px solid ' + c + '66;color:' + c + ';background:' + c + '1a;';
                risk.textContent = 'Risk ' + p.riskScore + ' · ' + (p.riskLevel || '');
                head.appendChild(risk);
            }
            panel.appendChild(head);

            const grid = document.createElement('div');
            grid.style.cssText = 'display:grid;grid-template-columns:1fr;gap:6px 24px;font-size:14px;';
            if (window.matchMedia && window.matchMedia('(min-width:768px)').matches) grid.style.gridTemplateColumns = '1fr 1fr';

            function chip(text) {
                const c = document.createElement('span');
                c.style.cssText = 'font-size:11px;padding:1px 8px;border-radius:4px;background:#1f2937;border:1px solid #374151;color:#cbd5e1;';
                c.textContent = text; return c;
            }
            function dangerChip(text) {
                const c = document.createElement('span');
                c.style.cssText = 'font-size:11px;padding:1px 8px;border-radius:4px;background:#7f1d1d33;border:1px solid #ef444466;color:#fca5a5;';
                c.textContent = text; return c;
            }
            function row(label, node) {
                const r = document.createElement('div'); r.style.cssText = 'display:flex;gap:8px;align-items:flex-start;';
                const l = document.createElement('span'); l.style.cssText = 'color:#64748b;flex-shrink:0;min-width:64px;'; l.textContent = label;
                r.appendChild(l); r.appendChild(node); grid.appendChild(r);
            }
            function chipRow(label, items) {
                const wrap = document.createElement('div'); wrap.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;';
                items.forEach(t => wrap.appendChild(chip(String(t).slice(0, 80))));
                row(label, wrap);
            }
            function textRow(label, text) {
                const n = document.createElement('span'); n.style.cssText = 'color:#e2e8f0;word-break:break-all;'; n.textContent = text;
                row(label, n);
            }

            if (p.likelyName) textRow('Name', p.likelyName);
            if ((p.locations || []).length) textRow('Location', p.locations.join(', '));
            if ((p.organizations || []).length) textRow('Org', p.organizations.join(', '));
            if ((p.emails || []).length) chipRow('Emails', p.emails);
            if ((p.phones || []).length) chipRow('Phones', p.phones);
            if ((p.handles || []).length) chipRow('Handles', p.handles.slice(0, 12).map(h => h.handle + ' (' + (h.platforms || []).length + ')'));
            if ((p.confirmedAccounts || []).length) {
                chipRow('Accounts', Array.from(new Set(p.confirmedAccounts.map(a => a.platform))).slice(0, 16));
            }
            if ((p.breaches || []).length) chipRow('Breaches', p.breaches.slice(0, 12));
            if ((p.exposedDataClasses || []).length) {
                const wrap = document.createElement('div'); wrap.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;';
                p.exposedDataClasses.slice(0, 16).forEach(dc => wrap.appendChild(dangerChip(dc)));
                row('Exposed data', wrap);
            }
            if ((p.exposedIPs || []).length) chipRow('IPs', p.exposedIPs.slice(0, 8));
            if ((p.exposedServices || []).length) {
                chipRow('Ports', p.exposedServices.slice(0, 8).map(s =>
                    s.ip + (s.ports && s.ports.length ? ' → ' + s.ports.slice(0, 12).join(',') : '')));
            }
            if ((p.vulnerabilities || []).length) {
                const wrap = document.createElement('div'); wrap.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;';
                p.vulnerabilities.slice(0, 16).forEach(v => wrap.appendChild(dangerChip(v)));
                if (p.vulnerabilities.length > 16) wrap.appendChild(chip('+' + (p.vulnerabilities.length - 16) + ' more'));
                row('CVEs', wrap);
            }

            panel.appendChild(grid);

            // Evidence-aware chronology. Values are always inserted through
            // textContent: provider-controlled labels/sources never become HTML.
            const timelineEvents = Array.isArray(p.timeline) ? p.timeline.slice(-100) : [];
            if (timelineEvents.length) {
                const sec = document.createElement('div');
                sec.style.cssText = 'margin-top:12px;padding-top:10px;border-top:1px solid #1f2937;';
                const timelineHead = document.createElement('div');
                timelineHead.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:8px;';
                const headingWrap = document.createElement('div');
                const lbl = document.createElement('div');
                lbl.style.cssText = 'color:#cbd5e1;font-size:13px;font-weight:700;';
                lbl.textContent = '🕓 Timeline intelligence';
                headingWrap.appendChild(lbl);
                const summary = p.timelineSummary || {};
                const summaryText = document.createElement('div');
                summaryText.style.cssText = 'color:#64748b;font-size:11px;margin-top:2px;';
                const total = Number.isFinite(Number(summary.totalEventCount))
                    ? Number(summary.totalEventCount) : timelineEvents.length;
                const conflicts = Math.max(0, Number(summary.conflictGroups) || 0);
                const recurrence = Math.max(0, Number(summary.breachRecurrenceCount) || 0);
                summaryText.textContent = total + ' events · ' + recurrence + ' recurring breach' +
                    (recurrence === 1 ? '' : 'es') + (conflicts ? ' · ' + conflicts + ' date conflict' + (conflicts === 1 ? '' : 's') : '');
                headingWrap.appendChild(summaryText);
                timelineHead.appendChild(headingWrap);

                const filter = document.createElement('select');
                filter.setAttribute('aria-label', 'Filter timeline by category');
                filter.style.cssText = 'min-height:32px;max-width:100%;background:#0f172a;border:1px solid #374151;border-radius:6px;color:#cbd5e1;font-size:11px;padding:4px 28px 4px 8px;';
                const categories = ['all', ...new Set(timelineEvents.map(ev => String(ev.category || '')).filter(Boolean))];
                categories.forEach(category => {
                    const option = document.createElement('option');
                    option.value = category;
                    option.textContent = category === 'all' ? 'All evidence' : category.charAt(0).toUpperCase() + category.slice(1);
                    filter.appendChild(option);
                });
                timelineHead.appendChild(filter);
                sec.appendChild(timelineHead);

                const list = document.createElement('div');
                list.style.cssText = 'display:flex;flex-direction:column;gap:6px;';
                sec.appendChild(list);
                const footer = document.createElement('div');
                footer.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;margin-top:8px;';
                const shown = document.createElement('span');
                shown.style.cssText = 'color:#64748b;font-size:11px;';
                const toggle = document.createElement('button');
                toggle.type = 'button';
                toggle.style.cssText = 'min-height:32px;padding:4px 10px;border-radius:6px;border:1px solid #374151;background:#1f2937;color:#cbd5e1;font-size:11px;';
                let expanded = false;

                const categoryStyles = {
                    account: ['👤', '#a5b4fc'], breach: ['⚠', '#fca5a5'],
                    domain: ['🌐', '#67e8f9'], certificate: ['🔐', '#c4b5fd'],
                    archive: ['🗄', '#fcd34d']
                };
                function renderTimelineRows() {
                    list.replaceChildren();
                    const category = filter.value;
                    const filtered = timelineEvents.filter(ev => category === 'all' || ev.category === category);
                    const visible = expanded ? filtered : filtered.slice(-12);
                    visible.forEach(ev => {
                        const style = categoryStyles[ev.category] || ['•', '#cbd5e1'];
                    const line = document.createElement('div');
                        line.style.cssText = 'display:grid;grid-template-columns:minmax(72px,90px) minmax(0,1fr);gap:8px;align-items:start;padding:7px 8px;border:1px solid #1f2937;border-radius:8px;background:#0f172a80;font-size:12px;';
                    const d = document.createElement('span');
                        d.style.cssText = 'color:#94a3b8;font-variant-numeric:tabular-nums;word-break:break-word;';
                        d.textContent = String(ev.date || '').slice(0, 10);
                        const body = document.createElement('div');
                        body.style.cssText = 'min-width:0;';
                        const titleLine = document.createElement('div');
                        titleLine.style.cssText = 'display:flex;align-items:flex-start;gap:5px;flex-wrap:wrap;color:' + style[1] + ';word-break:break-word;';
                        const titleText = document.createElement('span');
                        titleText.style.cssText = 'min-width:0;';
                        titleText.textContent = style[0] + ' ' + String(ev.label || '').slice(0, 160);
                        titleLine.appendChild(titleText);
                        const confidence = Math.max(0, Math.min(100, Math.round((Number(ev.confidence) || 0) * 100)));
                        const confidenceBadge = document.createElement('span');
                        confidenceBadge.style.cssText = 'flex-shrink:0;border:1px solid #475569;border-radius:999px;padding:0 5px;color:#94a3b8;font-size:10px;';
                        confidenceBadge.textContent = confidence + '%';
                        titleLine.appendChild(confidenceBadge);
                        if (ev.conflicting) {
                            const conflictBadge = document.createElement('span');
                            conflictBadge.style.cssText = 'flex-shrink:0;border:1px solid #f59e0b66;border-radius:999px;padding:0 5px;color:#fcd34d;font-size:10px;';
                            conflictBadge.textContent = 'conflict';
                            titleLine.appendChild(conflictBadge);
                        }
                        body.appendChild(titleLine);
                        const sources = Array.isArray(ev.sources) ? ev.sources.slice(0, 4).map(source => String(source).slice(0, 80)) : [];
                        if (sources.length) {
                            const provenance = document.createElement('div');
                            provenance.style.cssText = 'color:#64748b;font-size:10px;margin-top:2px;word-break:break-word;';
                            provenance.textContent = 'Sources: ' + sources.join(', ') +
                                (Number(ev.evidenceCount) > 1 ? ' · ' + Number(ev.evidenceCount) + ' observations' : '');
                            body.appendChild(provenance);
                        }
                        if (ev.conflicting && Array.isArray(ev.conflictDates)) {
                            const conflictDetail = document.createElement('div');
                            conflictDetail.style.cssText = 'color:#d97706;font-size:10px;margin-top:2px;word-break:break-word;';
                            conflictDetail.textContent = 'Reported dates: ' + ev.conflictDates.slice(0, 8).map(String).join(', ');
                            body.appendChild(conflictDetail);
                        }
                        line.appendChild(d); line.appendChild(body); list.appendChild(line);
                    });
                    shown.textContent = 'Showing ' + visible.length + ' of ' + filtered.length +
                        (timelineEvents.length < total ? ' recent events (' + total + ' total)' : '');
                    toggle.classList.toggle('hidden', filtered.length <= 12);
                    toggle.textContent = expanded ? 'Show recent 12' : 'Show all loaded';
                }
                filter.addEventListener('change', () => { expanded = false; renderTimelineRows(); });
                toggle.addEventListener('click', () => { expanded = !expanded; renderTimelineRows(); });
                footer.appendChild(shown);
                footer.appendChild(toggle);
                sec.appendChild(footer);
                renderTimelineRows();
                panel.appendChild(sec);
            }

            panel.classList.remove('hidden');
        }

        function displayResults(data) {
            setScanningState(false);
            lastScanData = data;
            resultsPanel.classList.remove('hidden');
            scanIdDisplay.textContent = data.scanID;

            // Scan age indicator
            const ageEl = document.getElementById('scan-age-display');
            if (data.completedAt) {
                ageEl.textContent = 'Scanned ' + formatRelativeDate(new Date(data.completedAt * 1000));
                ageEl.classList.remove('hidden');
            } else {
                ageEl.classList.add('hidden');
            }

            reRenderGrid();
            loadIdentity(data.scanID);
            loadExposureDiff(data.scanID);
            saveToHistory(data.scanID, data.input, data.results ? data.results.length : 0);
            // Refresh graph / surface if the user has that tab open.
            if (activeResultsTab === 'graph') renderD3Graph(data);
            if (activeResultsTab === 'surface') renderAttackSurface(data);
        }

        // Per-session SSE streaming. The server assigns a durable per-scan event
        // ID; native EventSource reconnects with Last-Event-ID and the Set below
        // makes rendering idempotent if a proxy replays the final frame.
        function startStreaming(scanID) {
            if (activeEventSource) activeEventSource.close();
            const token = Symbol();
            activeScanToken = token;

            // Show results panel early so cards appear live.
            resultsPanel.classList.remove('hidden');
            scanIdDisplay.textContent = scanID;
            emptyState.classList.add('hidden');
            resultsGrid.classList.remove('hidden');
            const idPanel = document.getElementById('identity-panel');
            if (idPanel) idPanel.classList.add('hidden'); // hide stale profile until the new scan settles

            // Show and reset the progress bar
            document.getElementById('scan-progress').classList.remove('hidden');
            document.getElementById('progress-bar-fill').style.width = '0%';
            document.getElementById('progress-count-label').textContent = '0 / 18';
            document.getElementById('progress-plugin-label').textContent = 'Starting scan…';

            if (typeof EventSource === 'undefined') {
                startPolling(scanID);
                return;
            }

            let receivedResults = 0;
            const seenEventIDs = new Set();
            let reconnectFallbackTimer = null;
            const evSource = new EventSource('/api/stream/' + encodeURIComponent(scanID));
            activeEventSource = evSource;

            evSource.onopen = () => {
                if (token !== activeScanToken) { evSource.close(); return; }
                if (reconnectFallbackTimer) {
                    clearTimeout(reconnectFallbackTimer);
                    reconnectFallbackTimer = null;
                }
            };

            evSource.addEventListener('result', (e) => {
                if (token !== activeScanToken) { evSource.close(); return; }
                if (e.lastEventId && seenEventIDs.has(e.lastEventId)) return;
                try {
                    const result = JSON.parse(e.data);
                    if (e.lastEventId) seenEventIDs.add(e.lastEventId);
                    // Apply live confidence + type filter during streaming.
                    const passConf = !confidenceFilterActive || result.confidenceScore >= 0.7;
                    const passType = !activeTypeFilter || result.type === activeTypeFilter;
                    if (passConf && passType) {
                        resultsGrid.appendChild(createResultCard(result));
                    }
                    receivedResults++;
                } catch (_) {}
            });

            evSource.addEventListener('progress', (e) => {
                if (token !== activeScanToken) { evSource.close(); return; }
                try {
                    const p = JSON.parse(e.data);
                    const pct = p.total > 0 ? Math.round((p.done / p.total) * 100) : 0;
                    document.getElementById('progress-bar-fill').style.width = pct + '%';
                    document.getElementById('progress-count-label').textContent = p.done + ' / ' + p.total;
                    if (p.lastPlugin) {
                        document.getElementById('progress-plugin-label').textContent = '✓ ' + p.lastPlugin;
                    }
                } catch (_) {}
            });

            // A named server error is terminal for this stream. Transport
            // failures use EventSource's reserved `error` event below.
            evSource.addEventListener('stream-error', (e) => {
                evSource.close();
                if (activeEventSource === evSource) activeEventSource = null;
                if (reconnectFallbackTimer) {
                    clearTimeout(reconnectFallbackTimer);
                    reconnectFallbackTimer = null;
                }
                if (token !== activeScanToken) return;
                setScanningState(false);
                logStatus('Live results are temporarily unavailable. Refresh and retry.', 'text-red-500');
            });

            evSource.addEventListener('done', (e) => {
                evSource.close();
                if (activeEventSource === evSource) activeEventSource = null;
                if (reconnectFallbackTimer) clearTimeout(reconnectFallbackTimer);
                if (token !== activeScanToken) return;
                try {
                    const info = JSON.parse(e.data);
                    setScanningState(false);
                    document.getElementById('scan-progress').classList.add('hidden');
                    if (info.status === 'failed') {
                        logStatus('Scan finished with errors. Partial results shown.', 'text-red-500');
                    } else if (info.status === 'timeout') {
                        logStatus('Scan timed out. Partial results shown.', 'text-yellow-500');
                    } else {
                        const riskLabel = info.riskLevel ? ` · Risk: ${info.riskLevel} (${info.riskScore}/100)` : '';
                        logStatus('Scan completed: ' + info.count + ' result(s)' + riskLabel + '.');
                    }
                    // Show risk badge above results grid
                    if (info.riskLevel) {
                        const riskColors = { Low: 'text-green-400', Medium: 'text-yellow-400', High: 'text-orange-400', Critical: 'text-red-500' };
                        const cls = riskColors[info.riskLevel] || 'text-slate-400';
                        let badge = document.getElementById('risk-score-badge');
                        if (!badge) {
                            badge = document.createElement('div');
                            badge.id = 'risk-score-badge';
                            badge.className = 'text-xs font-semibold uppercase tracking-wide mb-2';
                            resultsGrid.parentNode.insertBefore(badge, resultsGrid);
                        }
                        badge.className = `text-xs font-semibold uppercase tracking-wide mb-2 ${cls}`;
                        badge.textContent = `⚠ Exposure Risk: ${info.riskLevel} — ${info.riskScore}/100`;
                        badge.classList.remove('hidden');
                    }
                    if (receivedResults === 0) {
                        emptyState.classList.remove('hidden');
                        resultsGrid.classList.add('hidden');
                    }
                    // Fetch full scan data for export/share/history.
                    fetch('/api/results/' + encodeURIComponent(scanID))
                        .then(r => r.json())
                        .then(d => {
                            lastScanData = d;
                            saveToHistory(d.scanID, d.input, d.results ? d.results.length : 0);
                        })
                        .catch(() => {});
                    // Synthesized identity profile (after the pivot round settles).
                    loadIdentity(scanID);
                } catch (_) {}
            });

            evSource.onerror = () => {
                if (token !== activeScanToken) { evSource.close(); return; }
                if (reconnectFallbackTimer) return;
                logStatus('Stream interrupted — reconnecting from the last result…', 'text-yellow-500');
                // EventSource retries automatically (the server advertises 2s).
                // Fall back only if it could not reopen within a bounded window.
                reconnectFallbackTimer = setTimeout(() => {
                    reconnectFallbackTimer = null;
                    if (token !== activeScanToken) { evSource.close(); return; }
                    if (evSource.readyState === EventSource.OPEN) return;
                    evSource.close();
                    if (activeEventSource === evSource) activeEventSource = null;
                    logStatus('Streaming unavailable — switching to polling.');
                    startPolling(scanID);
                }, 7000);
            };
        }

        // Per-session polling: each call returns a unique token; callbacks discard themselves
        // if the token no longer matches (i.e. a newer scan has taken over the UI).
        function startPolling(scanID) {
            if (activeEventSource) {
                activeEventSource.close();
                activeEventSource = null;
            }
            const token = Symbol();
            activeScanToken = token;
            let count = 0;

            async function doPoll() {
                if (token !== activeScanToken) return;
                count++;
                logStatus(`Polling... (attempt ${count}/${MAX_POLLS})`);
                try {
                    const response = await fetch(`/api/results/${encodeURIComponent(scanID)}`);
                    if (!response.ok) throw new Error(`HTTP ${response.status}`);
                    const data = await response.json();
                    if (token !== activeScanToken) return;
                    logStatus(`Status: ${data.status} | ${data.results.length} result(s) found.`);
                    if (data.status === 'completed' || data.status === 'failed') {
                        displayResults(data);
                        if (data.status === 'failed') {
                            logStatus('Scan finished with errors. Partial results may be shown.', 'text-red-500');
                        } else {
                            logStatus('Scan completed successfully.');
                        }
                    } else if (count < MAX_POLLS) {
                        setTimeout(doPoll, POLL_INTERVAL_MS);
                    } else {
                        setScanningState(false);
                        logStatus('Scan taking longer than expected. Refresh to check.', 'text-yellow-500');
                    }
                } catch (error) {
                    if (token !== activeScanToken) return;
                    logStatus('Poll error: ' + error.message, 'text-red-500');
                    if (count < MAX_POLLS) {
                        setTimeout(doPoll, POLL_INTERVAL_MS);
                    } else {
                        setScanningState(false);
                        logStatus('Scan timed out.', 'text-red-500');
                    }
                }
            }
            setTimeout(doPoll, POLL_INTERVAL_MS);
        }

        // Load an existing scan by ID — only GETs results, never POSTs a new scan.
        async function loadScanByID(scanID) {
            activeScanToken = Symbol();
            resetResultsView();
            setScanningState(true);
            logStatus('Loading scan ' + scanID + '...');
            try {
                const response = await fetch('/api/results/' + encodeURIComponent(scanID));
                if (!response.ok) throw new Error('HTTP ' + response.status);
                const data = await response.json();
                if (data.input) input.value = data.input;
                if (data.status === 'completed' || data.status === 'failed') {
                    displayResults(data);
                } else {
                    logStatus('Scan still running — streaming live updates...');
                    startStreaming(scanID);
                }
            } catch (err) {
                setScanningState(false);
                logStatus('Failed to load scan: ' + err.message, 'text-red-500');
            }
        }

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const target = input.value.trim();
            if (!target) return;
            activeScanToken = Symbol();
            resetResultsView();
            setScanningState(true);
            logStatus('Initiating scan against target: ' + target);
            try {
                const selectedPlugins = getSelectedPlugins();
                const scanBody = { input: target };
                if (selectedPlugins) scanBody.plugins = selectedPlugins;
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(scanBody)
                });
                if (!response.ok) {
                    const errText = await response.text().catch(() => response.status);
                    throw new Error(String(errText));
                }
                const data = await response.json();
                logStatus('Scan queued with ID: ' + data.scanID);
                // Optionally schedule repeat scans.
                const scheduleCheck = document.getElementById('schedule-check');
                if (scheduleCheck && scheduleCheck.checked && currentUser) {
                    const interval = document.getElementById('schedule-interval').value;
                    await fetch('/api/scheduled-scans', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify({ input: target, interval })
                    }).catch(() => {});
                    logStatus('Scheduled ' + interval + ' scan created.');
                }
                startStreaming(data.scanID);
            } catch (error) {
                logStatus('Error initiating scan: ' + error.message, 'text-red-500');
                setScanningState(false);
            }
        });

        // ─── SCAN HISTORY ─────────────────────────────────────────────────────────
        const HISTORY_KEY = 'dft_history';
        const MAX_HISTORY = 20;

        function saveToHistory(scanID, target, resultCount) {
            try {
                let history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
                if (!Array.isArray(history)) history = [];
                history = history.filter(h => h && h.scanID !== scanID);
                history.unshift({ scanID, target: String(target || ''), resultCount: Number(resultCount) || 0, ts: Date.now() });
                if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
                localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
            } catch (_) {}
            renderHistory();
        }

        function renderHistory() {
            let history = [];
            try {
                history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
                if (!Array.isArray(history)) history = [];
            } catch (_) { history = []; }
            const panel = document.getElementById('history-panel');
            const list = document.getElementById('history-list');
            if (!history.length) { panel.classList.add('hidden'); return; }
            panel.classList.remove('hidden');
            list.innerHTML = '';
            history.forEach(h => {
                if (!h || typeof h.scanID !== 'string') return;
                const btn = document.createElement('button');
                btn.className = 'flex items-center justify-between w-full text-left px-3 py-2 rounded-lg hover:bg-dark-700 transition-colors';
                const left = document.createElement('span');
                left.className = 'flex items-center gap-2 min-w-0';
                const dot = document.createElement('span');
                dot.className = 'w-1.5 h-1.5 rounded-full bg-brand-500 flex-shrink-0';
                const targetEl = document.createElement('span');
                targetEl.className = 'text-white text-sm truncate max-w-[160px] sm:max-w-xs';
                targetEl.textContent = String(h.target || '');
                left.appendChild(dot);
                left.appendChild(targetEl);
                const right = document.createElement('span');
                right.className = 'flex items-center gap-3 flex-shrink-0 ml-2';
                const badge = document.createElement('span');
                badge.className = 'text-xs text-brand-500';
                badge.textContent = (h.resultCount || 0) + ' hit' + (h.resultCount !== 1 ? 's' : '');
                const time = document.createElement('span');
                time.className = 'text-xs text-slate-500';
                time.textContent = new Date(h.ts || 0).toLocaleDateString();
                right.appendChild(badge);
                right.appendChild(time);
                btn.appendChild(left);
                btn.appendChild(right);
                btn.addEventListener('click', () => loadScanByID(String(h.scanID)));
                list.appendChild(btn);
            });
        }

        document.getElementById('clear-history-btn').addEventListener('click', () => {
            try { localStorage.removeItem(HISTORY_KEY); } catch (_) {}
            renderHistory();
        });

        // ─── CONFIDENCE FILTER ────────────────────────────────────────────────────
        const confidenceFilterBtn = document.getElementById('confidence-filter-btn');
        const confFilterLabel = document.getElementById('conf-filter-label');
        confidenceFilterBtn.addEventListener('click', () => {
            confidenceFilterActive = !confidenceFilterActive;
            if (confidenceFilterActive) {
                confidenceFilterBtn.classList.add('border-green-500/50', 'text-green-400');
                confidenceFilterBtn.classList.remove('text-slate-400');
                confFilterLabel.textContent = 'ALL RESULTS';
            } else {
                confidenceFilterBtn.classList.remove('border-green-500/50', 'text-green-400');
                confidenceFilterBtn.classList.add('text-slate-400');
                confFilterLabel.textContent = 'HIGH CONF';
            }
            reRenderGrid();
        });

        // ─── FORCE RESCAN ─────────────────────────────────────────────────────────
        document.getElementById('force-rescan-btn').addEventListener('click', async () => {
            const target = input.value.trim();
            if (!target) return;
            activeScanToken = Symbol();
            resetResultsView();
            setScanningState(true);
            logStatus('Force rescanning: ' + target);
            try {
                const selectedPlugins = getSelectedPlugins();
                const rescanBody = { input: target, force: true };
                if (selectedPlugins) rescanBody.plugins = selectedPlugins;
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(rescanBody)
                });
                if (!response.ok) {
                    const errText = await response.text().catch(() => String(response.status));
                    throw new Error(errText);
                }
                const data = await response.json();
                logStatus('New scan queued: ' + data.scanID);
                startStreaming(data.scanID);
            } catch (error) {
                logStatus('Error: ' + error.message, 'text-red-500');
                setScanningState(false);
            }
        });

        // ─── EXPORT JSON ──────────────────────────────────────────────────────────
        document.getElementById('export-json-btn').addEventListener('click', () => {
            if (!lastScanData) return;
            const blob = new Blob([JSON.stringify(lastScanData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'footprint-' + lastScanData.scanID + '.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        });

        // ─── EXPORT GRAPHML ───────────────────────────────────────────────────────
        // Server-rendered relationship graph of the synthesized identity; the
        // attachment response downloads without navigating away.
        document.getElementById('export-graph-btn').addEventListener('click', () => {
            if (!lastScanData) return;
            const a = document.createElement('a');
            a.href = '/api/export/' + encodeURIComponent(lastScanData.scanID) + '/graph';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        });

        // ─── EXPORT REPORT (print-ready HTML; Ctrl+P → PDF) ───────────────────────
        // Opens the server-rendered report in a new tab. The raw Markdown is still
        // available at /api/export/:id/report for scripting.
        document.getElementById('export-report-btn').addEventListener('click', () => {
            if (!lastScanData) return;
            window.open('/api/export/' + encodeURIComponent(lastScanData.scanID) + '/report.html', '_blank', 'noopener');
        });

        // ─── EXPORT PDF ───────────────────────────────────────────────────────────
        document.getElementById('export-pdf-btn').addEventListener('click', () => window.print());

        // ─── SHARE LINK ───────────────────────────────────────────────────────────
        const shareModal = document.getElementById('share-modal');
        const shareButton = document.getElementById('share-btn');
        const shareList = document.getElementById('share-list');
        const SHARE_DEFAULT_EXPIRY = '604800';

        function closeShareModal() {
            shareModal.classList.add('hidden');
            document.body.classList.remove('overflow-hidden');
            shareButton.focus();
        }

        function formatShareDate(epochSeconds) {
            const value = Number(epochSeconds);
            if (!Number.isFinite(value)) return 'Unknown';
            return new Intl.DateTimeFormat(undefined, {
                dateStyle: 'medium', timeStyle: 'short'
            }).format(new Date(value * 1000));
        }

        function renderShareLinks(shares) {
            shareList.replaceChildren();
            if (!Array.isArray(shares) || shares.length === 0) {
                const empty = document.createElement('p');
                empty.className = 'text-[10px] text-slate-500 py-1';
                empty.textContent = 'No share links for this scan.';
                shareList.appendChild(empty);
                return;
            }

            for (const share of shares) {
                const row = document.createElement('div');
                row.className = 'flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-dark-900 border border-dark-700 rounded-lg px-3 py-2';

                const details = document.createElement('div');
                details.className = 'min-w-0';
                const expiry = Number(share.expiresAt);
                const hasExpiry = share.expiresAt !== null && share.expiresAt !== undefined && Number.isFinite(expiry);
                const expired = hasExpiry && expiry * 1000 <= Date.now();
                const headline = document.createElement('p');
                headline.className = expired ? 'text-[10px] text-red-400' : hasExpiry ? 'text-[10px] text-slate-300' : 'text-[10px] text-amber-400';
                headline.textContent = expired
                    ? `Expired ${formatShareDate(expiry)}`
                    : hasExpiry ? `Expires ${formatShareDate(expiry)}` : 'No expiry (legacy link)';

                const metadata = document.createElement('p');
                metadata.className = 'text-[9px] text-slate-500 mt-0.5';
                const views = Number.isFinite(Number(share.viewCount)) ? Number(share.viewCount) : 0;
                const created = share.createdAt !== null && share.createdAt !== undefined && Number.isFinite(Number(share.createdAt))
                    ? `Created ${formatShareDate(share.createdAt)} · ` : '';
                metadata.textContent = `${created}${views} view${views === 1 ? '' : 's'}${share.hasPassword ? ' · Password protected' : ''}`;
                details.append(headline, metadata);
                row.appendChild(details);

                const shareID = typeof share.id === 'string' ? share.id : '';
                if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(shareID)) {
                    const revoke = document.createElement('button');
                    revoke.type = 'button';
                    revoke.className = 'w-full sm:w-auto flex-shrink-0 text-[10px] px-3 py-1.5 rounded bg-red-900/40 text-red-300 hover:bg-red-800/60 transition-colors';
                    revoke.textContent = 'Revoke';
                    revoke.addEventListener('click', () => revokeShareLink(shareID, revoke));
                    row.appendChild(revoke);
                } else {
                    const legacy = document.createElement('span');
                    legacy.className = 'text-[9px] text-amber-500';
                    legacy.textContent = 'Revocation unavailable until backend update';
                    row.appendChild(legacy);
                }
                shareList.appendChild(row);
            }
        }

        async function loadShareLinks() {
            if (!lastScanData) return;
            shareList.textContent = 'Loading links…';
            try {
                const response = await fetch('/api/scans/' + encodeURIComponent(lastScanData.scanID) + '/shares', {
                    credentials: 'include'
                });
                if (!response.ok) throw new Error('HTTP ' + response.status);
                renderShareLinks(await response.json());
            } catch (error) {
                shareList.textContent = 'Could not load share links: ' + String(error && error.message || error);
            }
        }

        async function revokeShareLink(shareID, button) {
            if (!confirm('Revoke this share link immediately?')) return;
            button.disabled = true;
            button.textContent = 'Revoking…';
            try {
                const response = await fetch('/api/shares/' + encodeURIComponent(shareID), {
                    method: 'DELETE', credentials: 'include'
                });
                if (!response.ok) throw new Error('HTTP ' + response.status);
                showToast('Share link revoked.');
                await loadShareLinks();
            } catch (error) {
                showToast('Could not revoke share: ' + String(error && error.message || error), 'error');
                button.disabled = false;
                button.textContent = 'Revoke';
            }
        }

        shareButton.addEventListener('click', () => {
            if (!lastScanData) return;
            document.getElementById('share-result').classList.add('hidden');
            document.getElementById('share-url-output').value = '';
            document.getElementById('share-expiry-output').textContent = '';
            document.getElementById('share-password-input').value = '';
            document.getElementById('share-expires-select').value = SHARE_DEFAULT_EXPIRY;
            shareModal.classList.remove('hidden');
            document.body.classList.add('overflow-hidden');
            loadShareLinks();
            requestAnimationFrame(() => document.getElementById('share-expires-select').focus());
        });
        document.getElementById('share-modal-close').addEventListener('click', () => {
            closeShareModal();
        });
        shareModal.addEventListener('click', (event) => {
            if (event.target === shareModal) closeShareModal();
        });
        shareModal.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') {
                event.preventDefault();
                closeShareModal();
                return;
            }
            if (event.key !== 'Tab') return;
            const focusable = [...shareModal.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled])')];
            if (!focusable.length) return;
            const first = focusable[0], last = focusable[focusable.length - 1];
            if (event.shiftKey && document.activeElement === first) {
                event.preventDefault(); last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault(); first.focus();
            }
        });
        document.getElementById('share-refresh-btn').addEventListener('click', loadShareLinks);
        document.getElementById('share-create-btn').addEventListener('click', async () => {
            if (!lastScanData) return;
            const expiresIn = document.getElementById('share-expires-select').value;
            const password = document.getElementById('share-password-input').value.trim();
            const btn = document.getElementById('share-create-btn');
            if (password) {
                const passwordBytes = new TextEncoder().encode(password).length;
                if (passwordBytes < 8 || passwordBytes > 72) {
                    showToast('Share password must be 8–72 UTF-8 bytes.', 'error');
                    return;
                }
            }
            btn.textContent = 'Creating…';
            btn.disabled = true;
            try {
                const body = { expiresIn: parseInt(expiresIn, 10) };
                if (password) body.password = password;
                const resp = await fetch('/api/scans/' + lastScanData.scanID + '/share', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify(body)
                });
                if (!resp.ok) throw new Error('HTTP ' + resp.status);
                const data = await resp.json();
                document.getElementById('share-url-output').value = data.url;
                document.getElementById('share-expiry-output').textContent = Number.isFinite(Number(data.expiresAt))
                    ? 'Expires ' + formatShareDate(data.expiresAt) : '';
                document.getElementById('share-result').classList.remove('hidden');
                await loadShareLinks();
            } catch(err) {
                showToast('Failed to create share link: ' + String(err && err.message || err), 'error');
            } finally {
                btn.textContent = 'Generate Share Link';
                btn.disabled = false;
            }
        });
        document.getElementById('share-copy-btn').addEventListener('click', () => {
            const urlOut = document.getElementById('share-url-output');
            urlOut.select();
            document.execCommand('copy');
            copyToClipboard(urlOut.value, document.getElementById('share-copy-btn'));
        });

        // ─── E2: PLUGIN SELECTOR ─────────────────────────────────────────────────
        let availablePlugins = [];
        async function loadPlugins() {
            try {
                const resp = await fetch('/api/plugins');
                if (!resp.ok) return;
                availablePlugins = await resp.json();
                const container = document.getElementById('plugin-checkboxes');
                container.innerHTML = '';
                availablePlugins.forEach(p => {
                    const label = document.createElement('label');
                    label.className = 'flex items-center gap-1 text-[10px] text-slate-400 cursor-pointer hover:text-slate-200 select-none';
                    label.title = p.description || '';
                    label.innerHTML = `<input type="checkbox" class="plugin-checkbox" value="${escapeHtml(p.name)}" style="accent-color:#10b981"> ${escapeHtml(p.name)}`;
                    container.appendChild(label);
                });
            } catch(e) {}
        }
        function getSelectedPlugins() {
            const checked = [...document.querySelectorAll('.plugin-checkbox:checked')].map(cb => cb.value);
            return checked.length > 0 ? checked : null;
        }
        document.getElementById('advanced-toggle-btn').addEventListener('click', () => {
            const panel = document.getElementById('advanced-panel');
            const chevron = document.getElementById('advanced-chevron');
            panel.classList.toggle('hidden');
            chevron.style.transform = panel.classList.contains('hidden') ? '' : 'rotate(180deg)';
        });

        // ─── STATS DASHBOARD ──────────────────────────────────────────────────────
        async function loadStats() {
            try {
                const resp = await fetch('/api/stats');
                if (!resp.ok) return;
                const s = await resp.json();
                document.getElementById('stat-total').textContent   = s.totalScans   ?? '—';
                document.getElementById('stat-24h').textContent     = s.scansLast24h ?? '—';
                document.getElementById('stat-7d').textContent      = s.scansLast7d  ?? '—';
                document.getElementById('stat-results').textContent = s.totalResults ?? '—';

                const chartEl = document.getElementById('stats-bar-chart');
                const sourcesSection = document.getElementById('stats-sources');
                chartEl.innerHTML = '';
                if (s.topSources && s.topSources.length > 0) {
                    sourcesSection.classList.remove('hidden');
                    const max = s.topSources[0].hitCount || 1;
                    s.topSources.forEach(src => {
                        const pct = Math.max(4, Math.round((src.hitCount / max) * 100));
                        const row = document.createElement('div');
                        row.className = 'flex items-center gap-2';
                        const label = document.createElement('span');
                        label.className = 'text-xs text-slate-400 w-28 flex-shrink-0 truncate';
                        label.textContent = String(src.source || '');
                        const bar = document.createElement('div');
                        bar.className = 'flex-grow bg-dark-900 rounded overflow-hidden h-4 relative border border-dark-700';
                        const fill = document.createElement('div');
                        fill.className = 'h-full bg-brand-600/70 rounded transition-all duration-700';
                        fill.style.width = pct + '%';
                        const count = document.createElement('span');
                        count.className = 'text-xs text-slate-300 w-8 text-right flex-shrink-0';
                        count.textContent = src.hitCount;
                        bar.appendChild(fill);
                        row.appendChild(label);
                        row.appendChild(bar);
                        row.appendChild(count);
                        chartEl.appendChild(row);
                    });
                }
            } catch (_) {}
        }

        document.getElementById('refresh-stats-btn').addEventListener('click', loadStats);

        // ─── D3 FORCE-DIRECTED GRAPH TAB ─────────────────────────────────────────
        let graphSimulation = null;

        function switchResultsTab(tab) {
            activeResultsTab = tab;
            const resContent = document.getElementById('results-tab-content');
            const grContent  = document.getElementById('graph-tab-content');
            const mapContent = document.getElementById('map-tab-content');
            const surfContent = document.getElementById('surface-tab-content');
            const tabRes     = document.getElementById('tab-results');
            const tabGrp     = document.getElementById('tab-graph');
            const tabMap     = document.getElementById('tab-map');
            const tabSurf    = document.getElementById('tab-surface');
            if (!resContent || !grContent || !tabRes || !tabGrp) return;
            // Hide all, deactivate all tabs
            resContent.classList.add('hidden'); resContent.classList.remove('flex');
            grContent.classList.add('hidden');  grContent.classList.remove('flex');
            if (mapContent) { mapContent.classList.add('hidden'); mapContent.classList.remove('flex'); }
            if (surfContent) { surfContent.classList.add('hidden'); surfContent.classList.remove('flex'); }
            [tabRes, tabGrp, tabMap, tabSurf].forEach(t => { if(t) { t.classList.remove('border-brand-500','text-brand-400'); t.classList.add('border-transparent','text-slate-500'); }});
            if (tab === 'surface') {
                if (surfContent) { surfContent.classList.remove('hidden'); surfContent.classList.add('flex'); }
                if (tabSurf) { tabSurf.classList.add('border-brand-500', 'text-brand-400'); tabSurf.classList.remove('border-transparent', 'text-slate-500'); }
                if (lastScanData) renderAttackSurface(lastScanData);
            } else if (tab === 'graph') {
                grContent.classList.remove('hidden');
                grContent.classList.add('flex');
                tabGrp.classList.add('border-brand-500', 'text-brand-400');
                tabGrp.classList.remove('border-transparent', 'text-slate-500');
                if (lastScanData) renderD3Graph(lastScanData);
            } else if (tab === 'map') {
                if (mapContent) { mapContent.classList.remove('hidden'); mapContent.classList.add('flex'); }
                if (tabMap) { tabMap.classList.add('border-brand-500', 'text-brand-400'); tabMap.classList.remove('border-transparent', 'text-slate-500'); }
                initLeafletMap();
            } else {
                resContent.classList.remove('hidden');
                resContent.classList.add('flex');
                tabRes.classList.add('border-brand-500', 'text-brand-400');
                tabRes.classList.remove('border-transparent', 'text-slate-500');
            }
        }

        document.getElementById('tab-results').addEventListener('click', () => switchResultsTab('results'));
        document.getElementById('tab-graph').addEventListener('click', () => switchResultsTab('graph'));
        document.getElementById('tab-map').addEventListener('click', () => switchResultsTab('map'));
        document.getElementById('tab-surface').addEventListener('click', () => switchResultsTab('surface'));

        document.getElementById('toggle-graph-btn').addEventListener('click', () => {
            if (resultsPanel.classList.contains('hidden')) return;
            switchResultsTab(activeResultsTab === 'graph' ? 'results' : 'graph');
        });

        // ─── ATTACK SURFACE TAB ──────────────────────────────────────────────────
        // Host-centric rollup of the infrastructure findings: each IP with its
        // hostnames, open ports and CVEs; web-posture grade per domain; discovered
        // subdomains. Built entirely from the results payload (inline-styled because
        // the precompiled tailwind build is purged of arbitrary classes).
        function renderAttackSurface(scanData) {
            const root = document.getElementById('surface-tab-content');
            if (!root) return;
            root.innerHTML = '';
            const results = (scanData && scanData.results) || [];
            const splitCsv = s => (s || '').split(',').map(x => x.trim()).filter(Boolean);

            const hosts = {};    // ip -> { names:Set, ports:Set, cves:Set, geo:'' }
            const posture = {};  // domain -> { grade, missing, present, https, server }
            const subs = new Set();
            const host = ip => hosts[ip] || (hosts[ip] = { names: new Set(), ports: new Set(), cves: new Set(), geo: '' });
            const dom = d => posture[d] || (posture[d] = {});

            results.forEach(r => {
                const m = r.metadata || {};
                if (m.ip) {
                    const h = host(m.ip);
                    splitCsv(m.ports).forEach(p => h.ports.add(p));
                    if (m.port) h.ports.add(String(m.port));
                    splitCsv(m.cves).forEach(c => h.cves.add(c));
                    splitCsv(m.hostnames).forEach(n => h.names.add(n));
                    if (m.subdomain) h.names.add(m.subdomain);
                    if (r.type === 'ip_geolocation') {
                        const bits = [m.country, m.org].filter(Boolean);
                        if (bits.length) h.geo = bits.join(' · ');
                    }
                }
                if ((r.type === 'subdomain' || r.type === 'subdomain_ip') && m.subdomain) subs.add(m.subdomain);
                if (m.domain && r.type === 'security_headers') {
                    const d = dom(m.domain); d.grade = m.grade; d.missing = m.missing; d.present = m.present; d.https = m.https;
                }
                if (m.domain && r.type === 'insecure_transport') dom(m.domain).https = 'no';
                if (m.domain && r.type === 'tech_stack' && m.server) dom(m.domain).server = m.server;
            });

            const ipList = Object.keys(hosts);
            const domList = Object.keys(posture);
            if (!ipList.length && !domList.length && !subs.size) {
                const empty = document.createElement('div');
                empty.style.cssText = 'text-align:center;padding:40px 16px;color:#64748b;border:1px dashed #334155;border-radius:12px;';
                empty.textContent = 'No infrastructure surface — scan a domain or IP to map exposed hosts, ports and CVEs.';
                root.appendChild(empty);
                return;
            }

            const card = () => { const c = document.createElement('div'); c.style.cssText = 'background:#111827;border:1px solid #1f2937;border-radius:12px;padding:14px;'; return c; };
            const chipWrap = () => { const w = document.createElement('div'); w.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;margin-top:4px;'; return w; };
            const gradeColor = g => ({ A:'#4ade80', B:'#a3e635', C:'#facc15', D:'#fb923c', E:'#f87171', F:'#ef4444' }[g] || '#94a3b8');
            function chip(text, kind) {
                const styles = {
                    base: 'background:#1f2937;border:1px solid #374151;color:#cbd5e1;',
                    port: 'background:#0c4a6e33;border:1px solid #0ea5e966;color:#7dd3fc;',
                    cve:  'background:#7f1d1d33;border:1px solid #ef444466;color:#fca5a5;'
                };
                const c = document.createElement('span');
                c.style.cssText = 'font-size:11px;padding:1px 8px;border-radius:4px;font-family:monospace;' + (styles[kind] || styles.base);
                c.textContent = text; return c;
            }
            function sectionTitle(t, sub) {
                const h = document.createElement('div'); h.style.cssText = 'display:flex;align-items:baseline;gap:8px;margin:6px 0 2px;';
                const s = document.createElement('span'); s.style.cssText = 'font-weight:700;color:#e2e8f0;font-size:14px;'; s.textContent = t; h.appendChild(s);
                if (sub) { const c = document.createElement('span'); c.style.cssText = 'color:#64748b;font-size:12px;'; c.textContent = sub; h.appendChild(c); }
                return h;
            }
            function labelled(text, color) {
                const l = document.createElement('div'); l.style.cssText = 'font-size:11px;color:' + (color || '#64748b') + ';margin-top:8px;'; l.textContent = text; return l;
            }

            if (ipList.length) {
                root.appendChild(sectionTitle('Exposed Hosts', ipList.length + (ipList.length === 1 ? ' host' : ' hosts')));
                ipList.sort().forEach(ip => {
                    const h = hosts[ip]; const c = card();
                    const head = document.createElement('div'); head.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;';
                    const ipEl = document.createElement('span'); ipEl.style.cssText = 'font-family:monospace;font-weight:700;color:#e2e8f0;'; ipEl.textContent = ip; head.appendChild(ipEl);
                    if (h.geo) { const g = document.createElement('span'); g.style.cssText = 'font-size:12px;color:#94a3b8;'; g.textContent = h.geo; head.appendChild(g); }
                    c.appendChild(head);
                    if (h.names.size) { const n = document.createElement('div'); n.style.cssText = 'font-size:12px;color:#94a3b8;margin-top:4px;word-break:break-all;'; n.textContent = Array.from(h.names).slice(0, 12).join(', '); c.appendChild(n); }
                    if (h.ports.size) { c.appendChild(labelled('OPEN PORTS')); const w = chipWrap(); Array.from(h.ports).sort((a, b) => (+a || 0) - (+b || 0)).forEach(p => w.appendChild(chip(p, 'port'))); c.appendChild(w); }
                    if (h.cves.size) { c.appendChild(labelled(h.cves.size + ' KNOWN CVE' + (h.cves.size === 1 ? '' : 's'), '#fca5a5')); const w = chipWrap(); Array.from(h.cves).sort().slice(0, 30).forEach(cv => w.appendChild(chip(cv, 'cve'))); c.appendChild(w); }
                    root.appendChild(c);
                });
            }

            if (domList.length) {
                root.appendChild(sectionTitle('Web Posture', null));
                domList.sort().forEach(d => {
                    const p = posture[d]; const c = card();
                    const head = document.createElement('div'); head.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap;';
                    if (p.grade) { const col = gradeColor(p.grade); const b = document.createElement('span'); b.style.cssText = 'font-weight:800;font-size:16px;width:28px;height:28px;display:inline-flex;align-items:center;justify-content:center;border-radius:6px;color:' + col + ';border:1px solid ' + col + '66;background:' + col + '1a;'; b.textContent = p.grade; head.appendChild(b); }
                    const de = document.createElement('span'); de.style.cssText = 'font-family:monospace;color:#e2e8f0;font-weight:700;word-break:break-all;'; de.textContent = d; head.appendChild(de);
                    if (p.https === 'no') { const w = document.createElement('span'); w.style.cssText = 'font-size:11px;padding:1px 8px;border-radius:4px;background:#7f1d1d33;border:1px solid #ef444466;color:#fca5a5;'; w.textContent = 'NO HTTPS'; head.appendChild(w); }
                    c.appendChild(head);
                    if (p.server) { const s = document.createElement('div'); s.style.cssText = 'font-size:12px;color:#94a3b8;margin-top:6px;'; s.textContent = 'Server: ' + p.server; c.appendChild(s); }
                    const missing = splitCsv(p.missing);
                    if (missing.length) { c.appendChild(labelled('MISSING HEADERS')); const w = chipWrap(); missing.forEach(mi => w.appendChild(chip(mi, 'cve'))); c.appendChild(w); }
                    root.appendChild(c);
                });
            }

            if (subs.size) {
                root.appendChild(sectionTitle('Subdomains', subs.size + ' discovered'));
                const c = card(); const w = chipWrap(); w.style.marginTop = '0';
                Array.from(subs).sort().slice(0, 60).forEach(s => w.appendChild(chip(s, 'base')));
                c.appendChild(w);
                if (subs.size > 60) { const more = document.createElement('div'); more.style.cssText = 'font-size:11px;color:#64748b;margin-top:6px;'; more.textContent = '+' + (subs.size - 60) + ' more'; c.appendChild(more); }
                root.appendChild(c);
            }
        }

        // A first visit is a scan, which needs neither d3 (92 KB compressed) nor
        // qrcode; each loads the first time its feature opens. A failed load is
        // forgotten, so opening the feature again retries it.
        const lazyScripts = new Map();
        function loadScriptOnce(src) {
            if (!lazyScripts.has(src)) {
                lazyScripts.set(src, new Promise((resolve, reject) => {
                    const script = document.createElement('script');
                    script.src = src;
                    script.addEventListener('load', resolve);
                    script.addEventListener('error', () => {
                        lazyScripts.delete(src);
                        script.remove();
                        reject(new Error('Could not load ' + src));
                    });
                    document.head.appendChild(script);
                }));
            }
            return lazyScripts.get(src);
        }

        async function renderD3Graph(scanData) {
            if (!window.d3) {
                try { await loadScriptOnce('/d3.min.js'); } catch { return; }
            }
            const results = (scanData && scanData.results) || [];
            const noData       = document.getElementById('graph-no-data');
            const canvasWrap   = document.getElementById('graph-canvas-wrapper');
            if (!results.length) {
                noData.classList.remove('hidden');
                canvasWrap.classList.add('hidden');
                canvasWrap.classList.remove('flex');
                return;
            }
            noData.classList.add('hidden');
            canvasWrap.classList.remove('hidden');
            canvasWrap.classList.add('flex');

            const svgEl = document.getElementById('social-graph-svg');
            const cont  = svgEl.parentElement;
            const W = cont.clientWidth || 700;
            const H = 520;
            const d3 = window.d3;
            const svg = d3.select(svgEl);
            svg.selectAll('*').remove();
            if (graphSimulation) { graphSimulation.stop(); graphSimulation = null; }

            const targetLabel = scanData.input || 'Target';

            // Build nodes: target + sources + findings
            const nodes = [{ id: '__target__', label: targetLabel, ntype: 'target', rawData: targetLabel }];
            const sourceNames = new Set();
            results.forEach(r => sourceNames.add(r.source || 'Unknown'));
            sourceNames.forEach(src => nodes.push({
                id: '__src__' + src, label: src, ntype: 'source', sourceId: src, rawData: src
            }));
            results.forEach((r, i) => {
                const rd = r.rawData || '';
                nodes.push({
                    id: '__f__' + i,
                    label: rd.length > 40 ? rd.slice(0, 39) + '…' : rd,
                    ntype: 'finding',
                    confidence: r.confidenceScore || 0,
                    sourceId: r.source || 'Unknown',
                    rawData: rd,
                    fullResult: r
                });
            });

            // Build links
            const links = [];
            sourceNames.forEach(src => links.push({ source: '__target__', target: '__src__' + src }));
            results.forEach((r, i) => links.push({ source: '__src__' + (r.source || 'Unknown'), target: '__f__' + i }));

            const nodeColor = d => {
                if (d.ntype === 'target') return '#10b981';
                if (d.ntype === 'source') return '#3b82f6';
                const c = d.confidence || 0;
                return c >= 0.8 ? '#10b981' : c >= 0.5 ? '#f59e0b' : '#ef4444';
            };
            const nodeR = d => d.ntype === 'target' ? 22 : d.ntype === 'source' ? 13 : 6;

            // Background rect
            svg.append('rect').attr('width', W).attr('height', H).attr('fill', '#0f172a');
            const g = svg.append('g');

            // Zoom + pan
            const zoom = d3.zoom().scaleExtent([0.1, 6])
                .on('zoom', ev => g.attr('transform', ev.transform));
            svg.call(zoom).on('dblclick.zoom', null);

            const tooltip = document.getElementById('graph-tooltip');

            // Links
            const linkEl = g.append('g').selectAll('line').data(links).enter().append('line')
                .attr('stroke', d => {
                    const sNode = nodes.find(n => n.id === (typeof d.source === 'object' ? d.source.id : d.source));
                    return (sNode && sNode.ntype === 'target') ? '#1e3a5f' : '#1e293b';
                })
                .attr('stroke-width', 1).attr('stroke-opacity', 0.8);

            // Node groups
            const nodeEl = g.append('g').selectAll('g').data(nodes).enter().append('g')
                .attr('cursor', 'pointer')
                .call(d3.drag()
                    .on('start', (ev, d) => { if (!ev.active) graphSimulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
                    .on('drag',  (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
                    .on('end',   (ev, d) => { if (!ev.active) graphSimulation.alphaTarget(0); d.fx = null; d.fy = null; })
                )
                .on('mouseover', (ev, d) => {
                    if (d.ntype === 'finding' && d.rawData) {
                        tooltip.textContent = d.rawData;
                        tooltip.style.display = 'block';
                        const r = svgEl.getBoundingClientRect();
                        tooltip.style.left = (ev.clientX - r.left + 12) + 'px';
                        tooltip.style.top  = (ev.clientY - r.top  -  8) + 'px';
                    }
                })
                .on('mousemove', (ev, d) => {
                    if (d.ntype === 'finding') {
                        const r = svgEl.getBoundingClientRect();
                        tooltip.style.left = (ev.clientX - r.left + 12) + 'px';
                        tooltip.style.top  = (ev.clientY - r.top  -  8) + 'px';
                    }
                })
                .on('mouseout', () => { tooltip.style.display = 'none'; })
                .on('click', (ev, d) => { ev.stopPropagation(); showNodeDetail(d); });

            // Circles
            nodeEl.append('circle')
                .attr('r', d => nodeR(d))
                .attr('fill', d => d.ntype === 'target' ? '#0b1a2e' : '#0f172a')
                .attr('stroke', d => nodeColor(d))
                .attr('stroke-width', d => d.ntype === 'target' ? 3 : d.ntype === 'source' ? 2 : 1.5);

            // Target glow ring
            nodeEl.filter(d => d.ntype === 'target').append('circle')
                .attr('r', 30).attr('fill', '#10b981').attr('fill-opacity', 0.07)
                .attr('pointer-events', 'none');

            // Labels
            nodeEl.append('text')
                .attr('text-anchor', 'middle')
                .attr('dy', d => d.ntype === 'target' ? 5 : d.ntype === 'source' ? -19 : -10)
                .attr('fill', d => d.ntype === 'target' ? '#10b981' : d.ntype === 'source' ? '#93c5fd' : '#475569')
                .attr('font-size', d => d.ntype === 'target' ? '10px' : d.ntype === 'source' ? '9px' : '8px')
                .attr('font-family', 'monospace')
                .attr('pointer-events', 'none')
                .text(d => {
                    const max = d.ntype === 'target' ? 16 : d.ntype === 'source' ? 14 : 22;
                    return d.label.length > max ? d.label.slice(0, max - 1) + '…' : d.label;
                });

            // Force simulation
            graphSimulation = d3.forceSimulation(nodes)
                .force('link', d3.forceLink(links).id(d => d.id)
                    .distance(d => (d.source.ntype === 'target' ? 140 : 80)))
                .force('charge',    d3.forceManyBody().strength(d => d.ntype === 'finding' ? -40 : -200))
                .force('center',    d3.forceCenter(W / 2, H / 2))
                .force('collision', d3.forceCollide(d => nodeR(d) + 10))
                .on('tick', () => {
                    linkEl
                        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
                    nodeEl.attr('transform', d => `translate(${d.x},${d.y})`);
                });

            // Download as PNG
            document.getElementById('download-graph-btn').onclick = () => {
                const serializer = new XMLSerializer();
                const src = serializer.serializeToString(svgEl);
                const canvas = document.createElement('canvas');
                canvas.width = W; canvas.height = H;
                const ctx = canvas.getContext('2d');
                const img = new Image();
                img.onload = () => {
                    ctx.fillStyle = '#0f172a';
                    ctx.fillRect(0, 0, W, H);
                    ctx.drawImage(img, 0, 0);
                    const a = document.createElement('a');
                    a.download = 'graph-' + (scanData.input || 'export') + '.png';
                    a.href = canvas.toDataURL('image/png');
                    document.body.appendChild(a); a.click(); document.body.removeChild(a);
                };
                img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(src)));
            };

            // Click on SVG background closes detail panel
            svg.on('click', () => {
                document.getElementById('graph-detail-panel').classList.add('hidden');
            });
        }

        function showNodeDetail(d) {
            const panel = document.getElementById('graph-detail-panel');
            const title = document.getElementById('graph-detail-title');
            const body  = document.getElementById('graph-detail-body');
            panel.classList.remove('hidden');
            if (d.ntype === 'target') {
                title.textContent = 'TARGET';
                body.textContent  = d.rawData;
            } else if (d.ntype === 'source') {
                title.textContent = 'SOURCE: ' + d.label;
                const cnt = lastScanData && lastScanData.results
                    ? lastScanData.results.filter(r => r.source === d.sourceId).length : 0;
                body.textContent = cnt + ' finding' + (cnt !== 1 ? 's' : '') + ' from this source.';
            } else {
                const r = d.fullResult || {};
                title.textContent = (d.sourceId || '') + ' · Finding';
                const lines = ['Confidence: ' + ((d.confidence || 0) * 100).toFixed(0) + '%'];
                if (r.type) lines.push('Type: ' + r.type);
                lines.push('', d.rawData || '');
                body.textContent = lines.join('\n');
            }
        }

        document.getElementById('graph-detail-close').addEventListener('click', () => {
            document.getElementById('graph-detail-panel').classList.add('hidden');
        });

        // ─── AUTH ─────────────────────────────────────────────────────────────────
        let currentUser = null;

        async function loadAuthState() {
            try {
                const res = await fetch('/api/auth/me', { credentials: 'include' });
                if (res.ok) {
                    currentUser = await res.json();
                    document.getElementById('auth-logged-out').classList.add('hidden');
                    document.getElementById('auth-logged-in').classList.remove('hidden');
                    document.getElementById('auth-username-text').textContent = currentUser.username;
                    if (currentUser.isAdmin) {
                        document.getElementById('auth-admin-badge').classList.remove('hidden');
                        document.getElementById('admin-scans-btn').classList.remove('hidden');
                    }
                    // Show scheduled-scan option in search form.
                    document.getElementById('repeat-section').classList.remove('hidden');
                    // Pre-fill webhook URL in settings.
                    if (currentUser.webhookURL) {
                        document.getElementById('webhook-url-input').value = currentUser.webhookURL;
                    }
                    // Load user tags.
                    loadUserTags();
                    // Start notification polling.
                    loadNotifications();
                    if (!window._notifInterval) {
                        window._notifInterval = setInterval(loadNotifications, 30000);
                    }
                    // Account security UI (2FA state + email-verification banner).
                    refreshTwoFactorUI();
                    const banner = document.getElementById('email-verify-banner');
                    if (currentUser.emailVerified === false) {
                        banner.classList.remove('hidden'); banner.classList.add('flex');
                    } else {
                        banner.classList.add('hidden'); banner.classList.remove('flex');
                    }
                } else {
                    currentUser = null;
                    document.getElementById('auth-logged-out').classList.remove('hidden');
                    document.getElementById('auth-logged-in').classList.add('hidden');
                    document.getElementById('email-verify-banner').classList.add('hidden');
                }
            } catch (e) {
                document.getElementById('auth-logged-out').classList.remove('hidden');
            }
        }

        // ─── Account security: 2FA + email verification ───────────────────────────
        function twofaMsg(text, ok) {
            const el = document.getElementById('twofa-msg');
            el.textContent = text; el.classList.remove('hidden');
            el.className = 'text-[10px] mt-1 ' + (ok ? 'text-brand-400' : 'text-red-400');
        }
        function showTwofaBlock(id) {
            ['twofa-enable-block','twofa-setup-block','twofa-recovery-block','twofa-disable-block']
                .forEach(b => document.getElementById(b).classList.add('hidden'));
            if (id) document.getElementById(id).classList.remove('hidden');
        }
        function refreshTwoFactorUI() {
            if (!currentUser) return;
            const status = document.getElementById('twofa-status');
            if (currentUser.twoFactorEnabled) {
                status.innerHTML = '<span class="text-brand-400">● Enabled</span> — your account is protected by 2FA.';
                showTwofaBlock('twofa-disable-block');
            } else {
                status.innerHTML = '<span class="text-slate-500">○ Disabled</span> — add a second factor for stronger protection.';
                showTwofaBlock('twofa-enable-block');
            }
            document.getElementById('twofa-msg').classList.add('hidden');
        }
        document.getElementById('twofa-start-btn')?.addEventListener('click', async () => {
            try {
                const res = await fetch('/api/auth/2fa/setup', { method: 'POST', credentials: 'include' });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) return twofaMsg(data.reason || 'Setup failed.', false);
                document.getElementById('twofa-secret').textContent = data.secret;
                document.getElementById('twofa-uri').textContent = data.otpauthURI;
                document.getElementById('twofa-uri-link').href = data.otpauthURI;
                // Render a QR from the otpauth URI using the first-party qrcode.js
                // (fully offline — no network). White padding provides the quiet zone.
                try {
                    await loadScriptOnce('/qrcode.js');
                    const qr = qrcode(0, 'M');
                    qr.addData(data.otpauthURI);
                    qr.make();
                    document.getElementById('twofa-qr').innerHTML = qr.createSvgTag(4, 8);
                } catch (e) {
                    document.getElementById('twofa-qr').style.display = 'none';
                }
                showTwofaBlock('twofa-setup-block');
                document.getElementById('twofa-confirm-code').focus();
            } catch { twofaMsg('Network error.', false); }
        });
        document.getElementById('twofa-cancel-btn')?.addEventListener('click', refreshTwoFactorUI);
        document.getElementById('twofa-confirm-btn')?.addEventListener('click', async () => {
            const code = document.getElementById('twofa-confirm-code').value.trim();
            try {
                const res = await fetch('/api/auth/2fa/enable', {
                    method: 'POST', credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code })
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) return twofaMsg(data.reason || 'Incorrect code.', false);
                document.getElementById('twofa-recovery-codes').textContent = (data.recoveryCodes || []).join('\n');
                showTwofaBlock('twofa-recovery-block');
                if (currentUser) currentUser.twoFactorEnabled = true;
            } catch { twofaMsg('Network error.', false); }
        });
        document.getElementById('twofa-recovery-done-btn')?.addEventListener('click', refreshTwoFactorUI);
        document.getElementById('twofa-disable-btn')?.addEventListener('click', async () => {
            const password = document.getElementById('twofa-disable-pass').value;
            const code = document.getElementById('twofa-disable-code').value.trim();
            if (!password || !code) return twofaMsg('Enter your password and a current second-factor code.', false);
            try {
                const res = await fetch('/api/auth/2fa/disable', {
                    method: 'POST', credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password, code })
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) return twofaMsg(data.reason || 'Failed.', false);
                document.getElementById('twofa-disable-pass').value = '';
                document.getElementById('twofa-disable-code').value = '';
                if (currentUser) currentUser.twoFactorEnabled = false;
                refreshTwoFactorUI();
            } catch { twofaMsg('Network error.', false); }
        });
        document.getElementById('resend-verify-btn')?.addEventListener('click', async () => {
            const msg = document.getElementById('resend-verify-msg');
            try {
                const res = await fetch('/api/auth/resend-verification', { method: 'POST', credentials: 'include' });
                msg.textContent = res.ok ? '✓ Sent — check your inbox.' : 'Could not send.';
            } catch { msg.textContent = 'Network error.'; }
            msg.classList.remove('hidden');
        });

        document.getElementById('logout-btn').addEventListener('click', async () => {
            await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
            currentUser = null;
            userTags = [];
            clearInterval(window._notifInterval);
            window._notifInterval = null;
            document.getElementById('auth-logged-out').classList.remove('hidden');
            document.getElementById('auth-logged-in').classList.add('hidden');
            document.getElementById('my-scans-panel').classList.add('hidden');
            document.getElementById('settings-panel').classList.add('hidden');
            document.getElementById('repeat-section').classList.add('hidden');
        });

        document.getElementById('my-scans-toggle-btn').addEventListener('click', async () => {
            const panel = document.getElementById('my-scans-panel');
            if (!panel.classList.contains('hidden')) {
                panel.classList.add('hidden');
                return;
            }
            panel.classList.remove('hidden');
            myScansCurrentURL = '/api/my-scans';
            myScansCurrentPage = 1;
            await loadMyScans(myScansCurrentURL, 'MY SCANS');
            loadScheduledScans();
        });

        document.getElementById('close-my-scans-btn').addEventListener('click', () => {
            document.getElementById('my-scans-panel').classList.add('hidden');
        });

        document.getElementById('settings-toggle-btn').addEventListener('click', () => {
            const panel = document.getElementById('settings-panel');
            const wasHidden = panel.classList.contains('hidden');
            panel.classList.toggle('hidden');
            if (wasHidden && currentUser) {
                loadAPIKeys();
                const retSel = document.getElementById('retention-select');
                if (retSel && currentUser.retentionDays) {
                    retSel.value = String(currentUser.retentionDays);
                }
                if (currentUser) {
                    // Notification credentials are never returned by the server for security.
                    // Show "configured" placeholder when a value is already saved.
                    const discordInput = document.getElementById('discord-webhook-input');
                    const telegramTokenInput = document.getElementById('telegram-token-input');
                    const telegramChatInput = document.getElementById('telegram-chatid-input');
                    const slackInput = document.getElementById('slack-webhook-input');
                    if (discordInput) discordInput.placeholder = currentUser.discordConfigured ? '(configured — enter new value to change)' : 'https://discord.com/api/webhooks/...';
                    if (telegramTokenInput) telegramTokenInput.placeholder = currentUser.telegramConfigured ? '(configured — enter new value to change)' : 'bot token';
                    if (telegramChatInput) telegramChatInput.value = currentUser.telegramChatID || '';
                    if (slackInput) slackInput.placeholder = currentUser.slackConfigured ? '(configured — enter new value to change)' : 'https://hooks.slack.com/services/...';
                }
            }
        });

        document.getElementById('close-settings-btn').addEventListener('click', () => {
            document.getElementById('settings-panel').classList.add('hidden');
        });

        document.getElementById('save-webhook-btn').addEventListener('click', async () => {
            const url = document.getElementById('webhook-url-input').value.trim();
            const msg = document.getElementById('webhook-save-msg');
            try {
                const res = await fetch('/api/auth/webhook', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ webhookURL: url || null })
                });
                if (res.ok) {
                    msg.textContent = '✓ Saved';
                    msg.className = 'text-[10px] mt-1 text-green-400';
                } else {
                    msg.textContent = '✗ Failed';
                    msg.className = 'text-[10px] mt-1 text-red-400';
                }
            } catch {
                msg.textContent = '✗ Error';
                msg.className = 'text-[10px] mt-1 text-red-400';
            }
            msg.classList.remove('hidden');
            setTimeout(() => msg.classList.add('hidden'), 3000);
        });

        // ─── D3: NOTIFICATION CHANNEL SETTINGS ───────────────────────────────────
        document.getElementById('save-notification-settings-btn').addEventListener('click', async () => {
            const btn = document.getElementById('save-notification-settings-btn');
            const msg = document.getElementById('notif-settings-msg');
            btn.textContent = 'Saving…';
            btn.disabled = true;
            try {
                const body = {
                    discordWebhookURL: document.getElementById('discord-webhook-input').value.trim() || null,
                    telegramBotToken:  document.getElementById('telegram-token-input').value.trim() || null,
                    telegramChatID:    document.getElementById('telegram-chatid-input').value.trim() || null,
                    slackWebhookURL:   document.getElementById('slack-webhook-input').value.trim() || null,
                };
                const resp = await fetch('/api/auth/settings', {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify(body)
                });
                if (!resp.ok) throw new Error('HTTP ' + resp.status);
                const user = await resp.json();
                currentUser = user;
                msg.textContent = '✓ Saved';
                msg.className = 'text-[10px] mt-1 text-green-400';
                msg.classList.remove('hidden');
                setTimeout(() => msg.classList.add('hidden'), 2500);
            } catch(err) {
                msg.textContent = '✗ Failed: ' + err.message;
                msg.className = 'text-[10px] mt-1 text-red-400';
                msg.classList.remove('hidden');
            } finally {
                btn.textContent = 'Save Channels';
                btn.disabled = false;
            }
        });
        document.getElementById('test-notification-btn').addEventListener('click', async () => {
            const btn = document.getElementById('test-notification-btn');
            btn.textContent = 'Sending…';
            btn.disabled = true;
            try {
                const resp = await fetch('/api/auth/notifications/test', {
                    method: 'POST',
                    credentials: 'include'
                });
                const msg = document.getElementById('notif-settings-msg');
                const result = await resp.json().catch(() => null);
                if (!result) throw new Error('Invalid server response');
                const succeeded = result.succeeded || [];
                const failed = result.failed || [];
                const skipped = result.skipped || [];
                const parts = [];
                if (succeeded.length) parts.push('delivered: ' + succeeded.join(', '));
                if (failed.length) parts.push('failed: ' + failed.join(', '));
                if (skipped.length) parts.push('not configured: ' + skipped.join(', '));
                msg.textContent = (failed.length ? '⚠ ' : succeeded.length ? '✓ ' : '✗ ') + parts.join(' · ');
                msg.className = 'text-[10px] mt-1 ' + (failed.length ? 'text-amber-400' : succeeded.length ? 'text-green-400' : 'text-red-400');
                msg.classList.remove('hidden');
                setTimeout(() => msg.classList.add('hidden'), 2500);
            } catch(err) {
                alert('Test failed: ' + err.message);
            } finally {
                btn.textContent = 'Test';
                btn.disabled = false;
            }
        });

        document.getElementById('create-tag-btn').addEventListener('click', async () => {
            const name = document.getElementById('new-tag-name').value.trim();
            const colour = document.getElementById('new-tag-colour').value;
            if (!name) return;
            const res = await fetch('/api/tags', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ name, colour })
            });
            if (res.ok) {
                document.getElementById('new-tag-name').value = '';
                loadUserTags();
            }
        });

        document.getElementById('refresh-scheduled-btn').addEventListener('click', loadScheduledScans);

        document.getElementById('admin-scans-btn').addEventListener('click', async () => {
            myScansCurrentURL = '/api/admin/scans';
            myScansCurrentPage = 1;
            await loadMyScans(myScansCurrentURL, 'ALL SCANS (ADMIN)');
        });

        let myScansCurrentURL = '/api/my-scans';
        let myScansCurrentPage = 1;
        let myScansCurrentPages = 1;
        let myScansCurrentTitle = 'MY SCANS';
        let userTags = [];
        let scanTagsData = {};

        document.getElementById('my-scans-search').addEventListener('input', () => {
            myScansCurrentPage = 1;
            loadMyScans(myScansCurrentURL, myScansCurrentTitle);
        });

        document.getElementById('tag-filter').addEventListener('change', () => {
            myScansCurrentPage = 1;
            loadMyScans(myScansCurrentURL, myScansCurrentTitle);
        });

        document.getElementById('my-scans-prev').addEventListener('click', () => {
            if (myScansCurrentPage > 1) {
                myScansCurrentPage--;
                loadMyScans(myScansCurrentURL, myScansCurrentTitle);
            }
        });

        document.getElementById('my-scans-next').addEventListener('click', () => {
            if (myScansCurrentPage < myScansCurrentPages) {
                myScansCurrentPage++;
                loadMyScans(myScansCurrentURL, myScansCurrentTitle);
            }
        });

        async function loadMyScans(url, title) {
            myScansCurrentURL = url;
            myScansCurrentTitle = title;
            document.getElementById('my-scans-title').textContent = title;
            const list = document.getElementById('my-scans-list');
            list.innerHTML = '<p class="text-slate-500 text-xs">Loading...</p>';
            const q = document.getElementById('my-scans-search').value.trim();
            const tagFilter = document.getElementById('tag-filter').value;
            let fetchURL = url + '?page=' + myScansCurrentPage + '&limit=20' + (q ? '&q=' + encodeURIComponent(q) : '');
            // Apply client-side tag filter by fetching tags per scan after render.
            try {
                const res = await fetch(fetchURL, { credentials: 'include' });
                if (!res.ok) { list.innerHTML = '<p class="text-red-400 text-xs">Failed to load.</p>'; return; }
                const data = await res.json();
                let items = data.items || [];

                // Apply tag filter client-side (only for own scans).
                if (tagFilter && url === '/api/my-scans') {
                    const taggedScanIDs = new Set();
                    try {
                        const tRes = await fetch('/api/tags/' + encodeURIComponent(tagFilter) + '/scans', { credentials: 'include' });
                        if (tRes.ok) { const ids = await tRes.json(); ids.forEach(id => taggedScanIDs.add(id)); }
                    } catch {}
                    items = items.filter(s => taggedScanIDs.has(s.scanID));
                }

                myScansCurrentPages = data.pages || 1;

                // Update pagination
                const paginationEl = document.getElementById('my-scans-pagination');
                const pageInfo = document.getElementById('my-scans-page-info');
                const prevBtn = document.getElementById('my-scans-prev');
                const nextBtn = document.getElementById('my-scans-next');
                if (data.pages > 1 || data.total > 0) {
                    paginationEl.classList.remove('hidden');
                    pageInfo.textContent = 'Page ' + myScansCurrentPage + ' of ' + myScansCurrentPages + ' (' + data.total + ' total)';
                    prevBtn.disabled = myScansCurrentPage <= 1;
                    nextBtn.disabled = myScansCurrentPage >= myScansCurrentPages;
                } else {
                    paginationEl.classList.add('hidden');
                }

                if (!items.length) { list.innerHTML = '<p class="text-slate-500 text-xs">No scans yet.</p>'; return; }
                list.innerHTML = '';
                items.forEach(s => {
                    const date = s.createdAt ? new Date(s.createdAt * 1000).toLocaleString() : '—';
                    const statusColor = s.status === 'completed' ? 'text-green-400' : s.status === 'failed' ? 'text-red-400' : 'text-yellow-400';
                    const riskColors = { Low: 'text-green-400 border-green-800', Medium: 'text-yellow-400 border-yellow-800', High: 'text-orange-400 border-orange-800', Critical: 'text-red-500 border-red-800' };
                    const riskCls = (s.status === 'completed' && s.riskLevel) ? (riskColors[s.riskLevel] || 'text-slate-400 border-slate-700') : null;
                    const wrapper = document.createElement('div');
                    wrapper.id = 'scan-card-' + s.scanID;
                    wrapper.className = 'bg-dark-900 rounded border border-dark-700';
                    const div = document.createElement('div');
                    div.className = 'flex flex-wrap sm:flex-nowrap items-center justify-between px-3 py-2 gap-2';
                    const inputEl = document.createElement('span');
                    inputEl.className = 'text-slate-300 font-mono text-xs flex-grow truncate';
                    inputEl.textContent = s.input || '';
                    const statusEl = document.createElement('span');
                    statusEl.className = 'text-[10px] ' + statusColor + ' uppercase flex-shrink-0';
                    statusEl.textContent = s.status;
                    const hitsEl = document.createElement('span');
                    hitsEl.className = 'text-[10px] text-brand-500 flex-shrink-0';
                    hitsEl.textContent = (s.resultCount || 0) + ' hit' + (s.resultCount !== 1 ? 's' : '');
                    const dateEl = document.createElement('span');
                    dateEl.className = 'text-[10px] text-slate-600 flex-shrink-0';
                    dateEl.textContent = date;
                    div.appendChild(inputEl);
                    if (riskCls) {
                        const riskEl = document.createElement('span');
                        riskEl.className = `text-[10px] border rounded px-1 flex-shrink-0 ${riskCls}`;
                        riskEl.textContent = s.riskLevel + ' ' + s.riskScore;
                        div.appendChild(riskEl);
                    }
                    div.appendChild(statusEl);
                    div.appendChild(hitsEl);
                    div.appendChild(dateEl);
                    if (s.scanID) {
                        const viewBtn = document.createElement('button');
                        viewBtn.className = 'text-[10px] text-brand-400 hover:text-brand-300 flex-shrink-0 underline';
                        viewBtn.textContent = 'VIEW';
                        viewBtn.addEventListener('click', () => loadScanByID(s.scanID));
                        div.appendChild(viewBtn);
                        if (s.status === 'completed') {
                            const pdfBtn = document.createElement('a');
                            pdfBtn.className = 'text-[10px] text-slate-400 hover:text-slate-200 flex-shrink-0 underline';
                            pdfBtn.textContent = 'PDF';
                            pdfBtn.href = '/api/report/' + s.scanID;
                            pdfBtn.target = '_blank';
                            div.appendChild(pdfBtn);
                            const jsonBtn = document.createElement('a');
                            jsonBtn.className = 'text-[10px] text-slate-400 hover:text-slate-200 flex-shrink-0 underline';
                            jsonBtn.textContent = 'JSON';
                            jsonBtn.href = '/api/export/' + s.scanID;
                            jsonBtn.download = '';
                            div.appendChild(jsonBtn);
                            if (currentUser) {
                                const tagBtn = document.createElement('button');
                                tagBtn.className = 'text-[10px] text-slate-400 hover:text-brand-400 flex-shrink-0';
                                tagBtn.textContent = '🏷';
                                tagBtn.title = 'Manage tags';
                                tagBtn.addEventListener('click', () => openTagDropdown(s.scanID, tagBtn));
                                div.appendChild(tagBtn);

                                // Compare button for diff
                                const cmpBtn = document.createElement('button');
                                cmpBtn.className = 'text-[10px] flex-shrink-0 px-1.5 py-0.5 rounded border transition-colors';
                                const updateCmpBtn = () => {
                                    if (diffSelectA && diffSelectA.scanID === s.scanID) {
                                        cmpBtn.textContent = '✕ A';
                                        cmpBtn.className = 'text-[10px] flex-shrink-0 px-1.5 py-0.5 rounded border transition-colors border-brand-500/60 text-brand-400';
                                    } else if (diffSelectA) {
                                        cmpBtn.textContent = 'vs B';
                                        cmpBtn.className = 'text-[10px] flex-shrink-0 px-1.5 py-0.5 rounded border transition-colors border-green-600/60 text-green-400';
                                    } else {
                                        cmpBtn.textContent = '⇄';
                                        cmpBtn.className = 'text-[10px] flex-shrink-0 px-1.5 py-0.5 rounded border transition-colors border-dark-600 text-slate-500 hover:text-brand-400 hover:border-brand-500/50';
                                    }
                                };
                                updateCmpBtn();
                                cmpBtn.title = 'Compare (diff) with another scan';
                                cmpBtn.addEventListener('click', () => {
                                    if (diffSelectA && diffSelectA.scanID === s.scanID) {
                                        diffSelectA = null;
                                        // Reset all compare buttons
                                        document.querySelectorAll('[data-cmp-btn]').forEach(b => {
                                            b.textContent = '⇄';
                                            b.className = 'text-[10px] flex-shrink-0 px-1.5 py-0.5 rounded border transition-colors border-dark-600 text-slate-500 hover:text-brand-400 hover:border-brand-500/50';
                                        });
                                    } else if (diffSelectA) {
                                        openDiffModal(diffSelectA.scanID, s.scanID);
                                        diffSelectA = null;
                                        document.querySelectorAll('[data-cmp-btn]').forEach(b => {
                                            b.textContent = '⇄';
                                            b.className = 'text-[10px] flex-shrink-0 px-1.5 py-0.5 rounded border transition-colors border-dark-600 text-slate-500 hover:text-brand-400 hover:border-brand-500/50';
                                        });
                                    } else {
                                        diffSelectA = { scanID: s.scanID };
                                        document.querySelectorAll('[data-cmp-btn]').forEach(b => updateCmpBtn());
                                        updateCmpBtn();
                                    }
                                });
                                cmpBtn.dataset.cmpBtn = s.scanID;
                                div.appendChild(cmpBtn);
                            }
                        }
                    }
                    wrapper.appendChild(div);
                    // Tag display row
                    const tagContainer = document.createElement('div');
                    tagContainer.id = 'tags-' + s.scanID;
                    tagContainer.className = 'tag-container flex gap-1 flex-wrap px-3 pb-2';
                    wrapper.appendChild(tagContainer);
                    list.appendChild(wrapper);
                    // Load tags for this scan.
                    if (s.scanID && currentUser) loadScanTags(s.scanID);
                });
            } catch(e) {
                list.innerHTML = '<p class="text-red-400 text-xs">Error loading scans.</p>';
            }
        }

        // ─── TAGS ─────────────────────────────────────────────────────────────────
        async function loadUserTags() {
            try {
                const res = await fetch('/api/tags', { credentials: 'include' });
                if (!res.ok) return;
                userTags = await res.json();
                const sel = document.getElementById('tag-filter');
                sel.innerHTML = '<option value="">All tags</option>';
                userTags.forEach(t => {
                    const opt = document.createElement('option');
                    opt.value = t.id;
                    opt.textContent = t.name;
                    sel.appendChild(opt);
                });
                renderTagsList();
            } catch {}
        }

        function renderTagsList() {
            const container = document.getElementById('tags-list');
            if (!container) return;
            container.innerHTML = '';
            if (!userTags.length) { container.textContent = 'No tags yet.'; return; }
            userTags.forEach(t => {
                const chip = document.createElement('span');
                chip.className = 'flex items-center gap-1 px-2 py-0.5 rounded text-[10px] text-white';
                chip.style.background = t.colour;
                chip.textContent = t.name;
                const del = document.createElement('button');
                del.textContent = '×';
                del.className = 'ml-1 opacity-70 hover:opacity-100';
                del.addEventListener('click', async () => {
                    await fetch('/api/tags/' + t.id, { method: 'DELETE', credentials: 'include' });
                    loadUserTags();
                });
                chip.appendChild(del);
                container.appendChild(chip);
            });
        }

        async function loadScanTags(scanID) {
            try {
                const res = await fetch('/api/scans/' + scanID + '/tags', { credentials: 'include' });
                if (!res.ok) return;
                const tags = await res.json();
                scanTagsData[scanID] = tags;
                renderScanTags(scanID);
            } catch {}
        }

        function renderScanTags(scanID) {
            const container = document.getElementById('tags-' + scanID);
            if (!container) return;
            container.innerHTML = '';
            (scanTagsData[scanID] || []).forEach(t => {
                const chip = document.createElement('span');
                chip.className = 'px-1.5 py-0.5 rounded text-[9px] text-white';
                chip.style.background = t.colour;
                chip.textContent = t.name;
                container.appendChild(chip);
            });
        }

        function openTagDropdown(scanID, anchor) {
            closeAllTagDropdowns();
            const dropdown = document.createElement('div');
            dropdown.id = 'tag-dropdown';
            dropdown.className = 'absolute z-50 bg-dark-800 border border-dark-700 rounded shadow-xl p-2 min-w-[140px] text-xs';
            dropdown.style.cssText = 'position:fixed;';
            const rect = anchor.getBoundingClientRect();
            dropdown.style.top = (rect.bottom + 4) + 'px';
            dropdown.style.left = rect.left + 'px';
            const applied = new Set((scanTagsData[scanID] || []).map(t => t.id));
            if (!userTags.length) {
                dropdown.innerHTML = '<p class="text-slate-500">No tags. Create in Settings.</p>';
            } else {
                userTags.forEach(t => {
                    const row = document.createElement('div');
                    row.className = 'flex items-center gap-1.5 cursor-pointer hover:bg-dark-700 rounded px-1 py-0.5 select-none';
                    const dot = document.createElement('span');
                    dot.className = 'w-2 h-2 rounded-full flex-shrink-0';
                    dot.style.background = t.colour;
                    const lbl = document.createElement('span');
                    lbl.textContent = t.name;
                    lbl.className = applied.has(t.id) ? 'text-white font-bold' : 'text-slate-300';
                    row.appendChild(dot);
                    row.appendChild(lbl);
                    if (applied.has(t.id)) {
                        const check = document.createElement('span');
                        check.textContent = '✓';
                        check.className = 'ml-auto text-green-400';
                        row.appendChild(check);
                    }
                    row.addEventListener('click', async () => {
                        if (applied.has(t.id)) {
                            await fetch('/api/scans/' + scanID + '/tags/' + t.id, { method: 'DELETE', credentials: 'include' });
                        } else {
                            await fetch('/api/scans/' + scanID + '/tags/' + t.id, { method: 'POST', credentials: 'include' });
                        }
                        await loadScanTags(scanID);
                        closeAllTagDropdowns();
                    });
                    dropdown.appendChild(row);
                });
            }
            document.body.appendChild(dropdown);
            setTimeout(() => document.addEventListener('click', closeAllTagDropdowns, { once: true }), 0);
        }

        function closeAllTagDropdowns() {
            const d = document.getElementById('tag-dropdown');
            if (d) d.remove();
        }

        // ─── SCHEDULED SCANS ──────────────────────────────────────────────────────
        async function loadScheduledScans() {
            const el = document.getElementById('scheduled-scans-list');
            if (!el || !currentUser) return;
            el.innerHTML = '<span class="text-slate-600">Loading…</span>';
            try {
                const res = await fetch('/api/scheduled-scans', { credentials: 'include' });
                if (!res.ok) { el.textContent = 'Failed to load.'; return; }
                const items = await res.json();
                if (!items.length) { el.textContent = 'No scheduled scans.'; return; }
                el.innerHTML = '';
                items.forEach(ss => {
                    const row = document.createElement('div');
                    row.className = 'flex items-center gap-2 bg-dark-900 rounded px-2 py-1 border border-dark-700 text-[10px]';
                    const input = document.createElement('span');
                    input.className = 'font-mono text-slate-300 flex-grow truncate';
                    input.textContent = ss.input;
                    const intv = document.createElement('span');
                    intv.className = 'text-slate-500';
                    intv.textContent = ss.interval;
                    const toggle = document.createElement('button');
                    toggle.className = ss.isActive ? 'text-green-400 hover:text-yellow-400' : 'text-slate-600 hover:text-green-400';
                    toggle.textContent = ss.isActive ? '● ON' : '○ OFF';
                    toggle.addEventListener('click', async () => {
                        await fetch('/api/scheduled-scans/' + ss.id + '/toggle', { method: 'PATCH', credentials: 'include' });
                        loadScheduledScans();
                    });
                    const del = document.createElement('button');
                    del.className = 'text-slate-600 hover:text-red-400';
                    del.textContent = '✕';
                    del.addEventListener('click', async () => {
                        await fetch('/api/scheduled-scans/' + ss.id, { method: 'DELETE', credentials: 'include' });
                        loadScheduledScans();
                    });
                    row.appendChild(input);
                    row.appendChild(intv);
                    row.appendChild(toggle);
                    row.appendChild(del);
                    el.appendChild(row);
                });
            } catch { el.textContent = 'Error loading.'; }
        }

        // ─── URL AUTO-LOAD ────────────────────────────────────────────────────────
        // Validate UUID format client-side to avoid pointless API calls.
        (function checkURLScan() {
            const params = new URLSearchParams(location.search);
            const scanID = params.get('scan');
            if (scanID && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(scanID)) {
                loadScanByID(scanID);
            }
        })();

        // New links use /share#TOKEN: URL fragments never reach HTTP access
        // logs or Referer headers. Legacy /share/TOKEN links remain readable.
        const pathParts = window.location.pathname.split('/');
        const legacyShareToken = pathParts[1] === 'share' && pathParts[2] ? pathParts[2] : '';
        const fragmentShareToken = pathParts[1] === 'share' && window.location.hash.length > 1
            ? window.location.hash.slice(1) : '';
        const shareToken = fragmentShareToken || legacyShareToken;
        if (/^[A-Za-z0-9_-]{32}$/.test(shareToken)) {
            // Remove the capability from browser history/address bar as soon as
            // it has been captured in this closure.
            window.history.replaceState(null, '', '/share');
            (async () => {
                try {
                    async function requestSharedReport(password) {
                        const body = { token: shareToken };
                        if (password) body.password = password;
                        const response = await fetch('/api/share', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(body)
                        });
                        // Temporary compatibility with a backend that predates
                        // body-based token exchange. Fragment links never fall
                        // back to a token-bearing request URL.
                        if (!legacyShareToken || (response.status !== 404 && response.status !== 405)) return response;
                        return fetch('/api/share/' + encodeURIComponent(shareToken), password ? {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ password })
                        } : undefined);
                    }

                    let resp = await requestSharedReport();
                    if (resp.status === 401) {
                        const pw = prompt('This report is password-protected. Enter password:');
                        if (!pw) return;
                        resp = await requestSharedReport(pw);
                    }
                    if (!resp.ok) {
                        if (resp.status === 401) { alert('Wrong password.'); return; }
                        alert(resp.status === 410 ? 'This share link has expired.' : 'Share link not found.');
                        return;
                    }
                    const data = await resp.json();
                    lastScanData = { scanID: data.scan.id, input: data.scan.input, results: data.results, status: data.scan.status };
                    document.getElementById('target-input').value = data.scan.input;
                    displayResults(data.results || [], data.scan.input);
                    logStatus('Viewing shared report for: ' + data.scan.input + ' (' + (data.results || []).length + ' results)');
                    document.getElementById('results-panel').classList.remove('hidden');
                } catch(e) {
                    logStatus('Failed to load shared report: ' + e.message, 'text-red-500');
                }
            })();
        }

        // Notification bell dropdown toggle.
        document.getElementById('notif-bell-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            document.getElementById('notif-dropdown').classList.toggle('hidden');
        });
        document.addEventListener('click', (e) => {
            if (!document.getElementById('notif-bell-container').contains(e.target)) {
                document.getElementById('notif-dropdown').classList.add('hidden');
            }
        });
        document.getElementById('mark-all-read-btn').addEventListener('click', async () => {
            await fetch('/api/notifications/read-all', { method: 'POST', credentials: 'include' });
            loadNotifications();
        });

        async function loadNotifications() {
            if (!currentUser) return;
            try {
                const res = await fetch('/api/notifications', { credentials: 'include' });
                if (!res.ok) return;
                const notifs = await res.json();
                renderNotifications(notifs);
            } catch (_) {}
        }

        function renderNotifications(notifs) {
            const list = document.getElementById('notif-list');
            const empty = document.getElementById('notif-empty');
            const badge = document.getElementById('notif-badge');
            const unread = notifs.filter(n => !n.isRead).length;
            if (unread > 0) {
                badge.textContent = unread > 99 ? '99+' : unread;
                badge.classList.remove('hidden');
            } else {
                badge.classList.add('hidden');
            }
            if (!notifs.length) {
                list.innerHTML = '';
                empty.classList.remove('hidden');
                return;
            }
            empty.classList.add('hidden');
            list.innerHTML = notifs.map(n => `
              <div class="px-3 py-2 hover:bg-dark-700 cursor-pointer flex gap-2 items-start ${n.isRead ? 'opacity-50' : ''}" data-scanid="${escapeHtml(String(n.scanID))}" data-notifid="${escapeHtml(String(n.id))}">
                <span class="mt-0.5 text-base">${n.isRead ? '🔔' : '🆕'}</span>
                <div class="flex-1 min-w-0">
                  <div class="text-[11px] text-slate-200 leading-snug">${escapeHtml(n.message)}</div>
                  <div class="text-[9px] text-slate-500 mt-0.5">${timeAgo(n.createdAt)}</div>
                </div>
              </div>`).join('');
            list.querySelectorAll('[data-scanid]').forEach(el => {
                el.addEventListener('click', () => handleNotifClick(el.dataset.notifid, el.dataset.scanid));
            });
        }

        async function handleNotifClick(notifID, scanID) {
            document.getElementById('notif-dropdown').classList.add('hidden');
            await fetch(`/api/notifications/${notifID}/read`, { method: 'POST', credentials: 'include' });
            loadNotifications();
            if (scanID) loadScanByID(scanID);
        }

        async function loadCorrelations() {
            const el = document.getElementById('correlations-content');
            el.innerHTML = '<span class="text-slate-400">Loading…</span>';
            el.classList.remove('hidden');
            try {
                const res = await fetch('/api/correlations', { credentials: 'include' });
                if (!res.ok) { el.textContent = 'Failed to load correlations.'; return; }
                const data = await res.json();
                if (!data.correlations || !data.correlations.length) {
                    el.textContent = 'No cross-scan correlations found yet. Run more scans to see connections.';
                    return;
                }
                el.innerHTML = data.correlations.map(c => `
                  <div class="rounded-sm bg-dark-700 px-2 py-1.5 mb-1">
                    <div class="flex items-center gap-1 flex-wrap">
                      <span class="text-[10px] font-semibold text-brand-400 uppercase">${escapeHtml(c.entityType)}</span>
                      <span class="text-[11px] text-slate-200 font-mono">${escapeHtml(c.entity)}</span>
                    </div>
                    <div class="text-[9px] text-slate-400 mt-0.5">Found in ${c.occurrences.length} scan${c.occurrences.length !== 1 ? 's' : ''}: ${c.occurrences.map(o => escapeHtml(o.input)).join(', ')}</div>
                  </div>`).join('');
            } catch (e) { el.textContent = 'Error loading correlations.'; }
        }

        document.getElementById('load-correlations-btn').addEventListener('click', loadCorrelations);
        document.getElementById('toggle-correlations-btn').addEventListener('click', () => {
            const el = document.getElementById('correlations-content');
            const btn = document.getElementById('toggle-correlations-btn');
            el.classList.toggle('hidden');
            btn.textContent = el.classList.contains('hidden') ? '▼' : '▲';
        });

        function escapeHtml(s) {
            return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
        }
        function showToast(msg, type = 'success') {
            const t = document.createElement('div');
            const color = type === 'error' ? 'bg-red-600' : type === 'warning' ? 'bg-yellow-600' : 'bg-brand-600';
            t.className = `fixed bottom-6 right-6 z-[200] px-4 py-2.5 rounded-lg text-white text-sm shadow-xl transition-all duration-300 ${color}`;
            t.textContent = msg;
            document.body.appendChild(t);
            setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, 3500);
        }

        function timeAgo(dateInput) {
            if (!dateInput) return '';
            const d = typeof dateInput === 'number' ? new Date(dateInput * 1000) : new Date(dateInput);
            if (isNaN(d)) return '';
            const sec = Math.floor((Date.now() - d.getTime()) / 1000);
            if (sec < 60) return 'just now';
            if (sec < 3600) return `${Math.floor(sec/60)}m ago`;
            if (sec < 86400) return `${Math.floor(sec/3600)}h ago`;
            return `${Math.floor(sec/86400)}d ago`;
        }

        // ── API Keys ──────────────────────────────────────────────────────
        async function loadAPIKeys() {
            const container = document.getElementById('api-keys-list');
            if (!container) return;
            try {
                const res = await fetch('/api/auth/api-keys', { credentials: 'include' });
                if (!res.ok) { container.innerHTML = '<p class="text-[10px] text-slate-500">Not signed in.</p>'; return; }
                const keys = await res.json();
                renderAPIKeys(keys, container);
            } catch { container.innerHTML = '<p class="text-[10px] text-red-400">Error loading keys.</p>'; }
        }
        function renderAPIKeys(keys, container) {
            if (!keys.length) { container.innerHTML = '<p class="text-[10px] text-slate-500">No API keys yet.</p>'; return; }
            container.replaceChildren();
            for (const key of keys) {
                const row = document.createElement('div');
                row.className = 'flex items-center justify-between gap-2 mb-1 bg-dark-900 rounded px-2 py-1';

                const label = document.createElement('span');
                label.className = 'text-[10px] text-slate-300 font-mono truncate';
                label.append(document.createTextNode(String(key.label || 'Unnamed') + ' — '));
                const preview = document.createElement('code');
                preview.textContent = String(key.keyPreview || '');
                label.appendChild(preview);

                const remove = document.createElement('button');
                remove.type = 'button';
                remove.className = 'text-red-400 hover:text-red-300 text-[10px]';
                remove.setAttribute('aria-label', 'Delete API key ' + String(key.label || 'Unnamed'));
                remove.textContent = '✕';
                remove.addEventListener('click', () => deleteAPIKey(String(key.id || '')));
                row.append(label, remove);
                container.appendChild(row);
            }
        }
        async function generateAPIKey() {
            const label = document.getElementById('api-key-label').value.trim() || 'Unnamed';
            const res = await fetch('/api/auth/api-keys', {
                method: 'POST', credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ label })
            });
            if (!res.ok) { alert('Failed to create API key. You may have reached the limit (5 max).'); return; }
            const key = await res.json();
            prompt('Copy your new API key now — it will NOT be shown again:', key.key);
            document.getElementById('api-key-label').value = '';
            loadAPIKeys();
        }
        async function deleteAPIKey(id) {
            if (!confirm('Delete this API key?')) return;
            const response = await fetch(`/api/auth/api-keys/${encodeURIComponent(id)}`, {
                method: 'DELETE', credentials: 'include'
            });
            if (!response.ok) {
                showToast('Failed to delete API key (HTTP ' + response.status + ').', 'error');
                return;
            }
            loadAPIKeys();
        }
        document.getElementById('generate-api-key-btn')?.addEventListener('click', generateAPIKey);

        // ── Data Retention ────────────────────────────────────────────────
        document.getElementById('save-retention-btn')?.addEventListener('click', async () => {
            const val = document.getElementById('retention-select').value;
            const retentionDays = val ? parseInt(val, 10) : null;
            const status = document.getElementById('retention-status');
            const res = await fetch('/api/auth/retention', {
                method: 'POST', credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ retentionDays })
            });
            if (res.ok) {
                status.textContent = '✓ Saved'; status.className = 'text-[10px] mt-1 text-green-400';
            } else {
                status.textContent = '✗ Error saving.'; status.className = 'text-[10px] mt-1 text-red-400';
            }
            status.classList.remove('hidden');
            setTimeout(() => status.classList.add('hidden'), 3000);
        });

        // ─── E1: BULK SCAN ────────────────────────────────────────────────────────
        document.getElementById('bulk-scan-open-btn').addEventListener('click', () => {
            document.getElementById('bulk-results-list').innerHTML = '';
            document.getElementById('bulk-progress-section').classList.add('hidden');
            document.getElementById('bulk-scan-modal').classList.remove('hidden');
        });
        document.getElementById('bulk-modal-close').addEventListener('click', () => {
            document.getElementById('bulk-scan-modal').classList.add('hidden');
        });
        document.getElementById('bulk-scan-modal').addEventListener('click', (e) => {
            if (e.target === document.getElementById('bulk-scan-modal')) document.getElementById('bulk-scan-modal').classList.add('hidden');
        });
        document.getElementById('bulk-scan-submit-btn').addEventListener('click', async () => {
            const raw = document.getElementById('bulk-targets-textarea').value;
            const targets = raw.split('\n').map(t => t.trim()).filter(t => t.length > 0);
            if (targets.length === 0) { alert('Please enter at least one target.'); return; }
            if (targets.length > 50) { alert('Maximum 50 targets allowed.'); return; }
            const btn = document.getElementById('bulk-scan-submit-btn');
            const progressSection = document.getElementById('bulk-progress-section');
            const progressFill = document.getElementById('bulk-progress-fill');
            const statusText = document.getElementById('bulk-status-text');
            const resultsList = document.getElementById('bulk-results-list');
            btn.disabled = true;
            btn.textContent = 'Scanning…';
            progressSection.classList.remove('hidden');
            progressFill.style.width = '10%';
            statusText.textContent = 'Submitting…';
            resultsList.innerHTML = '';
            try {
                const selectedPlugins = getSelectedPlugins();
                const body = { targets };
                if (selectedPlugins) body.plugins = selectedPlugins;
                const resp = await fetch('/api/scan/bulk', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify(body)
                });
                if (!resp.ok) {
                    const err = await resp.text().catch(() => 'HTTP ' + resp.status);
                    throw new Error(err);
                }
                const results = await resp.json();
                // Close modal and show success toast
                document.getElementById('bulk-scan-modal').classList.add('hidden');
                document.getElementById('bulk-targets-textarea').value = '';
                progressSection.classList.add('hidden');
                progressFill.style.width = '0%';
                progressFill.classList.remove('bg-red-500');
                progressFill.classList.add('bg-purple-500');
                resultsList.innerHTML = '';
                showToast(`✓ ${results.length} scan${results.length !== 1 ? 's' : ''} queued successfully`);
            } catch(err) {
                statusText.textContent = 'Error: ' + err.message;
                progressFill.classList.add('bg-red-500');
                progressFill.classList.remove('bg-purple-500');
            } finally {
                btn.disabled = false;
                btn.textContent = 'START BULK SCAN';
            }
        });

        // ── Leaflet IP Geolocation Map ──────────────────────────────────────────
        let leafletLoaded = false;
        let leafletMapInstance = null;

        async function initLeafletMap() {
            const wrapper   = document.getElementById('leaflet-map-wrapper');
            const noData    = document.getElementById('map-no-data');
            const loading   = document.getElementById('map-loading');
            if (!noData || !wrapper || !loading) return;

            const results = (lastScanData && lastScanData.results) || [];
            const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
            const ips = [...new Set(
                results.flatMap(r => {
                    const text = [r.rawData, r.title, r.summary].filter(Boolean).join(' ');
                    return text.match(ipRegex) || [];
                }).filter(ip => !ip.startsWith('127.') && !ip.startsWith('0.') && !ip.startsWith('192.168') && !ip.startsWith('10.') && !ip.startsWith('172.'))
            )];

            if (!ips.length) { noData.classList.remove('hidden'); wrapper.classList.add('hidden'); loading.classList.add('hidden'); return; }
            noData.classList.add('hidden'); loading.classList.remove('hidden'); wrapper.classList.add('hidden');

            // Load Leaflet CSS+JS on demand. Served from the same origin
            // (frontend/leaflet.*) — no third-party CDN, no SRI required,
            // CSP can drop the unpkg.com allowlist entirely.
            if (!leafletLoaded) {
                await new Promise((resolve, reject) => {
                    const lnk = document.createElement('link');
                    lnk.rel = 'stylesheet'; lnk.href = '/leaflet.css';
                    document.head.appendChild(lnk);
                    const scr = document.createElement('script');
                    scr.src = '/leaflet.js';
                    scr.onload = () => { leafletLoaded = true; resolve(); };
                    scr.onerror = reject;
                    document.head.appendChild(scr);
                });
            }

            // Batch geo-lookup (max 100 per ip-api.com free tier)
            let geoData = [];
            try {
                const batch = ips.slice(0, 100);
                const res = await fetch('/api/geolocate', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(batch.map(q => ({query: q}))) });
                geoData = await res.json();
            } catch(e) { loading.classList.add('hidden'); noData.classList.remove('hidden'); return; }

            loading.classList.add('hidden');
            wrapper.classList.remove('hidden'); wrapper.classList.add('flex');

            if (!leafletMapInstance) {
                leafletMapInstance = window.L.map('leaflet-map', {scrollWheelZoom: true}).setView([20, 0], 2);
                window.L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
                    maxZoom: 18
                }).addTo(leafletMapInstance);
            } else {
                leafletMapInstance.eachLayer(l => { if (l instanceof window.L.Marker) leafletMapInstance.removeLayer(l); });
            }

            const valid = geoData.filter(d => d.status === 'success');
            valid.forEach(d => {
                window.L.marker([d.lat, d.lon])
                    .addTo(leafletMapInstance)
                    // bindPopup takes an HTML string. These values come from the
                    // offline GeoIP database rather than from a scanned page, so
                    // this is not reachable today — but it is the one place in
                    // this file where third-party text meets an HTML sink
                    // unescaped, and createResultCard sets the standard three
                    // thousand lines above: never innerHTML for API values.
                    .bindPopup(`<b>${escapeHtml(d.query)}</b><br>${escapeHtml(d.city || '')} ${escapeHtml(d.regionName || '')}, ${escapeHtml(d.country || '')}<br>ISP: ${escapeHtml(d.isp || '')}`);
            });
            if (valid.length) {
                const bounds = window.L.latLngBounds(valid.map(d => [d.lat, d.lon]));
                leafletMapInstance.fitBounds(bounds, {padding: [30, 30], maxZoom: 12});
            }
            // Invalidate size in case container was hidden during init
            setTimeout(() => leafletMapInstance.invalidateSize(), 100);
        }

        // ── Theme (dark / light) ────────────────────────────────────────────────
        function applyTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
            const btn = document.getElementById('theme-toggle-btn');
            if (btn) btn.textContent = theme === 'light' ? '🌙' : '☀';
        }
        // Init theme from storage
        applyTheme(localStorage.getItem('theme') || 'dark');

        document.getElementById('theme-toggle-btn').addEventListener('click', () => {
            const current = document.documentElement.getAttribute('data-theme') || 'dark';
            applyTheme(current === 'dark' ? 'light' : 'dark');
        });

        // ── Mobile hamburger ────────────────────────────────────────────────────
        const hamburgerBtn  = document.getElementById('hamburger-btn');
        const mobileMenuEl  = document.getElementById('auth-widget');
        function closeMobileMenu() {
            if (!hamburgerBtn || !mobileMenuEl) return;
            mobileMenuEl.classList.remove('mobile-open');
            hamburgerBtn.setAttribute('aria-expanded', 'false');
        }
        if (hamburgerBtn && mobileMenuEl) {
            hamburgerBtn.addEventListener('click', (event) => {
                event.stopPropagation();
                const isOpen = mobileMenuEl.classList.toggle('mobile-open');
                hamburgerBtn.setAttribute('aria-expanded', String(isOpen));
            });
            document.addEventListener('click', (event) => {
                if (mobileMenuEl.classList.contains('mobile-open')
                    && !mobileMenuEl.contains(event.target)) closeMobileMenu();
            });
            document.addEventListener('keydown', (event) => {
                if (event.key === 'Escape') closeMobileMenu();
            });
            window.addEventListener('resize', () => {
                if (window.innerWidth >= 768) closeMobileMenu();
            });
        }

        // ── Diff / Comparison ───────────────────────────────────────────────────
        async function openDiffModal(scanIDA, scanIDB) {
            const modal = document.getElementById('diff-modal');
            const header = document.getElementById('diff-header');
            const body   = document.getElementById('diff-body');
            if (!modal) return;
            body.innerHTML = '<p class="text-slate-500 text-sm">Loading…</p>';
            header.textContent = '';
            modal.classList.add('active');
            try {
                const res = await fetch(`/api/scans/${encodeURIComponent(scanIDA)}/diff/${encodeURIComponent(scanIDB)}`, {
                    credentials: 'include'
                });
                if (!res.ok) throw new Error('HTTP ' + res.status);
                const diff = await res.json();
                header.innerHTML = `Comparing scan <b class="text-brand-400">${scanIDA.slice(-6)}</b> vs <b class="text-brand-400">${scanIDB.slice(-6)}</b> — `
                    + `<span class="text-green-400">+${diff.new.length} new</span> · `
                    + `<span class="text-red-400">−${diff.removed.length} removed</span> · `
                    + `<span class="text-slate-400">${diff.unchanged.length} unchanged</span>`;
                body.innerHTML = '';
                if (!diff.new.length && !diff.removed.length) {
                    body.innerHTML = '<p class="text-slate-400 text-sm text-center py-6">No differences found — scans are identical.</p>';
                    return;
                }
                // All API values interpolated into innerHTML go through escapeHtml.
                // rawData is attacker-controllable (plugin output may include
                // scan input substituted into URL templates), so unescaped
                // interpolation here would be stored XSS reachable in the
                // admin / scan-owner context.
                const mkSection = (title, color, items) => {
                    if (!items.length) return '';
                    return `<div>
                        <h3 class="text-[10px] uppercase tracking-widest font-bold text-${color}-400 mb-2">${escapeHtml(title)}</h3>
                        <div class="flex flex-col gap-2">${items.map(r => {
                            const raw = escapeHtml(r.rawData || r.title || '');
                            return `<div class="text-xs bg-dark-900 rounded-sm px-3 py-2 border border-${color}-500/30">
                                <span class="font-semibold text-${color}-300">[${escapeHtml(r.type || '')}]</span>
                                <span class="text-slate-300 ml-1">${escapeHtml(r.source || '')}</span>
                                <div class="text-slate-400 mt-0.5 truncate" title="${raw}">${raw}</div>
                            </div>`;
                        }).join('')}
                        </div></div>`;
                };
                body.innerHTML = mkSection('New in B', 'green', diff.new) + mkSection('Removed in B', 'red', diff.removed);
            } catch(err) {
                body.innerHTML = `<p class="text-red-400 text-sm">Failed to load diff: ${escapeHtml(String(err && err.message || err))}</p>`;
            }
        }

        document.getElementById('diff-modal-close').addEventListener('click', () => {
            const m = document.getElementById('diff-modal');
            m.classList.remove('active');
            diffSelectA = null;
        });

        // ── Keyboard shortcuts ──────────────────────────────────────────────────
        let kbdHelpReturnFocus = null;
        const kbdHelpOverlay = document.getElementById('kbd-help-overlay');
        const kbdHelpClose = document.getElementById('kbd-help-close');
        const kbdHelpTrigger = document.getElementById('kbd-help-trigger');

        function openKeyboardHelp() {
            kbdHelpReturnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
            kbdHelpOverlay.classList.add('active');
            kbdHelpOverlay.setAttribute('aria-hidden', 'false');
            kbdHelpClose.focus();
        }

        function closeKeyboardHelp() {
            if (!kbdHelpOverlay.classList.contains('active')) return;
            kbdHelpOverlay.classList.remove('active');
            kbdHelpOverlay.setAttribute('aria-hidden', 'true');
            const returnTarget = kbdHelpReturnFocus && document.contains(kbdHelpReturnFocus)
                ? kbdHelpReturnFocus : kbdHelpTrigger;
            returnTarget.focus();
            kbdHelpReturnFocus = null;
        }

        kbdHelpOverlay.addEventListener('keydown', (event) => {
            if (event.key !== 'Tab') return;
            const focusable = [...kbdHelpOverlay.querySelectorAll('button, a[href], input, select, textarea, [tabindex]:not([tabindex="-1"])')]
                .filter(element => !element.disabled && element.getClientRects().length > 0);
            if (!focusable.length) return;
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (event.shiftKey && document.activeElement === first) {
                event.preventDefault(); last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault(); first.focus();
            }
        });

        document.addEventListener('keydown', (e) => {
            const tag = (e.target && e.target.tagName) || '';
            const inInput = ['INPUT','TEXTAREA','SELECT'].includes(tag) || e.target.isContentEditable;

            if (e.key === 'Escape') {
                // Close any open modal
                document.getElementById('diff-modal')?.classList.remove('active');
                closeKeyboardHelp();
                return;
            }
            if (inInput) return;
            if (e.key === '/' || e.key === 'n') {
                e.preventDefault();
                const inp = document.getElementById('target-input');
                if (inp) { inp.focus(); inp.select(); }
            }
            if (e.key === '?') {
                if (kbdHelpOverlay.classList.contains('active')) closeKeyboardHelp();
                else openKeyboardHelp();
            }
        });

        kbdHelpClose.addEventListener('click', closeKeyboardHelp);
        kbdHelpTrigger.addEventListener('click', openKeyboardHelp);

        // Render history panel on page load.
        renderHistory();
        // Load platform stats on page load.
        loadStats();
        loadPlugins();
        // Check auth state on page load.
        loadAuthState();
