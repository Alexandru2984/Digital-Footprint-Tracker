/* Bounded dark-web investigations.
 *
 * The browser only consumes the normalized worker contract. It deliberately
 * renders every server-provided value through textContent and never creates
 * links from findings, so an upstream onion page cannot become active markup.
 */
(function () {
  'use strict';

  var TERMINAL = { completed: true, failed: true, cancelled: true };
  var STATUSES = { pending: true, running: true, completed: true, failed: true, cancelled: true };
  var ALLOWED_TYPES = {
    email: true, domain: true, onion_service: true, ip: true, phone: true,
    username: true, messaging_handle: true, crypto_wallet: true, file_hash: true,
    vulnerability: true, malware: true, threat_actor: true, organization: true,
    date: true, technique: true, credential_exposure: true, network_indicator: true
  };
  var state = {
    open: false,
    config: null,
    jobs: [],
    selectedID: null,
    detail: null,
    busy: false,
    pollTimer: null,
    detailRequest: 0,
    previousFocus: null,
    previousOverflow: ''
  };

  function byID(id) { return document.getElementById(id); }
  function node(tag, className, text) {
    var item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  }
  function text(value, maximum) {
    if (typeof value !== 'string') return '';
    return value.slice(0, maximum || 512);
  }
  function number(value, fallback) {
    return typeof value === 'number' && Number.isFinite(value) ? value : (fallback || 0);
  }
  function statusOf(value) { return STATUSES[value] ? value : 'failed'; }
  function statusLabel(value) {
    return { pending: 'Queued', running: 'Running', completed: 'Completed', failed: 'Failed', cancelled: 'Cancelled' }[statusOf(value)];
  }
  function statusClass(value) { return 'dw-state dw-state-' + statusOf(value) + ' text-[10px] uppercase tracking-wider rounded-full px-2.5 py-1'; }
  function setStatusPill(element, value) {
    element.className = statusClass(value);
    element.textContent = statusLabel(value);
  }
  function formatDate(timestamp) {
    if (typeof timestamp !== 'number' || !Number.isFinite(timestamp)) return '—';
    var date = new Date(timestamp * 1000);
    return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
  }
  function setMessage(message, tone) {
    var item = byID('dark-web-form-message');
    item.textContent = message || '';
    item.className = 'min-h-[1.25rem] mt-2 text-[11px] ' +
      (tone === 'error' ? 'text-red-400' : tone === 'ok' ? 'text-brand-400' : 'text-slate-500');
  }

  async function api(method, path, body) {
    var options = {
      method: method,
      credentials: 'include',
      headers: { Accept: 'application/json' },
      cache: 'no-store'
    };
    if (body !== undefined) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
    var response;
    try {
      response = await fetch('/api/dark-web' + path, options);
    } catch (error) {
      throw new Error('The application server is unavailable.');
    }
    var data = null;
    if (response.status !== 204) {
      try { data = await response.json(); } catch (error) { data = null; }
    }
    if (!response.ok) {
      var fallback = {
        401: 'Sign in to use dark-web investigations.',
        403: 'Verify your email and confirm authorized defensive use.',
        409: 'This account already has an active investigation.',
        429: 'The investigation quota or queue limit has been reached.',
        503: 'Dark-web investigations are disabled on this deployment.'
      }[response.status] || 'The request could not be completed.';
      var reason = data && typeof data.reason === 'string' ? data.reason.slice(0, 240) : fallback;
      var failure = new Error(reason);
      failure.status = response.status;
      throw failure;
    }
    return data;
  }

  function normalizedResult(raw) {
    if (typeof raw === 'string') {
      try { raw = JSON.parse(raw); } catch (error) { return null; }
    }
    if (!raw || typeof raw !== 'object' || raw.schemaVersion !== 1) return null;
    var findings = Array.isArray(raw.findings) ? raw.findings.slice(0, 250).filter(function (finding) {
      return finding && typeof finding === 'object' && ALLOWED_TYPES[finding.type] &&
        typeof finding.value === 'string' && typeof finding.source === 'string';
    }).map(function (finding) {
      return {
        type: text(finding.type, 64), value: text(finding.value, 512),
        source: text(finding.source, 80), confidence: Math.max(0, Math.min(1, number(finding.confidence, 0))),
        firstSeen: text(finding.firstSeen, 10) || null,
        lastSeen: text(finding.lastSeen, 10) || null
      };
    }) : [];
    var relationships = Array.isArray(raw.relationships) ? raw.relationships.slice(0, 500).filter(function (relationship) {
      return relationship && typeof relationship === 'object' &&
        typeof relationship.source === 'string' && typeof relationship.target === 'string' &&
        typeof relationship.type === 'string';
    }).map(function (relationship) {
      return {
        source: text(relationship.source, 512), target: text(relationship.target, 512),
        type: text(relationship.type, 64), confidence: Math.max(0, Math.min(1, number(relationship.confidence, 0)))
      };
    }) : [];
    var sources = Array.isArray(raw.sources) ? raw.sources.slice(0, 64).filter(function (source) {
      return typeof source === 'string';
    }).map(function (source) { return text(source, 80); }) : [];
    return { schemaVersion: 1, status: 'completed', findings: findings, relationships: relationships, sources: sources };
  }

  function normalizedJob(raw) {
    if (!raw || typeof raw !== 'object' || typeof raw.id !== 'string' || typeof raw.target !== 'string') return null;
    return {
      id: text(raw.id, 36), target: text(raw.target, 255), targetKind: text(raw.targetKind, 24),
      status: statusOf(raw.status), resultCount: Math.max(0, Math.floor(number(raw.resultCount, 0))),
      failureCode: text(raw.failureCode, 64) || null, cancelRequested: raw.cancelRequested === true,
      createdAt: raw.createdAt, startedAt: raw.startedAt, completedAt: raw.completedAt,
      expiresAt: raw.expiresAt, result: normalizedResult(raw.result)
    };
  }

  function setAvailability(enabled, label) {
    var badge = byID('dark-web-availability');
    badge.className = 'dw-state text-[10px] uppercase tracking-wider rounded-full px-2.5 py-1 ' +
      (enabled ? 'dw-state-completed' : 'dw-state-failed');
    badge.textContent = label;
    byID('dark-web-target').disabled = !enabled;
    byID('dark-web-ack').disabled = !enabled;
    byID('dark-web-submit').disabled = !enabled || state.busy;
  }

  async function loadStatus() {
    try {
      var config = await api('GET', '/status');
      state.config = config && typeof config === 'object' ? config : null;
      var enabled = !!(state.config && state.config.enabled);
      setAvailability(enabled, enabled ? 'Available' : 'Disabled');
      if (enabled) {
        setMessage('Up to ' + number(state.config.maxJobsPerUserPerDay, 3) + ' jobs/day · ' +
          number(state.config.retentionHours, 72) + 'h encrypted retention.', 'info');
      } else {
        setMessage('The isolated worker is disabled on this deployment.', 'error');
      }
      return enabled;
    } catch (error) {
      state.config = null;
      setAvailability(false, 'Unavailable');
      setMessage(error.message, 'error');
      return false;
    }
  }

  function renderJobs() {
    var container = byID('dark-web-jobs');
    container.replaceChildren();
    if (!state.jobs.length) {
      container.appendChild(node('p', 'text-xs text-slate-500 py-3 text-center', 'No investigations yet.'));
      return;
    }
    state.jobs.forEach(function (job) {
      var button = node('button', 'dw-job w-full text-left rounded-lg border border-dark-700 bg-dark-900 p-3 hover:border-red-500/40 transition-colors');
      button.type = 'button';
      button.setAttribute('aria-current', String(job.id === state.selectedID));
      button.addEventListener('click', function () { selectJob(job.id); });

      var top = node('span', 'flex items-center gap-2');
      top.appendChild(node('span', 'dw-value min-w-0 flex-1 truncate text-xs font-semibold text-slate-200', job.target));
      var badge = node('span', statusClass(job.status), statusLabel(job.status));
      top.appendChild(badge);
      button.appendChild(top);

      var meta = node('span', 'flex items-center justify-between gap-2 mt-2 text-[10px] text-slate-500');
      meta.appendChild(node('span', 'uppercase', job.targetKind || 'target'));
      meta.appendChild(node('span', '', job.resultCount + ' finding' + (job.resultCount === 1 ? '' : 's')));
      button.appendChild(meta);
      container.appendChild(button);
    });
  }

  async function loadJobs(selectFirst) {
    try {
      var rows = await api('GET', '/investigations');
      state.jobs = Array.isArray(rows) ? rows.map(normalizedJob).filter(Boolean) : [];
      if (state.selectedID && !state.jobs.some(function (job) { return job.id === state.selectedID; })) {
        state.selectedID = null;
        state.detail = null;
      }
      if (!state.selectedID && selectFirst && state.jobs.length) state.selectedID = state.jobs[0].id;
      renderJobs();
      if (state.selectedID) await selectJob(state.selectedID, true);
      else renderDetail(null);
      schedulePoll();
    } catch (error) {
      state.jobs = [];
      renderJobs();
      renderDetail(null);
      setMessage(error.message, 'error');
    }
  }

  function failureMessage(code) {
    return {
      worker_configuration: 'The worker is not configured correctly.',
      worker_unavailable: 'The isolated worker could not be reached.',
      worker_authentication: 'The application and worker authentication keys do not match.',
      invalid_worker_response: 'The worker returned data outside the accepted contract.',
      worker_rejected: 'The worker rejected this investigation.',
      worker_timeout: 'The investigation exceeded its execution deadline.',
      worker_interrupted: 'The worker or application restarted while this job was running.',
      worker_internal: 'The investigation failed inside the isolated execution boundary.'
    }[code] || 'The investigation failed without exposing upstream diagnostic data.';
  }

  function renderSources(result) {
    var container = byID('dark-web-sources');
    container.replaceChildren();
    if (!result.sources.length) {
      container.appendChild(node('span', 'text-xs text-slate-500', 'No corroborating source names.'));
      return;
    }
    result.sources.forEach(function (source) {
      container.appendChild(node('span', 'dw-value text-[10px] rounded-full border border-dark-600 bg-dark-800 text-slate-300 px-2.5 py-1', source));
    });
  }

  function renderTimeline(result) {
    var events = [];
    var seen = {};
    result.findings.forEach(function (finding) {
      [['firstSeen', 'First observed'], ['lastSeen', 'Last observed']].forEach(function (item) {
        var date = finding[item[0]];
        if (!date) return;
        var key = date + '\u0000' + item[1] + '\u0000' + finding.type + '\u0000' + finding.value;
        if (seen[key]) return;
        seen[key] = true;
        events.push({ date: date, label: item[1] + ' · ' + finding.type.replace(/_/g, ' ') + ' · ' + finding.value });
      });
    });
    events.sort(function (a, b) { return a.date.localeCompare(b.date) || a.label.localeCompare(b.label); });
    var section = byID('dark-web-timeline-section');
    var container = byID('dark-web-timeline');
    container.replaceChildren();
    section.classList.toggle('hidden', events.length === 0);
    events.slice(0, 100).forEach(function (event) {
      var row = node('div', 'grid grid-cols-[6.5rem_minmax(0,1fr)] gap-2 rounded border border-dark-700 bg-dark-800 px-3 py-2 text-[11px]');
      row.appendChild(node('span', 'font-mono text-red-300', event.date));
      row.appendChild(node('span', 'dw-value text-slate-300', event.label));
      container.appendChild(row);
    });
  }

  function tableCell(label, className, value) {
    var cell = node('td', className, value);
    cell.setAttribute('data-label', label);
    return cell;
  }

  function renderFindings(result) {
    var body = byID('dark-web-findings');
    var empty = byID('dark-web-findings-empty');
    body.replaceChildren();
    empty.classList.toggle('hidden', result.findings.length !== 0);
    result.findings.forEach(function (finding) {
      var row = node('tr');
      row.appendChild(tableCell('Type', 'text-red-300 whitespace-nowrap', finding.type.replace(/_/g, ' ')));
      row.appendChild(tableCell('Indicator', 'dw-value text-slate-200 font-mono', finding.value));
      row.appendChild(tableCell('Source', 'dw-value text-slate-400', finding.source));
      row.appendChild(tableCell('Confidence', 'text-slate-300 whitespace-nowrap', Math.round(finding.confidence * 100) + '%'));
      var observed = finding.firstSeen || finding.lastSeen || '—';
      if (finding.firstSeen && finding.lastSeen && finding.firstSeen !== finding.lastSeen) observed = finding.firstSeen + ' → ' + finding.lastSeen;
      row.appendChild(tableCell('Observed', 'text-slate-400 whitespace-nowrap', observed));
      body.appendChild(row);
    });
  }

  function renderRelationships(result) {
    var container = byID('dark-web-relationships');
    container.replaceChildren();
    if (!result.relationships.length) {
      container.appendChild(node('p', 'text-xs text-slate-500', 'No explicit relationships were returned.'));
      return;
    }
    result.relationships.forEach(function (relationship) {
      var row = node('div', 'rounded-lg border border-dark-700 bg-dark-800 px-3 py-2 text-[11px]');
      var values = node('div', 'dw-value text-slate-300');
      values.appendChild(node('span', 'font-mono', relationship.source));
      values.appendChild(node('span', 'text-red-400 mx-2', '→ ' + relationship.type.replace(/_/g, ' ') + ' →'));
      values.appendChild(node('span', 'font-mono', relationship.target));
      row.appendChild(values);
      row.appendChild(node('div', 'text-[10px] text-slate-500 mt-1', Math.round(relationship.confidence * 100) + '% confidence'));
      container.appendChild(row);
    });
  }

  function renderResult(job) {
    var result = job.result;
    var results = byID('dark-web-results');
    if (job.status !== 'completed' || !result) {
      results.classList.add('hidden');
      return;
    }
    results.classList.remove('hidden');
    byID('dark-web-finding-count').textContent = String(result.findings.length);
    byID('dark-web-relation-count').textContent = String(result.relationships.length);
    byID('dark-web-source-count').textContent = String(result.sources.length);
    byID('dark-web-retention').textContent = number(state.config && state.config.retentionHours, 72) + 'h';
    renderSources(result);
    renderTimeline(result);
    renderFindings(result);
    renderRelationships(result);
  }

  function renderDetail(job) {
    var empty = byID('dark-web-detail-empty');
    var detail = byID('dark-web-detail');
    if (!job) {
      empty.classList.remove('hidden');
      detail.classList.add('hidden');
      return;
    }
    empty.classList.add('hidden');
    detail.classList.remove('hidden');
    setStatusPill(byID('dark-web-detail-status'), job.status);
    byID('dark-web-detail-kind').textContent = job.targetKind || 'target';
    byID('dark-web-detail-target').textContent = job.target;
    byID('dark-web-detail-meta').textContent = 'Created ' + formatDate(job.createdAt) + ' · expires ' + formatDate(job.expiresAt);

    var active = !TERMINAL[job.status];
    var cancel = byID('dark-web-cancel-btn');
    var remove = byID('dark-web-delete-btn');
    var board = byID('dark-web-board-btn');
    cancel.classList.toggle('hidden', !active);
    cancel.disabled = job.cancelRequested;
    cancel.textContent = job.cancelRequested ? 'Cancelling…' : 'Cancel';
    remove.classList.toggle('hidden', active);
    remove.disabled = false;
    board.classList.toggle('hidden', !(job.status === 'completed' && job.result));

    var progress = byID('dark-web-progress');
    progress.classList.toggle('hidden', !active);
    byID('dark-web-progress-text').textContent = job.status === 'running' ? 'Worker running through Tor…' : 'Waiting for the isolated worker…';
    var failure = byID('dark-web-failure');
    failure.classList.toggle('hidden', job.status !== 'failed');
    failure.textContent = job.status === 'failed' ? failureMessage(job.failureCode) : '';
    renderResult(job);
  }

  async function selectJob(id, quiet) {
    state.selectedID = id;
    renderJobs();
    var requestNumber = ++state.detailRequest;
    if (!quiet) byID('dark-web-detail-empty').querySelector('p').textContent = 'Loading investigation…';
    try {
      var raw = await api('GET', '/investigations/' + encodeURIComponent(id));
      if (requestNumber !== state.detailRequest) return;
      var job = normalizedJob(raw);
      if (!job) throw new Error('The server returned an invalid investigation record.');
      state.detail = job;
      renderDetail(job);
    } catch (error) {
      if (requestNumber !== state.detailRequest) return;
      state.detail = null;
      renderDetail(null);
      setMessage(error.message, 'error');
    }
  }

  function schedulePoll() {
    clearTimeout(state.pollTimer);
    state.pollTimer = null;
    if (!state.open || document.hidden || !state.jobs.some(function (job) { return !TERMINAL[job.status]; })) return;
    state.pollTimer = setTimeout(function () { loadJobs(false); }, 2500);
  }

  async function submitInvestigation(event) {
    event.preventDefault();
    if (state.busy || !state.config || !state.config.enabled) return;
    var target = byID('dark-web-target').value.trim();
    if (!target) { setMessage('Enter a target first.', 'error'); byID('dark-web-target').focus(); return; }
    if (!byID('dark-web-ack').checked) { setMessage('Confirm that the investigation is authorized.', 'error'); byID('dark-web-ack').focus(); return; }
    state.busy = true;
    setAvailability(true, 'Available');
    setMessage('Submitting the bounded job…', 'info');
    try {
      var raw = await api('POST', '/investigations', { target: target, acknowledgedAuthorizedUse: true });
      var job = normalizedJob(raw);
      if (!job) throw new Error('The server returned an invalid investigation record.');
      state.selectedID = job.id;
      state.detail = job;
      byID('dark-web-target').value = '';
      byID('dark-web-ack').checked = false;
      setMessage('Investigation queued. It is safe to close this window.', 'ok');
      await loadJobs(false);
    } catch (error) {
      setMessage(error.message, 'error');
    } finally {
      state.busy = false;
      setAvailability(!!(state.config && state.config.enabled), state.config && state.config.enabled ? 'Available' : 'Disabled');
    }
  }

  async function cancelSelected() {
    if (!state.detail || TERMINAL[state.detail.status]) return;
    byID('dark-web-cancel-btn').disabled = true;
    try {
      var job = normalizedJob(await api('POST', '/investigations/' + encodeURIComponent(state.detail.id) + '/cancel'));
      if (job) { state.detail = job; renderDetail(job); }
      await loadJobs(false);
    } catch (error) {
      setMessage(error.message, 'error');
      byID('dark-web-cancel-btn').disabled = false;
    }
  }

  async function deleteSelected() {
    if (!state.detail || !TERMINAL[state.detail.status]) return;
    if (!window.confirm('Delete this investigation and its encrypted results now?')) return;
    var id = state.detail.id;
    byID('dark-web-delete-btn').disabled = true;
    try {
      await api('DELETE', '/investigations/' + encodeURIComponent(id));
      state.selectedID = null;
      state.detail = null;
      setMessage('Investigation deleted.', 'ok');
      await loadJobs(true);
    } catch (error) {
      setMessage(error.message, 'error');
      byID('dark-web-delete-btn').disabled = false;
    }
  }

  function addSelectedToBoard() {
    if (!state.detail || !state.detail.result || !window.InvestigationBoards ||
        typeof window.InvestigationBoards.seedFromDarkWeb !== 'function') {
      setMessage('Investigation boards are not available.', 'error');
      return;
    }
    var detail = state.detail;
    closeDialog();
    window.InvestigationBoards.seedFromDarkWeb(detail.target, detail.result);
  }

  async function refresh() {
    await loadStatus();
    await loadJobs(true);
  }

  function openDialog() {
    if (state.open) return;
    state.open = true;
    state.previousFocus = document.activeElement;
    state.previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    var overlay = byID('dark-web-overlay');
    overlay.classList.remove('hidden');
    overlay.classList.add('flex');
    overlay.setAttribute('aria-hidden', 'false');
    byID('dark-web-panel').focus();
    refresh();
  }

  function closeDialog() {
    if (!state.open) return;
    state.open = false;
    clearTimeout(state.pollTimer);
    state.pollTimer = null;
    var overlay = byID('dark-web-overlay');
    overlay.classList.add('hidden');
    overlay.classList.remove('flex');
    overlay.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = state.previousOverflow;
    if (state.previousFocus && typeof state.previousFocus.focus === 'function') state.previousFocus.focus();
  }

  function trapKeys(event) {
    if (!state.open) return;
    if (event.key === 'Escape') { event.preventDefault(); closeDialog(); return; }
    if (event.key !== 'Tab') return;
    var focusable = Array.prototype.filter.call(byID('dark-web-panel').querySelectorAll('button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])'), function (item) {
      return item.offsetParent !== null;
    });
    if (!focusable.length) return;
    var first = focusable[0], last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }

  function ready() {
    var toggle = byID('dark-web-toggle-btn');
    if (!toggle || !byID('dark-web-overlay')) return;
    setAvailability(false, 'Checking…');
    toggle.addEventListener('click', openDialog);
    byID('dark-web-close-btn').addEventListener('click', closeDialog);
    byID('dark-web-overlay').addEventListener('click', function (event) { if (event.target === event.currentTarget) closeDialog(); });
    byID('dark-web-form').addEventListener('submit', submitInvestigation);
    byID('dark-web-refresh-btn').addEventListener('click', refresh);
    byID('dark-web-cancel-btn').addEventListener('click', cancelSelected);
    byID('dark-web-delete-btn').addEventListener('click', deleteSelected);
    byID('dark-web-board-btn').addEventListener('click', addSelectedToBoard);
    document.addEventListener('keydown', trapKeys);
    document.addEventListener('visibilitychange', function () { if (!document.hidden && state.open) loadJobs(false); else schedulePoll(); });

    var auth = byID('auth-logged-in');
    if (auth && window.MutationObserver) {
      new MutationObserver(function () { if (auth.classList.contains('hidden')) closeDialog(); })
        .observe(auth, { attributes: true, attributeFilter: ['class'] });
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ready); else ready();
})();
