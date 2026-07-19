/* Investigation Boards — a FlowSint-style interactive relationship graph.
 *
 * Self-contained (only depends on the global d3 from /d3.min.js and the DOM).
 * You add an entity, click it → Expand, and the app scans it and merges the
 * discovered entities/relationships into a persistent graph you can keep growing.
 * Boards are saved server-side (encrypted at rest) via /api/investigations.
 */
(function () {
  'use strict';

  var board = { id: null, name: '', nodes: [], edges: [] };
  var sim = null, dirty = false, saveTimer = null;
  var hiddenTypes = {};          // etype -> true when filtered out of the view
  var showEdgeLabels = null;     // null = auto (hide on busy graphs), else forced
  var zoomBehavior = null, zoomRoot = null;
  function isMobile() { return window.innerWidth < 768; }

  // ── small API helper ──────────────────────────────────────────────────────
  function api(method, path, body) {
    var opts = { method: method, credentials: 'include', headers: {} };
    if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    return fetch('/api' + path, opts);
  }
  function status(msg) {
    ['board-status', 'board-status-m'].forEach(function (id) {
      var el = document.getElementById(id); if (el) el.textContent = msg || '';
    });
  }

  // ── legend + type filters ─────────────────────────────────────────────────
  // Doubles as the colour legend: each chip shows the type, its colour and how
  // many nodes carry it; clicking hides/shows that type (an expansion can add 40
  // account nodes — this is how you cut the noise).
  function renderFilters() {
    var bar = document.getElementById('board-filters');
    if (!bar) return;
    var counts = {};
    board.nodes.forEach(function (n) { counts[n.etype] = (counts[n.etype] || 0) + 1; });
    var types = Object.keys(counts).sort();
    if (!types.length) { bar.innerHTML = '<span class="text-[11px] text-slate-600">No entities yet.</span>'; return; }
    bar.innerHTML = types.map(function (t) {
      var off = hiddenTypes[t];
      return '<button data-type="' + t + '" class="board-filter-chip text-[11px] px-2 py-1 rounded border transition-colors ' +
        (off ? 'border-dark-700 bg-dark-800 text-slate-600' : 'border-dark-600 bg-dark-800 text-slate-200') + '">' +
        '<span style="color:' + color(t) + ';opacity:' + (off ? '.35' : '1') + '">●</span> ' + escapeHtml(t) + ' <span class="text-slate-500">' + counts[t] + '</span></button>';
    }).join('') + '<span class="text-[11px] text-slate-600 ml-auto self-center">' + board.nodes.length + ' nodes · ' + board.edges.length + ' links</span>';
    Array.prototype.forEach.call(bar.querySelectorAll('.board-filter-chip'), function (b) {
      b.onclick = function () {
        var t = b.getAttribute('data-type');
        if (hiddenTypes[t]) delete hiddenTypes[t]; else hiddenTypes[t] = true;
        render();
      };
    });
  }

  /// Zoom/pan so the whole graph fits the viewport.
  function fitToView() {
    if (!zoomBehavior || !zoomRoot || !board.nodes.length) return;
    var d3 = window.d3, svgEl = document.getElementById('board-svg');
    var W = svgEl.clientWidth || 800, H = svgEl.clientHeight || 500;
    var vis = board.nodes.filter(function (n) { return !hiddenTypes[n.etype] && typeof n.x === 'number'; });
    if (!vis.length) return;
    var xs = vis.map(function (n) { return n.x; }), ys = vis.map(function (n) { return n.y; });
    var minX = Math.min.apply(null, xs), maxX = Math.max.apply(null, xs);
    var minY = Math.min.apply(null, ys), maxY = Math.max.apply(null, ys);
    var w = Math.max(maxX - minX, 50), h = Math.max(maxY - minY, 50);
    var k = Math.min(2, 0.85 * Math.min(W / w, H / h));
    var tx = W / 2 - k * (minX + maxX) / 2, ty = H / 2 - k * (minY + maxY) / 2;
    d3.select(svgEl).transition().duration(400)
      .call(zoomBehavior.transform, d3.zoomIdentity.translate(tx, ty).scale(k));
  }

  // ── entity typing ─────────────────────────────────────────────────────────
  var PIVOTABLE = { email: 1, username: 1, domain: 1, ip: 1, phone: 1 };
  function inferType(v) {
    v = String(v).trim();
    if (v.indexOf('@') > 0) return 'email';
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ip';
    if (/^\+?\d[\d\s\-]{6,}$/.test(v)) return 'phone';
    if (v.indexOf('.') > 0 && v.indexOf(' ') < 0) return 'domain';
    return 'username';
  }
  var COLORS = {
    root: '#10b981', email: '#22d3ee', username: '#3b82f6', domain: '#a78bfa',
    ip: '#f59e0b', phone: '#ec4899', account: '#64748b', breach: '#ef4444',
    exposure: '#ef4444', risk: '#f97316'
  };
  function color(t) { return COLORS[t] || '#94a3b8'; }
  // Bigger hit areas on touch screens — 6px dots are unusable with a finger.
  function radius(d) {
    var base = d.root ? 16 : PIVOTABLE[d.etype] ? 10 : 6;
    return isMobile() ? base + 4 : base;
  }

  // ── graph mutation ────────────────────────────────────────────────────────
  function nodeById(id) { for (var i = 0; i < board.nodes.length; i++) if (board.nodes[i].id === id) return board.nodes[i]; return null; }
  function addNode(id, label, etype, root) {
    id = String(id).trim().toLowerCase();
    if (!id) return null;
    var n = nodeById(id);
    if (n) { if (root) n.root = true; return n; }
    n = { id: id, label: (label || id).slice(0, 48), etype: etype || inferType(id), root: !!root, expanded: false };
    board.nodes.push(n);
    return n;
  }
  function addEdge(s, t, rel) {
    s = String(s).toLowerCase(); t = String(t).toLowerCase();
    if (s === t) return;
    for (var i = 0; i < board.edges.length; i++) {
      var e = board.edges[i];
      var es = (typeof e.source === 'object' ? e.source.id : e.source);
      var et = (typeof e.target === 'object' ? e.target.id : e.target);
      if (es === s && et === t) return;
    }
    board.edges.push({ source: s, target: t, rel: rel || 'related' });
  }

  // ── extract entities + relationships from a scan's results ────────────────
  function mergeScan(rootId, results) {
    rootId = String(rootId).toLowerCase();
    var accounts = 0, added = 0;
    (results || []).forEach(function (r) {
      var m = r.metadata || {}, t = (r.type || '').toLowerCase(), s = r.source || '';
      function link(id, label, etype, rel) {
        if (!id) return;
        id = String(id); if (id.toLowerCase() === rootId) return;
        if (addNode(id, label, etype)) added++;
        addEdge(rootId, id.toLowerCase(), rel);
      }
      if (m.email) link(m.email, m.email, 'email', 'email');
      if (m.username && m.username.toLowerCase() !== rootId) link(m.username, m.username, 'username', 'alias');
      if (m.domain && m.domain.toLowerCase() !== rootId) link(m.domain, m.domain, 'domain', 'domain');
      if (m.subdomain) link(m.subdomain, m.subdomain, 'domain', 'subdomain');
      if (m.ip) link(m.ip, m.ip, 'ip', 'resolves-to');
      if (t.indexOf('phone') >= 0 && (m.phone || r.rawData)) link(m.phone || r.rawData, m.phone || r.rawData, 'phone', 'phone');
      if (t.indexOf('breach') >= 0 && t !== 'breach_check') link('breach:' + (m.name || s), (m.name || (r.rawData || 'breach')).slice(0, 36), 'breach', 'breached-in');
      if (t === 'exposed_file') link('exposure:' + (m.url || r.rawData), (r.rawData || 'exposed file').slice(0, 40), 'exposure', 'exposes');
      if (t === 'email_spoofable') link('risk:' + rootId, 'email spoofable', 'risk', 'weak-email');
      if ((t.indexOf('account') >= 0 || t.indexOf('social') >= 0 || t.indexOf('profile') >= 0) && accounts < 40) {
        accounts++; link(rootId + ' @ ' + s, '@' + s, 'account', 'account-on');
      }
    });
    return added;
  }

  // ── named transforms per entity type (FlowSint-style enrichers) ───────────
  // Each transform runs a focused subset of plugins instead of all 32, so an
  // "email → breaches" pivot is fast and precise. Names are the API plugin names.
  var TRANSFORMS = {
    email: [
      { label: 'Breaches', plugins: ['haveibeenpwned'] },
      { label: 'Linked accounts', plugins: ['bulkemailosint'] },
      { label: 'Gravatar', plugins: ['gravatarcheck'] },
      { label: 'Email intel', plugins: ['emailintel'] },
      { label: 'Pastes', plugins: ['pastebinosint'] }
    ],
    username: [
      { label: 'Accounts (480+)', plugins: ['bulkosint'] },
      { label: 'GitHub / GitLab', plugins: ['githubaccountcheck', 'gitlabaccountcheck'] },
      { label: 'Social', plugins: ['reddit', 'twitterosint', 'mastodonosint', 'telegramosint', 'steamaccountcheck', 'hackernews', 'keybaseosint'] },
      { label: 'Packages', plugins: ['npmpackages', 'pypipackages'] }
    ],
    domain: [
      { label: 'DNS + WHOIS', plugins: ['domainosint', 'whois'] },
      { label: 'Email security', plugins: ['mailsecurity'] },
      { label: 'Subdomains', plugins: ['certificatetransparency', 'passivedns'] },
      { label: 'Attack surface', plugins: ['attacksurface'] },
      { label: 'Web posture', plugins: ['webposture'] },
      { label: 'Exposed files', plugins: ['exposedfiles'] },
      { label: 'Typosquats', plugins: ['typosquat'] },
      { label: 'Reputation', plugins: ['virustotal'] }
    ],
    ip: [
      { label: 'Ports & CVEs', plugins: ['internetdb', 'shodan'] },
      { label: 'Reputation', plugins: ['abuseipdb', 'virustotal'] },
      { label: 'DNS / Geo', plugins: ['domainosint'] }
    ],
    phone: [
      { label: 'Phone OSINT', plugins: ['phoneosint'] }
    ]
  };

  // ── expand: scan an entity and grow the graph ─────────────────────────────
  // `plugins` (optional) narrows the enrichers run — a named transform; omitted
  // runs everything.
  function expand(node, plugins, label) {
    if (!node) return;
    node.expanded = true;
    status((label ? label + ': ' : 'Expanding ') + node.label + ' …');
    var body = { input: node.id, force: false };
    if (plugins && plugins.length) body.plugins = plugins;
    api('POST', '/scan', body).then(function (res) {
      if (!res.ok) throw new Error('scan rejected');
      return res.json();
    }).then(function (d) {
      var sid = d.scanID;
      var tries = 0;
      (function poll() {
        api('GET', '/results/' + sid).then(function (r) { return r.json(); }).then(function (data) {
          if ((data.status === 'completed' || data.status === 'failed') || tries > 40) {
            var n = mergeScan(node.id, data.results || []);
            status(n + ' new entit' + (n === 1 ? 'y' : 'ies') + ' from ' + node.label);
            render(); scheduleSave();
          } else { tries++; setTimeout(poll, 1500); }
        }).catch(function () { status('Expand failed.'); });
      })();
    }).catch(function () { node.expanded = false; status('Could not scan ' + node.label + ' (rate limit or invalid).'); });
  }

  // ── persistence ───────────────────────────────────────────────────────────
  function serialize() {
    return JSON.stringify({
      nodes: board.nodes.map(function (n) { return { id: n.id, label: n.label, etype: n.etype, root: n.root, expanded: n.expanded, x: n.x, y: n.y }; }),
      edges: board.edges.map(function (e) { return { source: (typeof e.source === 'object' ? e.source.id : e.source), target: (typeof e.target === 'object' ? e.target.id : e.target), rel: e.rel }; })
    });
  }
  function scheduleSave() { dirty = true; clearTimeout(saveTimer); saveTimer = setTimeout(saveBoard, 1500); }
  function saveBoard() {
    if (!board.nodes.length && !board.id) return;
    var name = (document.getElementById('board-name-input').value || board.name || 'Untitled').trim();
    board.name = name;
    var payload = { name: name, data: serialize() };
    if (board.id) {
      api('PUT', '/investigations/' + board.id, payload).then(function (r) { status(r.ok ? 'Saved.' : 'Save failed.'); if (r.ok) dirty = false; });
    } else {
      api('POST', '/investigations', payload).then(function (r) { return r.ok ? r.json() : null; }).then(function (d) {
        if (d) { board.id = d.id; dirty = false; status('Saved.'); loadList(); }
      });
    }
  }
  function loadList() {
    api('GET', '/investigations').then(function (r) { return r.ok ? r.json() : []; }).then(function (list) {
      var sel = document.getElementById('board-list-select');
      sel.innerHTML = '<option value="">— open a board —</option>' +
        list.map(function (b) { return '<option value="' + b.id + '"' + (b.id === board.id ? ' selected' : '') + '>' + escapeHtml(b.name) + ' (' + b.nodeCount + ')</option>'; }).join('');
    });
  }
  // ── cross-board links ─────────────────────────────────────────────────────
  // A compact index (board → node ids) lets us spot an entity that also appears
  // in another investigation, and offer to pull that board in.
  var boardIndex = [];
  function loadIndex() {
    return api('GET', '/investigations/index').then(function (r) { return r.ok ? r.json() : []; })
      .then(function (ix) { boardIndex = ix || []; return boardIndex; }).catch(function () { boardIndex = []; });
  }
  /// Other boards (not the current one) that contain `nodeId`.
  function sharedWith(nodeId) {
    return boardIndex.filter(function (b) {
      return b.id !== board.id && (b.nodes || []).indexOf(nodeId) >= 0;
    });
  }
  function anyShared(nodeId) { return sharedWith(nodeId).length > 0; }

  /// Pull another board's nodes/edges into this one (dedup by node id).
  function mergeBoard(otherId, otherName) {
    api('GET', '/investigations/' + otherId).then(function (r) { return r.ok ? r.json() : null; }).then(function (d) {
      if (!d) return;
      var g; try { g = JSON.parse(d.data); } catch (e) { return; }
      var before = board.nodes.length;
      (g.nodes || []).forEach(function (n) { addNode(n.id, n.label, n.etype, n.root); });
      (g.edges || []).forEach(function (e) { addEdge(e.source, e.target, e.rel); });
      status('Merged “' + otherName + '” (+' + (board.nodes.length - before) + ' nodes).');
      detail(null); render(); scheduleSave();
    });
  }

  /// Seed a brand-new board from a completed scan (target + its entities).
  function seedFromScan(scan) {
    if (!scan || !scan.input) { status('Run a scan first.'); return; }
    newBoard();
    board.name = 'Scan: ' + scan.input;
    document.getElementById('board-name-input').value = board.name;
    var root = addNode(scan.input, scan.input, inferType(scan.input), true);
    root.expanded = true;
    var n = mergeScan(scan.input, scan.results || []);
    status('Seeded from scan — ' + n + ' entit' + (n === 1 ? 'y' : 'ies') + '.');
    open(); render(); scheduleSave(); setTimeout(fitToView, 900);
  }

  function loadBoard(id) {
    if (!id) return;
    api('GET', '/investigations/' + id).then(function (r) { return r.ok ? r.json() : null; }).then(function (d) {
      if (!d) return;
      var g = {};
      try { g = JSON.parse(d.data); } catch (e) { g = { nodes: [], edges: [] }; }
      board = { id: d.id, name: d.name, nodes: g.nodes || [], edges: g.edges || [] };
      document.getElementById('board-name-input').value = d.name;
      status('Opened “' + d.name + '”.'); render(); setTimeout(fitToView, 900);
    });
  }
  function newBoard() {
    board = { id: null, name: '', nodes: [], edges: [] };
    document.getElementById('board-name-input').value = '';
    document.getElementById('board-list-select').value = '';
    detail(null); status('New board.'); render();
  }
  function deleteBoard() {
    if (!board.id) { newBoard(); return; }
    if (!confirm('Delete this board?')) return;
    api('DELETE', '/investigations/' + board.id).then(function () { newBoard(); loadList(); });
  }

  function escapeHtml(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

  // ── export ────────────────────────────────────────────────────────────────
  function download(content, filename, mime) {
    var blob = new Blob([content], { type: mime });
    var a = document.createElement('a');
    a.download = filename; a.href = URL.createObjectURL(blob); document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  function safeName() { return (board.name || 'board').replace(/[^a-z0-9._-]+/gi, '_'); }

  /// GraphML for Maltego / Gephi / yEd. Node ids are index-based (values live in
  /// the label) so entity strings with @/spaces stay valid XML.
  function exportGraphML() {
    if (!board.nodes.length) { status('Nothing to export.'); return; }
    var idx = {}; board.nodes.forEach(function (n, i) { idx[n.id] = 'n' + i; });
    var x = '<?xml version="1.0" encoding="UTF-8"?>\n<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n' +
      '  <key id="label" for="node" attr.name="label" attr.type="string"/>\n' +
      '  <key id="type" for="node" attr.name="type" attr.type="string"/>\n' +
      '  <key id="rel" for="edge" attr.name="rel" attr.type="string"/>\n' +
      '  <graph edgedefault="directed">\n';
    board.nodes.forEach(function (n, i) {
      x += '    <node id="n' + i + '"><data key="label">' + escapeHtml(n.label) + '</data><data key="type">' + escapeHtml(n.etype) + '</data></node>\n';
    });
    board.edges.forEach(function (e, i) {
      var s = (typeof e.source === 'object' ? e.source.id : e.source), t = (typeof e.target === 'object' ? e.target.id : e.target);
      if (idx[s] && idx[t]) x += '    <edge id="e' + i + '" source="' + idx[s] + '" target="' + idx[t] + '"><data key="rel">' + escapeHtml(e.rel) + '</data></edge>\n';
    });
    x += '  </graph>\n</graphml>\n';
    download(x, safeName() + '.graphml', 'application/xml');
    status('Exported GraphML.');
  }

  function exportPNG() {
    var svg = document.getElementById('board-svg');
    var W = svg.clientWidth || 800, H = svg.clientHeight || 500;
    var clone = svg.cloneNode(true);
    clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    clone.setAttribute('width', W); clone.setAttribute('height', H);
    var bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    bg.setAttribute('width', W); bg.setAttribute('height', H); bg.setAttribute('fill', '#0b1120');
    clone.insertBefore(bg, clone.firstChild);
    var data = new XMLSerializer().serializeToString(clone);
    var img = new Image();
    img.onload = function () {
      var c = document.createElement('canvas'); c.width = W * 2; c.height = H * 2;
      var ctx = c.getContext('2d'); ctx.scale(2, 2); ctx.drawImage(img, 0, 0);
      var a = document.createElement('a'); a.download = safeName() + '.png'; a.href = c.toDataURL('image/png');
      document.body.appendChild(a); a.click(); a.remove();
      status('Exported PNG.');
    };
    img.onerror = function () { status('PNG export failed.'); };
    img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(data)));
  }

  // ── detail / actions panel ────────────────────────────────────────────────
  function detail(node) {
    var empty = document.getElementById('board-detail-empty');
    var content = document.getElementById('board-detail-content');
    var sheet = document.getElementById('board-detail');
    // On phones the panel is a bottom sheet: only raise it when a node is picked.
    if (!node) {
      empty.classList.remove('hidden'); content.classList.add('hidden');
      sheet.classList.remove('sheet-open');
      return;
    }
    sheet.classList.add('sheet-open');
    empty.classList.add('hidden'); content.classList.remove('hidden');
    var canExpand = PIVOTABLE[node.etype];
    var transforms = TRANSFORMS[node.etype] || [];
    var html =
      '<div class="text-sm text-white break-all mb-1">' + escapeHtml(node.label) + '</div>' +
      '<div class="text-[11px] mb-3"><span style="color:' + color(node.etype) + '">●</span> ' + node.etype + (node.root ? ' · root' : '') + '</div>';
    if (canExpand) {
      html += '<button id="board-expand-btn" class="w-full text-xs py-1.5 mb-2 bg-brand-600 hover:bg-brand-500 text-white rounded">' + (node.expanded ? '↻ Re-expand (all)' : '⚡ Expand (all)') + '</button>';
      if (transforms.length) {
        html += '<p class="text-[10px] text-slate-500 uppercase tracking-widest mt-3 mb-1">Transforms</p>';
        transforms.forEach(function (t, i) {
          html += '<button data-tf="' + i + '" class="board-tf-btn w-full text-left text-[11px] py-1 px-2 mb-1 bg-dark-800 hover:bg-dark-700 border border-dark-700 text-slate-300 rounded">↳ ' + escapeHtml(t.label) + '</button>';
        });
      }
    } else {
      html += '<p class="text-[11px] text-slate-500 mb-2">Leaf node (not scannable).</p>';
    }
    var also = sharedWith(node.id);
    if (also.length) {
      html += '<p class="text-[10px] text-amber-400 uppercase tracking-widest mt-3 mb-1">Also in ' + also.length + ' other board' + (also.length > 1 ? 's' : '') + '</p>';
      also.forEach(function (b, i) {
        html += '<button data-merge="' + i + '" class="board-merge-btn w-full text-left text-[11px] py-1 px-2 mb-1 bg-amber-900/20 hover:bg-amber-900/40 border border-amber-700/40 text-amber-200 rounded">⇄ Merge “' + escapeHtml(b.name) + '”</button>';
      });
    }
    html += '<button id="board-remove-btn" class="w-full text-xs py-1.5 mt-2 bg-dark-700 hover:bg-red-700/60 text-slate-300 rounded">Remove node</button>';
    content.innerHTML = html;
    Array.prototype.forEach.call(content.querySelectorAll('.board-merge-btn'), function (b) {
      b.onclick = function () { var o = also[+b.getAttribute('data-merge')]; mergeBoard(o.id, o.name); };
    });

    var eb = document.getElementById('board-expand-btn');
    if (eb) eb.onclick = function () { expand(node); };
    Array.prototype.forEach.call(content.querySelectorAll('.board-tf-btn'), function (b) {
      b.onclick = function () { var t = transforms[+b.getAttribute('data-tf')]; expand(node, t.plugins, t.label); };
    });
    document.getElementById('board-remove-btn').onclick = function () { removeNode(node); };
  }
  function removeNode(node) {
    board.nodes = board.nodes.filter(function (n) { return n.id !== node.id; });
    board.edges = board.edges.filter(function (e) {
      var s = (typeof e.source === 'object' ? e.source.id : e.source), t = (typeof e.target === 'object' ? e.target.id : e.target);
      return s !== node.id && t !== node.id;
    });
    detail(null); render(); scheduleSave();
  }

  // ── D3 render ─────────────────────────────────────────────────────────────
  function render() {
    var d3 = window.d3; if (!d3) return;
    var svgEl = document.getElementById('board-svg');
    document.getElementById('board-hint').style.display = board.nodes.length ? 'none' : 'flex';
    var W = svgEl.clientWidth || 800, H = svgEl.clientHeight || 500;
    var svg = d3.select(svgEl); svg.selectAll('*').remove();
    if (sim) { sim.stop(); }

    var g = svg.append('g');
    zoomRoot = g;
    zoomBehavior = d3.zoom().scaleExtent([0.2, 5]).on('zoom', function (ev) { g.attr('transform', ev.transform); });
    svg.call(zoomBehavior);

    // Apply type filters: keep visible nodes, and only edges whose endpoints survive.
    function eid(x) { return (x && typeof x === 'object') ? x.id : x; }
    var vnodes = board.nodes.filter(function (n) { return !hiddenTypes[n.etype]; });
    var vis = {}; vnodes.forEach(function (n) { vis[n.id] = 1; });
    var vedges = board.edges.filter(function (e) { return vis[eid(e.source)] && vis[eid(e.target)]; });
    // Relationship labels are noise on a busy board — auto-hide past 40 links
    // unless the user has explicitly toggled them.
    var labelsOn = (showEdgeLabels === null) ? (vedges.length <= 40) : showEdgeLabels;

    var link = g.append('g').selectAll('line').data(vedges).enter().append('line')
      .attr('stroke', '#334155').attr('stroke-width', 1.2);
    var linkLabel = g.append('g').selectAll('text').data(labelsOn ? vedges : []).enter().append('text')
      .text(function (d) { return d.rel; }).attr('font-size', 8).attr('fill', '#475569').attr('text-anchor', 'middle');

    var node = g.append('g').selectAll('g').data(vnodes).enter().append('g').style('cursor', 'pointer')
      .call(d3.drag()
        .on('start', function (ev, d) { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', function (ev, d) { d.fx = ev.x; d.fy = ev.y; })
        .on('end', function (ev, d) { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null; scheduleSave(); }))
      .on('click', function (ev, d) { ev.stopPropagation(); detail(d); })
      .on('dblclick', function (ev, d) { ev.stopPropagation(); if (PIVOTABLE[d.etype]) expand(d); })
      .on('mouseover', function (ev, d) {
        var tt = document.getElementById('board-graph-tooltip');
        tt.textContent = d.label + '  ·  ' + d.etype; tt.classList.remove('hidden');
        tt.style.left = (ev.offsetX + 12) + 'px'; tt.style.top = (ev.offsetY + 12) + 'px';
      })
      .on('mouseout', function () { document.getElementById('board-graph-tooltip').classList.add('hidden'); });

    // Amber dashed halo = this entity also exists in another investigation board.
    node.filter(function (d) { return anyShared(d.id); }).append('circle')
      .attr('r', function (d) { return radius(d) + 5; })
      .attr('fill', 'none').attr('stroke', '#f59e0b').attr('stroke-width', 1.2).attr('stroke-dasharray', '3,2');
    node.append('circle').attr('r', radius).attr('fill', function (d) { return color(d.root ? 'root' : d.etype); })
      .attr('stroke', '#0b1120').attr('stroke-width', 2);
    node.append('text').text(function (d) { return d.label; })
      .attr('x', function (d) { return radius(d) + 4; }).attr('y', 4).attr('font-size', 10).attr('fill', '#cbd5e1');

    renderFilters();

    sim = d3.forceSimulation(vnodes)
      .force('link', d3.forceLink(vedges).id(function (d) { return d.id; }).distance(90).strength(0.4))
      .force('charge', d3.forceManyBody().strength(-240))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide(function (d) { return radius(d) + 14; }))
      .on('tick', function () {
        link.attr('x1', function (d) { return d.source.x; }).attr('y1', function (d) { return d.source.y; })
          .attr('x2', function (d) { return d.target.x; }).attr('y2', function (d) { return d.target.y; });
        linkLabel.attr('x', function (d) { return (d.source.x + d.target.x) / 2; }).attr('y', function (d) { return (d.source.y + d.target.y) / 2; });
        node.attr('transform', function (d) { return 'translate(' + d.x + ',' + d.y + ')'; });
      });
  }

  // ── wiring ────────────────────────────────────────────────────────────────
  function open() {
    document.getElementById('board-overlay').classList.remove('hidden');
    document.getElementById('board-overlay').classList.add('flex');
    loadList();
    // Refresh the cross-board index, then redraw so shared-entity halos show.
    loadIndex().then(function () { render(); });
    setTimeout(render, 60);
  }
  function close() {
    if (dirty) saveBoard();
    document.getElementById('board-overlay').classList.add('hidden');
    document.getElementById('board-overlay').classList.remove('flex');
  }

  function ready() {
    var btn = document.getElementById('boards-toggle-btn');
    if (btn) btn.addEventListener('click', open);
    document.getElementById('board-close-btn').addEventListener('click', close);
    document.getElementById('board-new-btn').addEventListener('click', newBoard);
    document.getElementById('board-save-btn').addEventListener('click', saveBoard);
    document.getElementById('board-delete-btn').addEventListener('click', deleteBoard);
    document.getElementById('board-export-graphml-btn').addEventListener('click', exportGraphML);
    document.getElementById('board-export-png-btn').addEventListener('click', exportPNG);
    document.getElementById('board-more-btn').addEventListener('click', function () {
      document.getElementById('board-more').classList.toggle('open');
    });
    document.getElementById('board-fit-btn').addEventListener('click', fitToView);
    document.getElementById('board-labels-btn').addEventListener('click', function () {
      // auto → on → off → auto
      showEdgeLabels = (showEdgeLabels === null) ? true : (showEdgeLabels ? false : null);
      status('Relationship labels: ' + (showEdgeLabels === null ? 'auto' : showEdgeLabels ? 'on' : 'off'));
      render();
    });
    document.getElementById('board-detail-close').addEventListener('click', function () { detail(null); });
    // Re-render on rotate/resize so radii and layout follow the viewport.
    window.addEventListener('resize', function () { clearTimeout(window._boardRz); window._boardRz = setTimeout(render, 250); });
    document.getElementById('board-list-select').addEventListener('change', function (e) { if (e.target.value) loadBoard(e.target.value); });
    function addFromInput() {
      var inp = document.getElementById('board-add-input');
      var v = inp.value.trim(); if (!v) return;
      var n = addNode(v, v, inferType(v), true);
      inp.value = ''; detail(n); render(); scheduleSave();
    }
    document.getElementById('board-add-btn').addEventListener('click', addFromInput);
    document.getElementById('board-add-input').addEventListener('keydown', function (e) { if (e.key === 'Enter') addFromInput(); });
    document.getElementById('board-svg').addEventListener('click', function () { detail(null); });

    // "🕸 BOARD" in the scan-results toolbar: seed a fresh board from the scan
    // currently on screen. `lastScanData` is owned by the page's inline script.
    var seedBtn = document.getElementById('seed-board-btn');
    if (seedBtn) seedBtn.addEventListener('click', function () {
      var scan = null;
      try { scan = (typeof lastScanData !== 'undefined') ? lastScanData : null; } catch (e) { scan = null; }
      seedFromScan(scan);
    });
  }

  // Small public surface so the page can drive the board too.
  window.InvestigationBoards = { open: open, seedFromScan: seedFromScan };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ready); else ready();
})();
