let currentScanId = null;
let pollTimer = null;
let lastEventCount = 0;

// ---- Theme toggle ----
(function() {
  const toggle = document.getElementById('themeToggle');
  const saved = localStorage.getItem('theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const initial = saved || (prefersDark ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', initial);
  toggle.setAttribute('aria-pressed', initial === 'dark');

  toggle.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    toggle.setAttribute('aria-pressed', next === 'dark');
  });
})();

// ---- Health check ----
fetch('/api/health').then(r => r.json()).then(h => {
  const el = document.getElementById('health');
  const g = h.gemini_configured ? '<span class="ok">Gemini ●</span>' : '<span class="bad">Gemini ○</span>';
  const c = h.claude_configured ? '<span class="ok">Claude ●</span>' : '<span class="bad">Claude ○</span>';
  el.innerHTML = `Consensus Engine: ${g} &nbsp; ${c}`;
}).catch(() => {});

function fillExample(el) {
  document.getElementById('repoInput').value = el.textContent;
}

function newScan() {
  if (pollTimer) clearInterval(pollTimer);
  currentScanId = null;
  document.getElementById('workspace').classList.add('hidden');
  document.getElementById('setup').classList.remove('hidden');
  document.getElementById('repoInput').value = '';
  document.getElementById('setupStatus').textContent = '';
}

async function startScan() {
  const repo = document.getElementById('repoInput').value.trim();
  const status = document.getElementById('setupStatus');
  if (!repo) { status.className = 'setup-status err'; status.textContent = 'Please enter a GitHub repository.'; return; }

  const btn = document.getElementById('scanBtn');
  btn.disabled = true; btn.textContent = 'Starting...';
  status.className = 'setup-status'; status.textContent = 'Connecting to GitHub Core Stream...';

  try {
    const sel = document.getElementById('commitCount').value;
    const maxCommits = sel === 'auto' ? null : parseInt(sel);
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo_url: repo, max_commits: maxCommits })
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || 'Failed to start scan');
    currentScanId = data.scan_id;
    lastEventCount = 0;
    document.getElementById('setup').classList.add('hidden');
    document.getElementById('workspace').classList.remove('hidden');
    initTopology();
    poll();
    pollTimer = setInterval(poll, 1500);
  } catch (e) {
    status.className = 'setup-status err';
    status.textContent = 'Error: ' + e.message;
  } finally {
    btn.disabled = false; btn.textContent = 'Scan';
  }
}

async function poll() {
  if (!currentScanId) return;
  try {
    const resp = await fetch('/api/scan/' + currentScanId);
    const s = await resp.json();
    render(s);
    if (s.status === 'complete' || s.status === 'error') {
      clearInterval(pollTimer);
    }
  } catch (e) { /* keep polling */ }
}

function render(s) {
  // Repo header
  if (s.repo) {
    document.getElementById('repoTitle').textContent = s.repo.repo;
    const meta = [];
    if (s.repo.language) meta.push(s.repo.language);
    if (s.repo.commits) meta.push(s.repo.commits.length + ' commits scanned');
    if (s.repo.description) meta.push(s.repo.description);
    document.getElementById('repoMeta').textContent = meta.join('  •  ');
  } else {
    document.getElementById('repoTitle').textContent = s.repo_url;
  }

  // Risk chip
  const chip = document.getElementById('riskChip');
  if (s.status === 'complete' && s.overall_risk) {
    const r = s.overall_risk.toLowerCase();
    chip.className = 'risk-chip ' + r;
    chip.textContent = 'RISK: ' + r.toUpperCase();
  } else if (s.status === 'error') {
    chip.className = 'risk-chip critical'; chip.textContent = 'ERROR';
  } else {
    chip.className = 'risk-chip'; chip.textContent = s.status.toUpperCase();
  }

  // Severity
  const counts = s.counts || {};
  const sevGrid = document.getElementById('sevGrid');
  sevGrid.innerHTML = ['critical', 'high', 'medium', 'low'].map(sev =>
    `<div class="sev-cell ${sev}"><div class="n">${counts[sev] || 0}</div><div class="l">${sev}</div></div>`
  ).join('');

  // IOC stat
  const iocN = s.ioc_count || 0;
  document.getElementById('iocStat').innerHTML =
    `<div class="ioc-box ${iocN === 0 ? 'zero' : ''}"><span class="l">Confirmed IOCs</span><span class="n">${iocN}</span></div>`;

  // Agents (static roster + scan coverage)
  const agentList = document.getElementById('agentList');
  const active = (s.status === 'scanning' || s.status === 'reviewing');
  const st = s.status === 'complete' ? 'done' : (active ? 'scanning' : 'idle');
  const rows = [
    ['Agent 1 · Package & Name', st],
    ['Agent 2 · Secrets & Obfuscation', st],
    ['Agent 3 · Network Tracer', st],
    ['IOC Matcher · Indicators', st],
  ];
  let extra = '';
  if (typeof s.tokens_saved_commits === 'number') {
    extra = `<div class="agent-row"><span class="nm">Clean commits skipped (AI)</span><span class="st done">${s.tokens_saved_commits}</span></div>`
          + `<div class="agent-row"><span class="nm">Commits flagged</span><span class="st scanning">${s.flagged_count || 0}</span></div>`;
  }
  agentList.innerHTML = rows.map(([nm, status]) =>
    `<div class="agent-row"><span class="nm">${nm}</span><span class="st ${status}">${status}</span></div>`
  ).join('') + extra;

  // Activity
  const act = document.getElementById('activity');
  if ((s.events || []).length !== lastEventCount) {
    lastEventCount = s.events.length;
    act.innerHTML = s.events.map(e => {
      const t = new Date(e.t * 1000).toLocaleTimeString();
      return `<div class="act ${e.kind}"><span class="ts">${t}</span>${escapeHtml(e.message)}</div>`;
    }).join('');
    act.scrollTop = act.scrollHeight;
  }

  // Topology highlight
  updateTopology(s);

  // IOCs
  renderIOCs(s);

  // Findings
  renderFindings(s);

  // Report button
  document.getElementById('reportBtn').disabled = (s.status !== 'complete');

  // Error
  if (s.status === 'error' && s.error) {
    document.getElementById('consensusSummary').innerHTML =
      `<span class="cs-label" style="color:var(--crit)">Scan Error</span>${escapeHtml(s.error)}`;
  }
}

const IOC_TYPE_LABEL = {
  malicious_package: 'Malicious Package',
  c2_exfil_host: 'C2 / Exfil Host',
  suspicious_tld: 'High-Risk TLD',
  malicious_pattern: 'Execution Pattern',
};

function renderIOCs(s) {
  const iocs = s.iocs || [];
  document.getElementById('iocCount').textContent = iocs.length;
  const el = document.getElementById('iocs');
  if (iocs.length === 0) {
    if (s.status === 'complete') {
      el.innerHTML = '<div class="empty">No known indicators of compromise matched in the scanned commits.</div>';
    } else {
      el.innerHTML = '<div class="empty">Checking commits against known-bad indicator lists...</div>';
    }
    return;
  }
  el.innerHTML = iocs.map(i => {
    const sev = (i.severity || 'high').toLowerCase();
    const label = IOC_TYPE_LABEL[i.ioc_type] || 'Indicator';
    return `<div class="ioc ${sev}">
      <div class="ioc-head">
        <span class="ioc-type-badge">${escapeHtml(label)}</span>
        <span class="badge sev-${sev}">${sev}</span>
        <span class="ioc-indicator">${escapeHtml(i.indicator || i.title || '')}</span>
      </div>
      <div class="meta">${escapeHtml(i.filename || '')}${i.commit ? ' · ' + escapeHtml(i.commit) : ''}${i.evidence ? ' · ' + escapeHtml(i.evidence) : ''}</div>
      ${i.explanation ? `<div class="ioc-expl">${escapeHtml(i.explanation)}</div>` : ''}
    </div>`;
  }).join('');
}

function renderFindings(s) {
  const summaryEl = document.getElementById('consensusSummary');
  const findingsEl = document.getElementById('findings');
  const countEl = document.getElementById('findingsCount');

  const commits = s.commits || [];
  const flaggedCommits = commits.filter(c => c.flagged && c.verdict && c.verdict.worth_alerting);

  // Summary line
  if (s.status === 'complete') {
    const alertWord = flaggedCommits.length
      ? `CUSTOMER ALERT RECOMMENDED — ${flaggedCommits.length} commit(s) introduced risk.`
      : 'No alert required — no recent commit introduced new supply-chain risk.';
    summaryEl.innerHTML = `<span class="cs-label">Analyst Verdict</span>${escapeHtml(alertWord)}` +
      `<br><br><span style="color:var(--muted);font-size:11px">Walked ${commits.length} commit(s); ` +
      `${s.tokens_saved_commits || 0} clean commit(s) skipped AI review (token-efficient).</span>`;
  } else if (s.status === 'error') {
    summaryEl.innerHTML = `<span class="cs-label" style="color:var(--crit)">Scan Error</span>${escapeHtml(s.error || 'unknown')}`;
  } else {
    summaryEl.innerHTML = '<span class="cs-label">Per-Commit Analysis</span>Walking recent commits — only commits that introduce risk are sent to Gemini → Claude.';
  }

  countEl.textContent = flaggedCommits.length;

  // Per-commit timeline
  if (commits.length === 0) {
    findingsEl.innerHTML = '<div class="empty">Fetching commits...</div>';
    return;
  }

  findingsEl.innerHTML = commits.map(c => {
    const v = c.verdict || {};
    const flagged = c.flagged && v.worth_alerting;
    const risk = (v.commit_risk || (c.flagged ? 'noise' : 'clean')).toLowerCase();
    const sevClass = ['critical', 'high', 'medium', 'low'].includes(risk) ? risk : 'low';

    let body = '';
    if (!c.flagged) {
      body = `<div class="vnote" style="color:var(--low)">Clean — no new risk introduced (AI skipped, 0 tokens).</div>`;
    } else if (flagged) {
      body = `<div class="expl">${escapeHtml(v.summary || '')}</div>` +
        (v.findings || []).map(f => {
          const fs = (f.severity || 'low').toLowerCase();
          return `<div style="margin-top:8px;padding-left:10px;border-left:2px solid var(--border)">
            <span class="badge sev-${fs}">${fs}</span> <span class="badge cat">${escapeHtml(f.category || '')}</span>
            <div style="font-weight:600;margin:4px 0">${escapeHtml(f.title || '')}</div>
            ${f.filename ? `<div class="file">${escapeHtml(f.filename)}</div>` : ''}
            ${f.evidence ? `<div class="evidence">${escapeHtml(f.evidence)}</div>` : ''}
            ${f.explanation ? `<div class="expl">${escapeHtml(f.explanation)}</div>` : ''}
            ${f.remediation ? `<div class="rem"><strong>Fix:</strong> ${escapeHtml(f.remediation)}</div>` : ''}
          </div>`;
        }).join('');
    } else {
      body = `<div class="vnote">${escapeHtml(v.summary || 'Scanner flagged this commit, but AI consensus classified it as noise.')}</div>`;
    }

    return `<div class="finding ${sevClass}">
      <div class="finding-head">
        <span class="title">${escapeHtml(c.short_sha)} — ${escapeHtml((c.message || '').slice(0, 70))}</span>
        <span class="badges"><span class="badge sev-${sevClass}">${risk}</span></span>
      </div>
      <div class="file">${escapeHtml(c.author || '')} · ${escapeHtml((c.date || '').slice(0, 10))} · ${c.files_changed || 0} file(s)</div>
      ${body}
    </div>`;
  }).join('');
}

async function downloadReport() {
  const btn = document.getElementById('reportBtn');
  btn.disabled = true; btn.textContent = 'Generating...';
  try {
    const resp = await fetch('/api/scan/' + currentScanId + '/report', { method: 'POST' });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || 'Report failed');
    window.open(data.download_url, '_blank');
  } catch (e) {
    alert('Report error: ' + e.message);
  } finally {
    btn.disabled = false; btn.textContent = 'Download PDF Report';
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------------- D3 Topology ----------------
const PIPELINE = [
  { id: 'github', label: 'GitHub Core Stream', sub: 'commit diff deltas', x: 0.5, y: 0.07 },
  { id: 'core', label: 'Core Server', sub: 'dispatch parallel scans', x: 0.5, y: 0.27 },
  { id: 'a1', label: 'Agent 1', sub: 'Package & Name', x: 0.14, y: 0.48 },
  { id: 'a2', label: 'Agent 2', sub: 'Secrets & Obfuscation', x: 0.38, y: 0.48 },
  { id: 'a3', label: 'Agent 3', sub: 'Network Tracer', x: 0.62, y: 0.48 },
  { id: 'a4', label: 'IOC Matcher', sub: 'known indicators', x: 0.86, y: 0.48 },
  { id: 'ses', label: 'Evidence Store', sub: 'security findings', x: 0.5, y: 0.68 },
  { id: 'gemini', label: 'Gemini', sub: 'primary orchestrator', x: 0.32, y: 0.86 },
  { id: 'claude', label: 'Claude', sub: 'peer validator', x: 0.68, y: 0.86 },
];
const EDGES = [
  ['github', 'core'], ['core', 'a1'], ['core', 'a2'], ['core', 'a3'], ['core', 'a4'],
  ['a1', 'ses'], ['a2', 'ses'], ['a3', 'ses'], ['a4', 'ses'], ['ses', 'gemini'], ['gemini', 'claude'],
];

let svg, W, H;
function initTopology() {
  svg = d3.select('#topology');
  svg.selectAll('*').remove();
  const rect = document.getElementById('topology').getBoundingClientRect();
  W = rect.width || 600; H = 360;

  const pos = {};
  PIPELINE.forEach(n => pos[n.id] = { x: n.x * W, y: n.y * H });

  // edges
  svg.append('g').attr('class', 'edges').selectAll('path')
    .data(EDGES).enter().append('path')
    .attr('class', 'edge')
    .attr('id', d => `edge-${d[0]}-${d[1]}`)
    .attr('d', d => {
      const a = pos[d[0]], b = pos[d[1]];
      return `M${a.x},${a.y + 16} C${a.x},${(a.y + b.y) / 2} ${b.x},${(a.y + b.y) / 2} ${b.x},${b.y - 16}`;
    });

  const g = svg.append('g').attr('class', 'nodes').selectAll('g')
    .data(PIPELINE).enter().append('g')
    .attr('transform', d => `translate(${pos[d.id].x},${pos[d.id].y})`);

  g.append('rect')
    .attr('class', 'node-box')
    .attr('id', d => `node-${d.id}`)
    .attr('x', -68).attr('y', -16).attr('width', 136).attr('height', 36)
    .attr('rx', 8).attr('fill', '#f4f7fb').attr('stroke', '#d8e0ec').attr('stroke-width', 1.4);
  g.append('text').attr('class', 'node-label').attr('text-anchor', 'middle').attr('y', -1).text(d => d.label);
  g.append('text').attr('class', 'node-sublabel').attr('text-anchor', 'middle').attr('y', 11).text(d => d.sub);
}

function updateTopology(s) {
  if (!svg) return;
  const status = s.status;
  const IDLE = '#d8e0ec';
  const setNode = (id, color) => svg.select(`#node-${id}`).attr('stroke', color).attr('stroke-width', color === IDLE ? 1.4 : 2.2);
  const setEdge = (a, b, active) => svg.select(`#edge-${a}-${b}`).attr('stroke', active ? '#2f7fff' : IDLE).attr('stroke-width', active ? 2.2 : 1.6);

  PIPELINE.forEach(n => setNode(n.id, IDLE));

  if (status === 'streaming') setNode('github', '#5aa0ff');
  if (status === 'scanning') {
    setNode('github', '#2ecc71'); setNode('core', '#2f7fff');
    setEdge('github', 'core', true);
    ['a1', 'a2', 'a3', 'a4'].forEach(a => { setNode(a, '#ffc233'); setEdge('core', a, true); setEdge(a, 'ses', true); });
    setNode('ses', '#00bcd4');
  }
  if (status === 'reviewing') {
    setNode('github', '#2ecc71'); setNode('core', '#2ecc71');
    ['a1', 'a2', 'a3', 'a4'].forEach(a => { setNode(a, '#2ecc71'); setEdge('core', a, true); setEdge(a, 'ses', true); });
    setNode('ses', '#00bcd4'); setEdge('ses', 'gemini', true);
    setNode('gemini', '#8a6dff'); setNode('claude', '#d97757'); setEdge('gemini', 'claude', true);
  }
  if (status === 'complete') {
    PIPELINE.forEach(n => setNode(n.id, '#2ecc71'));
    EDGES.forEach(e => setEdge(e[0], e[1], true));
  }
}

window.addEventListener('resize', () => { if (currentScanId && svg) initTopology(); });
