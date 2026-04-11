/* ============================================= */
/*  Triangle AI Security Hub — Client Logic v3   */
/*  Persistent scan history + stable feed        */
/* ============================================= */

Chart.defaults.color = '#8892a4';
Chart.defaults.borderColor = '#2c3038';
Chart.defaults.font.family = "'Roboto', 'Helvetica Neue', Arial, sans-serif";
Chart.defaults.font.size = 11;

let ws = null;
let trendChart = null;
let verdictChart = null;
let currentFilter = 'all';
let lastKnownCount = 0;

// ===== Persistent History (localStorage) =====
const STORAGE_KEY = 'triangle_scan_history';
const MAX_HISTORY = 200;

function loadHistory() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); } 
  catch { return []; }
}
function saveHistory(arr) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(arr.slice(0, MAX_HISTORY)));
}
function mergeEvents(incoming) {
  const history = loadHistory();
  const seen = new Set(history.map(e => e.sha256 + e.timestamp));
  let added = 0;
  for (const ev of incoming) {
    const key = ev.sha256 + ev.timestamp;
    if (!seen.has(key)) {
      history.unshift(ev);
      seen.add(key);
      added++;
    }
  }
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  if (added > 0) saveHistory(history);
  return { history, added };
}

// ===== Init =====
document.addEventListener('DOMContentLoaded', () => {
  checkHealth();
  connectWebSocket();
  setupFilterButtons();
  setupHistoryFilter();
  setupHistorySort();
  document.getElementById('clearHistory')?.addEventListener('click', () => {
    if (confirm('Clear all scan history? This will reset the dashboard data.')) {
      localStorage.removeItem(STORAGE_KEY);
      location.reload();
    }
  });
  initTrendChart();
  initVerdictChart();
  // Render existing history immediately
  renderHistory(loadHistory());
  renderHistoryStats(loadHistory());
  setInterval(fetchData, 10000);
});

// ===== Health =====
async function checkHealth() {
  const el = document.getElementById('statusIndicator');
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    el.innerHTML = data.engine === 'ok'
      ? '<span class="status-dot online"></span><span class="status-text">Engine Online</span>'
      : '<span class="status-dot offline"></span><span class="status-text">Engine Offline</span>';
  } catch {
    el.innerHTML = '<span class="status-dot offline"></span><span class="status-text">Disconnected</span>';
  }
}

// ===== WebSocket =====
function connectWebSocket() {
  const wsUrl = `ws://${location.host}`;
  ws = new WebSocket(wsUrl);
  const wsEl = document.getElementById('wsStatus');
  ws.onopen = () => {
    wsEl.innerHTML = '<span class="ws-dot connected"></span><span class="ws-text">Live</span>';
  };
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === 'update') handleUpdate(msg.events, msg.stats);
  };
  ws.onclose = () => {
    wsEl.innerHTML = '<span class="ws-dot disconnected"></span><span class="ws-text">Reconnecting...</span>';
    setTimeout(connectWebSocket, 3000);
  };
  ws.onerror = () => ws.close();
}

// ===== Fallback =====
async function fetchData() {
  if (ws && ws.readyState === 1) return;
  try {
    const [evRes, stRes] = await Promise.all([
      fetch('/api/events').then(r => r.json()),
      fetch('/api/stats').then(r => r.json()),
    ]);
    handleUpdate(evRes.events, stRes);
  } catch {}
}

// ===== Central Update Handler =====
function handleUpdate(incomingEvents, stats) {
  // Skip if nothing new — prevents flickering
  const { history } = mergeEvents(incomingEvents || []);
  if (history.length === lastKnownCount) return;
  lastKnownCount = history.length;
  // 1. Merge new events into persistent history
  const added = history.length - (lastKnownCount - (history.length - lastKnownCount));

  // 2. Update live activity (only show latest 5 from this session)
  updateLiveFeed(incomingEvents || []);

  // 3. Update persistent scan history table
  renderHistory(history);
  const hStats = computeHistoryStats(history);
  updateStats(hStats);
  updateNodeMap(hStats.nodes);
  updateTrendChart(history);
  updateVerdictChart(hStats);
  updateAIPanel(history);

  // 5. Flash notification for new detections
  if (added > 0) {
    const counter = document.getElementById('newBadge');
    if (counter) { counter.textContent = `+${added}`; counter.style.display = 'inline'; 
      setTimeout(() => counter.style.display = 'none', 3000);
    }
  }
}

// ===== Persistent Stats Computation =====
function computeHistoryStats(history) {
  const nodes = {};
  let total = history.length;
  let threats = 0;
  let high = 0;
  let clean = 0;
  for (const e of history) {
    const n = e.node_name || 'unknown';
    if (!nodes[n]) nodes[n] = { total: 0, threats: 0, high_risk: 0 };
    nodes[n].total++;
    if (e.verdict === 'HIGH RISK' || e.verdict === 'MEDIUM RISK') {
      nodes[n].threats++;
      threats++;
    }
    if (e.verdict === 'HIGH RISK') {
      nodes[n].high_risk++;
      high++;
    }
    if (e.verdict === 'CLEAN') clean++;
  }
  return { total_scans: total, threats_detected: threats, high_risk: high, clean_files: clean, active_nodes: Object.keys(nodes).length, nodes };
}

// ===== Stats =====
function updateStats(s) {
  animateValue('statTotal', s.total_scans || 0);
  animateValue('statThreats', s.threats_detected || 0);
  animateValue('statHigh', s.high_risk || 0);
  animateValue('statClean', s.clean_files || 0);
  animateValue('statNodes', s.active_nodes || 0);
}
function animateValue(id, target) {
  const el = document.getElementById(id);
  const current = parseInt(el.textContent) || 0;
  if (current === target) return;
  const diff = target - current;
  const steps = Math.min(Math.abs(diff), 15);
  const stepVal = diff / steps;
  let i = 0;
  const timer = setInterval(() => {
    i++;
    el.textContent = Math.round(current + stepVal * i);
    if (i >= steps) { el.textContent = target; clearInterval(timer); }
  }, 30);
}

// ===== Node Map =====
function updateNodeMap(nodes) {
  const container = document.getElementById('nodeMap');
  if (!Object.keys(nodes).length) {
    container.innerHTML = '<div class="empty-state">Waiting for scanner data...</div>';
    return;
  }
  let html = '<div class="node-grid">';
  for (const [name, data] of Object.entries(nodes)) {
    const pct = data.total > 0 ? Math.round((data.threats / data.total) * 100) : 0;
    const cls = data.high_risk > 0 ? 'threat' : (data.threats > 0 ? 'warning' : 'clean');
    const barColor = data.high_risk > 0 ? 'var(--accent-red)' : (data.threats > 0 ? 'var(--accent-orange)' : 'var(--accent-green)');
    html += `
      <div class="node-card ${cls}">
        <div class="node-name">● ${name}</div>
        <div class="node-stats">
          <span>Scanned: <span class="node-stat-value">${data.total}</span></span>
          <span>Threats: <span class="node-stat-value" style="color:var(--accent-orange)">${data.threats}</span></span>
          <span>Critical: <span class="node-stat-value" style="color:var(--accent-red)">${data.high_risk}</span></span>
        </div>
        <div class="node-threat-bar"><div class="node-threat-fill" style="width:${Math.max(pct,2)}%;background:${barColor}"></div></div>
      </div>`;
  }
  container.innerHTML = html + '</div>';
}

// ===== Live Activity Feed (top 5, ephemeral) =====
function updateLiveFeed(events) {
  const tbody = document.getElementById('liveFeedBody');
  if (!events.length) return;
  const latest = events.slice(0, 5);
  tbody.innerHTML = latest.map((e, i) => {
    const time = new Date(e.timestamp).toLocaleTimeString();
    const cls = verdictClass(e.verdict);
    const scoreCls = e.risk_score >= 80 ? 'score-high' : e.risk_score >= 50 ? 'score-medium' : 'score-low';
    return `<tr class="${i === 0 ? 'new-event' : ''}">
      <td>${time}</td>
      <td><span class="verdict-badge verdict-${cls}">${e.verdict}</span></td>
      <td class="${scoreCls}">${e.risk_score}</td>
      <td><span class="ns-badge">${e.namespace || '—'}</span></td>
      <td><span class="pod-badge">${e.pod_name || '—'}</span></td>
      <td>${e.node_name}</td>
      <td title="${e.file_path}"><span class="path-text">${e.file_path || e.filename}</span></td>
      <td>${e.type}</td>
    </tr>`;
  }).join('');
}

// ===== Scan History (persistent, all results, sortable) =====
let historyFilter = 'all';
let historySortField = null;  // null | 'verdict' | 'score'
let historySortDir = 0;       // 0=default, 1=desc(high first), 2=asc(low first)

const VERDICT_ORDER = { 'HIGH RISK': 0, 'MEDIUM RISK': 1, 'CLEAN': 2, 'UNKNOWN': 3 };

function renderHistory(history) {
  const tbody = document.getElementById('historyBody');
  const countEl = document.getElementById('historyCount');
  let filtered = history;
  if (historyFilter !== 'all') filtered = history.filter(e => e.verdict === historyFilter);

  // Apply sort
  if (historySortField === 'verdict' && historySortDir > 0) {
    filtered = [...filtered].sort((a, b) => {
      const diff = (VERDICT_ORDER[a.verdict] || 9) - (VERDICT_ORDER[b.verdict] || 9);
      return historySortDir === 1 ? diff : -diff;
    });
  } else if (historySortField === 'score' && historySortDir > 0) {
    filtered = [...filtered].sort((a, b) =>
      historySortDir === 1 ? b.risk_score - a.risk_score : a.risk_score - b.risk_score
    );
  }

  if (countEl) countEl.textContent = `${filtered.length} / ${history.length}`;

  // Update sort indicators
  updateSortIndicators();

  if (!filtered.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="9">No scan results recorded yet.</td></tr>';
    return;
  }
  tbody.innerHTML = filtered.map(e => {
    const time = new Date(e.timestamp).toLocaleString();
    const cls = verdictClass(e.verdict);
    const scoreCls = e.risk_score >= 80 ? 'score-high' : e.risk_score >= 50 ? 'score-medium' : 'score-low';
    const detail = e.details && e.details.length > 0 ? e.details.join(', ') : '—';
    return `<tr>
      <td>${time}</td>
      <td><span class="verdict-badge verdict-${cls}">${e.verdict}</span></td>
      <td class="${scoreCls}">${e.risk_score}</td>
      <td><span class="ns-badge">${e.namespace || '—'}</span></td>
      <td><span class="pod-badge">${e.pod_name || '—'}</span></td>
      <td>${e.node_name || '—'}</td>
      <td title="${e.file_path || ''}"><span class="path-text">${e.file_path || e.filename || '—'}</span></td>
      <td>${e.type || '—'}</td>
      <td title="${detail}">${detail}</td>
    </tr>`;
  }).join('');
}

function updateSortIndicators() {
  const verdictTh = document.getElementById('sortVerdict');
  const scoreTh = document.getElementById('sortScore');
  if (verdictTh) {
    const arrow = historySortField === 'verdict' ? (historySortDir === 1 ? ' ▼' : historySortDir === 2 ? ' ▲' : '') : '';
    verdictTh.textContent = 'Verdict' + arrow;
  }
  if (scoreTh) {
    const arrow = historySortField === 'score' ? (historySortDir === 1 ? ' ▼' : historySortDir === 2 ? ' ▲' : '') : '';
    scoreTh.textContent = 'Score' + arrow;
  }
}

function setupHistorySort() {
  const verdictTh = document.getElementById('sortVerdict');
  const scoreTh = document.getElementById('sortScore');
  if (verdictTh) {
    verdictTh.addEventListener('click', () => {
      if (historySortField !== 'verdict') { historySortField = 'verdict'; historySortDir = 1; }
      else { historySortDir = (historySortDir + 1) % 3; }
      if (historySortDir === 0) historySortField = null;
      renderHistory(loadHistory());
    });
  }
  if (scoreTh) {
    scoreTh.addEventListener('click', () => {
      if (historySortField !== 'score') { historySortField = 'score'; historySortDir = 1; }
      else { historySortDir = (historySortDir + 1) % 3; }
      if (historySortDir === 0) historySortField = null;
      renderHistory(loadHistory());
    });
  }
}

function renderHistoryStats(history) {
  const hStats = computeHistoryStats(history);
  updateStats(hStats);
  updateNodeMap(hStats.nodes);
  updateTrendChart(history);
  updateVerdictChart(hStats);
}
function setupHistoryFilter() {
  document.querySelectorAll('.history-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.history-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      historyFilter = btn.dataset.filter;
      renderHistory(loadHistory());
    });
  });
}

// ===== Live Feed Filter =====
function setupFilterButtons() {
  document.querySelectorAll('.feed-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.feed-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
    });
  });
}

// ===== Trend Chart =====
function initTrendChart() {
  const ctx = document.getElementById('trendChart').getContext('2d');
  trendChart = new Chart(ctx, {
    type: 'line',
    data: { labels: [], datasets: [{
      label: 'Risk Score', data: [],
      borderColor: '#5794f2',
      backgroundColor: createGradient(ctx, 'rgba(87,148,242,0.25)', 'rgba(87,148,242,0.02)'),
      fill: true, tension: 0.35, borderWidth: 2,
      pointRadius: 3, pointHoverRadius: 5,
      pointBackgroundColor: '#5794f2', pointBorderColor: '#22262c', pointBorderWidth: 2,
    }]},
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { display: true, grid: { color: 'rgba(44,48,56,0.6)', drawBorder: false }, ticks: { maxTicksLimit: 10, font: { size: 10 } } },
        y: { beginAtZero: true, max: 100, grid: { color: 'rgba(44,48,56,0.6)', drawBorder: false }, ticks: { stepSize: 25, font: { size: 10 } } }
      },
      plugins: {
        legend: { display: false },
        tooltip: { backgroundColor: '#1e2228', borderColor: '#3a3f4a', borderWidth: 1, padding: 10, cornerRadius: 4 }
      },
      animation: { duration: 300 }
    }
  });
}
function createGradient(ctx, top, bottom) {
  const g = ctx.createLinearGradient(0, 0, 0, 250);
  g.addColorStop(0, top); g.addColorStop(1, bottom); return g;
}
function updateTrendChart(history) {
  // Use persistent history for a stable timeline
  const recent = history.slice(0, 30).reverse();
  if (!recent.length) return;
  trendChart.data.labels = recent.map(e => new Date(e.timestamp).toLocaleTimeString());
  trendChart.data.datasets[0].data = recent.map(e => e.risk_score);
  trendChart.data.datasets[0].pointBackgroundColor = recent.map(e =>
    e.risk_score >= 80 ? '#f2495c' : e.risk_score >= 50 ? '#ff9830' : '#73bf69'
  );
  trendChart.update('none');
}

// ===== Verdict Donut =====
function initVerdictChart() {
  const ctx = document.getElementById('verdictChart').getContext('2d');
  verdictChart = new Chart(ctx, {
    type: 'doughnut',
    data: { labels: ['High Risk', 'Medium Risk', 'Clean', 'Unknown'], datasets: [{
      data: [0,0,0,0], backgroundColor: ['#f2495c','#ff9830','#73bf69','#5a6270'], borderWidth: 0, spacing: 2,
    }]},
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '72%',
      plugins: {
        legend: { position: 'bottom', labels: { padding: 12, usePointStyle: true, pointStyle: 'circle', font: { size: 10 } } },
        tooltip: { backgroundColor: '#1e2228', borderColor: '#3a3f4a', borderWidth: 1, padding: 10, cornerRadius: 4 }
      }
    },
    plugins: [{ id: 'centerText', afterDraw(chart) {
      const { ctx: c, chartArea: { left, right, top, bottom } } = chart;
      const total = chart.data.datasets[0].data.reduce((a,b)=>a+b,0);
      c.save(); c.textAlign='center'; c.textBaseline='middle';
      c.fillStyle='#d8dee9'; c.font="300 28px 'Roboto'"; c.fillText(total,(left+right)/2,(top+bottom)/2-6);
      c.fillStyle='#5a6270'; c.font="500 10px 'Roboto'"; c.fillText('TOTAL',(left+right)/2,(top+bottom)/2+16);
      c.restore();
    }}]
  });
}
function updateVerdictChart(stats) {
  if (!verdictChart) return;
  const high = stats.high_risk || 0;
  const medium = (stats.threats_detected || 0) - high;
  const clean = stats.clean_files || 0;
  const unknown = (stats.total_scans || 0) - high - medium - clean;
  verdictChart.data.datasets[0].data = [high, Math.max(medium,0), clean, Math.max(unknown,0)];
  verdictChart.update('none');
}

// ===== AI Panel =====
function updateAIPanel(history) {
  const panel = document.getElementById('aiPanel');
  const content = document.getElementById('aiContent');
  const withInsight = history.filter(e => e.ai_insight && e.ai_insight.length > 20);
  if (!withInsight.length) { panel.style.display = 'none'; return; }
  panel.style.display = 'block';
  content.innerHTML = withInsight.slice(0, 3).map(e =>
    `<div class="ai-insight-card">
      <div class="ai-insight-header">⚠ ${e.filename} — ${e.node_name} — Score: ${e.risk_score}</div>
      <div class="ai-insight-body">${e.ai_insight}</div>
    </div>`
  ).join('');
}

// ===== Helpers =====
function verdictClass(v) {
  return v === 'HIGH RISK' ? 'HIGH' : v === 'MEDIUM RISK' ? 'MEDIUM' : v === 'CLEAN' ? 'CLEAN' : 'UNKNOWN';
}
