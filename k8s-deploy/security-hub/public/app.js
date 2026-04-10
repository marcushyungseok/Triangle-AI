/* ============================================= */
/*  Triangle AI Security Hub — Client Logic      */
/* ============================================= */
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#30363d';
Chart.defaults.font.family = "'Inter', sans-serif";

let ws = null;
let trendChart = null;
let allEvents = [];
let currentFilter = 'all';

// ===== Init =====
document.addEventListener('DOMContentLoaded', () => {
  checkHealth();
  connectWebSocket();
  setupFilterButtons();
  initTrendChart();
  // Fallback polling if WS fails
  setInterval(fetchData, 5000);
});

// ===== Health =====
async function checkHealth() {
  const el = document.getElementById('statusIndicator');
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    if (data.engine === 'ok') {
      el.innerHTML = '<span class="status-dot online"></span><span class="status-text">Engine Online</span>';
    } else {
      el.innerHTML = '<span class="status-dot offline"></span><span class="status-text">Engine Offline</span>';
    }
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
    if (msg.type === 'update') {
      updateDashboard(msg.events, msg.stats);
    }
  };

  ws.onclose = () => {
    wsEl.innerHTML = '<span class="ws-dot disconnected"></span><span class="ws-text">Reconnecting...</span>';
    setTimeout(connectWebSocket, 3000);
  };

  ws.onerror = () => ws.close();
}

// ===== Fallback Fetch =====
async function fetchData() {
  if (ws && ws.readyState === 1) return; // WS is working
  try {
    const [evRes, stRes] = await Promise.all([
      fetch('/api/events').then(r => r.json()),
      fetch('/api/stats').then(r => r.json()),
    ]);
    updateDashboard(evRes.events, stRes);
  } catch { /* ignored */ }
}

// ===== Update Dashboard =====
function updateDashboard(events, stats) {
  allEvents = events || [];
  updateStats(stats);
  updateNodeMap(stats.nodes || {});
  updateFeed(allEvents);
  updateTrendChart(stats.timeline || []);
  updateAIPanel(allEvents);
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
  el.textContent = target;
  el.style.transform = 'scale(1.15)';
  setTimeout(() => el.style.transform = 'scale(1)', 200);
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
    const cls = data.high_risk > 0 ? 'threat' : (data.threats > 0 ? '' : 'clean');
    const barColor = data.high_risk > 0 ? 'var(--accent-red)' : (data.threats > 0 ? 'var(--accent-orange)' : 'var(--accent-green)');
    html += `
      <div class="node-card ${cls}">
        <div class="node-name">🖥️ ${name}</div>
        <div class="node-stats">
          Scanned: ${data.total} &nbsp;|&nbsp; Threats: ${data.threats} &nbsp;|&nbsp; Critical: ${data.high_risk}
        </div>
        <div class="node-threat-bar">
          <div class="node-threat-fill" style="width:${pct}%;background:${barColor}"></div>
        </div>
      </div>`;
  }
  html += '</div>';
  container.innerHTML = html;
}

// ===== Feed =====
function updateFeed(events) {
  const tbody = document.getElementById('feedBody');
  let filtered = events;
  if (currentFilter !== 'all') {
    filtered = events.filter(e => e.verdict === currentFilter);
  }
  if (!filtered.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No events matching filter.</td></tr>';
    return;
  }
  tbody.innerHTML = filtered.map((e, i) => {
    const time = new Date(e.timestamp).toLocaleTimeString();
    const cls = e.verdict === 'HIGH RISK' ? 'HIGH' : e.verdict === 'MEDIUM RISK' ? 'MEDIUM' : e.verdict === 'CLEAN' ? 'CLEAN' : 'UNKNOWN';
    const scoreCls = e.risk_score >= 60 ? 'score-high' : e.risk_score >= 25 ? 'score-medium' : 'score-low';
    const detail = e.details && e.details.length > 0 ? e.details[0].substring(0, 40) : '—';
    return `<tr class="${i === 0 ? 'new-event' : ''}">
      <td>${time}</td>
      <td>${e.node_name}</td>
      <td title="${e.file_path}">${e.filename}</td>
      <td>${e.type}</td>
      <td class="${scoreCls}">${e.risk_score}</td>
      <td><span class="verdict-badge verdict-${cls}">${e.verdict}</span></td>
      <td title="${e.details?.join(', ')}">${detail}</td>
    </tr>`;
  }).join('');
}

function setupFilterButtons() {
  document.querySelectorAll('.feed-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.feed-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      updateFeed(allEvents);
    });
  });
}

// ===== Trend Chart =====
function initTrendChart() {
  const ctx = document.getElementById('trendChart').getContext('2d');
  trendChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Risk Score',
        data: [],
        borderColor: '#58a6ff',
        backgroundColor: 'rgba(88,166,255,0.08)',
        fill: true,
        tension: 0.4,
        borderWidth: 2,
        pointRadius: 3,
        pointBackgroundColor: '#58a6ff',
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: true,
      scales: {
        x: { display: true, grid: { color: 'rgba(48,54,61,0.5)' } },
        y: { beginAtZero: true, max: 100, grid: { color: 'rgba(48,54,61,0.5)' } }
      },
      plugins: { legend: { display: false } },
      animation: { duration: 400 }
    }
  });
}

function updateTrendChart(timeline) {
  if (!timeline.length) return;
  const labels = timeline.map(t => new Date(t.t).toLocaleTimeString()).reverse();
  const data = timeline.map(t => t.s).reverse();
  trendChart.data.labels = labels;
  trendChart.data.datasets[0].data = data;
  // Color points by severity
  trendChart.data.datasets[0].pointBackgroundColor = data.map(s =>
    s >= 60 ? '#f85149' : s >= 25 ? '#db6d28' : '#3fb950'
  );
  trendChart.update('none');
}

// ===== AI Panel =====
function updateAIPanel(events) {
  const panel = document.getElementById('aiPanel');
  const content = document.getElementById('aiContent');
  const highRisk = events.filter(e => e.ai_insight && e.ai_insight.length > 10);
  if (!highRisk.length) {
    panel.style.display = 'none';
    return;
  }
  panel.style.display = 'block';
  content.innerHTML = highRisk.slice(0, 3).map(e =>
    `<div style="margin-bottom:16px;padding:12px;background:var(--bg-secondary);border-radius:8px;border-left:3px solid var(--accent-red)">
      <div style="font-size:11px;color:var(--accent-red);margin-bottom:6px;font-weight:600">
        ⚠ ${e.filename} — ${e.node_name} — Score: ${e.risk_score}
      </div>
      <div style="font-size:12px;line-height:1.6;color:var(--text-secondary)">${e.ai_insight}</div>
    </div>`
  ).join('');
}
