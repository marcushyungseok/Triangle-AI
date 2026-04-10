/* ============================================= */
/*  Triangle AI Security Hub — Client Logic      */
/*  Grafana-inspired charts and real-time feed   */
/* ============================================= */

// Grafana chart defaults
Chart.defaults.color = '#8892a4';
Chart.defaults.borderColor = '#2c3038';
Chart.defaults.font.family = "'Roboto', 'Helvetica Neue', Arial, sans-serif";
Chart.defaults.font.size = 11;

let ws = null;
let trendChart = null;
let verdictChart = null;
let allEvents = [];
let currentFilter = 'all';

// ===== Init =====
document.addEventListener('DOMContentLoaded', () => {
  checkHealth();
  connectWebSocket();
  setupFilterButtons();
  initTrendChart();
  initVerdictChart();
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
    if (msg.type === 'update') updateDashboard(msg.events, msg.stats);
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
    updateDashboard(evRes.events, stRes);
  } catch {}
}

// ===== Dashboard Update =====
function updateDashboard(events, stats) {
  allEvents = events || [];
  updateStats(stats);
  updateNodeMap(stats.nodes || {});
  updateFeed(allEvents);
  updateTrendChart(stats.timeline || []);
  updateVerdictChart(stats);
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
  // Simple count-up animation
  const diff = target - current;
  const steps = Math.min(Math.abs(diff), 15);
  const stepVal = diff / steps;
  let i = 0;
  const timer = setInterval(() => {
    i++;
    el.textContent = Math.round(current + stepVal * i);
    if (i >= steps) {
      el.textContent = target;
      clearInterval(timer);
    }
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
          <span class="node-stat-item">Scanned: <span class="node-stat-value">${data.total}</span></span>
          <span class="node-stat-item">Threats: <span class="node-stat-value" style="color:var(--accent-orange)">${data.threats}</span></span>
          <span class="node-stat-item">Critical: <span class="node-stat-value" style="color:var(--accent-red)">${data.high_risk}</span></span>
        </div>
        <div class="node-threat-bar">
          <div class="node-threat-fill" style="width:${Math.max(pct, 2)}%;background:${barColor}"></div>
        </div>
      </div>`;
  }
  html += '</div>';
  container.innerHTML = html;
}

function updateFeed(events) {
  const tbody = document.getElementById('feedBody');
  let filtered = events;
  if (currentFilter !== 'all') {
    filtered = events.filter(e => e.verdict === currentFilter);
  }
  if (!filtered.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="9">No events matching filter.</td></tr>';
    return;
  }
  tbody.innerHTML = filtered.map((e, i) => {
    const time = new Date(e.timestamp).toLocaleTimeString();
    const cls = e.verdict === 'HIGH RISK' ? 'HIGH' : e.verdict === 'MEDIUM RISK' ? 'MEDIUM' : e.verdict === 'CLEAN' ? 'CLEAN' : 'UNKNOWN';
    const scoreCls = e.risk_score >= 60 ? 'score-high' : e.risk_score >= 25 ? 'score-medium' : 'score-low';
    const detail = e.details && e.details.length > 0 ? e.details[0] : '—';
    const ns = e.namespace || 'unknown';
    const pod = e.pod_name || 'unknown';
    const filePath = e.file_path || e.filename || '—';
    return `<tr class="${i === 0 ? 'new-event' : ''}">
      <td>${time}</td>
      <td><span class="verdict-badge verdict-${cls}">${e.verdict}</span></td>
      <td class="${scoreCls}">${e.risk_score}</td>
      <td><span class="ns-badge">${ns}</span></td>
      <td><span class="pod-badge">${pod}</span></td>
      <td>${e.node_name}</td>
      <td title="${filePath}"><span class="path-text">${filePath}</span></td>
      <td>${e.type}</td>
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

// ===== Trend Chart (Area) =====
function initTrendChart() {
  const ctx = document.getElementById('trendChart').getContext('2d');
  trendChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Risk Score',
        data: [],
        borderColor: '#5794f2',
        backgroundColor: createGradient(ctx, 'rgba(87,148,242,0.25)', 'rgba(87,148,242,0.02)'),
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 6,
        pointBackgroundColor: '#5794f2',
        pointBorderColor: '#22262c',
        pointBorderWidth: 2,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      layout: { padding: { top: 4 } },
      scales: {
        x: {
          display: true,
          grid: { color: 'rgba(44,48,56,0.6)', drawBorder: false },
          ticks: { maxTicksLimit: 8, font: { size: 10 } }
        },
        y: {
          beginAtZero: true, max: 100,
          grid: { color: 'rgba(44,48,56,0.6)', drawBorder: false },
          ticks: { stepSize: 25, font: { size: 10 } }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#1e2228',
          borderColor: '#3a3f4a',
          borderWidth: 1,
          titleFont: { family: "'Roboto', sans-serif", size: 12 },
          bodyFont: { family: "'Roboto Mono', monospace", size: 11 },
          padding: 10,
          cornerRadius: 4,
        }
      },
      animation: { duration: 300 }
    }
  });
}

function createGradient(ctx, top, bottom) {
  const g = ctx.createLinearGradient(0, 0, 0, 250);
  g.addColorStop(0, top);
  g.addColorStop(1, bottom);
  return g;
}

function updateTrendChart(timeline) {
  if (!timeline.length) return;
  const labels = timeline.map(t => new Date(t.t).toLocaleTimeString()).reverse();
  const data = timeline.map(t => t.s).reverse();
  trendChart.data.labels = labels;
  trendChart.data.datasets[0].data = data;
  trendChart.data.datasets[0].pointBackgroundColor = data.map(s =>
    s >= 60 ? '#f2495c' : s >= 25 ? '#ff9830' : '#73bf69'
  );
  trendChart.update('none');
}

// ===== Verdict Donut Chart =====
function initVerdictChart() {
  const ctx = document.getElementById('verdictChart').getContext('2d');
  verdictChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['High Risk', 'Medium Risk', 'Clean', 'Unknown'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: ['#f2495c', '#ff9830', '#73bf69', '#5a6270'],
        borderWidth: 0,
        spacing: 2,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      cutout: '72%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            padding: 12, usePointStyle: true, pointStyle: 'circle',
            font: { size: 10, family: "'Roboto', sans-serif" }
          }
        },
        tooltip: {
          backgroundColor: '#1e2228', borderColor: '#3a3f4a', borderWidth: 1,
          padding: 10, cornerRadius: 4,
        }
      },
    },
    plugins: [{
      id: 'centerText',
      afterDraw(chart) {
        const { ctx: c, chartArea: { left, right, top, bottom } } = chart;
        const total = chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
        const cx = (left + right) / 2;
        const cy = (top + bottom) / 2;
        c.save();
        c.textAlign = 'center'; c.textBaseline = 'middle';
        c.fillStyle = '#d8dee9';
        c.font = "300 28px 'Roboto'";
        c.fillText(total, cx, cy - 6);
        c.fillStyle = '#5a6270';
        c.font = "500 10px 'Roboto'";
        c.fillText('TOTAL', cx, cy + 16);
        c.restore();
      }
    }]
  });
}

function updateVerdictChart(stats) {
  if (!verdictChart) return;
  const high = stats.high_risk || 0;
  const medium = (stats.threats_detected || 0) - high;
  const clean = stats.clean_files || 0;
  const unknown = (stats.total_scans || 0) - high - medium - clean;
  verdictChart.data.datasets[0].data = [high, Math.max(medium, 0), clean, Math.max(unknown, 0)];
  verdictChart.update('none');
}

// ===== AI Panel =====
function updateAIPanel(events) {
  const panel = document.getElementById('aiPanel');
  const content = document.getElementById('aiContent');
  const highRisk = events.filter(e => e.ai_insight && e.ai_insight.length > 20);
  if (!highRisk.length) { panel.style.display = 'none'; return; }
  panel.style.display = 'block';
  content.innerHTML = highRisk.slice(0, 3).map(e =>
    `<div class="ai-insight-card">
      <div class="ai-insight-header">⚠ ${e.filename} — ${e.node_name} — Score: ${e.risk_score}</div>
      <div class="ai-insight-body">${e.ai_insight}</div>
    </div>`
  ).join('');
}
