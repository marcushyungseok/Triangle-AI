/* ================================================= */
/*  Triangle AI Dashboard — Frontend Logic & Charts  */
/* ================================================= */

// Chart.js global defaults — Grafana dark style
Chart.defaults.color = '#8b8fa3';
Chart.defaults.borderColor = '#2c2f36';
Chart.defaults.font.family = "'Inter', sans-serif";

const COLORS = {
  green: '#10b981', greenBg: 'rgba(16,185,129,0.15)',
  yellow: '#f59e0b', yellowBg: 'rgba(245,158,11,0.15)',
  orange: '#f97316', orangeBg: 'rgba(249,115,22,0.15)',
  red: '#ef4444', redBg: 'rgba(239,68,68,0.15)',
  blue: '#3b82f6', blueBg: 'rgba(59,130,246,0.15)',
  cyan: '#22d3ee', cyanBg: 'rgba(34,211,238,0.15)',
  purple: '#a855f7', purpleBg: 'rgba(168,85,247,0.15)',
};

let charts = {};

// ===== Init =====
document.addEventListener('DOMContentLoaded', () => {
  setupUpload();
  checkHealth();
});

// ===== Health Check =====
async function checkHealth() {
  const el = document.getElementById('statusIndicator');
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    if (data.analyzer === 'ok') {
      el.innerHTML = '<span class="status-dot online"></span><span class="status-text">Triangle AI Online</span>';
    } else {
      el.innerHTML = '<span class="status-dot offline"></span><span class="status-text">Analyzer Offline</span>';
    }
  } catch {
    el.innerHTML = '<span class="status-dot offline"></span><span class="status-text">Disconnected</span>';
  }
}

// ===== Upload =====
function setupUpload() {
  const zone = document.getElementById('uploadZone');
  const input = document.getElementById('fileInput');

  zone.addEventListener('click', () => input.click());

  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('dragover');
  });

  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));

  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) handleFile(e.dataTransfer.files[0]);
  });

  input.addEventListener('change', () => {
    if (input.files.length > 0) handleFile(input.files[0]);
  });

  document.getElementById('btnNewAnalysis').addEventListener('click', resetDashboard);
}

async function handleFile(file) {
  const allowed = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.js', '.html', '.htm', '.lnk', '.docm', '.xlsm', '.vbs', '.ps1', '.swf'];
  const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
  
  if (!allowed.includes(ext)) {
    alert('Unsupported file type. Supported: PDF, Office, JS, HTML, LNK, SWF');
    return;
  }

  document.getElementById('uploadSection').style.display = 'none';
  document.getElementById('loadingSection').style.display = 'flex';
  document.getElementById('dashboard').style.display = 'none';

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/analyze', { method: 'POST', body: formData });
    const data = await res.json();

    if (data.error) {
      alert('Analysis error: ' + data.error);
      resetDashboard();
      return;
    }

    renderDashboard(data);
  } catch (err) {
    alert('Failed to analyze: ' + err.message);
    resetDashboard();
  }
}

function resetDashboard() {
  document.getElementById('uploadSection').style.display = 'flex';
  document.getElementById('loadingSection').style.display = 'none';
  document.getElementById('dashboard').style.display = 'none';
  document.getElementById('fileInput').value = '';
  // Destroy old charts
  Object.values(charts).forEach(c => c.destroy());
  charts = {};
}

// ===== Render Dashboard =====
function renderDashboard(data) {
  document.getElementById('loadingSection').style.display = 'none';
  document.getElementById('dashboard').style.display = 'block';

  renderFileInfo(data.file_info, data.type);
  renderVerdict(data);
  renderGaugeChart(data.risk_score);
  
  // RESTORED: All panels are always visible but populated based on data
  renderPieChart(data.statistics || { correct_objects: 1, corrupted_objects: 0 });
  
  // Map category scores or use generic
  const radarData = data.category_scores || { 
      'Threat Level': data.risk_score, 
      'Obfuscation': data.risk_score > 30 ? 60 : 10,
      'Behavior': data.risk_score > 50 ? 80 : 20,
      'Persistence': data.risk_score > 70 ? 90 : 30,
      'Network': data.details && data.details.some(d => d.includes('http')) ? 100 : 0
  };
  renderRadarChart(radarData);
  
  // Bar chart for filters or findings
  const barData = (data.charts && data.charts.filter_distribution) || {};
  if (Object.keys(barData).length === 0 && data.details) {
      // Map details to bar chart for non-PDF
      data.details.forEach(d => {
          const key = d.split(':')[0].substring(0, 15);
          barData[key] = (barData[key] || 0) + 1;
      });
  }
  renderBarChart(barData);
  
  renderStats(data.statistics || { 
      total_objects: 'N/A', 
      total_streams: 'N/A', 
      total_javascripts: data.type.includes('Script') ? 1 : 0,
      total_errors: data.details ? data.details.length : 0,
      total_embedded_files: 0
  });

  renderFeatureTable(data.raw_features || {
      'Analysis Method': 'Static Analysis',
      'Target Format': data.type,
      'Risk Vector': data.details ? data.details[0] : 'None',
      'Engine Version': 'Triangle AI v1.0'
  });
  
  renderReport(data.report);
}

// ===== File Info Bar =====
function renderFileInfo(info, fileType) {
  const bar = document.getElementById('fileInfoBar');
  const items = [
    { label: 'File', value: info.filename },
    { label: 'Format', value: fileType },
    { label: 'Size', value: formatBytes(info.size) },
    { label: 'SHA256', value: info.sha256.substring(0, 14) + '...' },
    { label: 'Analyzed', value: new Date(info.analyzed_at).toLocaleString() },
  ];
  bar.innerHTML = items.map(i =>
    `<div class="file-info-item">
      <span class="file-info-label">${i.label}:</span>
      <span class="file-info-value">${i.value}</span>
    </div>`
  ).join('');
}

// ===== Verdict =====
function renderVerdict(data) {
  const body = document.getElementById('verdictBody');
  const v = data.verdict;
  const cls = v === 'CLEAN' ? 'CLEAN' : (v === 'LOW RISK' || v === 'UNKNOWN') ? 'LOW' : v === 'MEDIUM RISK' ? 'MEDIUM' : 'HIGH';
  const desc = data.report && data.report[0] ? data.report[0].content : "Analysis complete.";
  body.innerHTML = `
    <div class="verdict-badge verdict-${cls}">${v}</div>
    <p class="verdict-desc">${desc}</p>
  `;
}

// ===== Gauge Chart (Doughnut) =====
function renderGaugeChart(score) {
  const ctx = document.getElementById('gaugeChart').getContext('2d');
  const color = score >= 70 ? COLORS.red : score >= 40 ? COLORS.orange : score >= 15 ? COLORS.yellow : COLORS.green;

  charts.gauge = new Chart(ctx, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [score, 100 - score],
        backgroundColor: [color, 'rgba(44,47,54,0.5)'],
        borderWidth: 0,
        circumference: 270,
        rotation: 225,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      cutout: '78%',
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false },
      },
    },
    plugins: [{
      id: 'gaugeCenter',
      afterDraw(chart) {
        const { ctx, chartArea: { left, right, top, bottom } } = chart;
        const cx = (left + right) / 2;
        const cy = (top + bottom) / 2 + 10;
        ctx.save();
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = color;
        ctx.font = "bold 36px 'Inter'";
        ctx.fillText(score, cx, cy);
        ctx.fillStyle = '#8b8fa3';
        ctx.font = "500 12px 'Inter'";
        ctx.fillText('/ 100', cx, cy + 26);
        ctx.restore();
      }
    }]
  });
}

function renderPieChart(stats) {
  const ctx = document.getElementById('pieChart').getContext('2d');
  const correct = stats.correct_objects || 0;
  const corrupted = stats.corrupted_objects || 0;

  charts.pie = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Valid Elements', 'Corrupted/Suspicious'],
      datasets: [{
        data: [correct || 1, corrupted],
        backgroundColor: [COLORS.green, COLORS.red],
        borderWidth: 2,
        borderColor: '#1e2028',
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      cutout: '55%',
      plugins: {
        legend: { position: 'bottom', labels: { padding: 12, font: { size: 10 } } }
      }
    }
  });
}

function renderRadarChart(scores) {
  const ctx = document.getElementById('radarChart').getContext('2d');
  const labels = Object.keys(scores).map(k => k.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()));
  const values = Object.values(scores);

  charts.radar = new Chart(ctx, {
    type: 'radar',
    data: {
      labels,
      datasets: [{
        label: 'Risk',
        data: values,
        backgroundColor: 'rgba(34, 211, 238, 0.1)',
        borderColor: COLORS.cyan,
        borderWidth: 2,
        pointRadius: 3,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      scales: {
        r: {
          beginAtZero: true, max: 100,
          ticks: { display: false, stepSize: 20 },
          grid: { color: 'rgba(139, 143, 163, 0.1)' }
        }
      },
      plugins: { legend: { display: false } }
    }
  });
}

function renderBarChart(filters) {
  const ctx = document.getElementById('barChart').getContext('2d');
  const labels = Object.keys(filters).slice(0, 6);
  const values = Object.values(filters).slice(0, 6);

  if (labels.length === 0) {
    labels.push('No findings');
    values.push(0);
  }

  charts.bar = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: COLORS.blueBg,
        borderColor: COLORS.blue,
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      indexAxis: 'y',
      scales: {
        x: { grid: { color: 'rgba(139, 143, 163, 0.1)' } },
        y: { grid: { display: false } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

function renderStats(stats) {
  const row = document.getElementById('statsRow');
  const items = [
    { label: 'Total Tags/Obj', value: stats.total_objects, color: 'cyan' },
    { label: 'Data Streams', value: stats.total_streams, color: 'blue' },
    { label: 'Scripts', value: stats.total_javascripts, color: stats.total_javascripts > 0 ? 'red' : 'green' },
    { label: 'Anomalies', value: stats.total_errors, color: stats.total_errors > 0 ? 'yellow' : 'green' },
    { label: 'Embedded', value: stats.total_embedded_files, color: stats.total_embedded_files > 0 ? 'red' : 'green' },
  ];
  row.innerHTML = items.map(i =>
    `<div class="stat-card">
      <div class="stat-label">${i.label}</div>
      <div class="stat-value ${i.color}">${i.value}</div>
    </div>`
  ).join('');
}

function renderFeatureTable(features) {
  const table = document.getElementById('featureTable');
  let html = '<thead><tr><th>Feature</th><th>Value</th><th>Status</th></tr></thead><tbody>';
  for (const [key, value] of Object.entries(features)) {
    html += `<tr>
      <td>${key.replace(/_/g, ' ')}</td>
      <td>${value}</td>
      <td style="color:${COLORS.green};">●</td>
    </tr>`;
  }
  html += '</tbody>';
  table.innerHTML = html;
}

function renderReport(sections) {
  const container = document.getElementById('reportContent');
  container.innerHTML = sections.map(section =>
    `<div class="report-card">
      <div class="report-card-title">${section.title}</div>
      <div class="report-card-content">${section.content.replace(/\n/g, '<br/>')}</div>
    </div>`
  ).join('');
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
