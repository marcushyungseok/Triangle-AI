/* ================================================= */
/*  NPE Learner Dashboard — Frontend Logic & Charts  */
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
      el.innerHTML = '<span class="status-dot online"></span><span class="status-text">Multi-Analyzer Online</span>';
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
  // Accepted extensions
  const allowed = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.js', '.html', '.htm', '.lnk', '.docm', '.xlsm', '.vbs', '.ps1'];
  const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
  
  if (!allowed.includes(ext)) {
    alert('Unsupported file type. Supported: PDF, Office, JS, HTML, LNK');
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
  
  // Conditionally render PDF specific charts
  if (data.type === 'PDF Document' && data.statistics) {
    document.querySelector('.pie-panel').style.display = 'block';
    document.querySelector('.radar-panel').style.display = 'block';
    document.querySelector('.bar-panel').style.display = 'block';
    document.querySelector('.table-panel').style.display = 'block';
    document.getElementById('statsRow').style.display = 'grid';

    renderPieChart(data.statistics);
    renderRadarChart(data.category_scores);
    renderBarChart(data.charts.filter_distribution);
    renderStats(data.statistics);
    renderFeatureTable(data.raw_features);
  } else {
    // Hide non-relevant panels for other formats
    document.querySelector('.pie-panel').style.display = 'none';
    document.querySelector('.radar-panel').style.display = 'none';
    document.querySelector('.bar-panel').style.display = 'none';
    document.querySelector('.table-panel').style.display = 'none';
    document.getElementById('statsRow').style.display = 'none';
  }
  
  renderReport(data.report);
}

// ===== File Info Bar =====
function renderFileInfo(info, fileType) {
  const bar = document.getElementById('fileInfoBar');
  const items = [
    { label: 'File', value: info.filename },
    { label: 'Format', value: fileType },
    { label: 'Size', value: formatBytes(info.size) },
    { label: 'SHA256', value: info.sha256.substring(0, 16) + '...' },
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
  const cls = v === 'CLEAN' ? 'CLEAN' : v === 'LOW RISK' || v === 'UNKNOWN' ? 'LOW' : v === 'MEDIUM RISK' ? 'MEDIUM' : 'HIGH';
  body.innerHTML = `
    <div class="verdict-badge verdict-${cls}">${v}</div>
    <p class="verdict-desc">${data.report[0].content}</p>
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

// ===== Pie Chart — Object Integrity =====
function renderPieChart(stats) {
  const ctx = document.getElementById('pieChart').getContext('2d');
  const correct = stats.correct_objects || 0;
  const corrupted = stats.corrupted_objects || 0;

  charts.pie = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Valid Objects', 'Corrupted Objects'],
      datasets: [{
        data: [correct, corrupted],
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
        legend: {
          position: 'bottom',
          labels: { padding: 16, usePointStyle: true, pointStyle: 'circle', font: { size: 11 } }
        },
        tooltip: {
          backgroundColor: '#252830',
          titleColor: '#e6e9ef',
          bodyColor: '#8b8fa3',
          borderColor: '#2c2f36',
          borderWidth: 1,
          padding: 12,
        }
      }
    },
    plugins: [{
      id: 'pieCenter',
      afterDraw(chart) {
        const { ctx, chartArea: { left, right, top, bottom } } = chart;
        const cx = (left + right) / 2;
        const cy = (top + bottom) / 2;
        ctx.save();
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = '#e6e9ef';
        ctx.font = "bold 24px 'Inter'";
        ctx.fillText(correct + corrupted, cx, cy - 6);
        ctx.fillStyle = '#8b8fa3';
        ctx.font = "500 11px 'Inter'";
        ctx.fillText('total', cx, cy + 14);
        ctx.restore();
      }
    }]
  });
}

// ===== Radar Chart — Threat Categories =====
function renderRadarChart(scores) {
  if (!scores) return;
  const ctx = document.getElementById('radarChart').getContext('2d');
  const labels = Object.keys(scores).map(k => k.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()));
  const values = Object.values(scores);

  charts.radar = new Chart(ctx, {
    type: 'radar',
    data: {
      labels,
      datasets: [{
        label: 'Risk Level',
        data: values,
        backgroundColor: 'rgba(34, 211, 238, 0.1)',
        borderColor: COLORS.cyan,
        borderWidth: 2,
        pointBackgroundColor: COLORS.cyan,
        pointBorderColor: '#1e2028',
        pointBorderWidth: 2,
        pointRadius: 5,
        pointHoverRadius: 7,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      scales: {
        r: {
          beginAtZero: true,
          max: 100,
          ticks: {
            stepSize: 25, display: false,
          },
          grid: { color: 'rgba(44,47,54,0.6)' },
          angleLines: { color: 'rgba(44,47,54,0.6)' },
          pointLabels: { font: { size: 11, weight: '500' }, color: '#8b8fa3' },
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#252830',
          titleColor: '#e6e9ef',
          bodyColor: '#8b8fa3',
          borderColor: '#2c2f36',
          borderWidth: 1,
          callbacks: { label: (ctx) => `Risk: ${ctx.raw}/100` }
        }
      }
    }
  });
}

// ===== Bar Chart — Filter Distribution =====
function renderBarChart(filters) {
  if (!filters) return;
  const ctx = document.getElementById('barChart').getContext('2d');
  const labels = Object.keys(filters);
  const values = Object.values(filters);

  if (labels.length === 0) {
    labels.push('No filters detected');
    values.push(0);
  }

  const barColors = labels.map((_, i) => {
    const palette = [COLORS.cyan, COLORS.blue, COLORS.purple, COLORS.green, COLORS.yellow, COLORS.orange];
    return palette[i % palette.length];
  });

  charts.bar = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Count',
        data: values,
        backgroundColor: barColors.map(c => c + '33'),
        borderColor: barColors,
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      indexAxis: 'y',
      scales: {
        x: {
          grid: { color: 'rgba(44,47,54,0.4)' },
          ticks: { font: { size: 11 } },
        },
        y: {
          grid: { display: false },
          ticks: { font: { size: 11, family: "'JetBrains Mono'" } },
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#252830',
          titleColor: '#e6e9ef',
          bodyColor: '#8b8fa3',
          borderColor: '#2c2f36',
          borderWidth: 1,
        }
      }
    }
  });
}

// ===== Stats Row =====
function renderStats(stats) {
  if (!stats) return;
  const row = document.getElementById('statsRow');
  const items = [
    { label: 'Objects', value: stats.total_objects, color: 'cyan' },
    { label: 'Streams', value: stats.total_streams, color: 'blue' },
    { label: 'JavaScripts', value: stats.total_javascripts, color: stats.total_javascripts > 0 ? 'red' : 'green' },
    { label: 'Errors', value: stats.total_errors, color: stats.total_errors > 0 ? 'yellow' : 'green' },
    { label: 'Embedded Files', value: stats.total_embedded_files, color: stats.total_embedded_files > 0 ? 'red' : 'green' },
  ];
  row.innerHTML = items.map(i =>
    `<div class="stat-card">
      <div class="stat-label">${i.label}</div>
      <div class="stat-value ${i.color}">${i.value}</div>
    </div>`
  ).join('');
}

// ===== Feature Table =====
function renderFeatureTable(features) {
  if (!features) return;
  const table = document.getElementById('featureTable');
  const featureNames = {
    file_size: 'File Size (bytes)',
    ratio_hex_in_name: 'Hex Encoding Ratio in Names',
    num_hex_in_filter_name: 'Hex Characters in Filter Names',
    num_cmd: 'Command Objects',
    js_max_line_length: 'Max JS Line Length',
    js_ratio_in_size: 'JS Size / File Size Ratio',
    appended_tail_len: 'Appended Tail Length (bytes)',
    appended_tail_entropy: 'Tail Data Entropy',
  };

  let html = '<thead><tr><th>Feature</th><th>Value</th><th>Indicator</th></tr></thead><tbody>';
  for (const [key, value] of Object.entries(features)) {
    const name = featureNames[key] || key;
    let indicator = '●';
    let indColor = COLORS.green;

    if (key === 'js_max_line_length' && value > 500) { indicator = '▲'; indColor = COLORS.red; }
    else if (key === 'js_ratio_in_size' && value > 0.1) { indicator = '▲'; indColor = COLORS.orange; }
    else if (key === 'ratio_hex_in_name' && value > 0.3) { indicator = '▲'; indColor = COLORS.yellow; }
    else if (key === 'appended_tail_entropy' && value > 6) { indicator = '▲'; indColor = COLORS.orange; }
    else if (key === 'num_cmd' && value > 0) { indicator = '▲'; indColor = COLORS.yellow; }
    else if (value === 0) { indicator = '●'; indColor = COLORS.green; }

    html += `<tr>
      <td>${name}</td>
      <td>${value}</td>
      <td style="color:${indColor};font-size:16px;">${indicator}</td>
    </tr>`;
  }
  html += '</tbody>';
  table.innerHTML = html;
}

// ===== Report =====
function renderReport(sections) {
  const container = document.getElementById('reportContent');
  container.innerHTML = sections.map(section =>
    `<div class="report-card">
      <div class="report-card-title">${section.title}</div>
      <div class="report-card-content">${section.content.replace(/\n/g, '<br/>')}</div>
    </div>`
  ).join('');
}

// ===== Utility =====
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
