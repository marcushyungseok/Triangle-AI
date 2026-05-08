/* ================================================= */
/*  Triangle AI Security Hub — Client Logic v0.9     */
/*  eBPF + GPU Monitor + Admission + OTEL            */
/* ================================================= */
Chart.defaults.color = '#8892a4';
Chart.defaults.borderColor = '#2c3038';
Chart.defaults.font.family = "'Roboto', 'Helvetica Neue', Arial, sans-serif";
Chart.defaults.font.size = 11;

let ws = null, trendChart = null, verdictChart = null, gpuChart = null;
let currentFilter = 'all', lastKnownCount = 0;
let ebpfSeverityFilter = 'all';

// ===== Persistent History =====
const STORAGE_KEY = 'triangle_scan_history';
const MAX_HISTORY = 200;
function loadHistory() { try { return JSON.parse(localStorage.getItem(STORAGE_KEY)||'[]'); } catch { return []; } }
function saveHistory(a) { localStorage.setItem(STORAGE_KEY, JSON.stringify(a.slice(0,MAX_HISTORY))); }
function mergeEvents(incoming) {
  const h = loadHistory(), seen = new Set(h.map(e=>e.sha256+e.timestamp));
  let added = 0;
  for (const ev of incoming) { const k=ev.sha256+ev.timestamp; if(!seen.has(k)){h.unshift(ev);seen.add(k);added++;} }
  if(h.length>MAX_HISTORY) h.length=MAX_HISTORY;
  if(added>0) saveHistory(h);
  return {history:h, added};
}

// ===== Init =====
document.addEventListener('DOMContentLoaded', () => {
  checkHealth(); connectWebSocket(); setupFilterButtons(); setupHistoryFilter(); setupHistorySort(); setupEbpfFilter();
  document.getElementById('clearHistory')?.addEventListener('click', () => {
    if(confirm('Clear all scan history?')){localStorage.removeItem(STORAGE_KEY);location.reload();}
  });
  initTrendChart(); initVerdictChart(); initGpuChart();
  renderHistory(loadHistory()); renderHistoryStats(loadHistory());
  setInterval(fetchData, 10000);
});

// ===== Health =====
async function checkHealth() {
  const el = document.getElementById('statusIndicator');
  try {
    const res = await fetch('/api/health'); const data = await res.json();
    el.innerHTML = data.engine==='ok'
      ? '<span class="status-dot online"></span><span class="status-text">Engine Online</span>'
      : '<span class="status-dot offline"></span><span class="status-text">Engine Offline</span>';
  } catch { el.innerHTML = '<span class="status-dot offline"></span><span class="status-text">Disconnected</span>'; }
}

// ===== WebSocket =====
function connectWebSocket() {
  ws = new WebSocket(`ws://${location.host}`);
  const wsEl = document.getElementById('wsStatus');
  ws.onopen = () => { wsEl.innerHTML = '<span class="ws-dot connected"></span><span class="ws-text">Live</span>'; };
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if(msg.type==='update') {
      handleUpdate(msg.events, msg.stats);
      if(msg.ebpf_events) renderEbpfEvents(msg.ebpf_events, msg.ebpf_total);
      if(msg.admission_events) renderAdmissionEvents(msg.admission_events, msg.admission_total);
      updateGpuFromEbpf(msg.ebpf_events||[]);
    }
  };
  ws.onclose = () => { wsEl.innerHTML = '<span class="ws-dot disconnected"></span><span class="ws-text">Reconnecting...</span>'; setTimeout(connectWebSocket,3000); };
  ws.onerror = () => ws.close();
}

// ===== Fallback Polling =====
async function fetchData() {
  if(ws&&ws.readyState===1) return;
  try {
    const [evR,stR,ebR,adR] = await Promise.all([
      fetch('/api/events').then(r=>r.json()),
      fetch('/api/stats').then(r=>r.json()),
      fetch('/api/ebpf-events?limit=30').then(r=>r.json()).catch(()=>({events:[],total:0})),
      fetch('/api/admission-events?limit=20').then(r=>r.json()).catch(()=>({events:[],total:0})),
    ]);
    handleUpdate(evR.events, stR);
    renderEbpfEvents(ebR.events, ebR.total);
    renderAdmissionEvents(adR.events, adR.total);
    updateGpuFromEbpf(ebR.events||[]);
  } catch{}
}

// ===== Central Update =====
function handleUpdate(incomingEvents, stats) {
  const {history} = mergeEvents(incomingEvents||[]);
  if(history.length===lastKnownCount) return;
  const added = history.length - lastKnownCount;
  lastKnownCount = history.length;
  updateLiveFeed(incomingEvents||[]);
  renderHistory(history);
  const hStats = computeHistoryStats(history);
  updateStats(hStats); updateNodeMap(hStats.nodes);
  updateTrendChart(history); updateVerdictChart(hStats); updateAIPanel(history);
  if(added>0){ const c=document.getElementById('newBadge'); if(c){c.textContent=`+${added}`;c.style.display='inline';setTimeout(()=>c.style.display='none',3000);} }
}

// ===== Stats =====
function computeHistoryStats(h) {
  const nodes={}; let total=h.length,threats=0,high=0,clean=0;
  for(const e of h){const n=e.node_name||'unknown';if(!nodes[n])nodes[n]={total:0,threats:0,high_risk:0};nodes[n].total++;if(e.verdict==='HIGH RISK'||e.verdict==='MEDIUM RISK'){nodes[n].threats++;threats++;}if(e.verdict==='HIGH RISK'){nodes[n].high_risk++;high++;}if(e.verdict==='CLEAN')clean++;}
  return {total_scans:total,threats_detected:threats,high_risk:high,clean_files:clean,active_nodes:Object.keys(nodes).length,nodes};
}
function updateStats(s) {
  animateValue('statTotal',s.total_scans||0); animateValue('statThreats',s.threats_detected||0);
  animateValue('statHigh',s.high_risk||0); animateValue('statClean',s.clean_files||0);
  animateValue('statNodes',s.active_nodes||0);
}
function animateValue(id,target) {
  const el=document.getElementById(id); if(!el) return;
  const cur=parseInt(el.textContent)||0; if(cur===target) return;
  const diff=target-cur, steps=Math.min(Math.abs(diff),15), sv=diff/steps;
  let i=0; const t=setInterval(()=>{i++;el.textContent=Math.round(cur+sv*i);if(i>=steps){el.textContent=target;clearInterval(t);}},30);
}

// ===== Node Map =====
function updateNodeMap(nodes) {
  const c=document.getElementById('nodeMap');
  if(!Object.keys(nodes).length){c.innerHTML='<div class="empty-state">Waiting for scanner data...</div>';return;}
  let html='<div class="node-grid">';
  for(const[name,data] of Object.entries(nodes)){
    const pct=data.total>0?Math.round((data.threats/data.total)*100):0;
    const cls=data.high_risk>0?'threat':(data.threats>0?'warning':'clean');
    const bc=data.high_risk>0?'var(--accent-red)':(data.threats>0?'var(--accent-orange)':'var(--accent-green)');
    html+=`<div class="node-card ${cls}"><div class="node-name">● ${name}</div><div class="node-stats"><span>Scanned: <span class="node-stat-value">${data.total}</span></span><span>Threats: <span class="node-stat-value" style="color:var(--accent-orange)">${data.threats}</span></span><span>Critical: <span class="node-stat-value" style="color:var(--accent-red)">${data.high_risk}</span></span></div><div class="node-threat-bar"><div class="node-threat-fill" style="width:${Math.max(pct,2)}%;background:${bc}"></div></div></div>`;
  }
  c.innerHTML=html+'</div>';
}

// ===== Live Feed =====
function updateLiveFeed(events) {
  const tbody=document.getElementById('liveFeedBody'); if(!events.length) return;
  tbody.innerHTML=events.slice(0,5).map((e,i)=>{
    const t=new Date(e.timestamp).toLocaleTimeString(), cls=verdictClass(e.verdict);
    const sc=e.risk_score>=80?'score-high':e.risk_score>=50?'score-medium':'score-low';
    return `<tr class="${i===0?'new-event':''}"><td>${t}</td><td><span class="verdict-badge verdict-${cls}">${e.verdict}</span></td><td class="${sc}">${e.risk_score}</td><td><span class="ns-badge">${e.namespace||'—'}</span></td><td><span class="pod-badge">${e.pod_name||'—'}</span></td><td>${e.node_name}</td><td title="${e.file_path}"><span class="path-text">${e.file_path||e.filename}</span></td><td>${e.type}</td></tr>`;
  }).join('');
}

// ===== Scan History =====
let historyFilter='all', historySortField=null, historySortDir=0;
const VERDICT_ORDER={'HIGH RISK':0,'MEDIUM RISK':1,'CLEAN':2,'UNKNOWN':3};
function renderHistory(history) {
  const tbody=document.getElementById('historyBody'), countEl=document.getElementById('historyCount');
  let f=history; if(historyFilter!=='all') f=history.filter(e=>e.verdict===historyFilter);
  if(historySortField==='verdict'&&historySortDir>0) f=[...f].sort((a,b)=>{const d=(VERDICT_ORDER[a.verdict]||9)-(VERDICT_ORDER[b.verdict]||9);return historySortDir===1?d:-d;});
  else if(historySortField==='score'&&historySortDir>0) f=[...f].sort((a,b)=>historySortDir===1?b.risk_score-a.risk_score:a.risk_score-b.risk_score);
  if(countEl) countEl.textContent=`${f.length} / ${history.length}`;
  updateSortIndicators();
  if(!f.length){tbody.innerHTML='<tr class="empty-row"><td colspan="9">No scan results recorded yet.</td></tr>';return;}
  tbody.innerHTML=f.map(e=>{
    const t=new Date(e.timestamp).toLocaleString(), cls=verdictClass(e.verdict);
    const sc=e.risk_score>=80?'score-high':e.risk_score>=50?'score-medium':'score-low';
    const det=e.details&&e.details.length>0?e.details.join(', '):'—';
    return `<tr><td>${t}</td><td><span class="verdict-badge verdict-${cls}">${e.verdict}</span></td><td class="${sc}">${e.risk_score}</td><td><span class="ns-badge">${e.namespace||'—'}</span></td><td><span class="pod-badge">${e.pod_name||'—'}</span></td><td>${e.node_name||'—'}</td><td title="${e.file_path||''}"><span class="path-text">${e.file_path||e.filename||'—'}</span></td><td>${e.type||'—'}</td><td title="${det}">${det}</td></tr>`;
  }).join('');
}
function updateSortIndicators(){const v=document.getElementById('sortVerdict'),s=document.getElementById('sortScore');if(v){const a=historySortField==='verdict'?(historySortDir===1?' ▼':historySortDir===2?' ▲':''):'';v.textContent='Verdict'+a;}if(s){const a=historySortField==='score'?(historySortDir===1?' ▼':historySortDir===2?' ▲':''):'';s.textContent='Score'+a;}}
function setupHistorySort(){const v=document.getElementById('sortVerdict'),s=document.getElementById('sortScore');if(v)v.addEventListener('click',()=>{if(historySortField!=='verdict'){historySortField='verdict';historySortDir=1;}else historySortDir=(historySortDir+1)%3;if(historySortDir===0)historySortField=null;renderHistory(loadHistory());});if(s)s.addEventListener('click',()=>{if(historySortField!=='score'){historySortField='score';historySortDir=1;}else historySortDir=(historySortDir+1)%3;if(historySortDir===0)historySortField=null;renderHistory(loadHistory());});}
function renderHistoryStats(h){const s=computeHistoryStats(h);updateStats(s);updateNodeMap(s.nodes);updateTrendChart(h);updateVerdictChart(s);}
function setupHistoryFilter(){document.querySelectorAll('.history-btn:not(.ebpf-filter-btn)').forEach(b=>{b.addEventListener('click',()=>{document.querySelectorAll('.history-btn:not(.ebpf-filter-btn)').forEach(x=>x.classList.remove('active'));b.classList.add('active');historyFilter=b.dataset.filter;renderHistory(loadHistory());});});}
function setupFilterButtons(){document.querySelectorAll('.feed-btn').forEach(b=>{b.addEventListener('click',()=>{document.querySelectorAll('.feed-btn').forEach(x=>x.classList.remove('active'));b.classList.add('active');currentFilter=b.dataset.filter;});});}

// ===== eBPF Events =====
function setupEbpfFilter(){
  document.querySelectorAll('.ebpf-filter-btn').forEach(b=>{
    b.addEventListener('click',()=>{
      document.querySelectorAll('.ebpf-filter-btn').forEach(x=>x.classList.remove('active'));
      b.classList.add('active'); ebpfSeverityFilter=b.dataset.severity;
      // Re-render with current data
      const tbody=document.getElementById('ebpfBody');
      if(tbody._lastEvents) renderEbpfEvents(tbody._lastEvents, tbody._lastTotal);
    });
  });
}
function renderEbpfEvents(events, total) {
  const tbody=document.getElementById('ebpfBody'), countEl=document.getElementById('ebpfCount');
  tbody._lastEvents=events; tbody._lastTotal=total;
  animateValue('statEbpf', total||0);
  let filtered=events||[];
  if(ebpfSeverityFilter!=='all') filtered=filtered.filter(e=>e.severity===ebpfSeverityFilter);
  if(countEl) countEl.textContent=`${filtered.length} events`;
  if(!filtered.length){tbody.innerHTML='<tr class="empty-row"><td colspan="8">Waiting for eBPF kernel events...</td></tr>';return;}
  tbody.innerHTML=filtered.slice(0,30).map((e,i)=>{
    const t=new Date(e.timestamp).toLocaleTimeString();
    const sevCls=`severity-${e.severity||'low'}`;
    const catCls=`cat-${(e.category||'').replace(/\s/g,'_')}`;
    return `<tr class="${i===0?'new-event':''}"><td>${t}</td><td><span class="severity-badge ${sevCls}">${e.severity||'—'}</span></td><td><span class="category-badge ${catCls}">${e.category||'—'}</span></td><td>${e.comm||'—'}</td><td>${e.pid||'—'}</td><td>${e.syscall||'—'}</td><td title="${e.filename||''}"><span class="path-text">${e.filename||'—'}</span></td><td title="${e.description||''}" style="max-width:300px;white-space:normal;font-size:11px;color:var(--text-secondary)">${e.description||'—'}</td></tr>`;
  }).join('');
}

// ===== Admission Events =====
function renderAdmissionEvents(events, total) {
  const tbody=document.getElementById('admissionBody'), countEl=document.getElementById('admissionCount');
  animateValue('statAdmission', total||0);
  if(countEl) countEl.textContent=`${total||0} blocked`;
  if(!events||!events.length){tbody.innerHTML='<tr class="empty-row"><td colspan="5">No policy violations recorded.</td></tr>';return;}
  tbody.innerHTML=events.slice(0,20).map(e=>{
    const t=new Date(e.timestamp).toLocaleString();
    const viols=(e.violations||[]).map(v=>`• ${v}`).join('\n');
    return `<tr><td>${t}</td><td><span class="action-denied">${e.action||'DENIED'}</span></td><td><span class="ns-badge">${e.namespace||'—'}</span></td><td><span class="pod-badge">${e.pod_name||'—'}</span></td><td class="violation-text" title="${viols}">${(e.violations||[]).length} violation(s)</td></tr>`;
  }).join('');
}

// ===== GPU Security =====
let gpuStats = {device:0, model:0, memory:0, unapproved:0, score:0};
function updateGpuFromEbpf(events) {
  if(!events||!events.length) return;
  let dev=0,mod=0,mem=0;
  for(const e of events){
    if(e.category==='gpu_unauthorized_access') dev++;
    else if(e.category==='model_weight_access') mod++;
    else if(e.category==='process_injection') mem++;
  }
  gpuStats.device+=dev; gpuStats.model+=mod; gpuStats.memory+=mem;
  gpuStats.score = Math.min(100, gpuStats.device*15 + gpuStats.model*20 + gpuStats.memory*30 + gpuStats.unapproved*10);
  // Update stat card
  const totalGpu = gpuStats.device+gpuStats.model+gpuStats.memory+gpuStats.unapproved;
  animateValue('statGpu', totalGpu);
  // Update GPU metrics
  document.getElementById('gpuDeviceAccess').textContent = gpuStats.device;
  document.getElementById('gpuModelAccess').textContent = gpuStats.model;
  document.getElementById('gpuMemoryAttach').textContent = gpuStats.memory;
  document.getElementById('gpuUnapproved').textContent = gpuStats.unapproved;
  // Update score ring
  const scoreEl = document.querySelector('.gpu-score-value');
  if(scoreEl) scoreEl.textContent = gpuStats.score;
  updateGpuChart(gpuStats.score);
  // Show GPU badge if alerts exist
  const badge = document.getElementById('gpuBadge');
  if(badge && totalGpu > 0) badge.style.display = 'inline';
  // GPU status
  const status = document.getElementById('gpuStatus');
  if(status) status.textContent = totalGpu>0 ? `⚠ ${totalGpu} alerts` : '✅ Secure';
  // GPU alerts list
  const alertsEl = document.getElementById('gpuAlerts');
  const gpuEvents = (events||[]).filter(e=>['gpu_unauthorized_access','model_weight_access','process_injection'].includes(e.category));
  if(gpuEvents.length > 0) {
    alertsEl.innerHTML = gpuEvents.slice(0,5).map(e=>
      `<div class="gpu-alert-item">${new Date(e.timestamp).toLocaleTimeString()} — ${e.description||e.category}</div>`
    ).join('');
  }
}

// ===== Charts =====
function createGradient(ctx,top,bot){const g=ctx.createLinearGradient(0,0,0,250);g.addColorStop(0,top);g.addColorStop(1,bot);return g;}
function initTrendChart(){
  const ctx=document.getElementById('trendChart').getContext('2d');
  trendChart=new Chart(ctx,{type:'line',data:{labels:[],datasets:[{label:'Risk Score',data:[],borderColor:'#5794f2',backgroundColor:createGradient(ctx,'rgba(87,148,242,0.25)','rgba(87,148,242,0.02)'),fill:true,tension:0.35,borderWidth:2,pointRadius:3,pointHoverRadius:5,pointBackgroundColor:'#5794f2',pointBorderColor:'#22262c',pointBorderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,scales:{x:{display:true,grid:{color:'rgba(44,48,56,0.6)',drawBorder:false},ticks:{maxTicksLimit:10,font:{size:10}}},y:{beginAtZero:true,max:100,grid:{color:'rgba(44,48,56,0.6)',drawBorder:false},ticks:{stepSize:25,font:{size:10}}}},plugins:{legend:{display:false},tooltip:{backgroundColor:'#1e2228',borderColor:'#3a3f4a',borderWidth:1,padding:10,cornerRadius:4}},animation:{duration:300}}});
}
function updateTrendChart(h){
  const r=h.slice(0,30).reverse(); if(!r.length) return;
  trendChart.data.labels=r.map(e=>new Date(e.timestamp).toLocaleTimeString());
  trendChart.data.datasets[0].data=r.map(e=>e.risk_score);
  trendChart.data.datasets[0].pointBackgroundColor=r.map(e=>e.risk_score>=80?'#f2495c':e.risk_score>=50?'#ff9830':'#73bf69');
  trendChart.update('none');
}
function initVerdictChart(){
  const ctx=document.getElementById('verdictChart').getContext('2d');
  verdictChart=new Chart(ctx,{type:'doughnut',data:{labels:['High Risk','Medium Risk','Clean','Unknown'],datasets:[{data:[0,0,0,0],backgroundColor:['#f2495c','#ff9830','#73bf69','#5a6270'],borderWidth:0,spacing:2}]},options:{responsive:true,maintainAspectRatio:false,cutout:'72%',plugins:{legend:{position:'bottom',labels:{padding:12,usePointStyle:true,pointStyle:'circle',font:{size:10}}},tooltip:{backgroundColor:'#1e2228',borderColor:'#3a3f4a',borderWidth:1,padding:10,cornerRadius:4}}},plugins:[{id:'centerText',afterDraw(chart){const{ctx:c,chartArea:{left,right,top,bottom}}=chart;const total=chart.data.datasets[0].data.reduce((a,b)=>a+b,0);c.save();c.textAlign='center';c.textBaseline='middle';c.fillStyle='#d8dee9';c.font="300 28px 'Roboto'";c.fillText(total,(left+right)/2,(top+bottom)/2-6);c.fillStyle='#5a6270';c.font="500 10px 'Roboto'";c.fillText('TOTAL',(left+right)/2,(top+bottom)/2+16);c.restore();}}]});
}
function updateVerdictChart(s){
  if(!verdictChart) return;
  const h=s.high_risk||0,m=(s.threats_detected||0)-h,c=s.clean_files||0,u=(s.total_scans||0)-h-m-c;
  verdictChart.data.datasets[0].data=[h,Math.max(m,0),c,Math.max(u,0)];
  verdictChart.update('none');
}

// ===== GPU Score Ring Chart =====
function initGpuChart(){
  const canvas=document.getElementById('gpuScoreChart'); if(!canvas) return;
  const ctx=canvas.getContext('2d');
  gpuChart=new Chart(ctx,{type:'doughnut',data:{labels:['Risk','Safe'],datasets:[{data:[0,100],backgroundColor:['#33cccc','rgba(44,48,56,0.5)'],borderWidth:0,circumference:270,rotation:225}]},options:{responsive:true,maintainAspectRatio:true,cutout:'82%',plugins:{legend:{display:false},tooltip:{enabled:false}},animation:{duration:600}}});
}
function updateGpuChart(score){
  if(!gpuChart) return;
  const color = score>=70?'#f2495c':score>=40?'#ff9830':'#33cccc';
  gpuChart.data.datasets[0].data=[score, 100-score];
  gpuChart.data.datasets[0].backgroundColor=[color,'rgba(44,48,56,0.5)'];
  gpuChart.update('none');
  const v=document.querySelector('.gpu-score-value');
  if(v) v.style.color=color;
}

// ===== AI Panel =====
function updateAIPanel(h){
  const p=document.getElementById('aiPanel'),c=document.getElementById('aiContent');
  const w=h.filter(e=>e.ai_insight&&e.ai_insight.length>20);
  if(!w.length){p.style.display='none';return;}
  p.style.display='block';
  c.innerHTML=w.slice(0,3).map(e=>`<div class="ai-insight-card"><div class="ai-insight-header">⚠ ${e.filename} — ${e.node_name} — Score: ${e.risk_score}</div><div class="ai-insight-body">${e.ai_insight}</div></div>`).join('');
}

// ===== Helpers =====
function verdictClass(v){return v==='HIGH RISK'?'HIGH':v==='MEDIUM RISK'?'MEDIUM':v==='CLEAN'?'CLEAN':'UNKNOWN';}
