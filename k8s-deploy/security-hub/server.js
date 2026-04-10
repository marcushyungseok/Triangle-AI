const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const ANALYZER_URL = process.env.ANALYZER_URL || 'http://pdf-analyzer-service:5000';
const POLL_INTERVAL = parseInt(process.env.POLL_INTERVAL || '3000');

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Proxy endpoints to the engine
app.get('/api/events', async (req, res) => {
  try {
    const r = await fetch(`${ANALYZER_URL}/api/events?limit=50`, { timeout: 5000 });
    res.json(await r.json());
  } catch { res.json({ events: [], total: 0 }); }
});

app.get('/api/stats', async (req, res) => {
  try {
    const r = await fetch(`${ANALYZER_URL}/api/stats`, { timeout: 5000 });
    res.json(await r.json());
  } catch { res.json({ total_scans: 0, threats_detected: 0, clean_files: 0, active_nodes: 0 }); }
});

app.get('/api/health', async (req, res) => {
  try {
    const r = await fetch(`${ANALYZER_URL}/health`, { timeout: 3000 });
    const d = await r.json();
    res.json({ hub: 'ok', engine: d.status });
  } catch { res.json({ hub: 'ok', engine: 'unreachable' }); }
});

// WebSocket — push updates to all connected browsers
let lastEventCount = 0;

async function pollAndBroadcast() {
  try {
    const [eventsRes, statsRes] = await Promise.all([
      fetch(`${ANALYZER_URL}/api/events?limit=30`, { timeout: 5000 }),
      fetch(`${ANALYZER_URL}/api/stats`, { timeout: 5000 }),
    ]);
    const events = await eventsRes.json();
    const stats = await statsRes.json();

    // Only broadcast if new events arrived
    if (events.total !== lastEventCount) {
      lastEventCount = events.total;
      const payload = JSON.stringify({ type: 'update', events: events.events, stats });
      wss.clients.forEach(ws => {
        if (ws.readyState === 1) ws.send(payload);
      });
    }
  } catch (e) {
    // Engine unreachable, that's okay
  }
}

setInterval(pollAndBroadcast, POLL_INTERVAL);

wss.on('connection', (ws) => {
  console.log('Security Hub client connected');
  // Send initial data immediately
  pollAndBroadcast();
  ws.on('close', () => console.log('Client disconnected'));
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Security Hub running on port ${PORT}`);
  console.log(`Engine: ${ANALYZER_URL}`);
  console.log(`WebSocket polling every ${POLL_INTERVAL}ms`);
});
