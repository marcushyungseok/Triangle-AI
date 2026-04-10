const express = require('express');
const multer = require('multer');
const fetch = require('node-fetch');
const FormData = require('form-data');
const path = require('path');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

const ANALYZER_URL = process.env.ANALYZER_URL || 'http://pdf-analyzer-service:5000';

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Proxy analysis request to pdf-analyzer service
app.post('/api/analyze', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const form = new FormData();
    form.append('file', req.file.buffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype,
    });

    const response = await fetch(`${ANALYZER_URL}/analyze`, {
      method: 'POST',
      body: form,
      headers: form.getHeaders(),
      timeout: 120000,
    });

    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error('Analysis error:', err);
    res.status(500).json({ error: 'Analysis failed: ' + err.message });
  }
});

// Health check
app.get('/api/health', async (req, res) => {
  try {
    const response = await fetch(`${ANALYZER_URL}/health`, { timeout: 5000 });
    const data = await response.json();
    res.json({ dashboard: 'ok', analyzer: data.status });
  } catch (err) {
    res.json({ dashboard: 'ok', analyzer: 'unreachable' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Dashboard running on port ${PORT}`);
  console.log(`Analyzer URL: ${ANALYZER_URL}`);
});
