const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const FRONTEND_PORT = 5001;
const BACKEND_PORT = 5005;
const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, 'data', 'cards.json');

function readCards() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return [];
  }
}

function writeCards(cards) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(cards, null, 2), 'utf8');
}

function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, {
    'Content-Type': type,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(body);
}

function serveFile(res, filePath, type = 'text/html; charset=utf-8') {
  fs.readFile(filePath, (err, data) => {
    if (err) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
    send(res, 200, data, type);
  });
}

const backend = http.createServer((req, res) => {
  const u = new URL(req.url, `http://localhost:${BACKEND_PORT}`);

  if (req.method === 'OPTIONS') return send(res, 204, '');

  if (u.pathname === '/health') {
    return send(res, 200, JSON.stringify({ ok: true, service: 'backend', port: BACKEND_PORT }));
  }

  if (u.pathname === '/api/cards' && req.method === 'GET') {
    return send(res, 200, JSON.stringify(readCards()));
  }

  if (u.pathname === '/api/cards' && req.method === 'POST') {
    let raw = '';
    req.on('data', c => raw += c);
    req.on('end', () => {
      try {
        const payload = JSON.parse(raw || '{}');
        const cards = readCards();
        const card = {
          id: `c-${Date.now()}`,
          title: payload.title || '未命名',
          desc: payload.desc || '',
          link: payload.link || '#',
          image: payload.image || ''
        };
        cards.unshift(card);
        writeCards(cards);
        send(res, 201, JSON.stringify(card));
      } catch (e) {
        send(res, 400, JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }

  if (u.pathname.startsWith('/api/cards/') && req.method === 'PUT') {
    const id = u.pathname.split('/').pop();
    let raw = '';
    req.on('data', c => raw += c);
    req.on('end', () => {
      try {
        const payload = JSON.parse(raw || '{}');
        const cards = readCards();
        const idx = cards.findIndex(c => c.id === id);
        if (idx === -1) return send(res, 404, JSON.stringify({ error: 'Not found' }));
        cards[idx] = { ...cards[idx], ...payload, id };
        writeCards(cards);
        send(res, 200, JSON.stringify(cards[idx]));
      } catch {
        send(res, 400, JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }

  if (u.pathname.startsWith('/api/cards/') && req.method === 'DELETE') {
    const id = u.pathname.split('/').pop();
    const cards = readCards();
    const next = cards.filter(c => c.id !== id);
    writeCards(next);
    return send(res, 200, JSON.stringify({ ok: true }));
  }

  if (u.pathname === '/' || u.pathname === '/admin') {
    return serveFile(res, path.join(ROOT, 'admin', 'index.html'));
  }

  return send(res, 404, JSON.stringify({ error: 'Not found' }));
});

const frontend = http.createServer((req, res) => {
  const u = new URL(req.url, `http://localhost:${FRONTEND_PORT}`);

  if (u.pathname === '/health') {
    return send(res, 200, JSON.stringify({ ok: true, service: 'frontend', port: FRONTEND_PORT }));
  }

  if (u.pathname === '/' || u.pathname === '/index.html') {
    return serveFile(res, path.join(ROOT, 'frontend', 'index.html'));
  }

  return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
});

backend.listen(BACKEND_PORT, () => {
  console.log(`Backend admin running: http://localhost:${BACKEND_PORT}`);
});

frontend.listen(FRONTEND_PORT, () => {
  console.log(`Frontend running: http://localhost:${FRONTEND_PORT}`);
});
