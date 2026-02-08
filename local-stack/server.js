const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const FRONTEND_PORT = 5001;
const BACKEND_PORT = 5005;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const MEDIA_DIR = path.join(ROOT, 'media');

const FILES = {
  cards: path.join(DATA_DIR, 'cards.json'),
  ads: path.join(DATA_DIR, 'ads.json'),
  config: path.join(DATA_DIR, 'config.json')
};

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(MEDIA_DIR, { recursive: true });

const tokens = new Set();

const mime = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.pdf': 'application/pdf'
};

function readJson(file, fallback = []) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}
function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}
function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, {
    'Content-Type': type,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token'
  });
  res.end(body);
}
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', c => raw += c);
    req.on('end', () => {
      try { resolve(JSON.parse(raw || '{}')); }
      catch (e) { reject(e); }
    });
  });
}
function ensureAuth(req, res) {
  const t = req.headers['x-admin-token'];
  if (!t || !tokens.has(t)) {
    send(res, 401, JSON.stringify({ error: 'unauthorized' }));
    return false;
  }
  return true;
}
function serveStatic(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
    const ext = path.extname(filePath).toLowerCase();
    send(res, 200, data, mime[ext] || 'application/octet-stream');
  });
}

const backend = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://localhost:${BACKEND_PORT}`);
  if (req.method === 'OPTIONS') return send(res, 204, '');

  if (u.pathname === '/health') return send(res, 200, JSON.stringify({ ok: true, service: 'backend', port: BACKEND_PORT }));
  if (u.pathname === '/' || u.pathname === '/admin') return serveStatic(res, path.join(ROOT, 'admin', 'index.html'));

  // Public read APIs
  if (u.pathname === '/api/cards' && req.method === 'GET') return send(res, 200, JSON.stringify(readJson(FILES.cards, [])));
  if (u.pathname === '/api/ads' && req.method === 'GET') return send(res, 200, JSON.stringify(readJson(FILES.ads, [])));

  if (u.pathname === '/api/login' && req.method === 'POST') {
    try {
      const { password } = await parseBody(req);
      const cfg = readJson(FILES.config, { adminPassword: '123456' });
      if (password !== cfg.adminPassword) return send(res, 401, JSON.stringify({ error: '密码错误' }));
      const token = crypto.randomBytes(24).toString('hex');
      tokens.add(token);
      return send(res, 200, JSON.stringify({ ok: true, token }));
    } catch {
      return send(res, 400, JSON.stringify({ error: 'Invalid JSON' }));
    }
  }

  // Protected APIs
  if (u.pathname === '/api/upload' && req.method === 'POST') {
    if (!ensureAuth(req, res)) return;
    try {
      const { filename, contentBase64 } = await parseBody(req);
      if (!filename || !contentBase64) return send(res, 400, JSON.stringify({ error: 'missing fields' }));
      const safe = `${Date.now()}-${String(filename).replace(/[^a-zA-Z0-9._-]/g, '_')}`;
      const filePath = path.join(MEDIA_DIR, safe);
      fs.writeFileSync(filePath, Buffer.from(contentBase64, 'base64'));
      return send(res, 200, JSON.stringify({ ok: true, url: `/media/${safe}` }));
    } catch {
      return send(res, 400, JSON.stringify({ error: 'upload failed' }));
    }
  }

  if (u.pathname.startsWith('/media/')) {
    const rel = u.pathname.replace('/media/', '');
    const filePath = path.join(MEDIA_DIR, rel);
    if (!filePath.startsWith(MEDIA_DIR)) return send(res, 400, JSON.stringify({ error: 'bad path' }));
    return serveStatic(res, filePath);
  }

  // cards CRUD
  if (u.pathname === '/api/cards' && req.method === 'POST') {
    if (!ensureAuth(req, res)) return;
    const payload = await parseBody(req).catch(() => null);
    if (!payload) return send(res, 400, JSON.stringify({ error: 'Invalid JSON' }));
    const list = readJson(FILES.cards, []);
    const item = {
      id: `c-${Date.now()}`,
      title: payload.title || '未命名',
      summary: payload.summary || '',
      contentMd: payload.contentMd || '',
      link: payload.link || '#',
      image: payload.image || '',
      video: payload.video || ''
    };
    list.unshift(item);
    writeJson(FILES.cards, list);
    return send(res, 201, JSON.stringify(item));
  }
  if (u.pathname.startsWith('/api/cards/') && req.method === 'PUT') {
    if (!ensureAuth(req, res)) return;
    const id = u.pathname.split('/').pop();
    const payload = await parseBody(req).catch(() => null);
    if (!payload) return send(res, 400, JSON.stringify({ error: 'Invalid JSON' }));
    const list = readJson(FILES.cards, []);
    const i = list.findIndex(x => x.id === id);
    if (i < 0) return send(res, 404, JSON.stringify({ error: 'Not found' }));
    list[i] = { ...list[i], ...payload, id };
    writeJson(FILES.cards, list);
    return send(res, 200, JSON.stringify(list[i]));
  }
  if (u.pathname.startsWith('/api/cards/') && req.method === 'DELETE') {
    if (!ensureAuth(req, res)) return;
    const id = u.pathname.split('/').pop();
    const list = readJson(FILES.cards, []).filter(x => x.id !== id);
    writeJson(FILES.cards, list);
    return send(res, 200, JSON.stringify({ ok: true }));
  }

  // ads CRUD
  if (u.pathname === '/api/ads' && req.method === 'POST') {
    if (!ensureAuth(req, res)) return;
    const payload = await parseBody(req).catch(() => null);
    if (!payload) return send(res, 400, JSON.stringify({ error: 'Invalid JSON' }));
    const list = readJson(FILES.ads, []);
    const item = { id: `ad-${Date.now()}`, text: payload.text || '新广告', link: payload.link || '#' };
    list.push(item);
    writeJson(FILES.ads, list);
    return send(res, 201, JSON.stringify(item));
  }
  if (u.pathname.startsWith('/api/ads/') && req.method === 'PUT') {
    if (!ensureAuth(req, res)) return;
    const id = u.pathname.split('/').pop();
    const payload = await parseBody(req).catch(() => null);
    if (!payload) return send(res, 400, JSON.stringify({ error: 'Invalid JSON' }));
    const list = readJson(FILES.ads, []);
    const i = list.findIndex(x => x.id === id);
    if (i < 0) return send(res, 404, JSON.stringify({ error: 'Not found' }));
    list[i] = { ...list[i], ...payload, id };
    writeJson(FILES.ads, list);
    return send(res, 200, JSON.stringify(list[i]));
  }
  if (u.pathname.startsWith('/api/ads/') && req.method === 'DELETE') {
    if (!ensureAuth(req, res)) return;
    const id = u.pathname.split('/').pop();
    const list = readJson(FILES.ads, []).filter(x => x.id !== id);
    writeJson(FILES.ads, list);
    return send(res, 200, JSON.stringify({ ok: true }));
  }

  return send(res, 404, JSON.stringify({ error: 'Not found' }));
});

const frontend = http.createServer((req, res) => {
  const u = new URL(req.url, `http://localhost:${FRONTEND_PORT}`);
  if (u.pathname === '/health') return send(res, 200, JSON.stringify({ ok: true, service: 'frontend', port: FRONTEND_PORT }));
  if (u.pathname === '/' || u.pathname === '/index.html') return serveStatic(res, path.join(ROOT, 'frontend', 'index.html'));
  return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
});

backend.listen(BACKEND_PORT, () => console.log(`Backend admin running: http://localhost:${BACKEND_PORT}`));
frontend.listen(FRONTEND_PORT, () => console.log(`Frontend running: http://localhost:${FRONTEND_PORT}`));
