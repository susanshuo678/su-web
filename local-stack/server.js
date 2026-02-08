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
  config: path.join(DATA_DIR, 'config.json'),
  ads: path.join(DATA_DIR, 'ads.json'),
  shortcuts: path.join(DATA_DIR, 'shortcuts.json'),
  tabs: path.join(DATA_DIR, 'tabs.json'),
  cards: path.join(DATA_DIR, 'cards.json')
};

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(MEDIA_DIR, { recursive: true });

const tokens = new Set();
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.webp': 'image/webp', '.mp4': 'video/mp4', '.webm': 'video/webm'
};

function readJson(file, fallback) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; } }
function writeJson(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8'); }
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
    req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch (e) { reject(e); } });
  });
}
function serveFile(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
    send(res, 200, data, MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream');
  });
}
function auth(req, res) {
  const t = req.headers['x-admin-token'];
  if (!t || !tokens.has(t)) { send(res, 401, JSON.stringify({ error: 'unauthorized' })); return false; }
  return true;
}

function ensureDefaults() {
  if (!fs.existsSync(FILES.config)) writeJson(FILES.config, { adminPassword: '123456' });
  if (!fs.existsSync(FILES.ads)) writeJson(FILES.ads, [{ id: 'ad-1', title: '🔥 爆款福利专区', image: '', link: '#', order: 1 }]);
  if (!fs.existsSync(FILES.shortcuts)) writeJson(FILES.shortcuts, [
    { id: 's-1', name: '美团外卖', icon: '', link: '#', order: 1 },
    { id: 's-2', name: '饿了么', icon: '', link: '#', order: 2 }
  ]);
  if (!fs.existsSync(FILES.tabs)) writeJson(FILES.tabs, [
    { id: 't-1', name: '全部优惠', key: 'all', order: 1 },
    { id: 't-2', name: '外卖红包', key: 'food', order: 2 },
    { id: 't-3', name: '出行打车', key: 'taxi', order: 3 }
  ]);
  if (!fs.existsSync(FILES.cards)) writeJson(FILES.cards, [{
    id: 'c-1', title: '美团外卖', summary: '外卖优惠券\n下单更划算\n每日可领', contentMd: '',
    link: '#', image: '', video: '', category: 'food', buttonText: '领', order: 1, enabled: true
  }]);
}
ensureDefaults();

function sortByOrder(arr) { return [...arr].sort((a,b)=>(Number(a.order)||9999)-(Number(b.order)||9999)); }

function collectionRoutes(req, res, pathname, file, defaults = {}) {
  if (pathname === `/api/${file}` && req.method === 'GET') return send(res, 200, JSON.stringify(sortByOrder(readJson(FILES[file], []))));
  if (pathname === `/api/${file}` && req.method === 'POST') {
    if (!auth(req,res)) return true;
    parseBody(req).then(payload => {
      const list = readJson(FILES[file], []);
      const item = { id: `${file.slice(0,1)}-${Date.now()}`, ...defaults, ...payload };
      list.push(item); writeJson(FILES[file], list); send(res, 201, JSON.stringify(item));
    }).catch(()=>send(res,400,JSON.stringify({error:'Invalid JSON'})));
    return true;
  }
  if (pathname.startsWith(`/api/${file}/`) && req.method === 'PUT') {
    if (!auth(req,res)) return true;
    const id = pathname.split('/').pop();
    parseBody(req).then(payload => {
      const list = readJson(FILES[file], []); const i = list.findIndex(x=>x.id===id);
      if (i < 0) return send(res,404,JSON.stringify({error:'Not found'}));
      list[i] = { ...list[i], ...payload, id }; writeJson(FILES[file], list); send(res,200,JSON.stringify(list[i]));
    }).catch(()=>send(res,400,JSON.stringify({error:'Invalid JSON'})));
    return true;
  }
  if (pathname.startsWith(`/api/${file}/`) && req.method === 'DELETE') {
    if (!auth(req,res)) return true;
    const id = pathname.split('/').pop();
    writeJson(FILES[file], readJson(FILES[file], []).filter(x=>x.id!==id));
    return send(res,200,JSON.stringify({ok:true}));
  }
  return false;
}

const backend = http.createServer((req, res) => {
  const u = new URL(req.url, `http://localhost:${BACKEND_PORT}`);
  if (req.method === 'OPTIONS') return send(res, 204, '');

  if (u.pathname === '/health') return send(res, 200, JSON.stringify({ ok: true, service: 'backend', port: BACKEND_PORT }));
  if (u.pathname === '/' || u.pathname === '/admin') return serveFile(res, path.join(ROOT, 'admin', 'index.html'));

  if (u.pathname === '/api/login' && req.method === 'POST') {
    return parseBody(req).then(({ password }) => {
      const cfg = readJson(FILES.config, { adminPassword: '123456' });
      if (password !== cfg.adminPassword) return send(res, 401, JSON.stringify({ error: '密码错误' }));
      const token = crypto.randomBytes(20).toString('hex'); tokens.add(token);
      send(res, 200, JSON.stringify({ ok: true, token }));
    }).catch(()=>send(res,400,JSON.stringify({error:'Invalid JSON'})));
  }

  if (u.pathname === '/api/change-password' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(({ password }) => {
      if (!password || password.length < 4) return send(res, 400, JSON.stringify({ error: '密码至少4位' }));
      writeJson(FILES.config, { adminPassword: password });
      send(res, 200, JSON.stringify({ ok: true }));
    }).catch(()=>send(res,400,JSON.stringify({error:'Invalid JSON'})));
  }

  if (u.pathname === '/api/upload' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(({ filename, contentBase64 }) => {
      if (!filename || !contentBase64) return send(res,400,JSON.stringify({error:'missing fields'}));
      const safe = `${Date.now()}-${String(filename).replace(/[^a-zA-Z0-9._-]/g,'_')}`;
      fs.writeFileSync(path.join(MEDIA_DIR, safe), Buffer.from(contentBase64, 'base64'));
      send(res,200,JSON.stringify({ok:true,url:`/media/${safe}`}));
    }).catch(()=>send(res,400,JSON.stringify({error:'upload failed'})));
  }

  if (u.pathname.startsWith('/media/')) return serveFile(res, path.join(MEDIA_DIR, u.pathname.replace('/media/','')));

  if (collectionRoutes(req,res,u.pathname,'ads',{ title:'新广告', image:'', link:'#', order:999 })) return;
  if (collectionRoutes(req,res,u.pathname,'shortcuts',{ name:'新入口', icon:'', link:'#', order:999 })) return;
  if (collectionRoutes(req,res,u.pathname,'tabs',{ name:'新分类', key:'custom', order:999 })) return;
  if (collectionRoutes(req,res,u.pathname,'cards',{ title:'新卡片', summary:'', contentMd:'', link:'#', image:'', video:'', category:'all', buttonText:'领', order:999, enabled:true })) return;

  send(res, 404, JSON.stringify({ error: 'Not found' }));
});

const frontend = http.createServer((req, res) => {
  const u = new URL(req.url, `http://localhost:${FRONTEND_PORT}`);
  if (u.pathname === '/health') return send(res, 200, JSON.stringify({ ok: true, service: 'frontend', port: FRONTEND_PORT }));
  if (u.pathname === '/' || u.pathname === '/index.html') return serveFile(res, path.join(ROOT, 'frontend', 'index.html'));
  send(res, 404, 'Not found', 'text/plain; charset=utf-8');
});

backend.listen(BACKEND_PORT, () => console.log(`Backend admin running: http://localhost:${BACKEND_PORT}`));
frontend.listen(FRONTEND_PORT, () => console.log(`Frontend running: http://localhost:${FRONTEND_PORT}`));
