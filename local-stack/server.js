const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
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

const tokens = new Map();
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12h
const MAX_TOKENS = 500;

const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 10 * 60 * 1000; // 10min
const LOGIN_MAX_ATTEMPTS = 10;
const LOGIN_ATTEMPTS_MAX_KEYS = 5000;

function now() { return Date.now(); }

let bootstrapCache = null;
let bootstrapEtagCache = null;
let bootstrapBodyCache = null;
const BOOTSTRAP_CACHE_TTL_MS = 2000;
const PUBLIC_API_CACHE_CONTROL = 'public, max-age=15, stale-while-revalidate=60, must-revalidate';

function buildBootstrapPayload() {
  return {
    ads: getSortedCollection('ads'),
    shortcuts: getSortedCollection('shortcuts'),
    tabs: getSortedCollection('tabs'),
    cards: getSortedCollection('cards').filter(x => x.enabled !== false)
  };
}

function getBootstrapPayload() {
  const t = now();
  if (bootstrapCache && (t - bootstrapCache.ts) < BOOTSTRAP_CACHE_TTL_MS) return bootstrapCache.data;
  const data = buildBootstrapPayload();
  bootstrapCache = { ts: t, data };
  return data;
}

function getBootstrapEtag(data) {
  if (bootstrapEtagCache && bootstrapEtagCache.dataRef === data) return bootstrapEtagCache.etag;
  const etag = `W/"bootstrap-${crypto.createHash('sha1').update(JSON.stringify(data)).digest('hex').slice(0, 16)}"`;
  bootstrapEtagCache = { dataRef: data, etag };
  return etag;
}

function getBootstrapBody(data) {
  if (bootstrapBodyCache && bootstrapBodyCache.dataRef === data) return bootstrapBodyCache;
  const raw = Buffer.from(JSON.stringify(data), 'utf8');
  bootstrapBodyCache = {
    dataRef: data,
    raw,
    br: raw.length >= 1024 ? zlib.brotliCompressSync(raw, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } }) : null,
    gzip: raw.length >= 1024 ? zlib.gzipSync(raw, { level: 6 }) : null
  };
  return bootstrapBodyCache;
}


function pickJsonEncoding(req, bodyBuffer) {
  const ae = String(req.headers['accept-encoding'] || '');
  if (bodyBuffer.length < 1024) return null;
  if (/\bbr\b/i.test(ae)) return 'br';
  if (/\bgzip\b/i.test(ae)) return 'gzip';
  return null;
}

function maybeEncodeJson(req, bodyBuffer) {
  const encoding = pickJsonEncoding(req, bodyBuffer);
  if (!encoding) return { body: bodyBuffer, encoding: null };
  if (encoding === 'br') return { body: zlib.brotliCompressSync(bodyBuffer, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } }), encoding };
  if (encoding === 'gzip') return { body: zlib.gzipSync(bodyBuffer, { level: 6 }), encoding };
  return { body: bodyBuffer, encoding: null };
}

function etagMatches(ifNoneMatchHeader, etag) {
  if (!ifNoneMatchHeader || !etag) return false;
  const clean = (s) => String(s || '').trim().replace(/^W\//, '').trim();
  if (String(ifNoneMatchHeader).trim() === '*') return true;
  const target = clean(etag);
  return String(ifNoneMatchHeader)
    .split(',')
    .map(x => clean(x))
    .some(tag => tag === target);
}

const jsonResponseCache = new WeakMap();

function getCachedJsonPayload(data) {
  if (!data || (typeof data !== 'object' && typeof data !== 'function')) return null;
  const hit = jsonResponseCache.get(data);
  if (hit) return hit;
  const body = JSON.stringify(data);
  const raw = Buffer.from(body, 'utf8');
  const etag = `W/"json-${crypto.createHash('sha1').update(body).digest('hex').slice(0, 16)}"`;
  const payload = {
    etag,
    raw,
    br: raw.length >= 1024 ? zlib.brotliCompressSync(raw, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } }) : null,
    gzip: raw.length >= 1024 ? zlib.gzipSync(raw, { level: 6 }) : null
  };
  jsonResponseCache.set(data, payload);
  return payload;
}

function sendJsonWithEtag(req, res, data, cacheControl = 'private, max-age=0, must-revalidate') {
  const cached = getCachedJsonPayload(data);
  const etag = cached ? cached.etag : `W/"json-${crypto.createHash('sha1').update(JSON.stringify(data)).digest('hex').slice(0, 16)}"`;

  if (etagMatches(req.headers['if-none-match'], etag)) {
    res.writeHead(304, {
      'ETag': etag,
      'Cache-Control': cacheControl,
      'Access-Control-Allow-Origin': '*',
      'Vary': 'If-None-Match, Accept-Encoding'
    });
    return res.end();
  }

  const raw = cached ? cached.raw : Buffer.from(JSON.stringify(data), 'utf8');
  const ae = String(req.headers['accept-encoding'] || '');
  const encoded = cached
    ? ((cached.br && /\bbr\b/i.test(ae))
      ? { body: cached.br, encoding: 'br' }
      : ((cached.gzip && /\bgzip\b/i.test(ae))
        ? { body: cached.gzip, encoding: 'gzip' }
        : { body: raw, encoding: null }))
    : maybeEncodeJson(req, raw);

  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': encoded.body.length,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,HEAD,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Cache-Control': cacheControl,
    'ETag': etag,
    'Vary': 'If-None-Match, Accept-Encoding'
  };
  if (encoded.encoding) headers['Content-Encoding'] = encoded.encoding;
  res.writeHead(200, headers);
  if (req.method === 'HEAD') return res.end();
  res.end(encoded.body);
}

function sendBootstrap(req, res) {
  const data = getBootstrapPayload();
  const etag = getBootstrapEtag(data);
  const cacheControl = PUBLIC_API_CACHE_CONTROL;
  if (etagMatches(req.headers['if-none-match'], etag)) {
    res.writeHead(304, {
      'ETag': etag,
      'Cache-Control': cacheControl,
      'Access-Control-Allow-Origin': '*',
      'Vary': 'If-None-Match, Accept-Encoding'
    });
    return res.end();
  }

  const body = getBootstrapBody(data);
  const acceptEncoding = String(req.headers['accept-encoding'] || '');
  const useBr = !!body.br && /\bbr\b/i.test(acceptEncoding);
  const useGzip = !useBr && !!body.gzip && /\bgzip\b/i.test(acceptEncoding);
  const output = useBr ? body.br : (useGzip ? body.gzip : body.raw);

  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': output.length,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,HEAD,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Cache-Control': cacheControl,
    'ETag': etag,
    'Vary': 'If-None-Match, Accept-Encoding'
  };
  if (useBr) headers['Content-Encoding'] = 'br';
  else if (useGzip) headers['Content-Encoding'] = 'gzip';
  res.writeHead(200, headers);
  if (req.method === 'HEAD') return res.end();
  res.end(output);
}

function invalidateBootstrapCache() {
  bootstrapCache = null;
  bootstrapEtagCache = null;
  bootstrapBodyCache = null;
  sortedCollectionCache.clear();
}

function pruneTokens() {
  const t = now();
  for (const [token, exp] of tokens) if (exp <= t) tokens.delete(token);
  if (tokens.size > MAX_TOKENS) {
    const sorted = [...tokens.entries()].sort((a, b) => a[1] - b[1]);
    for (let i = 0; i < sorted.length - MAX_TOKENS; i++) tokens.delete(sorted[i][0]);
  }
}
function pruneLoginAttempts() {
  const t = now();
  for (const [ip, attempts] of loginAttempts.entries()) {
    const fresh = attempts.filter(ts => t - ts < LOGIN_WINDOW_MS);
    if (fresh.length) loginAttempts.set(ip, fresh);
    else loginAttempts.delete(ip);
  }
  if (loginAttempts.size > LOGIN_ATTEMPTS_MAX_KEYS) {
    // 异常情况下兜底清理，防止 map 无界增长
    const keys = [...loginAttempts.keys()];
    for (let i = 0; i < keys.length - LOGIN_ATTEMPTS_MAX_KEYS; i++) loginAttempts.delete(keys[i]);
  }
}
setInterval(() => {
  pruneTokens();
  pruneLoginAttempts();
}, 30 * 60 * 1000).unref();

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.webp': 'image/webp', '.mp4': 'video/mp4', '.webm': 'video/webm'
};
const ALLOWED_UPLOAD_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp4', '.webm']);

const jsonReadCache = new Map();
const JSON_READ_CACHE_MAX = 32;
const sortedCollectionCache = new Map();

const staticGzipCache = new Map();
const staticBrCache = new Map();
const STATIC_GZIP_CACHE_MAX = 64;
const STATIC_GZIP_MAX_BYTES = 256 * 1024;

function backupFilePath(file) {
  return `${file}.bak`;
}

function rotateBackups(file) {
  const bak1 = backupFilePath(file);
  const bak2 = `${bak1}.2`;
  const bak3 = `${bak1}.3`;
  try {
    if (fs.existsSync(bak2)) {
      try { fs.copyFileSync(bak2, bak3); } catch {}
    }
    if (fs.existsSync(bak1)) {
      try { fs.copyFileSync(bak1, bak2); } catch {}
    }
  } catch {}
}

function readJson(file, fallback) {
  try {
    const stat = fs.statSync(file);
    const key = `${stat.mtimeMs}-${stat.size}`;
    const hit = jsonReadCache.get(file);
    if (hit && hit.key === key) return hit.value;

    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    jsonReadCache.set(file, { key, value: parsed });
    // 稳定性优化：限制缓存上限，避免未来接入更多文件后缓存无界增长
    if (jsonReadCache.size > JSON_READ_CACHE_MAX) {
      const oldestKey = jsonReadCache.keys().next().value;
      if (oldestKey) jsonReadCache.delete(oldestKey);
    }
    return parsed;
  } catch (err) {
    // 稳定性优化：主文件损坏时尝试从 .bak 自动恢复，避免前台/后台整体空白
    try {
      const backup = backupFilePath(file);
      const candidates = [backup, `${backup}.2`, `${backup}.3`];
      for (const candidate of candidates) {
        if (!fs.existsSync(candidate)) continue;
        try {
          const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8'));
          writeJson(file, parsed);
          return parsed;
        } catch {}
      }
    } catch {}
    if (err && err.name === 'SyntaxError') {
      console.warn(`[readJson] ${path.basename(file)} JSON 解析失败，已回退默认值`);
    }
    return fallback;
  }
}
function writeJson(file, data) {
  const tmp = `${file}.tmp-${process.pid}-${Date.now()}`;
  const backup = backupFilePath(file);
  const content = JSON.stringify(data, null, 2);
  if (fs.existsSync(file)) {
    rotateBackups(file);
    try { fs.copyFileSync(file, backup); } catch {}
  }
  fs.writeFileSync(tmp, content, 'utf8');
  fs.renameSync(tmp, file);
  jsonReadCache.delete(file);
}
function send(res, status, body, type = 'application/json; charset=utf-8', method = 'GET') {
  res.writeHead(status, {
    'Content-Type': type,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,HEAD,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Cache-Control': 'no-store'
  });
  if (method === 'HEAD') return res.end();
  res.end(body);
}

function getCachedCompressedAsset(filePath, stat, encoding = 'gzip') {
  if (!filePath || !stat || stat.size > STATIC_GZIP_MAX_BYTES) return null;
  const key = `${stat.mtimeMs}-${stat.size}`;
  const cache = encoding === 'br' ? staticBrCache : staticGzipCache;
  const hit = cache.get(filePath);
  if (hit && hit.key === key) return hit.buf;

  const raw = fs.readFileSync(filePath);
  const buf = encoding === 'br'
    ? zlib.brotliCompressSync(raw, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } })
    : zlib.gzipSync(raw, { level: 6 });
  cache.set(filePath, { key, buf });
  if (cache.size > STATIC_GZIP_CACHE_MAX) {
    const oldest = cache.keys().next().value;
    if (oldest) cache.delete(oldest);
  }
  return buf;
}
function parseBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    let tooLarge = false;
    let settled = false;
    const MAX_BODY = 5 * 1024 * 1024; // 5MB
    const contentLength = Number(req.headers['content-length'] || 0);

    // 性能优化：已知超限时尽早拒绝，减少无效内存占用
    if (Number.isFinite(contentLength) && contentLength > MAX_BODY) {
      const err = new Error('Payload too large');
      err.code = 'PAYLOAD_TOO_LARGE';
      return reject(err);
    }

    const fail = (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    };
    const done = (val) => {
      if (settled) return;
      settled = true;
      resolve(val);
    };

    req.on('data', c => {
      bytes += c.length;
      if (bytes > MAX_BODY) {
        tooLarge = true;
        // 超限后继续读取并丢弃余下数据，确保稳定返回 413（避免连接被动重置）
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (tooLarge) {
        const err = new Error('Payload too large');
        err.code = 'PAYLOAD_TOO_LARGE';
        return fail(err);
      }
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        done(JSON.parse(raw || '{}'));
      } catch (e) {
        fail(e);
      }
    });
    req.on('aborted', () => {
      const err = new Error('Request aborted');
      err.code = tooLarge ? 'PAYLOAD_TOO_LARGE' : 'REQUEST_ABORTED';
      fail(err);
    });
    req.on('error', (err) => {
      fail(err);
    });
  });
}

function handleParseError(res, err, fallbackMsg = 'Invalid JSON') {
  if (err && err.code === 'PAYLOAD_TOO_LARGE') {
    return send(res, 413, JSON.stringify({ error: 'Payload too large' }));
  }
  return send(res, 400, JSON.stringify({ error: fallbackMsg }));
}

function serveFile(req, res, filePath) {
  fs.stat(filePath, (statErr, stat) => {
    if (statErr || !stat || !stat.isFile()) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');

    const ext = path.extname(filePath).toLowerCase();
    const type = MIME[ext] || 'application/octet-stream';
    const isStaticAsset = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp4', '.webm'].includes(ext);
    const isHtml = ext === '.html';
    const isTextLike = ['.html', '.css', '.js', '.json', '.svg', '.txt'].includes(ext);
    const acceptEncoding = String(req.headers['accept-encoding'] || '');
    const canBr = isTextLike && stat.size >= 1024 && /\bbr\b/i.test(acceptEncoding);
    const canGzip = !canBr && isTextLike && stat.size >= 1024 && /\bgzip\b/i.test(acceptEncoding);

    const lastModified = stat.mtime.toUTCString();
    const etag = `W/\"${stat.size.toString(16)}-${Buffer.from(String(stat.mtimeMs)).toString('base64')}\"`;
    const ifModifiedSince = req.headers['if-modified-since'];
    const isNotModifiedByDate = ifModifiedSince && new Date(ifModifiedSince).getTime() >= Math.floor(stat.mtimeMs);

    if (etagMatches(req.headers['if-none-match'], etag) || isNotModifiedByDate) {
      res.writeHead(304, {
        'ETag': etag,
        'Last-Modified': lastModified,
        'Cache-Control': isStaticAsset ? 'public, max-age=604800, immutable, stale-while-revalidate=86400' : 'no-cache',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'Vary': 'If-None-Match, Accept-Encoding'
      });
      return res.end();
    }

    const headers = {
      'Content-Type': type,
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,HEAD,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
      'ETag': etag,
      'Last-Modified': lastModified,
      'Cache-Control': isStaticAsset ? 'public, max-age=604800, immutable, stale-while-revalidate=86400' : 'no-cache',
      'Vary': 'If-None-Match, Accept-Encoding'
    };
    if (isHtml) {
      headers['Content-Security-Policy'] = "default-src 'self' https: data: blob:; img-src 'self' https: data: blob:; media-src 'self' https: data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'";
    }
    let cachedCompressed = null;
    let selectedEncoding = null;
    if (!canGzip && !canBr) {
      headers['Content-Length'] = stat.size;
    } else {
      selectedEncoding = canBr ? 'br' : 'gzip';
      headers['Content-Encoding'] = selectedEncoding;
      cachedCompressed = getCachedCompressedAsset(filePath, stat, selectedEncoding);
      if (cachedCompressed) headers['Content-Length'] = cachedCompressed.length;
    }

    res.writeHead(200, headers);
    if (req.method === 'HEAD') return res.end();
    if (cachedCompressed) return res.end(cachedCompressed);

    const stream = fs.createReadStream(filePath);
    stream.on('error', () => {
      if (!res.headersSent) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
      res.destroy();
    });
    if (selectedEncoding === 'br') return stream.pipe(zlib.createBrotliCompress({ params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } })).pipe(res);
    if (selectedEncoding === 'gzip') return stream.pipe(zlib.createGzip({ level: 6 })).pipe(res);
    stream.pipe(res);
  });
}
function auth(req, res) {
  const t = req.headers['x-admin-token'];
  const exp = t ? tokens.get(t) : null;
  if (!t || !exp || exp <= now()) {
    if (t) tokens.delete(t);
    send(res, 401, JSON.stringify({ error: 'unauthorized' }));
    return false;
  }
  tokens.set(t, now() + TOKEN_TTL_MS); // sliding expiration
  return true;
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) return xff.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

function getLoginRateLimitState(ip) {
  const t = now();
  pruneLoginAttempts();
  const bucket = (loginAttempts.get(ip) || []).filter(ts => t - ts < LOGIN_WINDOW_MS);
  const remaining = Math.max(0, LOGIN_MAX_ATTEMPTS - bucket.length);
  const oldest = bucket[0] || t;
  const resetSec = Math.max(0, Math.ceil((LOGIN_WINDOW_MS - (t - oldest)) / 1000));
  return { bucket, remaining, resetSec };
}

function canAttemptLogin(ip) {
  const t = now();
  const state = getLoginRateLimitState(ip);
  if (state.bucket.length >= LOGIN_MAX_ATTEMPTS) {
    loginAttempts.set(ip, state.bucket);
    return { ok: false, remaining: 0, resetSec: state.resetSec };
  }
  const next = [...state.bucket, t];
  loginAttempts.set(ip, next);
  const oldest = next[0] || t;
  const resetSec = Math.max(0, Math.ceil((LOGIN_WINDOW_MS - (t - oldest)) / 1000));
  return { ok: true, remaining: Math.max(0, LOGIN_MAX_ATTEMPTS - next.length), resetSec };
}

function resolveMediaPath(urlPath) {
  let relative = '';
  try {
    relative = decodeURIComponent(urlPath.replace('/media/', ''));
  } catch {
    return null;
  }
  const safePath = path.normalize(relative).replace(/^([.][.][/\\])+/, '');
  const absolute = path.join(MEDIA_DIR, safePath);
  return absolute.startsWith(MEDIA_DIR + path.sep) ? absolute : null;
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

function normalizeOrder(value, fallback = 9999) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function createId(prefix) {
  return `${prefix}-${Date.now().toString(36)}-${crypto.randomBytes(2).toString('hex')}`;
}

function sortByOrder(arr) {
  return [...arr].sort((a, b) => {
    const byOrder = normalizeOrder(a.order) - normalizeOrder(b.order);
    if (byOrder !== 0) return byOrder;
    return String(a.id || '').localeCompare(String(b.id || ''));
  });
}



function getFileVersionKey(file) {
  try {
    const st = fs.statSync(file);
    return `${st.mtimeMs}-${st.size}`;
  } catch {
    return '0-0';
  }
}

function getSortedCollection(fileKey) {
  const filePath = FILES[fileKey];
  const ver = getFileVersionKey(filePath);
  const hit = sortedCollectionCache.get(fileKey);
  if (hit && hit.ver === ver) return hit.data;
  const sorted = sortByOrder(readJson(filePath, []));
  sortedCollectionCache.set(fileKey, { ver, data: sorted });
  return sorted;
}

function getLatestDataUpdatedAt() {
  const files = [FILES.ads, FILES.shortcuts, FILES.tabs, FILES.cards];
  let maxTs = 0;
  for (const f of files) {
    try {
      const ts = fs.statSync(f).mtimeMs;
      if (ts > maxTs) maxTs = ts;
    } catch {}
  }
  if (!maxTs) return null;
  return new Date(maxTs).toISOString();
}

function buildExportPayload() {
  return {
    exportedAt: new Date().toISOString(),
    version: 1,
    data: {
      ads: getSortedCollection('ads'),
      shortcuts: getSortedCollection('shortcuts'),
      tabs: getSortedCollection('tabs'),
      cards: getSortedCollection('cards')
    }
  };
}

function resequenceCollection(fileKey, ids = []) {
  const list = readJson(FILES[fileKey], []);
  if (!Array.isArray(list) || !list.length) return { updated: 0, total: 0 };

  const idOrder = Array.isArray(ids) ? ids.map(x => String(x || '')).filter(Boolean) : [];
  const rank = new Map(idOrder.map((id, i) => [id, i]));
  const sorted = [...list].sort((a, b) => {
    const ra = rank.has(String(a.id || '')) ? rank.get(String(a.id || '')) : Number.MAX_SAFE_INTEGER;
    const rb = rank.has(String(b.id || '')) ? rank.get(String(b.id || '')) : Number.MAX_SAFE_INTEGER;
    if (ra !== rb) return ra - rb;
    const byOrder = normalizeOrder(a.order) - normalizeOrder(b.order);
    if (byOrder !== 0) return byOrder;
    return String(a.id || '').localeCompare(String(b.id || ''));
  });

  let updated = 0;
  const next = sorted.map((item, idx) => {
    const order = (idx + 1) * 10;
    if (normalizeOrder(item.order) !== order) updated++;
    return { ...item, order };
  });

  if (updated > 0) {
    writeJson(FILES[fileKey], next);
    invalidateBootstrapCache();
  }

  return { updated, total: next.length };
}

const COLLECTION_FIELD_LIMITS = {
  ads: { title: 80, image: 600, link: 600 },
  shortcuts: { name: 40, icon: 600, link: 600 },
  tabs: { name: 20, key: 40 },
  cards: { title: 120, summary: 1200, contentMd: 24000, contentHtml: 24000, link: 600, image: 600, video: 600, category: 40, buttonText: 20 }
};

function sanitizeCollectionPayload(file, payload = {}) {
  const limits = COLLECTION_FIELD_LIMITS[file] || {};
  const next = { ...payload };
  for (const [key, max] of Object.entries(limits)) {
    if (!(key in next) || next[key] == null) continue;
    const val = String(next[key]).trim();
    next[key] = val.length > max ? val.slice(0, max) : val;
  }
  if ('enabled' in next) next.enabled = next.enabled !== false && String(next.enabled) !== 'false';
  return next;
}

function collectionRoutes(req, res, pathname, file, defaults = {}) {
  if (pathname === `/api/${file}` && (req.method === 'GET' || req.method === 'HEAD')) {
    const data = getSortedCollection(file);
    // 性能优化：统一走 sendJsonWithEtag，避免 GET/HEAD 双分支重复序列化与散列计算
    sendJsonWithEtag(req, res, data, PUBLIC_API_CACHE_CONTROL);
    return true;
  }
  if (pathname === `/api/${file}` && req.method === 'POST') {
    if (!auth(req,res)) return true;
    parseBody(req).then(payload => {
      const list = readJson(FILES[file], []);
      const safePayload = sanitizeCollectionPayload(file, payload);
      const item = { id: createId(file.slice(0, 1)), ...defaults, ...safePayload };
      if ('order' in item) item.order = normalizeOrder(item.order, defaults.order ?? 9999);
      list.push(item);
      writeJson(FILES[file], list);
      invalidateBootstrapCache();
      send(res, 201, JSON.stringify(item));
    }).catch((err)=>handleParseError(res, err));
    return true;
  }
  if (pathname.startsWith(`/api/${file}/`) && req.method === 'PUT') {
    if (!auth(req,res)) return true;
    const id = pathname.split('/').pop();
    parseBody(req).then(payload => {
      const list = readJson(FILES[file], []); const i = list.findIndex(x=>x.id===id);
      if (i < 0) return send(res,404,JSON.stringify({error:'Not found'}));
      const safePayload = sanitizeCollectionPayload(file, payload);
      const next = { ...list[i], ...safePayload, id };
      if ('order' in next) next.order = normalizeOrder(next.order, list[i].order ?? defaults.order ?? 9999);
      list[i] = next;
      writeJson(FILES[file], list);
      invalidateBootstrapCache();
      send(res,200,JSON.stringify(list[i]));
    }).catch((err)=>handleParseError(res, err));
    return true;
  }
  if (pathname.startsWith(`/api/${file}/`) && req.method === 'DELETE') {
    if (!auth(req,res)) return true;
    const id = pathname.split('/').pop();
    const list = readJson(FILES[file], []);
    const next = list.filter(x => x.id !== id);
    if (next.length === list.length) {
      send(res, 404, JSON.stringify({ error: 'Not found' }));
      return true;
    }
    writeJson(FILES[file], next);
    invalidateBootstrapCache();
    send(res,200,JSON.stringify({ok:true}));
    return true;
  }
  return false;
}


function isSafeHttpLikeLink(raw) {
  const v = String(raw || '').trim();
  if (!v || v === '#') return true;
  if (v.startsWith('/') || v.startsWith('./') || v.startsWith('../')) return true;
  try {
    const u = new URL(v, 'http://localhost');
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

function collectInvalidLinks() {
  const checks = [
    { file: 'ads', fields: ['link', 'image'] },
    { file: 'shortcuts', fields: ['link', 'icon'] },
    { file: 'cards', fields: ['link', 'image', 'video'] }
  ];
  const invalid = [];
  for (const check of checks) {
    const list = getSortedCollection(check.file);
    for (const item of list) {
      for (const f of check.fields) {
        if (!(f in item)) continue;
        const v = String(item[f] || '').trim();
        if (!v) continue;
        if (!isSafeHttpLikeLink(v)) invalid.push({ collection: check.file, id: String(item.id || ''), field: f, value: v });
      }
    }
  }
  return invalid;
}


function autoFixInvalidLinks() {
  const checks = [
    { file: 'ads', fields: ['link', 'image'] },
    { file: 'shortcuts', fields: ['link', 'icon'] },
    { file: 'cards', fields: ['link', 'image', 'video'] }
  ];
  let fixed = 0;

  for (const check of checks) {
    const list = readJson(FILES[check.file], []);
    let changed = false;
    const next = list.map(item => {
      const copy = { ...item };
      for (const f of check.fields) {
        if (!(f in copy)) continue;
        const v = String(copy[f] || '').trim();
        if (!v) continue;
        if (!isSafeHttpLikeLink(v)) {
          copy[f] = (f === 'link') ? '#' : '';
          fixed++;
          changed = true;
        }
      }
      return copy;
    });
    if (changed) writeJson(FILES[check.file], next);
  }

  if (fixed > 0) invalidateBootstrapCache();
  return { fixed };
}

const backend = http.createServer((req, res) => {
  const u = new URL(req.url, `http://localhost:${BACKEND_PORT}`);
  if (req.method === 'OPTIONS') return send(res, 204, '');

  if (u.pathname === '/health') return send(res, 200, JSON.stringify({ ok: true, service: 'backend', port: BACKEND_PORT, uptimeSec: Math.floor(process.uptime()), tokens: tokens.size, rssMb: Math.round(process.memoryUsage().rss / 1024 / 1024), node: process.version, bootstrapCacheAgeMs: bootstrapCache ? (now() - bootstrapCache.ts) : null }), 'application/json; charset=utf-8', req.method);
  if (u.pathname === '/' || u.pathname === '/admin' || u.pathname === '/admin/' || u.pathname === '/admin/login' || u.pathname === '/admin/login/') return serveFile(req, res, path.join(ROOT, 'admin', 'index.html'));
  if (u.pathname === '/api/bootstrap' && (req.method === 'GET' || req.method === 'HEAD')) {
    return sendBootstrap(req, res);
  }

  if (u.pathname === '/api/login' && req.method === 'POST') {
    const ip = getClientIp(req);
    const attempt = canAttemptLogin(ip);
    res.setHeader('X-RateLimit-Limit', String(LOGIN_MAX_ATTEMPTS));
    res.setHeader('X-RateLimit-Remaining', String(attempt.remaining));
    res.setHeader('X-RateLimit-Reset', String(attempt.resetSec));
    if (!attempt.ok) {
      res.setHeader('Retry-After', String(attempt.resetSec));
      return send(res, 429, JSON.stringify({ error: '尝试次数过多，请稍后再试', retryAfterSec: attempt.resetSec }));
    }
    return parseBody(req).then(({ password }) => {
      if (typeof password !== 'string') return send(res, 400, JSON.stringify({ error: '密码格式错误' }));
      const normalizedPassword = password.trim();
      if (!normalizedPassword || normalizedPassword.length > 256) {
        return send(res, 400, JSON.stringify({ error: '密码格式错误' }));
      }
      const cfg = readJson(FILES.config, { adminPassword: '123456' });
      if (normalizedPassword !== cfg.adminPassword) return send(res, 401, JSON.stringify({ error: '密码错误' }));
      // 登录成功后清空该 IP 的失败轨迹
      loginAttempts.delete(ip);
      pruneTokens();
      const token = crypto.randomBytes(20).toString('hex');
      tokens.set(token, now() + TOKEN_TTL_MS);
      send(res, 200, JSON.stringify({ ok: true, token }));
    }).catch((err)=>handleParseError(res, err));
  }


  if (u.pathname === '/api/admin/summary' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    const ads = getSortedCollection('ads');
    const shortcuts = getSortedCollection('shortcuts');
    const tabs = getSortedCollection('tabs');
    const cards = getSortedCollection('cards');
    return sendJsonWithEtag(req, res, {
      adsCount: ads.length,
      shortcutsCount: shortcuts.length,
      tabsCount: tabs.length,
      cardsCount: cards.length,
      enabledCards: cards.filter(x => x.enabled !== false).length,
      updatedAt: getLatestDataUpdatedAt()
    }, 'private, max-age=3, stale-while-revalidate=15');
  }

  if (u.pathname === '/api/admin/validate-links' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    const invalid = collectInvalidLinks();
    return sendJsonWithEtag(req, res, {
      invalidCount: invalid.length,
      invalid
    }, 'private, max-age=0, must-revalidate');
  }

  if (u.pathname === '/api/admin/quick-fix-links' && req.method === 'POST') {
    if (!auth(req,res)) return;
    const result = autoFixInvalidLinks();
    return send(res, 200, JSON.stringify({ ok: true, fixed: result.fixed }));
  }

  if (u.pathname === '/api/admin/health-check' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    const files = ['ads', 'shortcuts', 'tabs', 'cards'].map((key) => {
      const filePath = FILES[key];
      try {
        const st = fs.statSync(filePath);
        return { key, exists: true, size: st.size, mtime: new Date(st.mtimeMs).toISOString() };
      } catch {
        return { key, exists: false, size: 0, mtime: null };
      }
    });
    const invalid = collectInvalidLinks();
    return sendJsonWithEtag(req, res, {
      files,
      invalidLinks: invalid.length,
      uptimeSec: Math.floor(process.uptime()),
      memoryRssMb: Math.round(process.memoryUsage().rss / 1024 / 1024)
    }, 'private, max-age=3, stale-while-revalidate=15');
  }

  if (u.pathname === '/api/change-password' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(({ password }) => {
      if (typeof password !== 'string' || password.trim().length < 4) return send(res, 400, JSON.stringify({ error: '密码至少4位' }));
      writeJson(FILES.config, { adminPassword: password.trim() });
      send(res, 200, JSON.stringify({ ok: true }));
    }).catch((err)=>handleParseError(res, err));
  }

  if (u.pathname === '/api/admin/export' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    return sendJsonWithEtag(req, res, buildExportPayload(), 'private, max-age=0, must-revalidate');
  }

  if (u.pathname === '/api/admin/resequence' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(({ collection, ids }) => {
      const allowed = new Set(['ads', 'shortcuts', 'tabs', 'cards']);
      const key = String(collection || '').trim();
      if (!allowed.has(key)) return send(res, 400, JSON.stringify({ error: 'invalid collection' }));
      const result = resequenceCollection(key, ids);
      return send(res, 200, JSON.stringify({ ok: true, collection: key, ...result }));
    }).catch((err)=>handleParseError(res, err));
  }

  if (u.pathname === '/api/admin/normalize-orders' && req.method === 'POST') {
    if (!auth(req,res)) return;
    const result = {
      ads: resequenceCollection('ads'),
      shortcuts: resequenceCollection('shortcuts'),
      tabs: resequenceCollection('tabs'),
      cards: resequenceCollection('cards')
    };
    return send(res, 200, JSON.stringify({ ok: true, ...result }));
  }

  if (u.pathname === '/api/admin/cards/batch-enabled' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(({ ids, enabled }) => {
      const idSet = new Set(Array.isArray(ids) ? ids.map(x => String(x || '')).filter(Boolean) : []);
      if (!idSet.size) return send(res, 400, JSON.stringify({ error: 'ids required' }));
      const list = readJson(FILES.cards, []);
      let updated = 0;
      const next = list.map(item => {
        const id = String(item.id || '');
        if (!idSet.has(id)) return item;
        const nextEnabled = enabled !== false && String(enabled) !== 'false';
        if ((item.enabled !== false) === nextEnabled) return item;
        updated++;
        return { ...item, enabled: nextEnabled };
      });
      if (updated > 0) {
        writeJson(FILES.cards, next);
        invalidateBootstrapCache();
      }
      return send(res, 200, JSON.stringify({ ok: true, updated, requested: idSet.size }));
    }).catch((err)=>handleParseError(res, err));
  }

  if (u.pathname === '/api/upload' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(async ({ filename, contentBase64 }) => {
      if (!filename || !contentBase64) return send(res,400,JSON.stringify({error:'missing fields'}));
      const originalName = String(filename);
      if (originalName.length > 120) {
        return send(res, 400, JSON.stringify({ error: 'filename too long (max 120 chars)' }));
      }
      const ext = path.extname(originalName).toLowerCase();
      if (!ALLOWED_UPLOAD_EXT.has(ext)) {
        return send(res, 400, JSON.stringify({ error: 'unsupported file type (image/video only)' }));
      }
      const safe = `${Date.now()}-${crypto.randomBytes(2).toString('hex')}-${originalName.replace(/[^a-zA-Z0-9._-]/g,'_')}`;
      const rawBase64 = String(contentBase64 || '').replace(/\s+/g, '');
      if (!/^[A-Za-z0-9+/=]+$/.test(rawBase64) || (rawBase64.length % 4 !== 0)) {
        return send(res, 400, JSON.stringify({ error: 'invalid base64 payload' }));
      }
      const MAX_UPLOAD_BYTES = 3 * 1024 * 1024;
      const estimatedBytes = Math.floor(rawBase64.length * 3 / 4) - (rawBase64.endsWith('==') ? 2 : (rawBase64.endsWith('=') ? 1 : 0));
      if (estimatedBytes > MAX_UPLOAD_BYTES) {
        return send(res, 413, JSON.stringify({ error: 'file too large (max 3MB)' }));
      }
      const buf = Buffer.from(rawBase64, 'base64');
      if (!buf.length) return send(res, 400, JSON.stringify({ error: 'empty file' }));
      if (buf.length > MAX_UPLOAD_BYTES) return send(res, 413, JSON.stringify({ error: 'file too large (max 3MB)' }));

      const target = path.join(MEDIA_DIR, safe);
      const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
      await fs.promises.writeFile(tmp, buf);
      await fs.promises.rename(tmp, target);
      send(res,200,JSON.stringify({ok:true,url:`/media/${safe}`}));
    }).catch((err)=>handleParseError(res, err, 'upload failed'));
  }

  if (u.pathname.startsWith('/media/')) {
    const mediaPath = resolveMediaPath(u.pathname);
    if (!mediaPath) return send(res, 400, JSON.stringify({ error: 'Invalid media path' }));
    return serveFile(req, res, mediaPath);
  }

  if (collectionRoutes(req,res,u.pathname,'ads',{ title:'新广告', image:'', link:'#', order:999 })) return;
  if (collectionRoutes(req,res,u.pathname,'shortcuts',{ name:'新入口', icon:'', link:'#', order:999 })) return;
  if (collectionRoutes(req,res,u.pathname,'tabs',{ name:'新分类', key:'custom', order:999 })) return;
  if (collectionRoutes(req,res,u.pathname,'cards',{ title:'新卡片', summary:'', contentMd:'', link:'#', image:'', video:'', category:'all', buttonText:'领', order:999, enabled:true })) return;

  send(res, 404, JSON.stringify({ error: 'Not found' }));
});

const frontend = http.createServer((req, res) => {
  const u = new URL(req.url, `http://localhost:${FRONTEND_PORT}`);
  if (u.pathname === '/health') return send(res, 200, JSON.stringify({ ok: true, service: 'frontend', port: FRONTEND_PORT, uptimeSec: Math.floor(process.uptime()) }), 'application/json; charset=utf-8', req.method);

  // 可用性优化：前台端口误访问 /admin 时自动跳转到后台登录页
  if (u.pathname === '/admin' || u.pathname === '/admin/' || u.pathname === '/admin/login' || u.pathname === '/admin/login/') {
    const host = String(req.headers.host || `localhost:${FRONTEND_PORT}`).replace(/:\d+$/, '');
    const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
    const proto = forwardedProto === 'https' || req.socket.encrypted ? 'https' : 'http';
    const target = `${proto}://${host}:${BACKEND_PORT}/admin/login`;
    res.writeHead(307, {
      Location: target,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    });
    return res.end();
  }

  // one-shot payload for fast first screen
  if (u.pathname === '/api/bootstrap' && (req.method === 'GET' || req.method === 'HEAD')) {
    return sendBootstrap(req, res);
  }

  // proxy-like read endpoints so mobile frontend can use same origin (avoid localhost CORS/mixed-content issues)
  if (u.pathname === '/api/ads' && (req.method === 'GET' || req.method === 'HEAD')) return sendJsonWithEtag(req, res, getSortedCollection('ads'), PUBLIC_API_CACHE_CONTROL);
  if (u.pathname === '/api/shortcuts' && (req.method === 'GET' || req.method === 'HEAD')) return sendJsonWithEtag(req, res, getSortedCollection('shortcuts'), PUBLIC_API_CACHE_CONTROL);
  if (u.pathname === '/api/tabs' && (req.method === 'GET' || req.method === 'HEAD')) return sendJsonWithEtag(req, res, getSortedCollection('tabs'), PUBLIC_API_CACHE_CONTROL);
  if (u.pathname === '/api/cards' && (req.method === 'GET' || req.method === 'HEAD')) return sendJsonWithEtag(req, res, getSortedCollection('cards').filter(x => x.enabled !== false), PUBLIC_API_CACHE_CONTROL);
  if (u.pathname.startsWith('/media/')) {
    const mediaPath = resolveMediaPath(u.pathname);
    if (!mediaPath) return send(res, 400, JSON.stringify({ error: 'Invalid media path' }));
    return serveFile(req, res, mediaPath);
  }

  if (u.pathname === '/' || u.pathname === '/index.html') return serveFile(req, res, path.join(ROOT, 'frontend', 'index.html'));
  send(res, 404, 'Not found', 'text/plain; charset=utf-8');
});

function configureServerTimeouts(server) {
  // 稳定性优化：限制请求与头部读取时间，降低慢连接占用风险
  server.requestTimeout = 15 * 1000;
  server.headersTimeout = 16 * 1000;
  server.keepAliveTimeout = 65 * 1000;
  // 稳定性优化：限制单 socket 可复用请求数，避免极端长连接长期占用
  server.maxRequestsPerSocket = 100;
}

let fatalBindError = false;

function startServer(server, port, name) {
  configureServerTimeouts(server);
  server.on('error', (err) => {
    if (err && err.code === 'EADDRINUSE') {
      console.error(`[${name}] 端口 ${port} 已被占用（EADDRINUSE）。请先停止重复实例后再启动。`);
    } else {
      console.error(`[${name}] 启动失败:`, err && err.message ? err.message : err);
    }

    // 稳定性优化：端口绑定失败时显式以非 0 退出，避免进程“看起来成功”但实际不可用
    if (!fatalBindError) {
      fatalBindError = true;
      process.exitCode = 1;
      setTimeout(() => {
        try { backend.close(); } catch {}
        try { frontend.close(); } catch {}
        process.exit(1);
      }, 50).unref();
    }
  });
  server.listen(port, () => console.log(`${name} running: http://localhost:${port}`));
}

startServer(backend, BACKEND_PORT, 'Backend admin');
startServer(frontend, FRONTEND_PORT, 'Frontend');

function gracefulShutdown(signal) {
  console.log(`收到 ${signal}，开始优雅关闭...`);
  backend.close(() => console.log('Backend admin 已关闭'));
  frontend.close(() => console.log('Frontend 已关闭'));
  setTimeout(() => process.exit(process.exitCode || 0), 800).unref();
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

process.on('unhandledRejection', (reason) => {
  console.error('[FATAL] Unhandled Rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('[FATAL] Uncaught Exception:', err && err.stack ? err.stack : err);
  // 稳定性优化：出现未捕获异常后优雅退出，交由守护进程拉起，避免进程处于未知状态
  process.exitCode = 1;
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});
