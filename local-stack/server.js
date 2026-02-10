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

const uploadAttempts = new Map();
const UPLOAD_WINDOW_MS = 60 * 1000;
const UPLOAD_MAX_PER_WINDOW = 20;
const UPLOAD_ATTEMPTS_MAX_KEYS = 5000;

function now() { return Date.now(); }

let bootstrapCache = null;
let bootstrapEtagCache = null;
let bootstrapBodyCache = null;
const BOOTSTRAP_CACHE_TTL_MS = 2000;
const PUBLIC_API_CACHE_CONTROL = 'public, max-age=15, stale-while-revalidate=60, must-revalidate';

function getEnabledCards() {
  const ver = getFileVersionKey(FILES.cards);
  if (enabledCardsCache.data && enabledCardsCache.ver === ver) return enabledCardsCache.data;
  const data = getSortedCollection('cards').filter(x => x.enabled !== false);
  enabledCardsCache.ver = ver;
  enabledCardsCache.data = data;
  return data;
}

function buildBootstrapPayload() {
  return {
    ads: getSortedCollection('ads'),
    shortcuts: getSortedCollection('shortcuts'),
    tabs: getSortedCollection('tabs'),
    cards: getEnabledCards()
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

  const baseHeaders = {
    'Content-Type': 'application/json; charset=utf-8',
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

  // 性能优化：HEAD 请求仅返回头部，不做编码选择与压缩体积计算
  if (req.method === 'HEAD') {
    res.writeHead(200, baseHeaders);
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

  const headers = { ...baseHeaders, 'Content-Length': encoded.body.length };
  if (encoded.encoding) headers['Content-Encoding'] = encoded.encoding;
  res.writeHead(200, headers);
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

  if (req.method === 'HEAD') {
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
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
  enabledCardsCache.ver = '';
  enabledCardsCache.data = null;
  cardSearchCache.clear();
  categoryStatsCache.ver = '';
  categoryStatsCache.data = null;
  recentCardsCache.clear();
  qualityOverviewCache.ver = '';
  qualityOverviewCache.data = null;
  claimLinksCache.clear();
  actionabilitySummaryCache.ver = '';
  actionabilitySummaryCache.data = null;
}

function pruneInternalCaches() {
  const t = now();
  for (const [key, value] of cardSearchCache.entries()) {
    if (!value || !value.ts || (t - value.ts) > CARD_SEARCH_CACHE_TTL_MS * 3) cardSearchCache.delete(key);
  }
  // recentCards 使用版本号作为 key，数据更新后旧 key 会积累；定期裁剪避免长期运行内存膨胀
  if (recentCardsCache.size > 12) {
    const keys = [...recentCardsCache.keys()];
    for (let i = 0; i < keys.length - 12; i++) recentCardsCache.delete(keys[i]);
  }
  if (claimLinksCache.size > 20) {
    const keys = [...claimLinksCache.keys()];
    for (let i = 0; i < keys.length - 20; i++) claimLinksCache.delete(keys[i]);
  }
}

function pruneTokens() {
  const t = now();
  for (const [token, exp] of tokens) if (exp <= t) tokens.delete(token);
  if (tokens.size > MAX_TOKENS) {
    const sorted = [...tokens.entries()].sort((a, b) => a[1] - b[1]);
    for (let i = 0; i < sorted.length - MAX_TOKENS; i++) tokens.delete(sorted[i][0]);
  }
}
function pruneUploadAttempts() {
  const t = now();
  for (const [ip, attempts] of uploadAttempts.entries()) {
    const fresh = attempts.filter(ts => t - ts < UPLOAD_WINDOW_MS);
    if (fresh.length) uploadAttempts.set(ip, fresh);
    else uploadAttempts.delete(ip);
  }
  if (uploadAttempts.size > UPLOAD_ATTEMPTS_MAX_KEYS) {
    const keys = [...uploadAttempts.keys()];
    for (let i = 0; i < keys.length - UPLOAD_ATTEMPTS_MAX_KEYS; i++) uploadAttempts.delete(keys[i]);
  }
}

function canUploadNow(ip) {
  const t = now();
  const bucket = (uploadAttempts.get(ip) || []).filter(ts => t - ts < UPLOAD_WINDOW_MS);
  if (bucket.length >= UPLOAD_MAX_PER_WINDOW) {
    const oldest = bucket[0] || t;
    const resetSec = Math.max(1, Math.ceil((UPLOAD_WINDOW_MS - (t - oldest)) / 1000));
    uploadAttempts.set(ip, bucket);
    return { ok: false, remaining: 0, resetSec };
  }
  const next = [...bucket, t];
  uploadAttempts.set(ip, next);
  const oldest = next[0] || t;
  const resetSec = Math.max(1, Math.ceil((UPLOAD_WINDOW_MS - (t - oldest)) / 1000));
  return { ok: true, remaining: Math.max(0, UPLOAD_MAX_PER_WINDOW - next.length), resetSec };
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
  pruneUploadAttempts();
  pruneInternalCaches();
}, 10 * 60 * 1000).unref();

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.webp': 'image/webp', '.mp4': 'video/mp4', '.webm': 'video/webm'
};
const ALLOWED_UPLOAD_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp4', '.webm']);

const jsonReadCache = new Map();
const JSON_READ_CACHE_MAX = 32;
const sortedCollectionCache = new Map();
const enabledCardsCache = { ver: '', data: null };

const staticGzipCache = new Map();
const staticBrCache = new Map();
const STATIC_GZIP_CACHE_MAX = 64;
const STATIC_GZIP_MAX_BYTES = 256 * 1024;

const cardSearchCache = new Map();
const CARD_SEARCH_CACHE_TTL_MS = 5000;
const CARD_SEARCH_CACHE_MAX = 40;

const categoryStatsCache = { ver: '', data: null };
const recentCardsCache = new Map();
const qualityOverviewCache = { ver: '', data: null };
const claimLinksCache = new Map();
const actionabilitySummaryCache = { ver: '', data: null };

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
  let oldContent = null;
  if (fs.existsSync(file)) {
    try { oldContent = fs.readFileSync(file, 'utf8'); } catch {}
    if (oldContent === content) {
      return false;
    }
    rotateBackups(file);
    try { fs.copyFileSync(file, backup); } catch {}
  }
  fs.writeFileSync(tmp, content, 'utf8');
  fs.renameSync(tmp, file);
  jsonReadCache.delete(file);
  return true;
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

    const contentType = String(req.headers['content-type'] || '').toLowerCase();
    if (contentType && !contentType.includes('application/json')) {
      const err = new Error('Unsupported Media Type');
      err.code = 'UNSUPPORTED_MEDIA_TYPE';
      return reject(err);
    }

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
  if (err && err.code === 'UNSUPPORTED_MEDIA_TYPE') {
    return send(res, 415, JSON.stringify({ error: 'Content-Type must be application/json' }));
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

function cloneCardById(cardId = '') {
  const id = String(cardId || '').trim();
  if (!id) return { ok: false, error: 'id required' };
  const list = readJson(FILES.cards, []);
  const source = list.find(x => String(x.id || '') === id);
  if (!source) return { ok: false, error: 'card not found' };
  const stamp = new Date().toISOString();
  const copy = {
    ...source,
    id: createId('c'),
    title: `${String(source.title || '未命名卡片').trim()}（副本）`.slice(0, 120),
    order: normalizeOrder(source.order, 9999) + 1,
    createdAt: stamp,
    updatedAt: stamp,
    enabled: false
  };
  list.push(copy);
  writeJson(FILES.cards, list);
  invalidateBootstrapCache();
  return { ok: true, newId: copy.id, sourceId: id };
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

function searchCardsForAdmin(query = '', category = '', limit = 30) {
  const q = String(query || '').trim().toLowerCase();
  const cat = String(category || '').trim().toLowerCase();
  const safeLimit = Math.min(100, Math.max(1, Number(limit) || 30));
  const cacheKey = `${q}::${cat}::${safeLimit}`;
  const hit = cardSearchCache.get(cacheKey);
  const t = now();
  if (hit && (t - hit.ts) < CARD_SEARCH_CACHE_TTL_MS) return hit.data;

  const list = getSortedCollection('cards');
  const matched = list.filter(item => {
    const inCategory = !cat || String(item.category || '').toLowerCase() === cat;
    if (!inCategory) return false;
    if (!q) return true;
    const text = `${item.id || ''} ${item.title || ''} ${item.summary || ''} ${item.category || ''}`.toLowerCase();
    return text.includes(q);
  });

  const data = {
    total: matched.length,
    limit: safeLimit,
    items: matched.slice(0, safeLimit).map(item => ({
      id: item.id,
      title: item.title || '',
      category: item.category || '',
      enabled: item.enabled !== false,
      order: normalizeOrder(item.order, 9999),
      summary: String(item.summary || '').slice(0, 120)
    }))
  };

  cardSearchCache.set(cacheKey, { ts: t, data });
  if (cardSearchCache.size > CARD_SEARCH_CACHE_MAX) {
    const oldest = cardSearchCache.keys().next().value;
    if (oldest) cardSearchCache.delete(oldest);
  }
  return data;
}

function getClaimableLinksForAdmin(category = '', limit = 300) {
  const cat = String(category || '').trim().toLowerCase();
  const safeLimit = Math.min(1000, Math.max(1, Number(limit) || 300));
  const ver = `${getFileVersionKey(FILES.cards)}::${cat}::${safeLimit}`;
  const hit = claimLinksCache.get(ver);
  if (hit) return hit;

  const rows = getSortedCollection('cards')
    .filter(item => item.enabled !== false)
    .filter(item => {
      const link = String(item.link || '').trim();
      if (!link || link === '#') return false;
      if (!cat) return true;
      return String(item.category || '').trim().toLowerCase() === cat;
    })
    .map(item => ({
      id: String(item.id || ''),
      title: String(item.title || ''),
      category: String(item.category || 'uncategorized'),
      link: String(item.link || '').trim(),
      updatedAt: String(item.updatedAt || item.createdAt || '')
    }))
    .sort((a, b) => {
      const ta = Date.parse(a.updatedAt || '') || 0;
      const tb = Date.parse(b.updatedAt || '') || 0;
      if (tb !== ta) return tb - ta;
      return a.id.localeCompare(b.id);
    });

  const data = {
    total: rows.length,
    category: cat || 'all',
    limit: safeLimit,
    items: rows.slice(0, safeLimit),
    generatedAt: new Date().toISOString()
  };
  claimLinksCache.set(ver, data);
  return data;
}

function auditCardSummaries() {
  const cards = getSortedCollection('cards');
  const issues = [];
  for (const item of cards) {
    const raw = String(item.summary || '');
    const normalized = raw.replace(/\r\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
    const lines = normalized ? normalized.split('\n') : [];
    if (!raw.trim()) {
      issues.push({ id: item.id, title: item.title || '', issue: 'empty-summary' });
      continue;
    }
    if (lines.length > 3) issues.push({ id: item.id, title: item.title || '', issue: 'too-many-lines', lines: lines.length });
    if (normalized !== raw) issues.push({ id: item.id, title: item.title || '', issue: 'format-needs-normalize' });
  }
  return { total: cards.length, issuesCount: issues.length, issues };
}

function normalizeCardSummaries() {
  const list = readJson(FILES.cards, []);
  let updated = 0;
  const next = list.map(item => {
    const raw = String(item.summary || '');
    const normalized = raw
      .replace(/\r\n/g, '\n')
      .replace(/[\t ]+\n/g, '\n')
      .replace(/\n{3,}/g, '\n\n')
      .split('\n')
      .slice(0, 3)
      .join('\n')
      .trim();
    if (normalized === raw) return item;
    updated++;
    return { ...item, summary: normalized };
  });
  if (updated > 0) {
    writeJson(FILES.cards, next);
    invalidateBootstrapCache();
  }
  return { updated, total: list.length };
}

function normalizeComparableText(v) {
  return String(v || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

function getCardDuplicateReport() {
  const cards = getSortedCollection('cards');
  const byTitle = new Map();
  const byLink = new Map();

  for (const card of cards) {
    const tKey = normalizeComparableText(card.title);
    if (tKey) {
      if (!byTitle.has(tKey)) byTitle.set(tKey, []);
      byTitle.get(tKey).push(card);
    }
    const lKey = normalizeComparableText(card.link);
    if (lKey && lKey !== '#') {
      if (!byLink.has(lKey)) byLink.set(lKey, []);
      byLink.get(lKey).push(card);
    }
  }

  const titleDuplicates = [...byTitle.entries()]
    .filter(([, list]) => list.length > 1)
    .map(([key, list]) => ({
      key,
      count: list.length,
      ids: list.map(x => x.id),
      titles: list.map(x => x.title || ''),
      enabledCount: list.filter(x => x.enabled !== false).length
    }));

  const linkDuplicates = [...byLink.entries()]
    .filter(([, list]) => list.length > 1)
    .map(([key, list]) => ({
      key,
      count: list.length,
      ids: list.map(x => x.id),
      titles: list.map(x => x.title || ''),
      enabledCount: list.filter(x => x.enabled !== false).length
    }));

  return {
    totalCards: cards.length,
    titleDuplicateGroups: titleDuplicates.length,
    linkDuplicateGroups: linkDuplicates.length,
    titleDuplicates,
    linkDuplicates
  };
}

function disableDuplicateCards(mode = 'title') {
  const cards = readJson(FILES.cards, []);
  const map = new Map();
  const keyOf = (item) => {
    if (mode === 'link') return normalizeComparableText(item.link);
    return normalizeComparableText(item.title);
  };

  for (const item of cards) {
    const k = keyOf(item);
    if (!k || k === '#') continue;
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(item);
  }

  const disableSet = new Set();
  for (const list of map.values()) {
    if (list.length <= 1) continue;
    const sorted = [...list].sort((a, b) => {
      const byEnabled = Number(b.enabled !== false) - Number(a.enabled !== false);
      if (byEnabled !== 0) return byEnabled;
      const byOrder = normalizeOrder(a.order) - normalizeOrder(b.order);
      if (byOrder !== 0) return byOrder;
      return String(a.id || '').localeCompare(String(b.id || ''));
    });
    const keeper = sorted[0]?.id;
    for (const x of sorted.slice(1)) {
      if ((x.enabled !== false) && x.id !== keeper) disableSet.add(String(x.id || ''));
    }
  }

  if (!disableSet.size) return { mode, updated: 0, total: cards.length };

  let updated = 0;
  const next = cards.map(item => {
    const id = String(item.id || '');
    if (!disableSet.has(id)) return item;
    if (item.enabled === false) return item;
    updated++;
    return { ...item, enabled: false };
  });

  if (updated > 0) {
    writeJson(FILES.cards, next);
    invalidateBootstrapCache();
  }
  return { mode, updated, total: cards.length };
}


function toggleCardsEnabledByCategory(category = '', enabled = true) {
  const cat = String(category || '').trim();
  if (!cat) return { updated: 0, total: 0, category: '', enabled: enabled !== false };
  const list = readJson(FILES.cards, []);
  let updated = 0;
  const nextEnabled = enabled !== false && String(enabled) !== 'false';
  const next = list.map(item => {
    if (String(item.category || '').trim() !== cat) return item;
    const current = item.enabled !== false;
    if (current === nextEnabled) return item;
    updated++;
    return { ...item, enabled: nextEnabled };
  });
  if (updated > 0) {
    writeJson(FILES.cards, next);
    invalidateBootstrapCache();
  }
  return { updated, total: list.filter(x => String(x.category || '').trim() === cat).length, category: cat, enabled: nextEnabled };
}

function touchCardsUpdatedAtByCategory(category = '') {
  const cat = String(category || '').trim();
  if (!cat) return { updated: 0, total: 0, category: '' };
  const list = readJson(FILES.cards, []);
  const nowIso = new Date().toISOString();
  let updated = 0;
  let total = 0;
  const next = list.map(item => {
    if (String(item.category || '').trim() !== cat) return item;
    total++;
    updated++;
    const createdAt = String(item.createdAt || '').trim() || nowIso;
    return { ...item, createdAt, updatedAt: nowIso };
  });
  if (updated > 0) {
    writeJson(FILES.cards, next);
    invalidateBootstrapCache();
  }
  return { updated, total, category: cat, updatedAt: nowIso };
}

function appendTrackingToUrl(rawUrl, params = {}) {
  const raw = String(rawUrl || '').trim();
  if (!raw || raw === '#') return raw;
  try {
    const u = new URL(raw);
    for (const [k, v] of Object.entries(params || {})) {
      const key = String(k || '').trim();
      const val = String(v || '').trim();
      if (!key || !val) continue;
      u.searchParams.set(key, val);
    }
    return u.toString();
  } catch {
    return raw;
  }
}

function batchAppendTrackingParams(ids = [], source = '', medium = '', campaign = '') {
  const idSet = new Set(Array.isArray(ids) ? ids.map(x => String(x || '').trim()).filter(Boolean) : []);
  if (!idSet.size) return { updated: 0, requested: 0 };

  const params = {
    utm_source: String(source || '').trim().slice(0, 60),
    utm_medium: String(medium || '').trim().slice(0, 60),
    utm_campaign: String(campaign || '').trim().slice(0, 80)
  };

  const list = readJson(FILES.cards, []);
  let updated = 0;
  const nowIso = new Date().toISOString();
  const next = list.map(item => {
    const id = String(item.id || '');
    if (!idSet.has(id)) return item;
    const link = String(item.link || '').trim();
    if (!link || link === '#') return item;
    const nextLink = appendTrackingToUrl(link, params);
    if (nextLink === link) return item;
    updated++;
    return { ...item, link: nextLink, updatedAt: nowIso };
  });

  if (updated > 0) {
    writeJson(FILES.cards, next);
    invalidateBootstrapCache();
  }
  return { updated, requested: idSet.size };
}

function getCardCategoryStats() {
  const ver = `${getFileVersionKey(FILES.tabs)}::${getFileVersionKey(FILES.cards)}`;
  if (categoryStatsCache.data && categoryStatsCache.ver === ver) return categoryStatsCache.data;

  const tabs = getSortedCollection('tabs');
  const cards = getSortedCollection('cards');
  const map = new Map();

  for (const tab of tabs) {
    const key = String(tab.key || '').trim();
    if (!key) continue;
    map.set(key, {
      key,
      tabName: String(tab.name || key),
      total: 0,
      enabled: 0,
      withLink: 0,
      withMedia: 0
    });
  }

  for (const card of cards) {
    const key = String(card.category || '').trim() || 'uncategorized';
    if (!map.has(key)) {
      map.set(key, { key, tabName: key === 'all' ? '全栏目' : key, total: 0, enabled: 0, withLink: 0, withMedia: 0 });
    }
    const row = map.get(key);
    row.total++;
    if (card.enabled !== false) row.enabled++;
    const link = String(card.link || '').trim();
    if (link && link !== '#') row.withLink++;
    if (String(card.image || '').trim() || String(card.video || '').trim()) row.withMedia++;
  }

  const rows = [...map.values()].sort((a, b) => b.total - a.total || a.key.localeCompare(b.key));
  categoryStatsCache.ver = ver;
  categoryStatsCache.data = rows;
  return rows;
}

function getAdminCategoryOptions() {
  const tabs = getSortedCollection('tabs');
  const cards = getSortedCollection('cards');
  const byCategory = new Map();
  for (const card of cards) {
    const key = String(card.category || '').trim() || 'all';
    if (!byCategory.has(key)) byCategory.set(key, { key, count: 0, enabled: 0, fromTab: false, name: key });
    const row = byCategory.get(key);
    row.count++;
    if (card.enabled !== false) row.enabled++;
  }
  for (const tab of tabs) {
    const key = String(tab.key || '').trim();
    if (!key) continue;
    if (!byCategory.has(key)) byCategory.set(key, { key, count: 0, enabled: 0, fromTab: true, name: String(tab.name || key) });
    const row = byCategory.get(key);
    row.fromTab = true;
    row.name = String(tab.name || key);
  }
  return {
    updatedAt: getLatestDataUpdatedAt(),
    rows: [...byCategory.values()].sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
  };
}

function getRecentCards(limit = 10) {
  const safeLimit = Math.min(50, Math.max(1, Number(limit) || 10));
  const ver = getFileVersionKey(FILES.cards);
  const cacheKey = `${ver}::${safeLimit}`;
  const hit = recentCardsCache.get(cacheKey);
  if (hit) return hit;

  const cards = getSortedCollection('cards');
  const fallbackTs = getLatestDataUpdatedAt() || new Date().toISOString();
  const rows = cards
    .map(item => ({
      id: item.id,
      title: String(item.title || ''),
      category: String(item.category || ''),
      enabled: item.enabled !== false,
      order: normalizeOrder(item.order, 9999),
      updatedAt: String(item.updatedAt || item.createdAt || fallbackTs)
    }))
    .sort((a, b) => {
      const ta = Date.parse(a.updatedAt || '') || 0;
      const tb = Date.parse(b.updatedAt || '') || 0;
      if (tb !== ta) return tb - ta;
      return a.order - b.order;
    })
    .slice(0, safeLimit);

  const data = { total: cards.length, limit: safeLimit, items: rows };
  recentCardsCache.set(cacheKey, data);
  if (recentCardsCache.size > 20) {
    const oldest = recentCardsCache.keys().next().value;
    if (oldest) recentCardsCache.delete(oldest);
  }
  return data;
}



function getCardActionabilitySummary() {
  const ver = getFileVersionKey(FILES.cards);
  if (actionabilitySummaryCache.data && actionabilitySummaryCache.ver === ver) return actionabilitySummaryCache.data;
  const cards = getSortedCollection('cards').filter(x => x.enabled !== false);
  const nowMs = Date.now();
  const rowsMap = new Map();

  for (const card of cards) {
    const key = String(card.category || 'uncategorized').trim() || 'uncategorized';
    if (!rowsMap.has(key)) {
      rowsMap.set(key, { category: key, total: 0, claimable: 0, stale14d: 0, noSummary: 0, withMedia: 0 });
    }
    const row = rowsMap.get(key);
    row.total++;
    const link = String(card.link || '').trim();
    if (link && link !== '#') row.claimable++;
    const summary = String(card.summary || '').trim();
    if (!summary) row.noSummary++;
    if (String(card.image || '').trim() || String(card.video || '').trim()) row.withMedia++;
    const ts = Date.parse(String(card.updatedAt || card.createdAt || ''));
    if (!Number.isFinite(ts) || (nowMs - ts) > 14 * 24 * 60 * 60 * 1000) row.stale14d++;
  }

  const rows = [...rowsMap.values()].map((x) => ({
    ...x,
    claimableRate: x.total ? Math.round((x.claimable / x.total) * 100) : 0,
    staleRate: x.total ? Math.round((x.stale14d / x.total) * 100) : 0
  })).sort((a, b) => b.claimableRate - a.claimableRate || b.total - a.total || a.category.localeCompare(b.category));

  const data = {
    generatedAt: new Date().toISOString(),
    totals: {
      enabledCards: cards.length,
      claimable: cards.filter(x => String(x.link || '').trim() && String(x.link || '').trim() !== '#').length
    },
    rows
  };
  actionabilitySummaryCache.ver = ver;
  actionabilitySummaryCache.data = data;
  return data;
}

function getCardsQualityOverview() {
  const ver = getFileVersionKey(FILES.cards);
  if (qualityOverviewCache.data && qualityOverviewCache.ver === ver) return qualityOverviewCache.data;

  const cards = getSortedCollection('cards');
  const nowMs = Date.now();
  const rows = cards.map(item => {
    const updatedAt = String(item.updatedAt || item.createdAt || '').trim();
    const ts = Date.parse(updatedAt);
    const daysSinceUpdated = Number.isFinite(ts) ? Math.floor((nowMs - ts) / (24 * 60 * 60 * 1000)) : null;
    const summary = String(item.summary || '').trim();
    const link = String(item.link || '').trim();
    return {
      id: item.id,
      title: String(item.title || ''),
      enabled: item.enabled !== false,
      hasLink: !!link && link !== '#',
      hasMedia: !!String(item.image || '').trim() || !!String(item.video || '').trim(),
      emptySummary: !summary,
      emptyButtonText: !String(item.buttonText || '').trim(),
      emptyCategory: !String(item.category || '').trim(),
      stale14d: !Number.isFinite(ts) || daysSinceUpdated >= 14,
      daysSinceUpdated
    };
  });

  const counts = {
    total: rows.length,
    enabled: rows.filter(x => x.enabled).length,
    withLink: rows.filter(x => x.hasLink).length,
    withMedia: rows.filter(x => x.hasMedia).length,
    emptySummary: rows.filter(x => x.emptySummary).length,
    emptyButtonText: rows.filter(x => x.emptyButtonText).length,
    emptyCategory: rows.filter(x => x.emptyCategory).length,
    stale14d: rows.filter(x => x.stale14d).length
  };

  const topStale = rows
    .filter(x => x.enabled)
    .sort((a, b) => (b.daysSinceUpdated || 0) - (a.daysSinceUpdated || 0))
    .slice(0, 5)
    .map(x => ({ id: x.id, title: x.title, daysSinceUpdated: x.daysSinceUpdated }));

  const data = { counts, topStale, generatedAt: new Date().toISOString() };
  qualityOverviewCache.ver = ver;
  qualityOverviewCache.data = data;
  return data;
}

function autoDisableLowQualityCards() {
  const list = readJson(FILES.cards, []);
  let updated = 0;
  const changedIds = [];
  const next = list.map(item => {
    const title = String(item.title || '').trim();
    const summaryText = String(item.summary || '').replace(/\s+/g, '').trim();
    const hasContent = !!String(item.contentHtml || item.contentMd || '').replace(/<[^>]+>/g, '').replace(/\s+/g, '').trim();
    const link = String(item.link || '').trim();
    const hasMedia = !!String(item.image || '').trim() || !!String(item.video || '').trim();
    const shouldDisable = !title || (!summaryText && !hasContent && !hasMedia && (!link || link === '#'));
    if (!shouldDisable || item.enabled === false) return item;
    updated++;
    changedIds.push(String(item.id || ''));
    return { ...item, enabled: false };
  });
  if (updated > 0) {
    writeJson(FILES.cards, next);
    invalidateBootstrapCache();
  }
  return { updated, total: list.length, changedIds: changedIds.slice(0, 60) };
}

function fillCardsUpdatedAt() {
  const list = readJson(FILES.cards, []);
  let updated = 0;
  const nowIso = new Date().toISOString();
  const next = list.map(item => {
    const createdAt = String(item.createdAt || '').trim();
    const updatedAt = String(item.updatedAt || '').trim();
    if (updatedAt) return item;
    updated++;
    return { ...item, updatedAt: createdAt || nowIso, createdAt: createdAt || nowIso };
  });
  if (updated > 0) {
    writeJson(FILES.cards, next);
    invalidateBootstrapCache();
  }
  return { updated, total: list.length };
}

function fillMissingCategory() {
  const list = readJson(FILES.cards, []);
  let updated = 0;
  const nowIso = new Date().toISOString();
  const next = list.map(item => {
    const category = String(item.category || '').trim();
    if (category) return item;
    updated++;
    return { ...item, category: 'all', updatedAt: nowIso };
  });
  if (updated > 0) {
    writeJson(FILES.cards, next);
    invalidateBootstrapCache();
  }
  return { updated, total: list.length, category: 'all' };
}

function fillMissingButtonText() {
  const list = readJson(FILES.cards, []);
  let updated = 0;
  const nowIso = new Date().toISOString();
  const next = list.map(item => {
    const text = String(item.buttonText || '').trim();
    if (text) return item;
    const link = String(item.link || '').trim();
    const nextText = (!link || link === '#') ? '查看详情' : '去领取';
    updated++;
    return { ...item, buttonText: nextText, updatedAt: nowIso };
  });
  if (updated > 0) {
    writeJson(FILES.cards, next);
    invalidateBootstrapCache();
  }
  return { updated, total: list.length };
}

function standardizeButtonText() {
  const list = readJson(FILES.cards, []);
  let updated = 0;
  const nowIso = new Date().toISOString();
  const next = list.map(item => {
    const link = String(item.link || '').trim();
    const expected = (!link || link === '#') ? '查看详情' : '去领取';
    const current = String(item.buttonText || '').trim();
    if (current === expected) return item;
    updated++;
    return { ...item, buttonText: expected, updatedAt: nowIso };
  });
  if (updated > 0) {
    writeJson(FILES.cards, next);
    invalidateBootstrapCache();
  }
  return { updated, total: list.length };
}

function getStaleCards(days = 14, limit = 20) {
  const safeDays = Math.min(365, Math.max(1, Number(days) || 14));
  const safeLimit = Math.min(100, Math.max(1, Number(limit) || 20));
  const nowMs = Date.now();
  const thresholdMs = safeDays * 24 * 60 * 60 * 1000;
  const rows = getSortedCollection('cards')
    .filter(x => x.enabled !== false)
    .map(item => {
      const tsRaw = String(item.updatedAt || item.createdAt || '').trim();
      const ts = Date.parse(tsRaw);
      const ageMs = Number.isFinite(ts) ? (nowMs - ts) : Number.MAX_SAFE_INTEGER;
      const daysSinceUpdated = Number.isFinite(ts) ? Math.floor(ageMs / (24 * 60 * 60 * 1000)) : null;
      return {
        id: item.id,
        title: String(item.title || ''),
        category: String(item.category || ''),
        updatedAt: tsRaw || null,
        daysSinceUpdated,
        isStale: ageMs >= thresholdMs
      };
    })
    .filter(x => x.isStale)
    .sort((a, b) => (b.daysSinceUpdated || 0) - (a.daysSinceUpdated || 0));

  return {
    days: safeDays,
    total: rows.length,
    items: rows.slice(0, safeLimit)
  };
}

function disableStaleCards(days = 30) {
  const safeDays = Math.min(365, Math.max(1, Number(days) || 30));
  const list = readJson(FILES.cards, []);
  const nowMs = Date.now();
  const thresholdMs = safeDays * 24 * 60 * 60 * 1000;
  let updated = 0;

  const next = list.map(item => {
    if (item.enabled === false) return item;
    const tsRaw = String(item.updatedAt || item.createdAt || '').trim();
    const ts = Date.parse(tsRaw);
    const stale = !Number.isFinite(ts) || (nowMs - ts >= thresholdMs);
    if (!stale) return item;
    updated++;
    return { ...item, enabled: false, updatedAt: new Date().toISOString() };
  });

  if (updated > 0) {
    writeJson(FILES.cards, next);
    invalidateBootstrapCache();
  }

  return { days: safeDays, updated, total: list.length };
}

function buildExportPayload(category = '') {
  const cat = String(category || '').trim();
  const cards = getSortedCollection('cards');
  const filteredCards = cat ? cards.filter(x => String(x.category || '').trim() === cat) : cards;
  return {
    exportedAt: new Date().toISOString(),
    version: 1,
    category: cat || 'all',
    data: {
      ads: getSortedCollection('ads'),
      shortcuts: getSortedCollection('shortcuts'),
      tabs: getSortedCollection('tabs'),
      cards: filteredCards
    }
  };
}

function getBootstrapMeta() {
  const data = getBootstrapPayload();
  const body = getBootstrapBody(data);
  const cards = data.cards || [];
  return {
    counts: {
      ads: (data.ads || []).length,
      shortcuts: (data.shortcuts || []).length,
      tabs: (data.tabs || []).length,
      cards: cards.length,
      enabledCards: cards.filter(x => x.enabled !== false).length
    },
    bytes: {
      raw: body.raw ? body.raw.length : 0,
      gzip: body.gzip ? body.gzip.length : null,
      br: body.br ? body.br.length : null
    },
    etag: getBootstrapEtag(data),
    updatedAt: getLatestDataUpdatedAt(),
    generatedAt: new Date().toISOString()
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
      const stamp = new Date().toISOString();
      const item = { id: createId(file.slice(0, 1)), ...defaults, ...safePayload, createdAt: stamp, updatedAt: stamp };
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
      const next = { ...list[i], ...safePayload, id, updatedAt: new Date().toISOString() };
      if (!next.createdAt) next.createdAt = new Date().toISOString();
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

  if (u.pathname === '/api/admin/bootstrap-meta' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    return sendJsonWithEtag(req, res, getBootstrapMeta(), 'private, max-age=2, stale-while-revalidate=10');
  }

  if (u.pathname === '/api/admin/cards/search' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    const q = String(u.searchParams.get('q') || '').slice(0, 80);
    const category = String(u.searchParams.get('category') || '').slice(0, 40);
    const limit = Math.min(100, Math.max(1, Number(u.searchParams.get('limit') || 30)));
    const data = searchCardsForAdmin(q, category, limit);
    return sendJsonWithEtag(req, res, data, 'private, max-age=2, stale-while-revalidate=10');
  }

  if (u.pathname === '/api/admin/cards/recent' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    const limit = Math.min(50, Math.max(1, Number(u.searchParams.get('limit') || 8)));
    const data = getRecentCards(limit);
    return sendJsonWithEtag(req, res, data, 'private, max-age=2, stale-while-revalidate=10');
  }

  if (u.pathname === '/api/admin/cards/claim-links' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    const category = String(u.searchParams.get('category') || '');
    const limit = Math.min(1000, Math.max(1, Number(u.searchParams.get('limit') || 300)));
    const data = getClaimableLinksForAdmin(category, limit);
    return sendJsonWithEtag(req, res, data, 'private, max-age=2, stale-while-revalidate=10');
  }


  if (u.pathname === '/api/admin/cards/actionability-summary' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    return sendJsonWithEtag(req, res, getCardActionabilitySummary(), 'private, max-age=3, stale-while-revalidate=20');
  }

  if (u.pathname === '/api/admin/cards/quality-overview' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    return sendJsonWithEtag(req, res, getCardsQualityOverview(), 'private, max-age=2, stale-while-revalidate=10');
  }

  if (u.pathname === '/api/admin/cards/category-stats' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    const rows = getCardCategoryStats();
    return sendJsonWithEtag(req, res, {
      rows,
      updatedAt: getLatestDataUpdatedAt()
    }, 'private, max-age=3, stale-while-revalidate=15');
  }

  if (u.pathname === '/api/admin/cards/category-options' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    return sendJsonWithEtag(req, res, getAdminCategoryOptions(), 'private, max-age=5, stale-while-revalidate=30');
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

  if (u.pathname === '/api/admin/runtime-metrics' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    const mem = process.memoryUsage();
    return sendJsonWithEtag(req, res, {
      uptimeSec: Math.floor(process.uptime()),
      tokens: tokens.size,
      loginAttemptsBuckets: loginAttempts.size,
      uploadAttemptsBuckets: uploadAttempts.size,
      memoryRssMb: Math.round(mem.rss / 1024 / 1024),
      memoryHeapUsedMb: Math.round(mem.heapUsed / 1024 / 1024),
      memoryHeapTotalMb: Math.round(mem.heapTotal / 1024 / 1024),
      caches: {
        jsonRead: jsonReadCache.size,
        sortedCollection: sortedCollectionCache.size,
        cardSearch: cardSearchCache.size,
        recentCards: recentCardsCache.size,
        staticGzip: staticGzipCache.size,
        staticBr: staticBrCache.size
      },
      generatedAt: new Date().toISOString()
    }, 'private, max-age=2, stale-while-revalidate=10');
  }

  if (u.pathname === '/api/admin/cards/duplicates' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    const data = getCardDuplicateReport();
    return sendJsonWithEtag(req, res, data, 'private, max-age=2, stale-while-revalidate=10');
  }

  if (u.pathname === '/api/admin/cards/duplicates-disable' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(({ mode }) => {
      const m = String(mode || 'title');
      if (m !== 'title' && m !== 'link') return send(res, 400, JSON.stringify({ error: 'mode must be title or link' }));
      const result = disableDuplicateCards(m);
      return send(res, 200, JSON.stringify({ ok: true, ...result }));
    }).catch((err)=>handleParseError(res, err));
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
    const category = String(u.searchParams.get('category') || '').slice(0, 40);
    return sendJsonWithEtag(req, res, buildExportPayload(category), 'private, max-age=0, must-revalidate');
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

  
  if (u.pathname === '/api/admin/cards/toggle-by-category' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(({ category, enabled }) => {
      const cat = String(category || '').trim();
      if (!cat) return send(res, 400, JSON.stringify({ error: 'category required' }));
      const result = toggleCardsEnabledByCategory(cat, enabled);
      return send(res, 200, JSON.stringify({ ok: true, ...result }));
    }).catch((err)=>handleParseError(res, err));
  }

  if (u.pathname === '/api/admin/cards/touch-by-category' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(({ category }) => {
      const cat = String(category || '').trim();
      if (!cat) return send(res, 400, JSON.stringify({ error: 'category required' }));
      const result = touchCardsUpdatedAtByCategory(cat);
      return send(res, 200, JSON.stringify({ ok: true, ...result }));
    }).catch((err)=>handleParseError(res, err));
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

  if (u.pathname === '/api/admin/cards/batch-category' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(({ ids, category }) => {
      const idSet = new Set(Array.isArray(ids) ? ids.map(x => String(x || '')).filter(Boolean) : []);
      const nextCategory = String(category || '').trim().slice(0, 40);
      if (!idSet.size) return send(res, 400, JSON.stringify({ error: 'ids required' }));
      if (!nextCategory) return send(res, 400, JSON.stringify({ error: 'category required' }));

      const list = readJson(FILES.cards, []);
      let updated = 0;
      const next = list.map(item => {
        const id = String(item.id || '');
        if (!idSet.has(id)) return item;
        if (String(item.category || '') === nextCategory) return item;
        updated++;
        return { ...item, category: nextCategory };
      });

      if (updated > 0) {
        writeJson(FILES.cards, next);
        invalidateBootstrapCache();
      }
      return send(res, 200, JSON.stringify({ ok: true, updated, requested: idSet.size, category: nextCategory }));
    }).catch((err)=>handleParseError(res, err));
  }

  if (u.pathname === '/api/admin/cards/batch-button-text' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(({ ids, buttonText }) => {
      const idSet = new Set(Array.isArray(ids) ? ids.map(x => String(x || '')).filter(Boolean) : []);
      const nextButtonText = String(buttonText || '').trim().slice(0, 20);
      if (!idSet.size) return send(res, 400, JSON.stringify({ error: 'ids required' }));
      if (!nextButtonText) return send(res, 400, JSON.stringify({ error: 'buttonText required' }));

      const list = readJson(FILES.cards, []);
      let updated = 0;
      const next = list.map(item => {
        const id = String(item.id || '');
        if (!idSet.has(id)) return item;
        if (String(item.buttonText || '') === nextButtonText) return item;
        updated++;
        return { ...item, buttonText: nextButtonText, updatedAt: new Date().toISOString() };
      });

      if (updated > 0) {
        writeJson(FILES.cards, next);
        invalidateBootstrapCache();
      }
      return send(res, 200, JSON.stringify({ ok: true, updated, requested: idSet.size, buttonText: nextButtonText }));
    }).catch((err)=>handleParseError(res, err));
  }

  if (u.pathname === '/api/admin/cards/batch-append-tracking' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(({ ids, utmSource, utmMedium, utmCampaign }) => {
      const result = batchAppendTrackingParams(ids, utmSource, utmMedium, utmCampaign);
      return send(res, 200, JSON.stringify({ ok: true, ...result }));
    }).catch((err)=>handleParseError(res, err));
  }

  if (u.pathname === '/api/admin/cards/clone' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(({ id }) => {
      const result = cloneCardById(id);
      if (!result.ok) {
        const status = result.error === 'card not found' ? 404 : 400;
        return send(res, status, JSON.stringify({ error: result.error }));
      }
      return send(res, 200, JSON.stringify({ ok: true, ...result }));
    }).catch((err)=>handleParseError(res, err));
  }

  if (u.pathname === '/api/admin/cards/summary-audit' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    const data = auditCardSummaries();
    return sendJsonWithEtag(req, res, data, 'private, max-age=2, stale-while-revalidate=10');
  }

  if (u.pathname === '/api/admin/cards/summary-normalize' && req.method === 'POST') {
    if (!auth(req,res)) return;
    const result = normalizeCardSummaries();
    return send(res, 200, JSON.stringify({ ok: true, ...result }));
  }

  if (u.pathname === '/api/admin/cards/auto-disable-empty' && req.method === 'POST') {
    if (!auth(req,res)) return;
    const result = autoDisableLowQualityCards();
    return send(res, 200, JSON.stringify({ ok: true, ...result }));
  }

  if (u.pathname === '/api/admin/cards/fill-updated-at' && req.method === 'POST') {
    if (!auth(req,res)) return;
    const result = fillCardsUpdatedAt();
    return send(res, 200, JSON.stringify({ ok: true, ...result }));
  }

  if (u.pathname === '/api/admin/cards/fill-category' && req.method === 'POST') {
    if (!auth(req,res)) return;
    const result = fillMissingCategory();
    return send(res, 200, JSON.stringify({ ok: true, ...result }));
  }

  if (u.pathname === '/api/admin/cards/fill-button-text' && req.method === 'POST') {
    if (!auth(req,res)) return;
    const result = fillMissingButtonText();
    return send(res, 200, JSON.stringify({ ok: true, ...result }));
  }

  if (u.pathname === '/api/admin/cards/button-text-standardize' && req.method === 'POST') {
    if (!auth(req,res)) return;
    const result = standardizeButtonText();
    return send(res, 200, JSON.stringify({ ok: true, ...result }));
  }

  if (u.pathname === '/api/admin/cards/stale' && (req.method === 'GET' || req.method === 'HEAD')) {
    if (!auth(req,res)) return;
    const days = Math.min(365, Math.max(1, Number(u.searchParams.get('days') || 14)));
    const limit = Math.min(100, Math.max(1, Number(u.searchParams.get('limit') || 20)));
    const data = getStaleCards(days, limit);
    return sendJsonWithEtag(req, res, data, 'private, max-age=2, stale-while-revalidate=10');
  }

  if (u.pathname === '/api/admin/cards/stale-disable' && req.method === 'POST') {
    if (!auth(req,res)) return;
    return parseBody(req).then(({ days }) => {
      const result = disableStaleCards(days);
      return send(res, 200, JSON.stringify({ ok: true, ...result }));
    }).catch((err)=>handleParseError(res, err));
  }

  if (u.pathname === '/api/upload' && req.method === 'POST') {
    if (!auth(req,res)) return;
    const ip = getClientIp(req);
    const uploadState = canUploadNow(ip);
    res.setHeader('X-Upload-RateLimit-Limit', String(UPLOAD_MAX_PER_WINDOW));
    res.setHeader('X-Upload-RateLimit-Remaining', String(uploadState.remaining));
    res.setHeader('X-Upload-RateLimit-Reset', String(uploadState.resetSec));
    if (!uploadState.ok) {
      res.setHeader('Retry-After', String(uploadState.resetSec));
      return send(res, 429, JSON.stringify({ error: '上传过于频繁，请稍后重试', retryAfterSec: uploadState.resetSec }));
    }
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
      try {
        await fs.promises.writeFile(tmp, buf);
        await fs.promises.rename(tmp, target);
        send(res,200,JSON.stringify({ok:true,url:`/media/${safe}`}));
      } finally {
        try { if (fs.existsSync(tmp)) await fs.promises.unlink(tmp); } catch {}
      }
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
