/*!
 * ZK-Vault — server lưu trữ blob đã mã hoá (zero-dependency).
 *
 *   node src/server.js            # mặc định http://127.0.0.1:8787
 *   PORT=9000 node src/server.js
 *
 * Server này CỐ TÌNH không biết gì về nội dung tệp:
 *   - chỉ nhận ciphertext, không có encKey
 *   - không có bảng user, không có mật khẩu, không có log nội dung
 *   - id để định vị blob là SHA-256("zkv1/id" ‖ authKey) — không thể đảo ngược
 *
 * API:
 *   POST   /api/blob?ttl=<giây>&burn=0|1   Authorization: Bearer <authKey>
 *          body: application/octet-stream (container ZKV2)
 *   GET    /api/blob                        Authorization: Bearer <authKey>
 *   DELETE /api/blob                        Authorization: Bearer <authKey>
 *   GET    /api/health
 */
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const DEFAULTS = {
    port: Number(process.env.PORT || 8787),
    host: process.env.HOST || '127.0.0.1',
    maxBytes: 25 * 1024 * 1024,          // 25 MB / tệp
    maxTtl: 7 * 24 * 3600,               // 7 ngày
    defaultTtl: 7 * 24 * 3600,
    minTtl: 300,                         // 5 phút
    rateWindowMs: 60_000,
    rateMaxPost: 20,
    rateMaxGet: 120
};

const SECURITY_HEADERS = {
    'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' blob: data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'"
    ].join('; '),
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
};

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.ico': 'image/x-icon',
    '.json': 'application/json; charset=utf-8'
};

/* ------------------------------------------------------------------ */

function createVaultServer(options = {}) {
    const cfg = { ...DEFAULTS, ...options };
    const dataDir = cfg.dataDir || path.join(__dirname, '..', 'data');
    const publicDir = cfg.publicDir || path.join(__dirname, '..', 'public');
    const blobDir = path.join(dataDir, 'blobs');
    const now = cfg.now || (() => Date.now());

    fs.mkdirSync(blobDir, { recursive: true });

    const db = new DatabaseSync(path.join(dataDir, 'vault.db'));
    db.exec(`
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS blobs (
            id          TEXT PRIMARY KEY,
            size        INTEGER NOT NULL,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL,
            max_views   INTEGER NOT NULL DEFAULT 0,
            views       INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_blobs_expires ON blobs(expires_at);
    `);

    const qGet = db.prepare('SELECT * FROM blobs WHERE id = ?');
    const qInsert = db.prepare(`
        INSERT INTO blobs (id, size, created_at, expires_at, max_views, views)
        VALUES (?, ?, ?, ?, ?, 0)
        ON CONFLICT(id) DO UPDATE SET
            size = excluded.size,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at,
            max_views = excluded.max_views,
            views = 0
    `);
    const qIncr = db.prepare('UPDATE blobs SET views = views + 1 WHERE id = ?');
    const qDelete = db.prepare('DELETE FROM blobs WHERE id = ?');
    const qExpired = db.prepare('SELECT id FROM blobs WHERE expires_at <= ?');

    const blobPath = (id) => path.join(blobDir, id + '.blob');

    /* ---------------- rate limit (theo IP, cửa sổ trượt đơn giản) ---------------- */

    const buckets = new Map();

    function rateLimited(ip, kind) {
        const key = ip + '|' + kind;
        const t = now();
        const limit = kind === 'post' ? cfg.rateMaxPost : cfg.rateMaxGet;
        let b = buckets.get(key);
        if (!b || t - b.start > cfg.rateWindowMs) {
            b = { start: t, count: 0 };
            buckets.set(key, b);
        }
        b.count++;
        return b.count > limit;
    }

    if (cfg.rateWindowMs > 0) {
        const sweeper = setInterval(() => {
            const t = now();
            for (const [k, b] of buckets) {
                if (t - b.start > cfg.rateWindowMs) buckets.delete(k);
            }
        }, 60_000);
        sweeper.unref?.();
    }

    /* ---------------- xoá blob hết hạn ---------------- */

    async function purge(id) {
        qDelete.run(id);
        await fsp.rm(blobPath(id), { force: true });
    }

    async function sweepExpired() {
        const rows = qExpired.all(now());
        for (const row of rows) await purge(row.id);
        return rows.length;
    }

    const sweepTimer = setInterval(() => { sweepExpired().catch(() => {}); }, 10 * 60 * 1000);
    sweepTimer.unref?.();

    /* ---------------- helpers ---------------- */

    function json(res, status, payload) {
        const body = Buffer.from(JSON.stringify(payload));
        res.writeHead(status, {
            ...SECURITY_HEADERS,
            'Content-Type': 'application/json; charset=utf-8',
            'Content-Length': body.length,
            'Cache-Control': 'no-store'
        });
        res.end(body);
    }

    function fail(res, status, code, message) {
        json(res, status, { error: code, message });
    }

    function tokenFromRequest(req) {
        const header = req.headers.authorization || '';
        const m = /^Bearer\s+([A-Za-z0-9_-]{43})$/.exec(header);
        return m ? m[1] : null;
    }

    /** authKey (base64url) -> id. Đây là toàn bộ "khoá ngoài đời" của server. */
    function idFromToken(token) {
        const auth = Buffer.from(token, 'base64url');
        if (auth.length !== 32) return null;
        return crypto.createHash('sha256')
            .update('zkv1/id')
            .update(auth)
            .digest()
            .subarray(0, 16)
            .toString('hex');
    }

    function clientIp(req) {
        return (req.socket && req.socket.remoteAddress) || 'unknown';
    }

    function readBody(req, limit) {
        return new Promise((resolve, reject) => {
            const chunks = [];
            let size = 0;
            let done = false;

            const finish = (err, value) => {
                if (done) return;
                done = true;
                err ? reject(err) : resolve(value);
            };

            req.on('data', (chunk) => {
                if (done) return;
                size += chunk.length;
                if (size > limit) {
                    const err = new Error('Tệp vượt quá giới hạn ' + Math.floor(limit / (1024 * 1024)) + ' MB.');
                    err.code = 'PAYLOAD_TOO_LARGE';
                    // Ngừng đọc nhưng KHÔNG huỷ socket ngay, để còn kịp trả lời 413.
                    req.pause();
                    finish(err);
                    return;
                }
                chunks.push(chunk);
            });
            req.on('end', () => finish(null, Buffer.concat(chunks)));
            req.on('error', (err) => finish(err));
            req.on('aborted', () => finish(new Error('Kết nối bị huỷ.')));
        });
    }

    /* ---------------- API handlers ---------------- */

    async function handlePost(req, res) {
        const token = tokenFromRequest(req);
        if (!token) return fail(res, 401, 'UNAUTHORIZED', 'Thiếu hoặc sai header Authorization.');
        if (rateLimited(clientIp(req), 'post')) {
            return fail(res, 429, 'RATE_LIMITED', 'Bạn gửi quá nhiều tệp. Thử lại sau một phút.');
        }

        const id = idFromToken(token);
        if (!id) return fail(res, 401, 'UNAUTHORIZED', 'authKey không hợp lệ.');

        const url = new URL(req.url, 'http://localhost');
        let ttl = Number(url.searchParams.get('ttl') || cfg.defaultTtl);
        if (!Number.isFinite(ttl) || ttl <= 0) ttl = cfg.defaultTtl;
        ttl = Math.min(Math.max(ttl, cfg.minTtl), cfg.maxTtl);

        const burn = url.searchParams.get('burn') === '1';
        const maxViews = burn ? 1 : 0;

        let body;
        try {
            body = await readBody(req, cfg.maxBytes);
        } catch (err) {
            // Trả 413 dứt khoát rồi mới đóng kết nối, tránh việc client chỉ thấy "socket closed"
            const payload = Buffer.from(JSON.stringify({
                error: 'PAYLOAD_TOO_LARGE',
                message: err.message
            }));
            res.writeHead(413, {
                ...SECURITY_HEADERS,
                'Content-Type': 'application/json; charset=utf-8',
                'Content-Length': payload.length,
                'Cache-Control': 'no-store',
                'Connection': 'close'
            });
            res.end(payload, () => req.destroy());
            return undefined;
        }

        if (body.length < 36) {
            return fail(res, 400, 'BAD_CONTAINER', 'Dữ liệu gửi lên quá ngắn để là một tệp ZK-Vault.');
        }

        const tmp = blobPath(id) + '.tmp-' + process.pid;
        await fsp.writeFile(tmp, body);
        await fsp.rename(tmp, blobPath(id));

        const createdAt = now();
        const expiresAt = createdAt + ttl * 1000;
        qInsert.run(id, body.length, createdAt, expiresAt, maxViews);

        return json(res, 201, {
            ok: true,
            id,
            size: body.length,
            expiresAt,
            burn,
            ttl
        });
    }

    async function handleGet(req, res) {
        if (rateLimited(clientIp(req), 'get')) {
            return fail(res, 429, 'RATE_LIMITED', 'Quá nhiều yêu cầu. Thử lại sau một phút.');
        }

        const token = tokenFromRequest(req);
        if (!token) return fail(res, 401, 'UNAUTHORIZED', 'Thiếu hoặc sai header Authorization.');

        const id = idFromToken(token);
        const row = id ? qGet.get(id) : undefined;

        if (!row) {
            return fail(res, 404, 'NOT_FOUND', 'Không tìm thấy tệp với key này (hoặc tệp đã hết hạn / đã bị xoá).');
        }
        if (row.expires_at <= now()) {
            await purge(id);
            return fail(res, 404, 'EXPIRED', 'Tệp đã hết hạn và đã bị xoá khỏi server.');
        }
        if (row.max_views > 0 && row.views >= row.max_views) {
            await purge(id);
            return fail(res, 404, 'CONSUMED', 'Tệp đã được tải đủ số lần cho phép và đã bị xoá.');
        }

        qIncr.run(id);
        const remaining = row.max_views > 0 ? Math.max(0, row.max_views - (row.views + 1)) : -1;

        let data;
        try {
            data = await fsp.readFile(blobPath(id));
        } catch {
            await purge(id);
            return fail(res, 404, 'NOT_FOUND', 'Tệp không còn trên server.');
        }

        if (row.max_views > 0 && row.views + 1 >= row.max_views) {
            await purge(id); // tự huỷ ngay sau lần tải đầu
        }

        res.writeHead(200, {
            ...SECURITY_HEADERS,
            'Content-Type': 'application/octet-stream',
            'Content-Length': data.length,
            'Content-Disposition': 'attachment; filename="zk-vault.bin"',
            'Cache-Control': 'no-store',
            'X-ZKV-Expires': String(row.expires_at),
            'X-ZKV-Remaining': String(remaining)
        });
        res.end(data);
    }

    async function handleDelete(req, res) {
        const token = tokenFromRequest(req);
        if (!token) return fail(res, 401, 'UNAUTHORIZED', 'Thiếu hoặc sai header Authorization.');

        const id = idFromToken(token);
        const row = id ? qGet.get(id) : undefined;
        if (!row) return fail(res, 404, 'NOT_FOUND', 'Không tìm thấy tệp với key này.');

        await purge(id);
        return json(res, 200, { ok: true, deleted: true });
    }

    /* ---------------- static ---------------- */

    // Thư viện mã hoá dùng chung: phục vụ thẳng từ src/ để không phải copy sang public/
    const SOURCE_ASSETS = new Map([
        ['/crypto.js', path.join(__dirname, 'crypto.js')],
        ['/keycode.js', path.join(__dirname, 'keycode.js')]
    ]);

    // Các thư mục demo tĩnh: /poc-text/ -> <repo>/poc-text/
    const EXTRA_ROOTS = new Map([
        ['/poc-text/', path.join(__dirname, '..', 'poc-text')]
    ]);

    /** pathname -> đường dẫn file tuyệt đối, hoặc null nếu không hợp lệ. */
    function resolveStatic(pathname) {
        const alias = SOURCE_ASSETS.get(pathname);
        if (alias) return alias;

        for (const [prefix, root] of EXTRA_ROOTS) {
            const bare = prefix.slice(0, -1);
            if (pathname === bare || pathname.startsWith(prefix)) {
                const rest = pathname === bare
                    ? 'index.html'
                    : (decodeURIComponent(pathname.slice(prefix.length)) || 'index.html');
                const file = path.resolve(root, rest);
                return file.startsWith(path.resolve(root)) ? file : null;
            }
        }

        const rel = pathname === '/' ? 'index.html' : decodeURIComponent(pathname).replace(/^\/+/, '');
        const file = path.resolve(publicDir, rel);
        return file.startsWith(path.resolve(publicDir)) ? file : null;
    }

    async function serveStatic(req, res, pathname) {
        const file = resolveStatic(pathname);

        if (!file) {
            return fail(res, 403, 'FORBIDDEN', 'Đường dẫn không hợp lệ.');
        }

        let stat;
        try {
            stat = await fsp.stat(file);
        } catch {
            return fail(res, 404, 'NOT_FOUND', 'Không tìm thấy trang.');
        }
        if (stat.isDirectory()) return fail(res, 404, 'NOT_FOUND', 'Không tìm thấy trang.');

        const type = MIME[path.extname(file).toLowerCase()] || 'application/octet-stream';
        res.writeHead(200, {
            ...SECURITY_HEADERS,
            'Content-Type': type,
            'Content-Length': stat.size,
            'Cache-Control': 'no-cache'
        });
        if (req.method === 'HEAD') return res.end();

        fs.createReadStream(file).pipe(res);
        return undefined;
    }

    /* ---------------- router ---------------- */

    const server = http.createServer(async (req, res) => {
        try {
            const url = new URL(req.url, 'http://localhost');
            const pathname = url.pathname;

            if (pathname === '/api/health') {
                return json(res, 200, { ok: true, service: 'zk-vault', time: now() });
            }
            if (pathname === '/api/blob') {
                if (req.method === 'POST') return await handlePost(req, res);
                if (req.method === 'GET') return await handleGet(req, res);
                if (req.method === 'DELETE') return await handleDelete(req, res);
                res.setHeader('Allow', 'GET, POST, DELETE');
                return fail(res, 405, 'METHOD_NOT_ALLOWED', 'Phương thức không được hỗ trợ.');
            }
            if (pathname.startsWith('/api/')) {
                return fail(res, 404, 'NOT_FOUND', 'API không tồn tại.');
            }
            if (req.method === 'GET' || req.method === 'HEAD') {
                return await serveStatic(req, res, pathname);
            }
            return fail(res, 405, 'METHOD_NOT_ALLOWED', 'Phương thức không được hỗ trợ.');
        } catch (err) {
            if (!res.headersSent) {
                fail(res, 500, 'INTERNAL', 'Lỗi máy chủ: ' + err.message);
            } else {
                res.destroy();
            }
        }
    });

    // Đóng server thì dừng sweeper và đóng database
    const originalClose = server.close.bind(server);
    server.close = (cb) => {
        clearInterval(sweepTimer);
        server.closeIdleConnections?.(); // không phải chờ keep-alive hết hạn
        originalClose(() => {
            try { db.close(); } catch { /* ignore */ }
            cb && cb();
        });
    };

    return { server, db, cfg, sweepExpired, blobPath, dataDir };
}

/* ------------------------------------------------------------------ */

if (require.main === module) {
    const { server, cfg } = createVaultServer();
    server.listen(cfg.port, cfg.host, () => {
        console.log('ZK-Vault đang chạy tại http://' + cfg.host + ':' + cfg.port);
        console.log('  giới hạn   : ' + Math.floor(cfg.maxBytes / (1024 * 1024)) + ' MB / tệp');
        console.log('  TTL tối đa : ' + Math.floor(cfg.maxTtl / 86400) + ' ngày');
        console.log('  dữ liệu ở  : ' + path.join(__dirname, '..', 'data'));
    });
}

module.exports = { createVaultServer };
