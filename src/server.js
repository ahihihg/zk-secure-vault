/*!
 * server.js — nhận, giữ và trả lại bản mã. Không có khả năng đọc nội dung.
 *
 *   node src/server.js         →  http://127.0.0.1:8787
 *   PORT=9000 node src/server.js
 *
 * Server này cố tình "ngố": nó chỉ biết
 *   - một chuỗi hex gọi là `id` (do client tính ra từ key)
 *   - một cục byte đã mã hoá
 *   - thời điểm hết hạn
 * Nó không có bảng user, không có mật khẩu, không có `encKey`, không log nội dung.
 *
 * API
 *   POST   /api/secret   Authorization: Bearer <authKey>   body: gói tin ZKV1 (tạo mới / ghi đè)
 *   GET    /api/secret   Authorization: Bearer <authKey>
 *   PUT    /api/secret   Authorization: Bearer <authKey>   body: gói tin ZKV1 (sửa bản mã hiện có)
 *   DELETE /api/secret   Authorization: Bearer <authKey>
 *   GET    /api/health
 */
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const { createS3Client } = require('./s3.js');

const DEFAULTS = {
    port: Number(process.env.PORT || 8787),
    host: process.env.HOST || '127.0.0.1',
    maxBytes: 25 * 1024 * 1024,      // 25 MB — hỗ trợ cả văn bản và tệp đính kèm mã hoá
    ttlSeconds: 7 * 24 * 3600,       // 7 ngày
    rateWindowMs: 60 * 1000,
    rateMaxPost: 20,
    rateMaxGet: 120
};

const SECURITY_HEADERS = {
    'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'"
    ].join('; '),
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin'
};

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
};

const MIN_CONTAINER_BYTES = 1 + 12 + 16; // version + IV + tag

/* ------------------------------------------------------------------ */

function createServer(options = {}) {
    const cfg = { ...DEFAULTS, ...options };
    const dataDir = cfg.dataDir || path.join(__dirname, '..', 'data');
    const publicDir = cfg.publicDir || path.join(__dirname, '..', 'public');
    const now = cfg.now || (() => Date.now());
    const s3 = cfg.s3 || null; // khi có kết nối MinIO S3, bản mã lưu trên bucket MinIO dưới tên <id>.zkv

    fs.mkdirSync(dataDir, { recursive: true });

    const db = new DatabaseSync(path.join(dataDir, 'vault.db'));
    db.exec(`
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS secrets (
            id          TEXT PRIMARY KEY,
            body        BLOB NOT NULL,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(expires_at);
    `);

    const qGet = db.prepare('SELECT body, expires_at FROM secrets WHERE id = ?');
    const qPut = db.prepare(`
        INSERT INTO secrets (id, body, created_at, expires_at) VALUES (?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET body = excluded.body, expires_at = excluded.expires_at
    `);
    const qDel = db.prepare('DELETE FROM secrets WHERE id = ?');
    const qExpired = db.prepare('SELECT id FROM secrets WHERE expires_at <= ?');

    /* ---------------- tiện ích ---------------- */

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

    const fail = (res, status, error, message) => json(res, status, { error, message });

    /**
     * authKey (Base64URL) -> id (hex 32 ký tự).
     * Đây là toàn bộ "khoá ngoài đời" của server: nó không thể đảo ngược để lấy key.
     */
    function idFromAuthKey(token) {
        const auth = Buffer.from(token, 'base64url');
        if (auth.length !== 32) return null;
        return crypto.createHash('sha256')
            .update('zkv1/id')
            .update(auth)
            .digest()
            .subarray(0, 16)
            .toString('hex');
    }

    function tokenFrom(req) {
        const header = req.headers.authorization || '';
        const m = /^Bearer\s+([A-Za-z0-9_-]{43})$/.exec(header);
        return m ? m[1] : null;
    }

    const clientIp = (req) => (req.socket && req.socket.remoteAddress) || 'unknown';

    /* ---------------- rate limit theo IP ---------------- */

    const buckets = new Map();

    function limited(ip, kind) {
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

    const bucketCleaner = setInterval(() => {
        const t = now();
        for (const [k, b] of buckets) {
            if (t - b.start > cfg.rateWindowMs) buckets.delete(k);
        }
    }, 60_000);
    bucketCleaner.unref?.();

    /* ---------------- dọn dữ liệu hết hạn ---------------- */

    function sweepExpired() {
        const rows = qExpired.all(now());
        for (const row of rows) {
            qDel.run(row.id);
            if (s3) s3.deleteObject(row.id + '.zkv').catch(() => {});
        }
        return rows.length;
    }

    const sweeper = setInterval(sweepExpired, 10 * 60 * 1000);
    sweeper.unref?.();

    /* ---------------- đọc body có giới hạn ---------------- */

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
                    // Ngừng đọc nhưng chưa huỷ socket, để còn kịp trả lời 413
                    req.pause();
                    finish(new Error('Dữ liệu vượt quá giới hạn ' + limit + ' byte.'));
                    return;
                }
                chunks.push(chunk);
            });
            req.on('end', () => finish(null, Buffer.concat(chunks)));
            req.on('error', finish);
        });
    }

    /* ---------------- API ---------------- */

    async function handlePost(req, res) {
        if (limited(clientIp(req), 'post')) {
            return fail(res, 429, 'RATE_LIMITED', 'Bạn gửi quá nhiều. Thử lại sau một phút.');
        }

        const token = tokenFrom(req);
        if (!token) return fail(res, 401, 'UNAUTHORIZED', 'Thiếu hoặc sai header Authorization.');
        const id = idFromAuthKey(token);
        if (!id) return fail(res, 401, 'UNAUTHORIZED', 'authKey không hợp lệ.');

        let body;
        try {
            body = await readBody(req, cfg.maxBytes);
        } catch (err) {
            const payload = Buffer.from(JSON.stringify({ error: 'PAYLOAD_TOO_LARGE', message: err.message }));
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

        if (body.length < MIN_CONTAINER_BYTES) {
            return fail(res, 400, 'BAD_CONTAINER', 'Dữ liệu quá ngắn để là một gói tin ZK-Vault.');
        }

        const createdAt = now();
        const expiresAt = createdAt + cfg.ttlSeconds * 1000;

        if (s3) {
            await s3.putObject(id + '.zkv', body);
            qPut.run(id, Buffer.alloc(0), createdAt, expiresAt);
        } else {
            qPut.run(id, body, createdAt, expiresAt);
        }

        return json(res, 201, {
            ok: true,
            id,
            size: body.length,
            expiresAt,
            storage: s3 ? 'minio-s3' : 'sqlite'
        });
    }

    async function handleGet(req, res) {
        if (limited(clientIp(req), 'get')) {
            return fail(res, 429, 'RATE_LIMITED', 'Quá nhiều yêu cầu. Thử lại sau một phút.');
        }

        const token = tokenFrom(req);
        if (!token) return fail(res, 401, 'UNAUTHORIZED', 'Thiếu hoặc sai header Authorization.');

        const id = idFromAuthKey(token);
        const row = id ? qGet.get(id) : undefined;

        if (!row) {
            return fail(res, 404, 'NOT_FOUND', 'Không tìm thấy văn bản với key này (hoặc đã hết hạn).');
        }
        if (row.expires_at <= now()) {
            qDel.run(id);
            if (s3) await s3.deleteObject(id + '.zkv').catch(() => {});
            return fail(res, 404, 'EXPIRED', 'Văn bản đã hết hạn và bị xoá khỏi server.');
        }

        let body = Buffer.from(row.body);
        if (s3 && body.length === 0) {
            const s3Data = await s3.getObject(id + '.zkv');
            if (!s3Data) {
                qDel.run(id);
                return fail(res, 404, 'NOT_FOUND', 'Không tìm thấy gói bản mã trên MinIO.');
            }
            body = s3Data;
        }

        res.writeHead(200, {
            ...SECURITY_HEADERS,
            'Content-Type': 'application/octet-stream',
            'Content-Length': body.length,
            'Cache-Control': 'no-store',
            'X-ZKV-Expires': String(row.expires_at)
        });
        res.end(body);
        return undefined;
    }

    async function handlePut(req, res) {
        if (limited(clientIp(req), 'post')) {
            return fail(res, 429, 'RATE_LIMITED', 'Bạn gửi quá nhiều. Thử lại sau một phút.');
        }

        const token = tokenFrom(req);
        if (!token) return fail(res, 401, 'UNAUTHORIZED', 'Thiếu hoặc sai header Authorization.');
        const id = idFromAuthKey(token);
        if (!id) return fail(res, 401, 'UNAUTHORIZED', 'authKey không hợp lệ.');

        const row = qGet.get(id);
        if (!row) {
            return fail(res, 404, 'NOT_FOUND', 'Không tìm thấy văn bản với key này (hoặc đã hết hạn).');
        }
        if (row.expires_at <= now()) {
            qDel.run(id);
            if (s3) await s3.deleteObject(id + '.zkv').catch(() => {});
            return fail(res, 404, 'EXPIRED', 'Văn bản đã hết hạn và bị xoá khỏi server.');
        }

        let body;
        try {
            body = await readBody(req, cfg.maxBytes);
        } catch (err) {
            const payload = Buffer.from(JSON.stringify({ error: 'PAYLOAD_TOO_LARGE', message: err.message }));
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

        if (body.length < MIN_CONTAINER_BYTES) {
            return fail(res, 400, 'BAD_CONTAINER', 'Dữ liệu quá ngắn để là một gói tin ZK-Vault.');
        }

        const updatedAt = now();
        const expiresAt = updatedAt + cfg.ttlSeconds * 1000;

        if (s3) {
            await s3.putObject(id + '.zkv', body);
            qPut.run(id, Buffer.alloc(0), updatedAt, expiresAt);
        } else {
            qPut.run(id, body, updatedAt, expiresAt);
        }

        return json(res, 200, {
            ok: true,
            id,
            size: body.length,
            expiresAt,
            storage: s3 ? 'minio-s3' : 'sqlite'
        });
    }

    async function handleDelete(req, res) {
        if (limited(clientIp(req), 'post')) {
            return fail(res, 429, 'RATE_LIMITED', 'Bạn gửi quá nhiều. Thử lại sau một phút.');
        }

        const token = tokenFrom(req);
        if (!token) return fail(res, 401, 'UNAUTHORIZED', 'Thiếu hoặc sai header Authorization.');
        const id = idFromAuthKey(token);
        if (!id) return fail(res, 401, 'UNAUTHORIZED', 'authKey không hợp lệ.');

        const row = qGet.get(id);
        if (!row) {
            return fail(res, 404, 'NOT_FOUND', 'Không tìm thấy văn bản với key này (hoặc đã hết hạn).');
        }
        if (row.expires_at <= now()) {
            qDel.run(id);
            if (s3) await s3.deleteObject(id + '.zkv').catch(() => {});
            return fail(res, 404, 'EXPIRED', 'Văn bản đã hết hạn và bị xoá khỏi server.');
        }

        if (s3) await s3.deleteObject(id + '.zkv');
        qDel.run(id);
        return json(res, 200, { ok: true, id });
    }

    /* ---------------- file tĩnh ---------------- */

    // Dùng chung thư viện mã hoá ở src/ thay vì copy sang public/
    const SOURCE_ASSETS = new Map([
        ['/crypto.js', path.join(__dirname, 'crypto.js')],
        ['/keycode.js', path.join(__dirname, 'keycode.js')]
    ]);

    function resolveStatic(pathname) {
        const alias = SOURCE_ASSETS.get(pathname);
        if (alias) return alias;

        const rel = pathname === '/' ? 'index.html' : decodeURIComponent(pathname).replace(/^\/+/, '');
        const file = path.resolve(publicDir, rel);
        return file.startsWith(path.resolve(publicDir)) ? file : null;
    }

    async function serveStatic(req, res, pathname) {
        const file = resolveStatic(pathname);
        if (!file) return fail(res, 403, 'FORBIDDEN', 'Đường dẫn không hợp lệ.');

        let stat;
        try {
            stat = await fsp.stat(file);
        } catch {
            return fail(res, 404, 'NOT_FOUND', 'Không tìm thấy trang.');
        }
        if (stat.isDirectory()) return fail(res, 404, 'NOT_FOUND', 'Không tìm thấy trang.');

        res.writeHead(200, {
            ...SECURITY_HEADERS,
            'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
            'Content-Length': stat.size,
            'Cache-Control': 'no-cache'
        });
        fs.createReadStream(file).pipe(res);
        return undefined;
    }

    /* ---------------- router ---------------- */

    const server = http.createServer(async (req, res) => {
        try {
            const { pathname } = new URL(req.url, 'http://localhost');

            if (pathname === '/api/health') {
                return json(res, 200, {
                    ok: true,
                    service: 'zk-vault',
                    storage: s3 ? 'minio-s3' : 'sqlite',
                    time: now()
                });
            }
            if (pathname === '/api/secret') {
                if (req.method === 'POST') return await handlePost(req, res);
                if (req.method === 'GET') return await handleGet(req, res);
                if (req.method === 'PUT') return await handlePut(req, res);
                if (req.method === 'DELETE') return await handleDelete(req, res);
                res.setHeader('Allow', 'GET, POST, PUT, DELETE');
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
            if (!res.headersSent) fail(res, 500, 'INTERNAL', 'Lỗi máy chủ: ' + err.message);
            else res.destroy();
            return undefined;
        }
    });

    const closeOriginal = server.close.bind(server);
    server.close = (cb) => {
        clearInterval(sweeper);
        clearInterval(bucketCleaner);
        server.closeIdleConnections?.();
        closeOriginal(() => {
            try { db.close(); } catch { /* bỏ qua */ }
            if (cb) cb();
        });
    };

    return { server, db, cfg, dataDir, s3, sweepExpired };
}

/* ------------------------------------------------------------------ */

if (require.main === module) {
    (async () => {
        let activeS3 = null;
        if (process.env.USE_MINIO !== '0') {
            const candidate = createS3Client();
            try {
                await candidate.ensureBucket();
                activeS3 = candidate;
            } catch {
                activeS3 = null;
            }
        }

        const { server, cfg, dataDir } = createServer({ s3: activeS3 });
        server.listen(cfg.port, cfg.host, () => {
            console.log('ZK-Vault chạy tại http://' + cfg.host + ':' + cfg.port);
            console.log('  giới hạn : ' + Math.round(cfg.maxBytes / (1024 * 1024)) + ' MB / lần gửi');
            console.log('  TTL      : ' + Math.round(cfg.ttlSeconds / 86400) + ' ngày');
            if (activeS3) {
                console.log('  lưu trữ  : MinIO S3 (' + activeS3.cfg.endpoint + ' / bucket: ' + activeS3.cfg.bucket + ')');
            } else {
                console.log('  lưu trữ  : SQLite cục bộ (' + dataDir + ') — bật Docker MinIO ("docker compose up -d") để lưu trên S3');
            }
        });
    })();
}

module.exports = { createServer };
