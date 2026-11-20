/**
 * Test API server: lưu / trả lại bản mã, TTL, giới hạn, phân quyền.
 * Chạy: node --test test/server.test.js
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const http = require('node:http');
const { createServer } = require('../src/server.js');
const { createS3Client } = require('../src/s3.js');
const zk = require('../src/crypto.js');

let counter = 0;

async function startServer(options = {}) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkv-test-' + (counter++) + '-'));
    const vault = createServer({ dataDir, ...options });
    await new Promise((r) => vault.server.listen(0, '127.0.0.1', r));

    return {
        vault,
        base: 'http://127.0.0.1:' + vault.server.address().port,
        async close() {
            await new Promise((r) => vault.server.close(r));
            fs.rmSync(dataDir, { recursive: true, force: true });
        }
    };
}

/** Mã hoá văn bản y như client thật, trả về dữ liệu cần cho fetch. */
async function seal(text) {
    const rootKey = zk.randomKey();
    const sealed = await zk.encryptText(text, rootKey);
    return { rootKey, ...sealed };
}

const auth = (authKeyB64) => ({ Authorization: 'Bearer ' + authKeyB64 });

/* ------------------------------------------------------------------ */

test('health check', async () => {
    const s = await startServer();
    try {
        const res = await fetch(s.base + '/api/health');
        assert.equal(res.status, 200);
        assert.equal((await res.json()).ok, true);
    } finally {
        await s.close();
    }
});

test('gửi rồi lấy lại đúng byte bản mã', async () => {
    const s = await startServer();
    try {
        const sealed = await seal('mã két sắt 4821');

        const up = await fetch(s.base + '/api/secret', {
            method: 'POST', headers: auth(sealed.authKeyB64), body: sealed.container
        });
        assert.equal(up.status, 201);
        const info = await up.json();
        assert.equal(info.id, sealed.id);
        assert.equal(info.size, sealed.container.length);

        const down = await fetch(s.base + '/api/secret', { headers: auth(sealed.authKeyB64) });
        assert.equal(down.status, 200);
        assert.deepEqual(Buffer.from(await down.arrayBuffer()), Buffer.from(sealed.container));
    } finally {
        await s.close();
    }
});

test('đi trọn vòng: gửi bằng máy A, đọc lại bằng key ở máy B', async () => {
    const s = await startServer();
    try {
        const text = 'Hợp đồng thuê nhà số 42 — 12 triệu/tháng';
        const rootKey = zk.randomKey();
        const sealed = await zk.encryptText(text, rootKey);

        await fetch(s.base + '/api/secret', {
            method: 'POST', headers: auth(sealed.authKeyB64), body: sealed.container
        });

        // "Máy B" chỉ có key, không có gì khác
        const keyText = require('../src/keycode.js').encode(rootKey);
        const keyBytes = require('../src/keycode.js').decode(keyText);
        const derived = await zk.deriveKeys(keyBytes);

        const res = await fetch(s.base + '/api/secret', { headers: auth(derived.authKeyB64) });
        const container = new Uint8Array(await res.arrayBuffer());

        assert.equal(await zk.decryptText(container, keyBytes), text);
    } finally {
        await s.close();
    }
});

test('server không lưu được nội dung đọc được', async () => {
    const s = await startServer();
    try {
        const sealed = await seal('nội dung tuyệt mật hop-dong');
        await fetch(s.base + '/api/secret', {
            method: 'POST', headers: auth(sealed.authKeyB64), body: sealed.container
        });

        const rows = s.vault.db.prepare('SELECT id, body FROM secrets').all();
        assert.equal(rows.length, 1);

        const stored = Buffer.from(rows[0].body).toString('latin1');
        assert.equal(stored.includes('hop-dong'), false);
        assert.equal(stored.includes('tuyệt mật'), false);

        // và bảng không có cột nào chứa key
        assert.deepEqual(Object.keys(rows[0]), ['id', 'body']);
    } finally {
        await s.close();
    }
});

test('key khác thì không tìm thấy gì', async () => {
    const s = await startServer();
    try {
        const sealed = await seal('x');
        await fetch(s.base + '/api/secret', {
            method: 'POST', headers: auth(sealed.authKeyB64), body: sealed.container
        });

        const other = await zk.deriveKeys(zk.randomKey());
        const res = await fetch(s.base + '/api/secret', { headers: auth(other.authKeyB64) });
        assert.equal(res.status, 404);
    } finally {
        await s.close();
    }
});

test('thiếu Authorization -> 401', async () => {
    const s = await startServer();
    try {
        assert.equal((await fetch(s.base + '/api/secret')).status, 401);
        assert.equal((await fetch(s.base + '/api/secret', {
            method: 'POST', body: Buffer.alloc(30)
        })).status, 401);
    } finally {
        await s.close();
    }
});

test('hết hạn TTL thì văn bản bị xoá', async () => {
    let clock = Date.now();
    const s = await startServer({ now: () => clock, ttlSeconds: 60 });
    try {
        const sealed = await seal('sống ngắn');
        await fetch(s.base + '/api/secret', {
            method: 'POST', headers: auth(sealed.authKeyB64), body: sealed.container
        });

        assert.equal((await fetch(s.base + '/api/secret', { headers: auth(sealed.authKeyB64) })).status, 200);

        clock += 61_000;
        assert.equal((await fetch(s.base + '/api/secret', { headers: auth(sealed.authKeyB64) })).status, 404);

        const rows = s.vault.db.prepare('SELECT COUNT(*) AS n FROM secrets').get();
        assert.equal(rows.n, 0);
    } finally {
        await s.close();
    }
});

test('dữ liệu vượt giới hạn -> 413', async () => {
    const s = await startServer({ maxBytes: 256 });
    try {
        const sealed = await seal('a'.repeat(1000));
        const res = await fetch(s.base + '/api/secret', {
            method: 'POST', headers: auth(sealed.authKeyB64), body: sealed.container
        });
        assert.equal(res.status, 413);
    } finally {
        await s.close();
    }
});

test('gói tin quá ngắn -> 400', async () => {
    const s = await startServer();
    try {
        const d = await zk.deriveKeys(zk.randomKey());
        const res = await fetch(s.base + '/api/secret', {
            method: 'POST', headers: auth(d.authKeyB64), body: Buffer.alloc(5)
        });
        assert.equal(res.status, 400);
    } finally {
        await s.close();
    }
});

test('rate limit chặn gửi dồn dập', async () => {
    const s = await startServer({ rateMaxPost: 3 });
    try {
        const statuses = [];
        for (let i = 0; i < 5; i++) {
            const sealed = await seal('r');
            const res = await fetch(s.base + '/api/secret', {
                method: 'POST', headers: auth(sealed.authKeyB64), body: sealed.container
            });
            statuses.push(res.status);
        }
        assert.deepEqual(statuses.slice(0, 3), [201, 201, 201]);
        assert.deepEqual(statuses.slice(3), [429, 429]);
    } finally {
        await s.close();
    }
});

test('không phục vụ file ngoài thư mục public', async () => {
    const s = await startServer();
    try {
        const res = await fetch(s.base + '/../../src/server.js');
        assert.ok(res.status === 403 || res.status === 404, 'phải chặn, nhận ' + res.status);
    } finally {
        await s.close();
    }
});

test('trang chủ trả HTML kèm CSP chặt', async () => {
    const s = await startServer();
    try {
        const res = await fetch(s.base + '/');
        assert.equal(res.status, 200);
        assert.match(res.headers.get('content-type'), /text\/html/);

        const csp = res.headers.get('content-security-policy');
        assert.match(csp, /default-src 'self'/);
        assert.match(csp, /frame-ancestors 'none'/);
        assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    } finally {
        await s.close();
    }
});

test('thư viện dùng chung được phục vụ từ src/', async () => {
    const s = await startServer();
    try {
        for (const p of ['/crypto.js', '/keycode.js', '/app.js', '/style.css']) {
            assert.equal((await fetch(s.base + p)).status, 200, 'phải phục vụ được ' + p);
        }
    } finally {
        await s.close();
    }
});

test('PUT /api/secret sửa lại văn bản theo cùng key (IV mới)', async () => {
    const s = await startServer();
    try {
        const rootKey = zk.randomKey();
        const v1 = await zk.encryptText('nội dung ban đầu', rootKey);

        const postRes = await fetch(s.base + '/api/secret', {
            method: 'POST', headers: auth(v1.authKeyB64), body: v1.container
        });
        assert.equal(postRes.status, 201);

        const v2 = await zk.encryptText('nội dung đã chỉnh sửa lần 2', rootKey);
        assert.equal(v2.id, v1.id);
        // IV 12 byte ở vị trí [1..13] phải khác nhau giữa 2 lần mã hoá
        assert.notDeepEqual(v1.container.slice(1, 13), v2.container.slice(1, 13));

        const putRes = await fetch(s.base + '/api/secret', {
            method: 'PUT', headers: auth(v2.authKeyB64), body: v2.container
        });
        assert.equal(putRes.status, 200);
        const putInfo = await putRes.json();
        assert.equal(putInfo.ok, true);
        assert.equal(putInfo.id, v1.id);
        assert.equal(putInfo.size, v2.container.length);

        const getRes = await fetch(s.base + '/api/secret', { headers: auth(v1.authKeyB64) });
        assert.equal(getRes.status, 200);
        const container = new Uint8Array(await getRes.arrayBuffer());
        assert.equal(await zk.decryptText(container, rootKey), 'nội dung đã chỉnh sửa lần 2');

        // PUT với key chưa tồn tại -> 404
        const unknown = await seal('không tồn tại');
        const badPut = await fetch(s.base + '/api/secret', {
            method: 'PUT', headers: auth(unknown.authKeyB64), body: unknown.container
        });
        assert.equal(badPut.status, 404);
    } finally {
        await s.close();
    }
});

test('DELETE /api/secret xoá văn bản theo key', async () => {
    const s = await startServer();
    try {
        const sealed = await seal('bí mật cần xoá ngay');
        await fetch(s.base + '/api/secret', {
            method: 'POST', headers: auth(sealed.authKeyB64), body: sealed.container
        });

        const delRes = await fetch(s.base + '/api/secret', {
            method: 'DELETE', headers: auth(sealed.authKeyB64)
        });
        assert.equal(delRes.status, 200);
        const delInfo = await delRes.json();
        assert.equal(delInfo.ok, true);
        assert.equal(delInfo.id, sealed.id);

        // Đọc lại hoặc xoá lần 2 đều trả 404
        assert.equal((await fetch(s.base + '/api/secret', { headers: auth(sealed.authKeyB64) })).status, 404);
        assert.equal((await fetch(s.base + '/api/secret', {
            method: 'DELETE', headers: auth(sealed.authKeyB64)
        })).status, 404);
    } finally {
        await s.close();
    }
});

test('MinIO S3 (AWS4-HMAC-SHA256): lưu, đọc, sửa và xoá tệp đính kèm mã hoá trên S3 bucket', async () => {
    // Dựng S3/MinIO server giả lập kiểm tra chữ ký AWS4-HMAC-SHA256
    const buckets = new Set();
    const objects = new Map();

    const mockMinio = http.createServer((req, res) => {
        const authHeader = req.headers['authorization'] || '';
        const contentSha = req.headers['x-amz-content-sha256'] || '';
        const amzDate = req.headers['x-amz-date'] || '';

        if (!authHeader.startsWith('AWS4-HMAC-SHA256 Credential=minioadmin/') || !contentSha || !amzDate) {
            res.writeHead(403);
            return res.end('Invalid SigV4');
        }

        const parts = req.url.split('/').filter(Boolean);
        const bucket = parts[0];
        const key = parts.slice(1).join('/');

        if (!key) {
            if (req.method === 'HEAD') {
                res.writeHead(buckets.has(bucket) ? 200 : 404);
                return res.end();
            }
            if (req.method === 'PUT') {
                buckets.add(bucket);
                res.writeHead(200);
                return res.end();
            }
        }

        const fullKey = `${bucket}/${key}`;
        if (req.method === 'PUT') {
            const chunks = [];
            req.on('data', (c) => chunks.push(c));
            req.on('end', () => {
                objects.set(fullKey, Buffer.concat(chunks));
                res.writeHead(200);
                res.end();
            });
            return undefined;
        }
        if (req.method === 'GET') {
            if (!objects.has(fullKey)) {
                res.writeHead(404);
                return res.end();
            }
            const buf = objects.get(fullKey);
            res.writeHead(200, { 'Content-Length': buf.length });
            return res.end(buf);
        }
        if (req.method === 'DELETE') {
            objects.delete(fullKey);
            res.writeHead(204);
            return res.end();
        }
        res.writeHead(405);
        return res.end();
    });

    await new Promise((r) => mockMinio.listen(0, '127.0.0.1', r));
    const minioEndpoint = 'http://127.0.0.1:' + mockMinio.address().port;

    const s3 = createS3Client({
        endpoint: minioEndpoint,
        bucket: 'zk-vault',
        accessKey: 'minioadmin',
        secretKey: 'minioadmin'
    });
    await s3.ensureBucket();
    assert.equal(buckets.has('zk-vault'), true);

    const s = await startServer({ s3 });
    try {
        const rootKey = zk.randomKey();
        const fileContent = new Uint8Array([10, 20, 30, 40, 50, 60]);
        const v1 = await zk.encryptPayload(
            {
                text: 'Tài liệu mật gửi lên MinIO',
                file: { name: 'so-do-mang.png', type: 'image/png', data: fileContent }
            },
            rootKey
        );

        // 1. POST lên server -> lưu vào MinIO S3, SQLite chỉ giữ metadata (body rỗng)
        const up = await fetch(s.base + '/api/secret', {
            method: 'POST', headers: auth(v1.authKeyB64), body: v1.container
        });
        assert.equal(up.status, 201);
        const upInfo = await up.json();
        assert.equal(upInfo.storage, 'minio-s3');

        // Kiểm tra: MinIO có object <id>.zkv, còn SQLite không chứa bytes bản mã
        assert.equal(objects.has(`zk-vault/${v1.id}.zkv`), true);
        const sqliteRow = s.vault.db.prepare('SELECT body FROM secrets WHERE id = ?').get(v1.id);
        assert.equal(sqliteRow.body.byteLength, 0);

        // 2. GET tải về và giải mã lại đúng cả text lẫn file
        const down = await fetch(s.base + '/api/secret', { headers: auth(v1.authKeyB64) });
        assert.equal(down.status, 200);
        const decrypted = await zk.decryptPayload(new Uint8Array(await down.arrayBuffer()), rootKey);
        assert.equal(decrypted.text, 'Tài liệu mật gửi lên MinIO');
        assert.equal(decrypted.file.name, 'so-do-mang.png');
        assert.deepEqual(decrypted.file.data, fileContent);

        // 3. DELETE xoá cả trên MinIO lẫn SQLite
        const del = await fetch(s.base + '/api/secret', {
            method: 'DELETE', headers: auth(v1.authKeyB64)
        });
        assert.equal(del.status, 200);
        assert.equal(objects.has(`zk-vault/${v1.id}.zkv`), false);
    } finally {
        await s.close();
        await new Promise((r) => mockMinio.close(r));
    }
});
