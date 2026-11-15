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

const { createServer } = require('../src/server.js');
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
