/**
 * Test API của server: upload / download / delete, TTL, chế độ tự huỷ, rate limit.
 * Chạy: node --test test/server.test.js
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createVaultServer } = require('../src/server.js');
const zk = require('../src/crypto.js');
const kc = require('../src/keycode.js');

let counter = 0;

async function startServer(options = {}) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkv-test-' + (counter++) + '-'));
    const vault = createVaultServer({ dataDir, ...options });
    await new Promise((resolve) => vault.server.listen(0, '127.0.0.1', resolve));
    const port = vault.server.address().port;
    return {
        vault,
        port,
        base: 'http://127.0.0.1:' + port,
        dataDir,
        async close() {
            await new Promise((resolve) => vault.server.close(resolve));
            fs.rmSync(dataDir, { recursive: true, force: true });
        }
    };
}

/** Mã hoá một tệp y như client thật rồi trả về { rootKey, authKey, container }. */
async function seal(name, type, bytes) {
    const rootKey = zk.randomKey();
    const enc = await zk.encryptFile({ bytes, name, type, rootKey });
    return { rootKey, authKey: enc.authKey, container: Buffer.from(enc.container), id: enc.id };
}

const auth = (authKey) => ({ Authorization: 'Bearer ' + authKey });

test('health check', async () => {
    const s = await startServer();
    try {
        const res = await fetch(s.base + '/api/health');
        assert.equal(res.status, 200);
        const body = await res.json();
        assert.equal(body.ok, true);
    } finally {
        await s.close();
    }
});

test('upload rồi download trả về đúng byte đã gửi', async () => {
    const s = await startServer();
    try {
        const payload = Buffer.from([0, 1, 2, 3, 250, 251, 252, 253]);
        const sealed = await seal('a.bin', 'application/octet-stream', payload);

        const up = await fetch(s.base + '/api/blob?ttl=3600', {
            method: 'POST', headers: auth(sealed.authKey), body: sealed.container
        });
        assert.equal(up.status, 201);
        const upBody = await up.json();
        assert.equal(upBody.id, sealed.id);
        assert.equal(upBody.size, sealed.container.length);

        const down = await fetch(s.base + '/api/blob', { headers: auth(sealed.authKey) });
        assert.equal(down.status, 200);
        const got = Buffer.from(await down.arrayBuffer());
        assert.deepEqual(got, sealed.container);
        assert.equal(down.headers.get('content-type'), 'application/octet-stream');
        assert.ok(down.headers.get('x-zkv-expires'));
    } finally {
        await s.close();
    }
});

test('server không lưu được bất cứ thứ gì đọc được từ tệp', async () => {
    const s = await startServer();
    try {
        const sealed = await seal('hop-dong-mat.pdf', 'application/pdf', Buffer.from('nội dung tuyệt mật'));
        await fetch(s.base + '/api/blob', { method: 'POST', headers: auth(sealed.authKey), body: sealed.container });

        const onDisk = fs.readFileSync(s.vault.blobPath(sealed.id)).toString('latin1');
        assert.equal(onDisk.includes('hop-dong-mat'), false);
        assert.equal(onDisk.includes('tuyệt mật'), false);

        // Trong DB chỉ có id (hash) và metadata vận hành
        const rows = s.vault.db.prepare('SELECT * FROM blobs').all();
        assert.equal(rows.length, 1);
        assert.equal(rows[0].id, sealed.id);
        assert.equal(Object.keys(rows[0]).includes('key'), false);
    } finally {
        await s.close();
    }
});

test('key khác thì không tìm thấy tệp (và không có oracle để dò)', async () => {
    const s = await startServer();
    try {
        const sealed = await seal('a.txt', 'text/plain', Buffer.from('x'));
        await fetch(s.base + '/api/blob', { method: 'POST', headers: auth(sealed.authKey), body: sealed.container });

        const otherKey = kc.encode(zk.randomKey());
        const otherAuth = (await zk.deriveKeys(kc.decode(otherKey))).authKey;
        const res = await fetch(s.base + '/api/blob', {
            headers: auth(zk.bytesToBase64Url(otherAuth))
        });
        assert.equal(res.status, 404);
    } finally {
        await s.close();
    }
});

test('thiếu Authorization -> 401', async () => {
    const s = await startServer();
    try {
        const res = await fetch(s.base + '/api/blob');
        assert.equal(res.status, 401);
    } finally {
        await s.close();
    }
});

test('chế độ tự huỷ: tải lần đầu được, lần hai mất', async () => {
    const s = await startServer();
    try {
        const sealed = await seal('burn.txt', 'text/plain', Buffer.from('chỉ xem một lần'));
        await fetch(s.base + '/api/blob?burn=1', { method: 'POST', headers: auth(sealed.authKey), body: sealed.container });

        const first = await fetch(s.base + '/api/blob', { headers: auth(sealed.authKey) });
        assert.equal(first.status, 200);
        assert.equal(first.headers.get('x-zkv-remaining'), '0');

        const second = await fetch(s.base + '/api/blob', { headers: auth(sealed.authKey) });
        assert.equal(second.status, 404);
        assert.equal(fs.existsSync(s.vault.blobPath(sealed.id)), false);
    } finally {
        await s.close();
    }
});

test('hết hạn TTL thì tệp bị xoá', async () => {
    let clock = Date.now();
    const s = await startServer({ now: () => clock, minTtl: 1 });
    try {
        const sealed = await seal('ttl.txt', 'text/plain', Buffer.from('sống ngắn'));
        await fetch(s.base + '/api/blob?ttl=1', { method: 'POST', headers: auth(sealed.authKey), body: sealed.container });

        assert.equal((await fetch(s.base + '/api/blob', { headers: auth(sealed.authKey) })).status, 200);

        clock += 5000; // tua đồng hồ 5 giây
        const expired = await fetch(s.base + '/api/blob', { headers: auth(sealed.authKey) });
        assert.equal(expired.status, 404);
        assert.equal(fs.existsSync(s.vault.blobPath(sealed.id)), false);
    } finally {
        await s.close();
    }
});

test('DELETE bằng key đúng thì xoá', async () => {
    const s = await startServer();
    try {
        const sealed = await seal('del.txt', 'text/plain', Buffer.from('x'));
        await fetch(s.base + '/api/blob', { method: 'POST', headers: auth(sealed.authKey), body: sealed.container });

        const del = await fetch(s.base + '/api/blob', { method: 'DELETE', headers: auth(sealed.authKey) });
        assert.equal(del.status, 200);

        assert.equal((await fetch(s.base + '/api/blob', { headers: auth(sealed.authKey) })).status, 404);
    } finally {
        await s.close();
    }
});

test('tệp vượt giới hạn dung lượng -> 413', async () => {
    const s = await startServer({ maxBytes: 1024 });
    try {
        const sealed = await seal('big.bin', 'application/octet-stream', Buffer.alloc(4096, 1));
        const res = await fetch(s.base + '/api/blob', {
            method: 'POST', headers: auth(sealed.authKey), body: sealed.container
        });
        assert.equal(res.status, 413);
    } finally {
        await s.close();
    }
});

test('rate limit chặn upload hàng loạt', async () => {
    const s = await startServer({ rateMaxPost: 3 });
    try {
        const statuses = [];
        for (let i = 0; i < 5; i++) {
            const sealed = await seal('r.txt', 'text/plain', Buffer.from('r'));
            const res = await fetch(s.base + '/api/blob', {
                method: 'POST', headers: auth(sealed.authKey), body: sealed.container
            });
            statuses.push(res.status);
        }
        assert.deepEqual(statuses.slice(0, 3), [201, 201, 201]);
        assert.deepEqual(statuses.slice(3), [429, 429]);
    } finally {
        await s.close();
    }
});

test('không phục vụ được file ngoài thư mục public (path traversal)', async () => {
    const s = await startServer();
    try {
        const res = await fetch(s.base + '/../src/server.js');
        assert.ok(res.status === 403 || res.status === 404, 'phải chặn, nhận ' + res.status);
    } finally {
        await s.close();
    }
});

test('trang chủ trả về HTML kèm CSP chặt', async () => {
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

test('PoC văn bản phục vụ được ở /poc-text/', async () => {
    const s = await startServer();
    try {
        for (const p of ['/poc-text', '/poc-text/', '/poc-text/app.js', '/poc-text/style.css']) {
            const res = await fetch(s.base + p);
            assert.equal(res.status, 200, 'phải phục vụ được ' + p);
        }
        const html = await (await fetch(s.base + '/poc-text/')).text();
        assert.match(html, /Gửi văn bản bằng một key/);

        // vẫn chặn thoát khỏi thư mục
        const bad = await fetch(s.base + '/poc-text/..%2f..%2fsrc%2fserver.js');
        assert.ok(bad.status === 403 || bad.status === 404, 'phải chặn traversal, nhận ' + bad.status);
    } finally {
        await s.close();
    }
});
