/**
 * Test cho crypto.js — dẫn xuất khoá và mã hoá/giải mã văn bản.
 * Chạy: node --test test/crypto.test.js
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');

const zk = require('../src/crypto.js');

/** Server tính id đúng như thế này từ authKey nhận được. */
function serverId(authKeyB64) {
    const auth = Buffer.from(authKeyB64, 'base64url');
    return nodeCrypto.createHash('sha256')
        .update('zkv1/id')
        .update(auth)
        .digest()
        .subarray(0, 16)
        .toString('hex');
}

/* ---------------- dẫn xuất khoá ---------------- */

test('client và server tính ra cùng một id', async () => {
    for (let i = 0; i < 20; i++) {
        const d = await zk.deriveKeys(zk.randomKey());
        assert.equal(serverId(d.authKeyB64), d.id);
    }
});

test('dẫn xuất khoá là tất định', async () => {
    const rootKey = zk.randomKey();
    const a = await zk.deriveKeys(rootKey);
    const b = await zk.deriveKeys(rootKey);

    assert.equal(a.id, b.id);
    assert.equal(a.authKeyB64, b.authKeyB64);
    assert.deepEqual(Array.from(a.authKey), Array.from(b.authKey));
});

test('key khác nhau cho ra authKey và id khác nhau', async () => {
    const a = await zk.deriveKeys(zk.randomKey());
    const b = await zk.deriveKeys(zk.randomKey());

    assert.notEqual(a.authKeyB64, b.authKeyB64);
    assert.notEqual(a.id, b.id);
});

test('id chỉ dài 16 byte, không chứa đủ thông tin để dựng lại authKey', async () => {
    const d = await zk.deriveKeys(zk.randomKey());
    assert.equal(d.id.length, 32);        // 16 byte -> 32 ký tự hex
    assert.equal(d.authKey.length, 32);   // authKey 256 bit
});

test('key sai kích thước bị từ chối', async () => {
    await assert.rejects(() => zk.deriveKeys(new Uint8Array(16)), (e) => e.code === 'BAD_KEY');
});

/* ---------------- mã hoá / giải mã ---------------- */

test('roundtrip văn bản ngắn', async () => {
    const rootKey = zk.randomKey();
    const text = 'Mã két sắt: 4821. Hạn đổi: 30/11.';

    const { container } = await zk.encryptText(text, rootKey);
    assert.equal(await zk.decryptText(container, rootKey), text);
});

test('roundtrip tiếng Việt có dấu và emoji', async () => {
    const rootKey = zk.randomKey();
    const text = 'Xin chào! Đây là bí mật 🔐 — 日本語 — Ω';

    const { container } = await zk.encryptText(text, rootKey);
    assert.equal(await zk.decryptText(container, rootKey), text);
});

test('roundtrip văn bản ~2 KB (200 từ)', async () => {
    const rootKey = zk.randomKey();
    const text = Array.from({ length: 200 }, (_, i) => 'từ' + i).join(' ');

    const { container } = await zk.encryptText(text, rootKey);
    assert.equal(await zk.decryptText(container, rootKey), text);
});

test('văn bản xuống dòng và khoảng trắng được giữ nguyên', async () => {
    const rootKey = zk.randomKey();
    const text = 'dòng 1\n\ndòng 3   có   nhiều khoảng trắng\n';

    const { container } = await zk.encryptText(text, rootKey);
    assert.equal(await zk.decryptText(container, rootKey), text);
});

/* ---------------- cấu trúc gói tin ---------------- */

test('gói tin đúng định dạng [1B version][12B IV][bản mã][16B tag]', async () => {
    const rootKey = zk.randomKey();
    const text = 'kiểm tra cấu trúc';
    const { container } = await zk.encryptText(text, rootKey);

    const plainBytes = new TextEncoder().encode(text).length;
    assert.equal(container[0], zk.VERSION);
    assert.equal(container.length, 1 + 12 + plainBytes + 16);
});

test('mỗi lần mã hoá cho IV và bản mã khác nhau', async () => {
    const rootKey = zk.randomKey();
    const a = await zk.encryptText('cùng một văn bản', rootKey);
    const b = await zk.encryptText('cùng một văn bản', rootKey);

    assert.notDeepEqual(Array.from(a.container.slice(1, 13)), Array.from(b.container.slice(1, 13)));
    assert.notDeepEqual(Array.from(a.container), Array.from(b.container));
});

test('gói tin không chứa văn bản gốc', async () => {
    const { container } = await zk.encryptText('hop-dong-mat: 42 trieu', zk.randomKey());
    const asLatin = Buffer.from(container).toString('latin1');
    assert.equal(asLatin.includes('hop-dong'), false);
    assert.equal(asLatin.includes('42 trieu'), false);
});

/* ---------------- chống can thiệp ---------------- */

test('sai key -> lỗi xác thực', async () => {
    const { container } = await zk.encryptText('bí mật', zk.randomKey());
    await assert.rejects(
        () => zk.decryptText(container, zk.randomKey()),
        (e) => e.code === 'AUTH_FAILED'
    );
});

test('sửa 1 bit trong bản mã -> phát hiện', async () => {
    const rootKey = zk.randomKey();
    const { container } = await zk.encryptText('bí mật', rootKey);
    const tampered = new Uint8Array(container);
    tampered[15] ^= 0x01;

    await assert.rejects(() => zk.decryptText(tampered, rootKey), (e) => e.code === 'AUTH_FAILED');
});

test('sửa IV -> phát hiện', async () => {
    const rootKey = zk.randomKey();
    const { container } = await zk.encryptText('bí mật', rootKey);
    const tampered = new Uint8Array(container);
    tampered[3] ^= 0x01;

    await assert.rejects(() => zk.decryptText(tampered, rootKey), (e) => e.code === 'AUTH_FAILED');
});

test('sửa thẻ tag -> phát hiện', async () => {
    const rootKey = zk.randomKey();
    const { container } = await zk.encryptText('bí mật', rootKey);
    const tampered = new Uint8Array(container);
    tampered[tampered.length - 1] ^= 0x01;

    await assert.rejects(() => zk.decryptText(tampered, rootKey), (e) => e.code === 'AUTH_FAILED');
});

test('đổi byte version -> bị chặn', async () => {
    const rootKey = zk.randomKey();
    const { container } = await zk.encryptText('bí mật', rootKey);
    const tampered = new Uint8Array(container);
    tampered[0] = 0x09;

    await assert.rejects(() => zk.decryptText(tampered, rootKey), (e) => e.code === 'BAD_VERSION');
});

test('cắt bớt gói tin -> báo lỗi', async () => {
    const rootKey = zk.randomKey();
    const { container } = await zk.encryptText('một đoạn văn bản đủ dài để cắt bớt', rootKey);

    await assert.rejects(() => zk.decryptText(container.slice(0, container.length - 5), rootKey));
    await assert.rejects(() => zk.decryptText(container.slice(0, 10), rootKey), (e) => e.code === 'BAD_CONTAINER');
});

test('dữ liệu rác không phải gói tin -> báo lỗi rõ ràng', async () => {
    await assert.rejects(
        () => zk.decryptText(new Uint8Array(100), zk.randomKey()),
        (e) => e.code === 'BAD_VERSION'
    );
});

/* ---------------- Gói tin v2: Văn bản + File đính kèm ---------------- */

test('encryptPayload / decryptPayload roundtrip cho cả văn bản và tệp đính kèm', async () => {
    const rootKey = zk.randomKey();
    const fileData = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37, 0x0a, 0x99, 0xaa]);

    const sealed = await zk.encryptPayload(
        {
            text: 'Đính kèm hợp đồng PDF',
            file: { name: 'hop-dong-mat-2026.pdf', type: 'application/pdf', data: fileData }
        },
        rootKey
    );

    assert.equal(sealed.container[0], zk.VERSION_PAYLOAD);

    // Không rò rỉ tên file hay nội dung trong bản mã
    const rawStr = Buffer.from(sealed.container).toString('latin1');
    assert.equal(rawStr.includes('hop-dong-mat-2026.pdf'), false);
    assert.equal(rawStr.includes('application/pdf'), false);

    const out = await zk.decryptPayload(sealed.container, rootKey);
    assert.equal(out.text, 'Đính kèm hợp đồng PDF');
    assert.ok(out.file);
    assert.equal(out.file.name, 'hop-dong-mat-2026.pdf');
    assert.equal(out.file.type, 'application/pdf');
    assert.equal(out.file.size, fileData.length);
    assert.deepEqual(out.file.data, fileData);
});

test('decryptPayload đọc tương thích ngược gói tin v1 (chỉ văn bản)', async () => {
    const rootKey = zk.randomKey();
    const v1 = await zk.encryptText('văn bản kiểu v1', rootKey);

    const out = await zk.decryptPayload(v1.container, rootKey);
    assert.equal(out.text, 'văn bản kiểu v1');
    assert.equal(out.file, null);
});
