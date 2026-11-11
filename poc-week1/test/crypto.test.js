/**
 * Test cho PoC tuần 1 — chứng minh thuật toán mã hoá văn bản hoạt động đúng.
 *
 * Chạy:  node --test poc-week1/test/
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const zk = require('../crypto.js');

const key32 = () => zk.randomKey();

test('roundtrip: văn bản ASCII', async () => {
    const original = 'Hello, ZK-Vault!';
    const sealed = await zk.encryptText(original);
    const opened = await zk.decryptPacked(sealed.packed, sealed.keyBytes);
    assert.equal(opened.plaintext, original);
});

test('roundtrip: tiếng Việt có dấu và emoji (UTF-8 nhiều byte)', async () => {
    const original = 'Xin chào! Đây là bí mật 🔐 của tôi — 日本語 — Ω';
    const sealed = await zk.encryptText(original);
    const opened = await zk.decryptPacked(sealed.packed, sealed.keyBytes);
    assert.equal(opened.plaintext, original);
    // UTF-8 phải dài hơn số ký tự vì ký tự nhiều byte
    assert.ok(sealed.plaintextBytes.length > original.length);
});

test('roundtrip: chuỗi rỗng vẫn có thẻ xác thực hợp lệ', async () => {
    const sealed = await zk.encryptText('');
    assert.equal(sealed.packed.length, zk.MIN_PACKED_BYTES);
    const opened = await zk.decryptPacked(sealed.packed, sealed.keyBase64Url);
    assert.equal(opened.plaintext, '');
});

test('cấu trúc gói tin đúng định dạng [1B version][12B IV][bản mã][16B tag]', async () => {
    const sealed = await zk.encryptText('kiểm tra cấu trúc');
    assert.equal(sealed.packed.length, 1 + 12 + sealed.plaintextBytes.length + 16);
    assert.equal(sealed.packed[0], zk.VERSION);
    assert.deepEqual(Array.from(sealed.packed.slice(1, 13)), Array.from(sealed.iv));
    assert.deepEqual(Array.from(sealed.tag), Array.from(sealed.packed.slice(-16)));

    const parsed = zk.parsePacked(sealed.packed);
    assert.equal(parsed.version, 1);
    assert.equal(parsed.iv.length, 12);
    assert.equal(parsed.tag.length, 16);
});

test('mỗi lần mã hoá cho ra IV và bản mã khác nhau (tính ngẫu nhiên)', async () => {
    const text = 'cùng một văn bản';
    const a = await zk.encryptText(text);
    const b = await zk.encryptText(text);

    assert.notDeepEqual(Array.from(a.iv), Array.from(b.iv));
    assert.notEqual(a.packedBase64Url, b.packedBase64Url);
});

test('sai khoá -> ném lỗi xác thực, không trả về rác', async () => {
    const sealed = await zk.encryptText('dữ liệu mật');
    await assert.rejects(
        () => zk.decryptPacked(sealed.packed, zk.randomKey()),
        (err) => err.code === 'AUTH_FAILED'
    );
});

test('sửa 1 bit trong bản mã -> phát hiện được', async () => {
    const sealed = await zk.encryptText('dữ liệu toàn vẹn');
    const tampered = zk.flipBit(sealed.packed, 20); // nằm trong phần bản mã
    await assert.rejects(
        () => zk.decryptPacked(tampered, sealed.keyBytes),
        (err) => err.code === 'AUTH_FAILED'
    );
});

test('sửa 1 bit trong thẻ tag -> phát hiện được', async () => {
    const sealed = await zk.encryptText('dữ liệu toàn vẹn');
    const tampered = zk.flipBit(sealed.packed, -1); // byte cuối = tag
    await assert.rejects(
        () => zk.decryptPacked(tampered, sealed.keyBytes),
        (err) => err.code === 'AUTH_FAILED'
    );
});

test('sửa IV -> phát hiện được', async () => {
    const sealed = await zk.encryptText('dữ liệu toàn vẹn');
    const tampered = zk.flipBit(sealed.packed, 3); // trong vùng IV
    await assert.rejects(
        () => zk.decryptPacked(tampered, sealed.keyBytes),
        (err) => err.code === 'AUTH_FAILED'
    );
});

test('đổi byte version -> bị chặn (AAD ràng buộc phiên bản)', async () => {
    const sealed = await zk.encryptText('dữ liệu');
    const tampered = new Uint8Array(sealed.packed);
    tampered[0] = 0x02;

    // Chặn ngay ở bước kiểm tra cấu trúc
    assert.throws(() => zk.parsePacked(tampered), /Phiên bản định dạng không hỗ trợ/);
});

test('cắt bớt gói tin (truncation) -> bị chặn', async () => {
    const sealed = await zk.encryptText('dữ liệu dài hơn một chút');
    const truncated = sealed.packed.slice(0, sealed.packed.length - 1);

    await assert.rejects(
        () => zk.decryptPacked(truncated, sealed.keyBytes),
        (err) => err.code === 'AUTH_FAILED'
    );
});

test('gói tin quá ngắn -> báo lỗi cấu trúc rõ ràng', async () => {
    assert.throws(() => zk.parsePacked(new Uint8Array(5)), /quá ngắn/);
});

test('khoá sai độ dài -> báo lỗi rõ ràng', async () => {
    const sealed = await zk.encryptText('abc');
    await assert.rejects(() => zk.decryptPacked(sealed.packed, new Uint8Array(16)), /32 byte/);
});

test('văn bản lớn (1 MB) không bị giới hạn stack như bản PoC cũ', async () => {
    const original = 'A'.repeat(1024 * 1024);
    const sealed = await zk.encryptText(original);

    // Base64URL của ~1MB phải encode được (bản cũ chết ở ~121 KB)
    assert.ok(sealed.packedBase64Url.length > 1024 * 1024);

    const opened = await zk.decryptPacked(sealed.packedBase64Url, sealed.keyBase64Url);
    assert.equal(opened.plaintext, original);
});

test('flipBit nhận cả Uint8Array lẫn chuỗi Base64URL', async () => {
    const sealed = await zk.encryptText('abc');
    const fromBytes = zk.flipBit(sealed.packed, -1);
    const fromString = zk.flipBit(sealed.packedBase64Url, -1);
    assert.deepEqual(Array.from(fromBytes), Array.from(fromString));
});

test('Base64URL: roundtrip đúng với mọi độ dài 0..64 byte', () => {
    for (let n = 0; n <= 64; n++) {
        const bytes = new Uint8Array(n);
        for (let i = 0; i < n; i++) bytes[i] = (i * 37 + 11) & 0xff;

        const encoded = zk.bytesToBase64Url(bytes);
        assert.equal(encoded.length, Math.ceil((n * 4) / 3));
        assert.ok(!/[+/=]/.test(encoded), 'không được chứa ký tự +/-/= : ' + encoded);
        assert.deepEqual(Array.from(zk.base64UrlToBytes(encoded)), Array.from(bytes));
    }
});

test('Base64URL: từ chối ký tự ngoài bảng chữ cái', () => {
    assert.throws(() => zk.base64UrlToBytes('abc$def'), /không hợp lệ/);
    assert.throws(() => zk.base64UrlToBytes('abcd='), /không hợp lệ/);
});

test('Base64URL: từ chối bit thừa khác 0 (chống link giả mạo)', () => {
    // "QQ" hợp lệ (giải ra 1 byte 0x41); "QR" có 2 bit thừa khác 0 -> phải bị từ chối
    assert.deepEqual(Array.from(zk.base64UrlToBytes('QQ')), [0x41]);
    assert.throws(() => zk.base64UrlToBytes('QR'), /canonical/);
});

test('Base64URL: từ chối độ dài không hợp lệ', () => {
    assert.throws(() => zk.base64UrlToBytes('A'), /Độ dài/);
});
