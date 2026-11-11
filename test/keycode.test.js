/**
 * Test cho keycode.js — cách biến 32 byte thành chuỗi ZKV1-… và ngược lại.
 * Chạy: node --test test/keycode.test.js
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const kc = require('../src/keycode.js');

/** 32 byte cố định để test tái lập được. */
const sample = () => Uint8Array.from({ length: 32 }, (_, i) => (i * 17 + 5) & 0xff);

test('encode ra đúng hình dạng người dùng thấy', () => {
    const text = kc.encode(sample());
    assert.match(text, /^ZKV1(-[0-9A-HJKMNP-TV-Z]{4}){14}$/);
    assert.equal(text.replace(/-/g, '').length, 4 + 56);
});

test('encode/decode roundtrip 200 key ngẫu nhiên', () => {
    for (let i = 0; i < 200; i++) {
        const raw = new Uint8Array(32).map(() => Math.floor(Math.random() * 256));
        assert.deepEqual(Array.from(kc.decode(kc.encode(raw))), Array.from(raw));
    }
});

test('đọc được key dán vào với đủ kiểu định dạng lộn xộn', () => {
    const raw = sample();
    const text = kc.encode(raw);

    const variants = [
        text.toLowerCase(),
        text.replace(/-/g, ''),
        text.replace(/-/g, ' '),
        '   ' + text + '   ',
        text.replace(/^ZKV1-/, '')
    ];
    for (const v of variants) {
        assert.deepEqual(Array.from(kc.decode(v)), Array.from(raw), 'phải đọc được: ' + v);
    }
});

test('tự sửa nhầm lẫn khi đọc key từ giấy: O->0, I/L->1', () => {
    const raw = sample();
    const text = kc.encode(raw);
    const confusable = text.replace(/0/g, 'O').replace(/1/g, 'l');
    assert.deepEqual(Array.from(kc.decode(confusable)), Array.from(raw));
});

test('phát hiện key gõ sai 1 ký tự', () => {
    const text = kc.encode(sample());
    const broken = text.slice(0, 10) + (text[10] === 'A' ? 'B' : 'A') + text.slice(11);
    assert.throws(
        () => kc.decode(broken),
        (err) => err.code === 'BAD_KEY_FORMAT' && /checksum/.test(err.message)
    );
});

test('phát hiện key thiếu ký tự', () => {
    assert.throws(() => kc.decode(kc.encode(sample()).slice(0, 40)), /phải có 56 ký tự/);
});

test('từ chối ký tự ngoài bảng chữ cái Crockford', () => {
    const text = kc.encode(sample());
    // Chữ U không có trong bảng chữ cái (checksum sẽ lệch trước khi tới bước giải mã)
    const broken = text.slice(0, 5) + 'U' + text.slice(6);
    assert.throws(() => kc.decode(broken), (err) => err.code === 'BAD_KEY_FORMAT');
});

test('key rỗng báo lỗi rõ ràng', () => {
    assert.throws(() => kc.decode(''), /Chưa nhập key/);
    assert.throws(() => kc.decode(null), /Chưa nhập key/);
});

test('isValid không ném lỗi ra ngoài', () => {
    assert.equal(kc.isValid(kc.encode(sample())), true);
    assert.equal(kc.isValid('ZKV1-0000'), false);
    assert.equal(kc.isValid(''), false);
});

test('encode từ chối key sai kích thước', () => {
    assert.throws(() => kc.encode(new Uint8Array(16)), /32 byte/);
});
