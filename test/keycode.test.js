/**
 * Test cho keycode (Crockford Base32 + checksum).
 * Chạy: node --test test/keycode.test.js
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const kc = require('../src/keycode.js');

const sample = () => {
    const b = new Uint8Array(32);
    for (let i = 0; i < 32; i++) b[i] = (i * 17 + 5) & 0xff;
    return b;
};

test('encoded key có đúng hình dạng người dùng thấy', () => {
    const text = kc.encode(sample());
    assert.match(text, /^ZKV1(-[0-9A-HJKMNP-TV-Z]{4}){14}$/);
    assert.equal(text.replace(/-/g, '').length, 4 + 56);
});

test('encode/decode roundtrip với 200 key ngẫu nhiên', () => {
    for (let i = 0; i < 200; i++) {
        const raw = new Uint8Array(32).map(() => Math.floor(Math.random() * 256));
        const text = kc.encode(raw);
        const back = kc.decode(text);
        assert.deepEqual(Array.from(back), Array.from(raw));
    }
});

test('chấp nhận key dán vào với đủ kiểu định dạng lộn xộn', () => {
    const raw = sample();
    const text = kc.encode(raw);
    const variants = [
        text.toLowerCase(),
        text.replace(/-/g, ''),
        text.replace(/-/g, ' '),
        '  ' + text + '  ',
        text.replace(/^ZKV1-/, ''),
        text.replace(/-/g, '_')
    ];
    for (const v of variants) {
        assert.deepEqual(Array.from(kc.decode(v)), Array.from(raw), 'phải đọc được: ' + v);
    }
});

test('tự sửa nhầm lẫn O/0 và I,L/1', () => {
    const raw = sample();
    const text = kc.encode(raw);
    // Cố tình gõ sai kiểu người đọc từ giấy
    const confusable = text.replace(/0/g, 'O').replace(/1/g, 'l');
    assert.deepEqual(Array.from(kc.decode(confusable)), Array.from(raw));
});

test('phát hiện key gõ sai 1 ký tự', () => {
    const text = kc.encode(sample());
    const idx = 10;
    const wrong = text[idx] === 'A' ? 'B' : 'A';
    const broken = text.slice(0, idx) + wrong + text.slice(idx + 1);
    assert.throws(() => kc.decode(broken), (err) => err.code === 'BAD_KEY_FORMAT' && /checksum/.test(err.message));
});

test('phát hiện key thiếu/thiếu ký tự', () => {
    const text = kc.encode(sample());
    assert.throws(() => kc.decode(text.slice(0, 40)), /phải có 56 ký tự/);
});

test('từ chối ký tự nằm ngoài bảng chữ cái Crockford', () => {
    const text = kc.encode(sample());
    // U không có trong bảng chữ cái Crockford
    const broken = text.slice(0, 5) + 'U' + text.slice(6);
    assert.throws(() => kc.decode(broken), (err) => err.code === 'BAD_KEY_FORMAT');
});

test('key rỗng báo lỗi rõ ràng', () => {
    assert.throws(() => kc.decode(''), /Chưa nhập key/);
    assert.throws(() => kc.decode(null), /Chưa nhập key/);
});

test('isValid không ném lỗi', () => {
    assert.equal(kc.isValid(kc.encode(sample())), true);
    assert.equal(kc.isValid('ZKV1-0000'), false);
    assert.equal(kc.isValid(''), false);
});

test('encode từ chối key sai kích thước', () => {
    assert.throws(() => kc.encode(new Uint8Array(16)), /32 byte/);
});
