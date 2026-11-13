/**
 * Test cho keycode.js — mã hoá 32 byte thành chuỗi ZKV1-… (Base64URL).
 * Chạy: node --test test/keycode.test.js
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const kc = require('../src/keycode.js');

/** 32 byte cố định để test tái lập được. */
const sample = () => Uint8Array.from({ length: 32 }, (_, i) => (i * 17 + 5) & 0xff);

test('encode ra đúng hình dạng: ZKV1- + 43 ký tự Base64URL', () => {
    const text = kc.encode(sample());
    assert.match(text, /^ZKV1-[A-Za-z0-9_-]{43}$/);
    assert.equal(text.length, kc.PREFIX.length + 1 + kc.TOTAL_CHARS);
});

test('encode/decode roundtrip 200 key ngẫu nhiên', () => {
    for (let i = 0; i < 200; i++) {
        const raw = new Uint8Array(32).map(() => Math.floor(Math.random() * 256));
        assert.deepEqual(Array.from(kc.decode(kc.encode(raw))), Array.from(raw));
    }
});

test('đọc được key dán vào với khoảng trắng hoặc thiếu tiền tố', () => {
    const raw = sample();
    const text = kc.encode(raw);

    const variants = [
        text,
        text.replace(/^ZKV1-/, ''),                       // thiếu tiền tố
        '  ' + text + '  ',                               // thừa khoảng trắng hai đầu
        text.slice(0, 20) + ' ' + text.slice(20),         // khoảng trắng chen vào
        text.slice(0, 20) + '\n' + text.slice(20)         // xuống dòng khi copy
    ];
    for (const v of variants) {
        assert.deepEqual(Array.from(kc.decode(v)), Array.from(raw), 'phải đọc được: ' + JSON.stringify(v));
    }
});

test('tiền tố viết thường vẫn nhận', () => {
    const raw = sample();
    const text = kc.encode(raw).replace(/^ZKV1/, 'zkv1');
    assert.deepEqual(Array.from(kc.decode(text)), Array.from(raw));
});

test('phần dữ liệu phân biệt hoa thường (Base64URL là case-sensitive)', () => {
    const raw = sample();
    const text = kc.encode(raw);
    const payload = text.slice(5);

    const idx = payload.search(/[a-zA-Z]/);
    assert.ok(idx >= 0, 'payload phải có ít nhất một chữ cái');

    const flipped = payload[idx] === payload[idx].toUpperCase()
        ? payload[idx].toLowerCase()
        : payload[idx].toUpperCase();

    const broken = text.slice(0, 5 + idx) + flipped + text.slice(6 + idx);

    let outcome;
    try {
        outcome = Array.from(kc.decode(broken));
    } catch {
        outcome = null; // bị từ chối cũng là đúng
    }

    if (outcome) {
        assert.notDeepEqual(outcome, Array.from(raw), 'đổi hoa/thường phải cho ra key khác');
    }
});

test('phát hiện key thiếu ký tự', () => {
    assert.throws(() => kc.decode(kc.encode(sample()).slice(0, 30)), /phải có 43 ký tự/);
});

test('từ chối ký tự nằm ngoài bảng chữ cái Base64URL', () => {
    const text = kc.encode(sample());
    assert.throws(() => kc.decode(text.slice(0, 10) + '+' + text.slice(11)), /không hợp lệ/);
    assert.throws(() => kc.decode(text.slice(0, 10) + '=' + text.slice(11)), /không hợp lệ/);
});

test('key rỗng báo lỗi rõ ràng', () => {
    assert.throws(() => kc.decode(''), /Chưa nhập key/);
    assert.throws(() => kc.decode(null), /Chưa nhập key/);
    assert.throws(() => kc.decode('   '), /Chưa nhập key/);
});

test('isValid không ném lỗi ra ngoài', () => {
    assert.equal(kc.isValid(kc.encode(sample())), true);
    assert.equal(kc.isValid('ZKV1-0000'), false);
    assert.equal(kc.isValid(''), false);
});

test('encode từ chối key sai kích thước', () => {
    assert.throws(() => kc.encode(new Uint8Array(16)), /32 byte/);
});

test('key luôn dài đúng 48 ký tự dù dữ liệu khác nhau', () => {
    for (let i = 0; i < 50; i++) {
        const raw = new Uint8Array(32).map(() => Math.floor(Math.random() * 256));
        assert.equal(kc.encode(raw).length, 48);
    }
});
