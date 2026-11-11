/**
 * Kiểm tra tĩnh trang demo: cú pháp JS + mọi id được $() tham chiếu đều tồn tại.
 * (Không thay thế được test trình duyệt thật, nhưng bắt được lỗi gõ sai id/cú pháp.)
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const dir = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(dir, 'index.html'), 'utf8');

let failed = 0;
const ok = (msg) => console.log('  ok   ' + msg);
const bad = (msg) => { failed++; console.log('  FAIL ' + msg); };

// 1) id có trong HTML
const ids = new Set();
for (const m of html.matchAll(/\bid="([^"]+)"/g)) {
    if (ids.has(m[1])) bad('id trùng lặp: ' + m[1]);
    ids.add(m[1]);
}
ok(ids.size + ' id trong HTML');

// 2) các script
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
if (scripts.length !== 1) bad('mong đợi đúng 1 script inline, thấy ' + scripts.length);
else ok('1 script inline');

for (const [i, code] of scripts.entries()) {
    try {
        new vm.Script(code, { filename: 'inline-' + i + '.js' });
        ok('script inline #' + i + ' hợp lệ về cú pháp');
    } catch (e) {
        bad('script inline #' + i + ': ' + e.message);
    }

    // 3) mọi $('id') phải tồn tại
    const refs = new Set();
    for (const m of code.matchAll(/\$\('([^']+)'\)/g)) refs.add(m[1]);
    const missing = [...refs].filter((id) => !ids.has(id));
    if (missing.length) bad('tham chiếu id không tồn tại: ' + missing.join(', '));
    else ok(refs.size + ' tham chiếu $() đều tồn tại');
}

// 4) script src trỏ tới file có thật
for (const m of html.matchAll(/<script[^>]*\bsrc="([^"]+)"/g)) {
    const p = path.join(dir, m[1]);
    if (fs.existsSync(p)) ok('script src "' + m[1] + '" tồn tại');
    else bad('script src "' + m[1] + '" KHÔNG tồn tại');
}

// 5) crypto.js phải nạp được và phơi đủ API mà trang dùng
const zk = require('../crypto.js');
const needed = ['encryptText', 'decryptPacked', 'bytesToHex', 'bytesToBase64Url', 'flipBit', 'randomKey'];
const absent = needed.filter((k) => typeof zk[k] !== 'function');
if (absent.length) bad('crypto.js thiếu API: ' + absent.join(', '));
else ok('crypto.js phơi đủ ' + needed.length + ' API mà trang dùng');

process.exit(failed ? 1 : 0);
