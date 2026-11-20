/**
 * Kiểm thử end-to-end bằng Chrome headless: thao tác thật như người dùng.
 *
 *   node test/e2e.cjs
 *
 * Cần Chrome hoặc Edge (đặt biến môi trường CHROME nếu cài ở chỗ khác).
 * Script tự bật một server tạm trên cổng ngẫu nhiên rồi mở trình duyệt.
 */
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { createServer } = require('../src/server.js');

const CHROME = process.env.CHROME || [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
].find((p) => fs.existsSync(p));

if (!CHROME) {
    console.log('Bỏ qua e2e: không tìm thấy Chrome/Edge. Đặt biến môi trường CHROME.');
    process.exit(0);
}

const DOCS = path.join(__dirname, '..', 'docs');
const PORT_DEBUG = 9336;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ----------------------------- CDP ----------------------------- */

class CDP {
    constructor(ws) {
        this.ws = ws;
        this.id = 0;
        this.pending = new Map();
        this.errors = [];

        ws.addEventListener('message', (ev) => {
            const m = JSON.parse(ev.data);
            if (m.id && this.pending.has(m.id)) {
                const { resolve, reject } = this.pending.get(m.id);
                this.pending.delete(m.id);
                m.error ? reject(new Error(JSON.stringify(m.error))) : resolve(m.result);
            } else if (m.method === 'Runtime.exceptionThrown') {
                this.errors.push(m.params.exceptionDetails.text);
            }
        });
    }

    send(method, params = {}) {
        const id = ++this.id;
        return new Promise((resolve, reject) => {
            this.pending.set(id, { resolve, reject });
            this.ws.send(JSON.stringify({ id, method, params }));
        });
    }

    async eval(expr) {
        const r = await this.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
        if (r.exceptionDetails) {
            throw new Error(r.exceptionDetails.text + ' ' + (r.exceptionDetails.exception?.description || ''));
        }
        return r.result.value;
    }

    async waitFor(expr, timeoutMs = 8000) {
        const end = Date.now() + timeoutMs;
        while (Date.now() < end) {
            if (await this.eval(expr)) return true;
            await sleep(80);
        }
        return false;
    }
}

async function openTab(url) {
    const res = await fetch('http://127.0.0.1:' + PORT_DEBUG + '/json/new?' + encodeURIComponent(url), { method: 'PUT' });
    const target = await res.json();

    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
        ws.addEventListener('open', resolve, { once: true });
        ws.addEventListener('error', reject, { once: true });
    });

    const cdp = new CDP(ws);
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1100, height: 820, deviceScaleFactor: 1, mobile: false });

    // Điều hướng tường minh: không dựa vào /json/new?url= (hành vi khác nhau giữa các bản Chrome)
    await cdp.send('Page.navigate', { url });
    await sleep(1000);

    return { cdp, ws };
}

async function shot(cdp, file) {
    const png = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
    fs.mkdirSync(DOCS, { recursive: true });
    fs.writeFileSync(file, Buffer.from(png.data, 'base64'));
}

/* ----------------------------- chạy ----------------------------- */

function createMemoryS3() {
    const objects = new Map();
    return {
        async putObject(key, data) { objects.set(key, Buffer.from(data)); return true; },
        async getObject(key) { return objects.has(key) ? Buffer.from(objects.get(key)) : null; },
        async deleteObject(key) { objects.delete(key); return true; }
    };
}

(async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkv-e2e-'));
    const vault = createServer({ dataDir, s3: createMemoryS3() });
    await new Promise((r) => vault.server.listen(0, '127.0.0.1', r));
    const origin = 'http://127.0.0.1:' + vault.server.address().port;

    const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkv-chrome-'));
    const chrome = spawn(CHROME, [
        '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
        '--hide-scrollbars', '--remote-debugging-port=' + PORT_DEBUG, '--user-data-dir=' + userDataDir, 'about:blank'
    ], { stdio: 'ignore' });

    let fails = 0;
    const check = (cond, label, extra = '') => {
        console.log((cond ? '  ok   ' : '  FAIL ') + label + (extra ? '  -> ' + extra : ''));
        if (!cond) fails++;
    };

    const tabs = [];

    try {
        for (let i = 0; i < 60; i++) {
            try { await fetch('http://127.0.0.1:' + PORT_DEBUG + '/json/version'); break; }
            catch { await sleep(250); }
        }

        /* -------- gửi -------- */
        const sendPage = await openTab(origin + '/');
        tabs.push(sendPage.ws);
        const cdp = sendPage.cdp;

        check(await cdp.eval('!!window.ZKCrypto && !!window.ZKKeycode'), 'trang nạp được thư viện mã hoá');
        check(await cdp.eval(`document.getElementById('send').disabled`), 'nút gửi bị khoá khi chưa nhập gì');
        check((await cdp.eval(`getComputedStyle(document.getElementById('keyIn')).textTransform`)) === 'none',
            'ô nhập key không bị CSS đổi hoa/thường');

        const tooLong = Array.from({ length: 201 }, (_, i) => 'tu' + i).join(' ');
        await cdp.eval(`(function(){const el=document.getElementById('plain');el.value=${JSON.stringify(tooLong)};el.dispatchEvent(new Event('input'));})()`);
        check(await cdp.eval(`document.getElementById('send').disabled`), 'vượt 200 từ thì không gửi được');
        check((await cdp.eval(`document.getElementById('counter').textContent`)) === '201/200 từ', 'bộ đếm báo 201/200 từ');

        const text = 'Mã dự phòng két sắt: 4821. Hạn đổi ngày 30/11. Ai đọc được nhớ huỷ sau khi dùng.';
        await cdp.eval(`(function(){const el=document.getElementById('plain');el.value=${JSON.stringify(text)};el.dispatchEvent(new Event('input'));})()`);
        check(!(await cdp.eval(`document.getElementById('send').disabled`)), 'nhập text hợp lệ thì bật nút gửi');

        await cdp.eval(`document.getElementById('send').click()`);
        check(await cdp.waitFor(`!document.getElementById('keyBox').hidden`), 'mã hoá và lưu xong, hiện key');

        const keyText = await cdp.eval(`document.getElementById('keyOut').textContent`);
        check(/^ZKV1-[A-Za-z0-9_-]{43}$/.test(keyText), 'key đúng định dạng', keyText.slice(0, 22) + '…');

        await shot(cdp, path.join(DOCS, 'screenshot-send.png'));

        /* -------- nhận -------- */
        const recvPage = await openTab(origin + '/');
        tabs.push(recvPage.ws);

        await recvPage.cdp.eval(`(function(){const el=document.getElementById('keyIn');el.value=${JSON.stringify(keyText)};el.dispatchEvent(new Event('input'));})()`);
        check(await recvPage.cdp.waitFor(`!document.getElementById('result').hidden`), 'dán key là tự động mở (không bấm nút)');
        check((await recvPage.cdp.eval(`document.getElementById('textOut').textContent`)) === text, 'trả về đúng văn bản gốc');

        await shot(recvPage.cdp, path.join(DOCS, 'screenshot-open.png'));

        /* -------- sửa văn bản theo key -------- */
        const updatedText = 'Mã dự phòng két sắt mới: 9900 (đã cập nhật).';
        await recvPage.cdp.eval(`document.getElementById('editBtn').click()`);
        check(await recvPage.cdp.eval(`!document.getElementById('editBox').hidden`), 'bấm Sửa hiện ô chỉnh sửa');
        await recvPage.cdp.eval(`(function(){const el=document.getElementById('editPlain');el.value=${JSON.stringify(updatedText)};el.dispatchEvent(new Event('input'));})()`);
        await recvPage.cdp.eval(`document.getElementById('saveEditBtn').click()`);
        check(await recvPage.cdp.waitFor(`document.getElementById('editBox').hidden && document.getElementById('textOut').textContent === ${JSON.stringify(updatedText)}`),
            'lưu chỉnh sửa thành công và cập nhật nội dung hiển thị');

        /* -------- xoá văn bản theo key -------- */
        await recvPage.cdp.eval(`document.getElementById('delBtn').click()`);
        check(await recvPage.cdp.waitFor(`document.getElementById('result').hidden`), 'xoá xong ẩn khung kết quả');
        check(/Đã xoá văn bản/i.test(await recvPage.cdp.eval(`document.getElementById('recvMsg').textContent`)), 'thông báo đã xoá văn bản');

        /* -------- key sai -------- */
        const broken = keyText.slice(0, 10) + (keyText[10] === 'A' ? 'B' : 'A') + keyText.slice(11);
        await recvPage.cdp.eval(`(function(){const el=document.getElementById('keyIn');el.value=${JSON.stringify(broken)};el.dispatchEvent(new Event('input'));})()`);
        await sleep(500);
        check(await recvPage.cdp.eval(`document.getElementById('result').hidden`), 'key gõ sai thì không hiện gì');
        check(/không tìm thấy|43 ký tự|không hợp lệ/i.test(await recvPage.cdp.eval(`document.getElementById('recvMsg').textContent`)), 'báo rõ là key không dùng được');

        /* -------- lỗi JS -------- */
        const errors = cdp.errors.concat(recvPage.cdp.errors);
        check(errors.length === 0, 'không có lỗi JS', errors[0] || '');

        console.log(fails ? '\n' + fails + ' kiểm tra THẤT BẠI' : '\nTất cả kiểm tra đều đạt');
        process.exitCode = fails ? 1 : 0;
    } catch (err) {
        console.error('LỖI:', err.message);
        process.exitCode = 1;
    } finally {
        for (const ws of tabs) { try { ws.close(); } catch { /* bỏ qua */ } }
        chrome.kill();
        await new Promise((r) => vault.server.close(r));
        fs.rmSync(dataDir, { recursive: true, force: true });
    }
})();
