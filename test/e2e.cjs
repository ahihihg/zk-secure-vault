/**
 * E2E: chạy server thật + Chrome headless, thao tác như người dùng.
 *   - thả tệp vào ô drop -> bấm mã hoá -> nhận key
 *   - mở tab khác, dán key -> giải mã -> xem trước
 *   - gõ sai key -> báo lỗi checksum
 *   - chế độ tự huỷ: tải lần 2 phải thất bại
 *
 * Chạy: node test/e2e.cjs
 * Cần Chrome hoặc Edge (đặt biến môi trường CHROME nếu cài ở đường dẫn khác).
 */
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { createVaultServer } = require('../src/server.js');

const CHROME = process.env.CHROME || [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
].find((p) => fs.existsSync(p));

if (!CHROME) {
    console.log('Bỏ qua e2e: không tìm thấy Chrome/Edge. Đặt biến môi trường CHROME.');
    process.exit(0);
}

const DOCS = path.join(__dirname, '..', 'docs');
const PNG_1x1 = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
    'base64'
);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ------------------------- CDP ------------------------- */

class CDP {
    constructor(ws) {
        this.ws = ws;
        this.id = 0;
        this.pending = new Map();
        this.events = new Map();
        this.errors = [];
        ws.addEventListener('message', (ev) => {
            const msg = JSON.parse(ev.data);
            if (msg.id && this.pending.has(msg.id)) {
                const { resolve, reject } = this.pending.get(msg.id);
                this.pending.delete(msg.id);
                msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
            } else if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
                this.errors.push(msg.params.entry.text);
            } else if (msg.method === 'Network.responseReceived' && msg.params.response.status >= 400) {
                this.errors.push('HTTP ' + msg.params.response.status + ' ' + msg.params.response.url);
            } else if (msg.method === 'Runtime.exceptionThrown') {
                this.errors.push(msg.params.exceptionDetails.text + ' ' +
                    (msg.params.exceptionDetails.exception?.description || ''));
            } else if (msg.method && this.events.has(msg.method)) {
                for (const fn of this.events.get(msg.method)) fn(msg.params);
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
    once(method) {
        return new Promise((resolve) => {
            const fn = (p) => { this.events.delete(method); resolve(p); };
            if (!this.events.has(method)) this.events.set(method, []);
            this.events.get(method).push(fn);
        });
    }
    async eval(expr) {
        const r = await this.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
        if (r.exceptionDetails) {
            throw new Error('JS exception: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
        }
        return r.result.value;
    }
    async waitFor(expr, timeoutMs = 8000) {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            if (await this.eval(expr)) return true;
            await sleep(80);
        }
        return false;
    }
}

async function connect(wsUrl) {
    const ws = new WebSocket(wsUrl);
    await new Promise((resolve, reject) => {
        ws.addEventListener('open', resolve, { once: true });
        ws.addEventListener('error', reject, { once: true });
    });
    const cdp = new CDP(ws);
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Log.enable');
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1000, height: 1400, deviceScaleFactor: 1, mobile: false });
    return { cdp, ws };
}

async function openTab(url) {
    const res = await fetch('http://127.0.0.1:9334/json/new?' + encodeURIComponent(url), { method: 'PUT' });
    const target = await res.json();
    const { cdp, ws } = await connect(target.webSocketDebuggerUrl);
    await cdp.send('Network.enable');
    await sleep(700);
    return { cdp, ws };
}

async function capture(cdp, file) {
    const metrics = await cdp.send('Page.getLayoutMetrics');
    const h = Math.min(metrics.cssContentSize.height, 6000);
    const shot = await cdp.send('Page.captureScreenshot', {
        format: 'png', captureBeyondViewport: true,
        clip: { x: 0, y: 0, width: 1000, height: h, scale: 1 }
    });
    fs.writeFileSync(file, Buffer.from(shot.data, 'base64'));
}

/* ------------------------- main ------------------------- */

(async () => {
    fs.mkdirSync(DOCS, { recursive: true });
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkv-e2e-'));
    const vault = createVaultServer({ dataDir });
    await new Promise((r) => vault.server.listen(0, '127.0.0.1', r));
    const origin = 'http://127.0.0.1:' + vault.server.address().port;
    console.log('server ' + origin);

    const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkv-chrome-'));
    const chrome = spawn(CHROME, [
        '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
        '--hide-scrollbars', '--remote-debugging-port=9334', '--user-data-dir=' + userDataDir, 'about:blank'
    ], { stdio: 'ignore' });

    let failures = 0;
    const check = (cond, label, extra = '') => {
        console.log((cond ? '  ok   ' : '  FAIL ') + label + (extra ? '  -> ' + extra : ''));
        if (!cond) failures++;
    };

    const tabs = [];
    try {
        let version = null;
        for (let i = 0; i < 60 && !version; i++) {
            try { version = await (await fetch('http://127.0.0.1:9334/json/version')).json(); }
            catch { await sleep(250); }
        }
        if (!version) throw new Error('Chrome không mở được cổng debugging');
        console.log('chrome ' + version.Browser);

        const page = await openTab(origin + '/');
        tabs.push(page.ws);
        const { cdp } = page;

        check(await cdp.eval('!!window.ZKCrypto && !!window.ZKKeycode'), 'thư viện client đã nạp');
        check(await cdp.eval(`document.getElementById('sendBtn').disabled`), 'nút gửi bị khoá khi chưa chọn tệp');
        await cdp.send('Network.enable');

        /* ---------- kịch bản 1: gửi tệp văn bản ---------- */
        const textContent = 'Hợp đồng thuê nhà số 42 — giá 12 triệu/tháng 🔐';
        await cdp.eval(`
            (function(){
                const dt = new DataTransfer();
                dt.items.add(new File([${JSON.stringify(textContent)}], 'hop-dong.txt', { type: 'text/plain' }));
                document.getElementById('dropZone').dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true }));
            })()
        `);
        check(await cdp.eval(`!document.getElementById('sendBtn').disabled`), 'thả tệp xong thì nút gửi bật');
        check((await cdp.eval(`document.getElementById('fileChip').textContent`)).includes('hop-dong.txt'),
            'hiện đúng tên tệp đã chọn');

        await cdp.eval(`document.getElementById('sendBtn').click()`);
        check(await cdp.waitFor(`!document.getElementById('keyBox').hidden`), 'mã hoá + upload xong, hiện key');

        const keyText = await cdp.eval(`document.getElementById('keyValue').textContent`);
        check(/^ZKV1(-[0-9A-HJKMNP-TV-Z]{4}){14}$/.test(keyText), 'key đúng định dạng ZKV1-…', keyText.slice(0, 22) + '…');
        check(await cdp.eval(`document.getElementById('sendStatus').textContent.includes('Đã lưu')`), 'báo trạng thái đã lưu');

        await capture(cdp, path.join(DOCS, 'screenshot-app-send.png'));

        /* ---------- kịch bản 2: tab khác mở bằng key ---------- */
        const tab2 = await openTab(origin + '/');
        tabs.push(tab2.ws);
        await tab2.cdp.eval(`document.getElementById('tab-open').click()`);
        await tab2.cdp.eval(`(function(){ const el = document.getElementById('keyInput'); el.value = ${JSON.stringify(keyText)}; el.dispatchEvent(new Event('input')); })()`);
        check(await tab2.cdp.eval(`document.getElementById('keyInput').classList.contains('valid')`), 'ô key báo hợp lệ khi dán');

        await tab2.cdp.eval(`document.getElementById('openBtn').click()`);
        check(await tab2.cdp.waitFor(`!document.getElementById('resultBox').hidden`), 'mở khoá thành công ở tab mới');

        const name = await tab2.cdp.eval(`document.getElementById('resultName').textContent`);
        check(name === 'hop-dong.txt', 'lấy đúng tên tệp gốc', name);

        const preview = await tab2.cdp.eval(`document.getElementById('resultPreview').textContent`);
        check(preview.includes('Hợp đồng thuê nhà'), 'xem trước đúng nội dung đã giải mã');

        await capture(tab2.cdp, path.join(DOCS, 'screenshot-app-open.png'));

        /* ---------- kịch bản 3: gõ sai key ---------- */
        const brokenKey = keyText.slice(0, 10) + (keyText[10] === 'A' ? 'B' : 'A') + keyText.slice(11);
        await tab2.cdp.eval(`(function(){ const el = document.getElementById('keyInput'); el.value = ${JSON.stringify(brokenKey)}; el.dispatchEvent(new Event('input')); })()`);
        await tab2.cdp.eval(`document.getElementById('openBtn').click()`);
        await tab2.cdp.waitFor(`document.getElementById('openStatus').textContent.includes('checksum')`);
        const typoMsg = await tab2.cdp.eval(`document.getElementById('openStatus').textContent`);
        check(/checksum|sai/i.test(typoMsg), 'gõ sai 1 ký tự bị bắt ngay', typoMsg.slice(0, 60));

        /* ---------- kịch bản 4: ảnh + tự huỷ ---------- */
        const tab3 = await openTab(origin + '/');
        tabs.push(tab3.ws);
        await tab3.cdp.eval(`
            (function(){
                document.getElementById('burnCheck').checked = true;
                const dt = new DataTransfer();
                dt.items.add(new File([new Uint8Array(${JSON.stringify(Array.from(PNG_1x1))})], 'anh.png', { type: 'image/png' }));
                document.getElementById('dropZone').dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true }));
            })()
        `);
        await tab3.cdp.eval(`document.getElementById('sendBtn').click()`);
        check(await tab3.cdp.waitFor(`!document.getElementById('keyBox').hidden`), 'gửi ảnh ở chế độ tự huỷ');
        const pngKey = await tab3.cdp.eval(`document.getElementById('keyValue').textContent`);

        const tab4 = await openTab(origin + '/');
        tabs.push(tab4.ws);
        const openWith = async (key) => {
            await tab4.cdp.eval(`document.getElementById('tab-open').click()`);
            await tab4.cdp.eval(`(function(){ const el = document.getElementById('keyInput'); el.value = ${JSON.stringify(key)}; el.dispatchEvent(new Event('input')); })()`);
            await tab4.cdp.eval(`document.getElementById('openBtn').click()`);
            await sleep(1200);
        };

        await openWith(pngKey);
        check(await tab4.cdp.eval(`!!document.querySelector('#resultPreview img')`), 'ảnh được xem trước trực tiếp');
        check(await tab4.cdp.eval(`document.querySelector('#resultPreview img').naturalWidth === 1`), 'ảnh giải mã đúng kích thước gốc');

        const firstStatus = await tab4.cdp.eval(`document.getElementById('openStatus').textContent`);
        check(/xoá khỏi server/i.test(firstStatus), 'báo tệp đã tự huỷ sau lần tải đầu', firstStatus.slice(0, 70));

        await tab4.cdp.eval(`document.getElementById('openBtn').click()`);
        await sleep(1200);
        const secondStatus = await tab4.cdp.eval(`document.getElementById('openStatus').textContent`);
        check(/không tìm thấy|hết hạn|tải đủ số lần/i.test(secondStatus), 'lần tải thứ hai bị từ chối', secondStatus.slice(0, 70));

        /* ---------- không có lỗi console/CSP nào ngoài 404 có chủ đích ---------- */
        const allErrors = [].concat(cdp.errors, tab2.cdp.errors, tab3.cdp.errors, tab4.cdp.errors);
        const network404 = allErrors.filter((e) => e.startsWith('HTTP 404 '));
        const consoleErrors = allErrors.filter((e) => !e.startsWith('HTTP ') && !/status of 404/i.test(e));

        check(network404.every((e) => e.includes('/api/blob')),
            'mọi HTTP 404 đều là /api/blob (nhánh tệp đã tự huỷ)',
            network404.join(' | ') || 'không có 404 nào');
        check(consoleErrors.length === 0, 'không có lỗi JS/CSP nào', consoleErrors.slice(0, 3).join(' | '));

        console.log(failures ? '\n' + failures + ' kiểm tra THẤT BẠI' : '\nTất cả kiểm tra đều đạt');
        process.exitCode = failures ? 1 : 0;
    } catch (err) {
        console.error('LỖI:', err.message);
        process.exitCode = 1;
    } finally {
        for (const ws of tabs) { try { ws.close(); } catch { /* ignore */ } }
        chrome.kill();
        await new Promise((r) => vault.server.close(r));
        fs.rmSync(dataDir, { recursive: true, force: true });
        await sleep(300);
    }
})();
