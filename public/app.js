/*
 * app.js — phần giao diện. Toàn bộ khoá chỉ nằm trong biến của trang này:
 * không localStorage, không cookie, không gửi key lên server.
 *
 * Luồng gửi:
 *   text --(AES-GCM tại máy)--> bản mã --POST--> server
 *                                          └──> hiện key ZKV1-… cho người dùng
 *
 * Luồng nhận:
 *   key --(HKDF)--> authKey --GET--> bản mã --(AES-GCM tại máy)--> text
 */
(function () {
    'use strict';

    const MAX_WORDS = 200;

    const $ = (id) => document.getElementById(id);
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    /* ------------------------------------------------------------------ */
    /* Tiện ích                                                            */
    /* ------------------------------------------------------------------ */

    function countWords(text) {
        const t = text.trim();
        return t === '' ? 0 : t.split(/\s+/).length;
    }

    function setMsg(which, kind, html) {
        const el = $(which === 'send' ? 'sendMsg' : 'recvMsg');
        if (!kind) {
            el.hidden = true;
            el.innerHTML = '';
            return;
        }
        el.hidden = false;
        el.className = 'msg ' + kind;
        el.innerHTML = html;
    }

    const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

    /* ------------------------------------------------------------------ */
    /* Bộ đếm từ                                                           */
    /* ------------------------------------------------------------------ */

    function refreshCounter() {
        const words = countWords($('plain').value);
        const counter = $('counter');

        counter.textContent = words + '/' + MAX_WORDS + ' từ';
        counter.classList.toggle('over', words > MAX_WORDS);
        $('send').disabled = words === 0 || words > MAX_WORDS;
    }

    $('plain').addEventListener('input', refreshCounter);

    /* ------------------------------------------------------------------ */
    /* Gửi                                                                 */
    /* ------------------------------------------------------------------ */

    async function sendText() {
        const text = $('plain').value.trim();
        const words = countWords(text);

        if (!text) return setMsg('send', 'err', 'Hãy nhập văn bản trước.');
        if (words > MAX_WORDS) return setMsg('send', 'err', 'Vượt quá ' + MAX_WORDS + ' từ.');

        $('send').disabled = true;
        $('keyBox').hidden = true;
        setMsg('send', 'info', '<span class="spinner"></span>Đang mã hoá trên máy bạn…');

        try {
            const rootKey = ZKCrypto.randomKey();
            const sealed = await ZKCrypto.encryptText(text, rootKey);

            setMsg('send', 'info', '<span class="spinner"></span>Đang lưu ' +
                sealed.container.length + ' byte bản mã lên server…');

            const res = await fetch('/api/secret', {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + sealed.authKeyB64,
                    'Content-Type': 'application/octet-stream'
                },
                body: sealed.container
            });

            if (!res.ok) {
                const info = await res.json().catch(() => ({}));
                throw new Error(info.message || ('Lưu thất bại (HTTP ' + res.status + ').'));
            }

            const info = await res.json();

            $('keyOut').textContent = ZKKeycode.encode(rootKey);
            $('keyBox').hidden = false;
            setMsg('send', 'ok', 'Đã lưu ' + info.size + ' byte bản mã. Copy key và gửi cho người nhận — ' +
                'server không có key này nên không có cách nào khôi phục hộ.');
        } catch (err) {
            setMsg('send', 'err', esc(err.message));
        } finally {
            $('send').disabled = false;
        }
    }

    $('send').addEventListener('click', sendText);
    $('plain').addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') sendText();
    });

    /* ------------------------------------------------------------------ */
    /* Copy key                                                            */
    /* ------------------------------------------------------------------ */

    $('copyBtn').addEventListener('click', async () => {
        const key = $('keyOut').textContent;
        try {
            await navigator.clipboard.writeText(key);
        } catch {
            const ta = document.createElement('textarea');
            ta.value = key;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
        }
        $('copyBtn').textContent = 'Đã copy ✓';
        setTimeout(() => { $('copyBtn').textContent = 'Copy key'; }, 1600);
    });

    $('tryBtn').addEventListener('click', () => {
        $('keyIn').value = $('keyOut').textContent;
        $('keyIn').dispatchEvent(new Event('input'));
        $('keyIn').focus();
    });

    /* ------------------------------------------------------------------ */
    /* Nhận — tự động mở khi key hợp lệ                                    */
    /* ------------------------------------------------------------------ */

    let debounce = null;
    let busy = false;
    let lastKey = '';

    async function openText(rawKey) {
        if (busy) return;
        busy = true;

        $('result').hidden = true;
        setMsg('recv', 'info', '<span class="spinner"></span>Đang tìm văn bản trên server…');

        try {
            // Bước 1: key -> authKey (và id) bằng HKDF
            const rootKey = ZKKeycode.decode(rawKey);
            const derived = await ZKCrypto.deriveKeys(rootKey);

            // Bước 2: server tra cứu theo id suy ra từ authKey
            const res = await fetch('/api/secret', {
                headers: { 'Authorization': 'Bearer ' + derived.authKeyB64 }
            });

            if (!res.ok) {
                const info = await res.json().catch(() => ({}));
                throw new Error(info.message || 'Không tìm thấy văn bản với key này.');
            }

            const container = new Uint8Array(await res.arrayBuffer());

            // Bước 3: giải mã tại máy
            setMsg('recv', 'info', '<span class="spinner"></span>Đang giải mã trên máy bạn…');
            const text = await ZKCrypto.decryptText(container, rootKey);

            $('textOut').textContent = text;
            $('result').hidden = false;
            setMsg('recv', null);
        } catch (err) {
            $('result').hidden = true;
            setMsg('recv', 'err', esc(err.message));
        } finally {
            busy = false;
        }
    }

    $('keyIn').addEventListener('input', () => {
        clearTimeout(debounce);

        const value = $('keyIn').value;

        if (!ZKKeycode.isValid(value)) {
            $('result').hidden = true;
            lastKey = '';

            if (value.trim() === '') {
                setMsg('recv', null);
            } else {
                // Hiện đúng lý do: thiếu ký tự, sai bảng chữ cái, hay bit đệm khác 0
                try {
                    ZKKeycode.decode(value);
                } catch (err) {
                    setMsg('recv', 'err', esc(err.message));
                }
            }
            return;
        }

        if (value === lastKey) return;
        lastKey = value;

        // Chờ một nhịp cho người dùng dán xong rồi tự động mở
        debounce = setTimeout(() => openText(value), 250);
    });

    /* ------------------------------------------------------------------ */
    /* Khởi động                                                           */
    /* ------------------------------------------------------------------ */

    refreshCounter();

    if (!window.ZKCrypto || !window.ZKKeycode) {
        setMsg('send', 'err', 'Không tải được thư viện mã hoá. Hãy mở qua http://localhost.');
    }
})();
