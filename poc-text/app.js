/*
 * PoC: gửi văn bản bằng key.
 *
 *   soạn text ──► mã hoá tại trình duyệt ──► POST bản mã ──► hiện key
 *   dán key   ──► tìm blob theo id dẫn xuất ──► giải mã ──► hiện text
 *
 * Khoá không bao giờ rời khỏi trang này.
 */
(function () {
    'use strict';

    const MAX_WORDS = 200;
    const TTL_SECONDS = 7 * 24 * 3600;

    const $ = (id) => document.getElementById(id);
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    /* ---------------- tiện ích ---------------- */

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

    const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

    /* ---------------- bộ đếm từ ---------------- */

    function refreshCounter() {
        const words = countWords($('plain').value);
        const counter = $('counter');

        counter.textContent = words + '/' + MAX_WORDS + ' từ';
        counter.classList.toggle('over', words > MAX_WORDS);

        $('send').disabled = words === 0 || words > MAX_WORDS;
    }

    $('plain').addEventListener('input', refreshCounter);

    /* ---------------- gửi ---------------- */

    async function sendText() {
        const text = $('plain').value.trim();
        const words = countWords(text);

        if (!text) return setMsg('send', 'err', 'Hãy nhập văn bản trước.');
        if (words > MAX_WORDS) return setMsg('send', 'err', 'Vượt quá ' + MAX_WORDS + ' từ.');

        $('send').disabled = true;
        $('keyBox').hidden = true;
        setMsg('send', 'info', '<span class="spinner"></span>Đang mã hoá trên máy bạn...');

        try {
            const rootKey = ZKCrypto.randomKey();

            const sealed = await ZKCrypto.encryptFile({
                bytes: enc.encode(text),
                name: 'van-ban.txt',
                type: 'text/plain',
                rootKey
            });

            setMsg('send', 'info', '<span class="spinner"></span>Đang lưu ' +
                sealed.container.length + ' byte bản mã lên server...');

            const res = await fetch('/api/blob?ttl=' + TTL_SECONDS, {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + sealed.authKey,
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

    /* ---------------- copy ---------------- */

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

    /* ---------------- nhận (tự động khi key hợp lệ) ---------------- */

    let debounce = null;
    let busy = false;
    let lastKey = '';

    async function openText(rawKey) {
        if (busy) return;
        busy = true;

        $('result').hidden = true;
        setMsg('recv', 'info', '<span class="spinner"></span>Đang tìm văn bản trên server...');

        try {
            const rootKey = ZKKeycode.decode(rawKey);
            const derived = await ZKCrypto.deriveKeys(rootKey);

            const res = await fetch('/api/blob', {
                headers: { 'Authorization': 'Bearer ' + ZKCrypto.bytesToBase64Url(derived.authKey) }
            });

            if (!res.ok) {
                const info = await res.json().catch(() => ({}));
                throw new Error(info.message || 'Không tìm thấy văn bản với key này.');
            }

            const container = new Uint8Array(await res.arrayBuffer());

            setMsg('recv', 'info', '<span class="spinner"></span>Đang giải mã trên máy bạn...');

            const plain = await ZKCrypto.decryptFile({ container, rootKey });

            $('textOut').textContent = dec.decode(plain.bytes);
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
            const empty = value.trim() === '';
            setMsg('recv', empty ? null : 'err', empty ? null : 'Key chưa đúng định dạng ZKV1-…');
            $('result').hidden = true;
            lastKey = '';
            return;
        }

        if (value === lastKey) return;
        lastKey = value;

        // Chờ một nhịp cho người dùng dán xong, rồi tự động mở
        debounce = setTimeout(() => openText(value), 250);
    });

    /* ---------------- khởi động ---------------- */

    refreshCounter();

    if (!window.ZKCrypto || !window.ZKKeycode) {
        setMsg('send', 'err', 'Không tải được thư viện mã hoá. Hãy mở qua http://localhost.');
    }
})();
