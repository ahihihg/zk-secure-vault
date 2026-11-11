/*
 * ZK-Vault — luồng giao diện.
 *
 * Nguyên tắc: mọi thứ liên quan tới khoá chỉ tồn tại trong biến JS của trang này.
 * Không có localStorage, không có cookie, không gửi key lên server.
 */
(function () {
    'use strict';

    const $ = (id) => document.getElementById(id);

    const MAX_BYTES = 25 * 1024 * 1024;
    const state = {
        file: null,
        rootKey: null,
        keyText: '',
        opened: null,
        blobUrl: null
    };

    /* ---------------- tiện ích ---------------- */

    function fmtBytes(n) {
        if (n < 1024) return n + ' B';
        if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
        return (n / (1024 * 1024)).toFixed(2) + ' MB';
    }

    function extOf(name) {
        const m = /\.([a-z0-9]{1,5})$/i.exec(name || '');
        return m ? m[1].toUpperCase() : 'TỆP';
    }

    function setStatus(el, kind, html) {
        if (!kind) {
            el.hidden = true;
            el.innerHTML = '';
            return;
        }
        el.hidden = false;
        el.className = 'status ' + kind;
        el.innerHTML = html;
    }

    const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

    function revokeBlob() {
        if (state.blobUrl) {
            URL.revokeObjectURL(state.blobUrl);
            state.blobUrl = null;
        }
    }

    /* ---------------- tab ---------------- */

    function selectTab(which) {
        const isSend = which === 'send';
        $('tab-send').setAttribute('aria-selected', String(isSend));
        $('tab-open').setAttribute('aria-selected', String(!isSend));
        $('panel-send').hidden = !isSend;
        $('panel-open').hidden = isSend;
    }

    $('tab-send').addEventListener('click', () => selectTab('send'));
    $('tab-open').addEventListener('click', () => selectTab('open'));

    /* ---------------- chọn tệp ---------------- */

    function setFile(file) {
        state.file = file;
        $('keyBox').hidden = true;
        setStatus($('sendStatus'), null);

        if (!file) {
            $('fileChip').hidden = true;
            $('sendBtn').disabled = true;
            return;
        }

        if (file.size > MAX_BYTES) {
            setStatus($('sendStatus'), 'err',
                'Tệp ' + fmtBytes(file.size) + ' vượt quá giới hạn ' + fmtBytes(MAX_BYTES) + '.');
            $('fileChip').hidden = true;
            $('sendBtn').disabled = true;
            return;
        }

        $('fileChip').hidden = false;
        $('fileChip').innerHTML =
            '<div class="file-chip">' +
            '<div class="file-icon">' + esc(extOf(file.name)) + '</div>' +
            '<div><div class="name">' + esc(file.name) + '</div>' +
            '<div class="meta">' + fmtBytes(file.size) + ' · ' + esc(file.type || 'không rõ loại') + '</div></div>' +
            '</div>';
        $('sendBtn').disabled = false;
    }

    const dropZone = $('dropZone');
    const fileInput = $('fileInput');

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            fileInput.click();
        }
    });
    fileInput.addEventListener('change', () => {
        if (fileInput.files && fileInput.files[0]) setFile(fileInput.files[0]);
    });

    ['dragenter', 'dragover'].forEach((evt) => {
        dropZone.addEventListener(evt, (e) => {
            e.preventDefault();
            dropZone.classList.add('over');
        });
    });
    ['dragleave', 'drop'].forEach((evt) => {
        dropZone.addEventListener(evt, (e) => {
            e.preventDefault();
            dropZone.classList.remove('over');
        });
    });
    dropZone.addEventListener('drop', (e) => {
        const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
        if (f) setFile(f);
    });

    // chặn trình duyệt mở tệp khi thả ra ngoài vùng drop
    window.addEventListener('dragover', (e) => e.preventDefault());
    window.addEventListener('drop', (e) => e.preventDefault());

    /* ---------------- gõ văn bản ---------------- */

    $('textToggle').addEventListener('click', () => {
        const wrap = $('textWrap');
        wrap.hidden = !wrap.hidden;
        if (!wrap.hidden) {
            $('textInput').focus();
            if (!state.file) {
                $('fileChip').hidden = true;
                $('sendBtn').disabled = false;
            }
        }
    });

    /* ---------------- gửi tệp ---------------- */

    function currentPayload() {
        const textWrap = $('textWrap');
        const text = $('textInput').value;

        if (!textWrap.hidden && text.trim()) {
            return new File([text], 'ghi-chu.txt', { type: 'text/plain' });
        }
        return state.file;
    }

    async function send() {
        const payload = currentPayload();
        if (!payload) {
            setStatus($('sendStatus'), 'err', 'Hãy chọn một tệp hoặc gõ văn bản trước.');
            return;
        }

        const ttl = $('ttlSelect').value;
        const burn = $('burnCheck').checked;

        $('sendBtn').disabled = true;
        $('keyBox').hidden = true;
        setStatus($('sendStatus'), 'info', '<span class="spinner"></span>Đang mã hoá trên máy bạn...');

        try {
            const bytes = new Uint8Array(await payload.arrayBuffer());
            const rootKey = ZKCrypto.randomKey();

            const enc = await ZKCrypto.encryptFile({
                bytes,
                name: payload.name || 'tep',
                type: payload.type || 'application/octet-stream',
                rootKey
            });

            setStatus($('sendStatus'), 'info',
                '<span class="spinner"></span>Đang tải lên ' + fmtBytes(enc.container.length) + ' dữ liệu đã mã hoá...');

            const res = await fetch('/api/blob?ttl=' + encodeURIComponent(ttl) + '&burn=' + (burn ? '1' : '0'), {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + enc.authKey,
                    'Content-Type': 'application/octet-stream'
                },
                body: enc.container
            });

            const info = await res.json().catch(() => ({}));
            if (!res.ok) {
                throw new Error(info.message || ('Upload thất bại (HTTP ' + res.status + ').'));
            }

            state.rootKey = rootKey;
            state.keyText = ZKKeycode.encode(rootKey);

            $('keyValue').textContent = state.keyText;
            $('keyBox').hidden = false;
            $('keyBox').scrollIntoView({ behavior: 'smooth', block: 'center' });
            $('copyKeyBtn').textContent = 'Copy key';

            const expiry = new Date(info.expiresAt).toLocaleString('vi-VN');
            setStatus($('sendStatus'), 'ok',
                'Đã lưu ' + fmtBytes(info.size) + ' bản mã. ' +
                (burn ? 'Tệp chỉ tải được <b>1 lần</b> rồi tự huỷ. ' : '') +
                'Hết hạn lúc ' + esc(expiry) + '.');

            $('textInput').value = '';
        } catch (err) {
            setStatus($('sendStatus'), 'err', esc(err.message));
        } finally {
            $('sendBtn').disabled = false;
        }
    }

    $('sendBtn').addEventListener('click', send);

    /* ---------------- copy key ---------------- */

    async function copyKey() {
        try {
            await navigator.clipboard.writeText(state.keyText);
        } catch {
            const ta = document.createElement('textarea');
            ta.value = state.keyText;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
        }
        $('copyKeyBtn').textContent = 'Đã copy ✓';
        setTimeout(() => { $('copyKeyBtn').textContent = 'Copy key'; }, 1800);
    }

    $('copyKeyBtn').addEventListener('click', copyKey);

    $('openNowBtn').addEventListener('click', () => {
        selectTab('open');
        $('keyInput').value = state.keyText;
        $('keyInput').dispatchEvent(new Event('input'));
        $('keyInput').focus();
    });

    /* ---------------- mở key ---------------- */

    $('keyInput').addEventListener('input', () => {
        const value = $('keyInput').value;
        const valid = ZKKeycode.isValid(value);
        $('keyInput').classList.toggle('valid', valid);
        $('keyHint').textContent = value.trim() === ''
            ? ''
            : (valid ? 'Key hợp lệ ✓' : 'Chưa đúng định dạng key');
    });

    function renderPreview(bytes, type) {
        const box = $('resultPreview');
        box.hidden = true;
        box.innerHTML = '';

        if (type.startsWith('image/')) {
            const blob = new Blob([bytes], { type });
            state.blobUrl = URL.createObjectURL(blob);
            const img = document.createElement('img');
            img.src = state.blobUrl;
            img.alt = 'Xem trước ảnh đã giải mã';
            box.appendChild(img);
            box.hidden = false;
            return;
        }

        if (type.startsWith('text/')) {
            const text = new TextDecoder().decode(bytes.slice(0, 20000));
            const pre = document.createElement('pre');
            pre.textContent = bytes.length > 20000 ? text + '\n… (đã cắt bớt)' : text;
            box.appendChild(pre);
            box.hidden = false;
        }
    }

    async function openWithKey() {
        setStatus($('openStatus'), null);
        $('resultBox').hidden = true;
        revokeBlob();

        let rootKey;
        try {
            rootKey = ZKKeycode.decode($('keyInput').value);
        } catch (err) {
            setStatus($('openStatus'), 'err', esc(err.message));
            return;
        }

        $('openBtn').disabled = true;
        setStatus($('openStatus'), 'info', '<span class="spinner"></span>Đang tìm tệp trên server...');

        try {
            const { authKey } = await ZKCrypto.deriveKeys(rootKey);
            const res = await fetch('/api/blob', {
                headers: { 'Authorization': 'Bearer ' + ZKCrypto.bytesToBase64Url(authKey) }
            });

            if (!res.ok) {
                const info = await res.json().catch(() => ({}));
                throw new Error(info.message || ('Không mở được tệp (HTTP ' + res.status + ').'));
            }

            setStatus($('openStatus'), 'info', '<span class="spinner"></span>Đang giải mã trên máy bạn...');

            const container = new Uint8Array(await res.arrayBuffer());
            const plain = await ZKCrypto.decryptFile({ container, rootKey });

            state.opened = plain;
            state.rootKey = rootKey;

            $('resultIcon').textContent = extOf(plain.name);
            $('resultName').textContent = plain.name;
            $('resultMeta').textContent = fmtBytes(plain.size) + ' · ' + plain.type;

            renderPreview(plain.bytes, plain.type);

            const remaining = res.headers.get('X-ZKV-Remaining');
            const expiredAt = Number(res.headers.get('X-ZKV-Expires') || 0);
            const bits = [];
            if (remaining === '0') bits.push('Tệp này đã được xoá khỏi server sau lần tải vừa rồi.');
            else if (expiredAt) bits.push('Server sẽ xoá tệp lúc ' + new Date(expiredAt).toLocaleString('vi-VN') + '.');

            setStatus($('openStatus'), 'ok',
                'Đã mở khoá và kiểm tra toàn vẹn thành công.' + (bits.length ? ' ' + esc(bits.join(' ')) : ''));

            $('resultBox').hidden = false;
        } catch (err) {
            setStatus($('openStatus'), 'err', esc(err.message));
        } finally {
            $('openBtn').disabled = false;
        }
    }

    $('openBtn').addEventListener('click', openWithKey);
    $('keyInput').addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) openWithKey();
    });

    /* ---------------- tải về / xoá ---------------- */

    $('downloadBtn').addEventListener('click', () => {
        if (!state.opened) return;
        const blob = new Blob([state.opened.bytes], { type: state.opened.type || 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = state.opened.name || 'tep';
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 4000);
    });

    $('deleteBtn').addEventListener('click', async () => {
        if (!state.rootKey) return;
        if (!confirm('Xoá tệp khỏi server? Thao tác này không thể hoàn tác.')) return;

        try {
            const { authKey } = await ZKCrypto.deriveKeys(state.rootKey);
            const res = await fetch('/api/blob', {
                method: 'DELETE',
                headers: { 'Authorization': 'Bearer ' + ZKCrypto.bytesToBase64Url(authKey) }
            });
            if (!res.ok) throw new Error('Server không xoá được (HTTP ' + res.status + ').');
            $('resultBox').hidden = true;
            revokeBlob();
            setStatus($('openStatus'), 'ok', 'Đã xoá tệp khỏi server.');
        } catch (err) {
            setStatus($('openStatus'), 'err', esc(err.message));
        }
    });

    /* ---------------- khởi động ---------------- */

    if (!window.ZKCrypto || !window.ZKKeycode) {
        setStatus($('sendStatus'), 'err',
            'Không tải được thư viện mã hoá. Hãy mở trang qua http://localhost thay vì file://.');
    }
})();
