/*
 * app.js — phần giao diện. Toàn bộ khoá chỉ nằm trong biến của trang này:
 * không localStorage, không cookie, không gửi key lên server.
 *
 * Luồng gửi:
 *   text + file --(AES-GCM tại máy)--> bản mã --POST--> server (MinIO S3)
 *                                                 └──> hiện key ZKV1-… cho người dùng
 *
 * Luồng nhận / sửa / xoá:
 *   key --(HKDF)--> authKey --GET/PUT/DELETE--> bản mã --(AES-GCM tại máy)--> text + file
 */
(function () {
    'use strict';

    const MAX_WORDS = 200;
    const MAX_FILE_BYTES = 20 * 1024 * 1024; // 20 MB

    const $ = (id) => document.getElementById(id);

    /* ------------------------------------------------------------------ */
    /* Tiện ích                                                            */
    /* ------------------------------------------------------------------ */

    function countWords(text) {
        const t = text.trim();
        return t === '' ? 0 : t.split(/\s+/).length;
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' byte';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
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
    /* Chọn tệp & Bộ đếm từ (Cột Gửi)                                      */
    /* ------------------------------------------------------------------ */

    let selectedSendFile = null;

    function refreshCounter() {
        const words = countWords($('plain').value);
        const counter = $('counter');

        counter.textContent = words + '/' + MAX_WORDS + ' từ';
        counter.classList.toggle('over', words > MAX_WORDS);

        const hasValidContent = words > 0 || selectedSendFile != null;
        $('send').disabled = !hasValidContent || words > MAX_WORDS;
    }

    $('plain').addEventListener('input', refreshCounter);

    $('fileIn').addEventListener('change', () => {
        const f = $('fileIn').files && $('fileIn').files[0];
        if (!f) return;

        if (f.size > MAX_FILE_BYTES) {
            $('fileIn').value = '';
            selectedSendFile = null;
            $('fileMeta').hidden = true;
            $('clearFileBtn').hidden = true;
            setMsg('send', 'err', 'Tệp vượt quá giới hạn 20 MB (' + formatBytes(f.size) + ').');
            refreshCounter();
            return;
        }

        selectedSendFile = f;
        $('fileMeta').textContent = f.name + ' (' + formatBytes(f.size) + ')';
        $('fileMeta').hidden = false;
        $('clearFileBtn').hidden = false;
        setMsg('send', null);
        refreshCounter();
    });

    $('clearFileBtn').addEventListener('click', () => {
        $('fileIn').value = '';
        selectedSendFile = null;
        $('fileMeta').hidden = true;
        $('clearFileBtn').hidden = true;
        refreshCounter();
    });

    /* ------------------------------------------------------------------ */
    /* Gửi                                                                 */
    /* ------------------------------------------------------------------ */

    async function sendText() {
        const text = $('plain').value.trim();
        const words = countWords(text);

        if (!text && !selectedSendFile) {
            return setMsg('send', 'err', 'Hãy nhập văn bản hoặc chọn tệp đính kèm.');
        }
        if (words > MAX_WORDS) {
            return setMsg('send', 'err', 'Vượt quá ' + MAX_WORDS + ' từ.');
        }

        $('send').disabled = true;
        $('keyBox').hidden = true;
        setMsg('send', 'info', '<span class="spinner"></span>Đang mã hoá trên máy bạn…');

        try {
            const rootKey = ZKCrypto.randomKey();
            let sealed;

            if (selectedSendFile) {
                const fileBuf = new Uint8Array(await selectedSendFile.arrayBuffer());
                sealed = await ZKCrypto.encryptPayload(
                    {
                        text,
                        file: {
                            name: selectedSendFile.name,
                            type: selectedSendFile.type || 'application/octet-stream',
                            data: fileBuf
                        }
                    },
                    rootKey
                );
            } else {
                sealed = await ZKCrypto.encryptText(text, rootKey);
            }

            setMsg('send', 'info', '<span class="spinner"></span>Đang lưu ' +
                formatBytes(sealed.container.length) + ' bản mã lên server…');

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
            const storageLabel = info.storage === 'minio-s3' ? ' (MinIO S3)' : '';

            $('keyOut').textContent = ZKKeycode.encode(rootKey);
            $('keyBox').hidden = false;
            setMsg('send', 'ok', 'Đã lưu ' + info.size + ' byte bản mã' + storageLabel +
                '. Copy key và gửi cho người nhận — server không có key này nên không có cách nào khôi phục hộ.');
        } catch (err) {
            setMsg('send', 'err', esc(err.message));
        } finally {
            refreshCounter();
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
        lastKey = '';
        $('keyIn').value = $('keyOut').textContent;
        $('keyIn').dispatchEvent(new Event('input'));
        $('keyIn').focus();
    });

    /* ------------------------------------------------------------------ */
    /* Nhận — tự động mở khi key hợp lệ, tải file, sửa & xoá theo key      */
    /* ------------------------------------------------------------------ */

    let debounce = null;
    let busy = false;
    let lastKey = '';
    let activeRootKey = null;
    let activeAuthKeyB64 = '';
    let activeFile = null;       // { name, type, size, data: Uint8Array } | null
    let pendingEditFile = null;  // file đang giữ trong chế độ Sửa

    function renderDecryptedResult(text, file) {
        activeFile = file || null;

        if (text) {
            $('textOut').textContent = text;
            $('textOut').hidden = false;
            $('textLabel').hidden = false;
        } else if (file) {
            $('textOut').textContent = '';
            $('textOut').hidden = true;
            $('textLabel').hidden = true;
        } else {
            $('textOut').textContent = '';
            $('textOut').hidden = false;
            $('textLabel').hidden = false;
        }

        if (file) {
            $('fileNameOut').textContent = file.name;
            $('fileSizeOut').textContent = formatBytes(file.size) + (file.type ? ' · ' + file.type : '');
            $('fileResult').hidden = false;
        } else {
            $('fileResult').hidden = true;
        }
    }

    $('downloadFileBtn').addEventListener('click', () => {
        if (!activeFile) return;
        const blob = new Blob([activeFile.data], { type: activeFile.type || 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = activeFile.name || 'secret.bin';
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 3000);
    });

    function closeEditMode() {
        $('editBox').hidden = true;
        $('resultActions').hidden = false;
    }

    function refreshEditCounter() {
        const words = countWords($('editPlain').value);
        const counter = $('editCounter');

        counter.textContent = words + '/' + MAX_WORDS + ' từ';
        counter.classList.toggle('over', words > MAX_WORDS);

        const hasValidContent = words > 0 || pendingEditFile != null;
        $('saveEditBtn').disabled = !hasValidContent || words > MAX_WORDS;
    }

    $('editPlain').addEventListener('input', refreshEditCounter);

    function syncEditFileUI() {
        if (pendingEditFile) {
            $('editFileMeta').textContent = pendingEditFile.name + ' (' + formatBytes(pendingEditFile.size) + ')';
            $('editFileMeta').hidden = false;
            $('removeEditFileBtn').hidden = false;
        } else {
            $('editFileMeta').hidden = true;
            $('removeEditFileBtn').hidden = true;
        }
        refreshEditCounter();
    }

    $('editFileIn').addEventListener('change', async () => {
        const f = $('editFileIn').files && $('editFileIn').files[0];
        if (!f) return;

        if (f.size > MAX_FILE_BYTES) {
            $('editFileIn').value = '';
            setMsg('recv', 'err', 'Tệp vượt quá giới hạn 20 MB (' + formatBytes(f.size) + ').');
            return;
        }

        const buf = new Uint8Array(await f.arrayBuffer());
        pendingEditFile = {
            name: f.name,
            type: f.type || 'application/octet-stream',
            size: buf.length,
            data: buf
        };
        setMsg('recv', null);
        syncEditFileUI();
    });

    $('removeEditFileBtn').addEventListener('click', () => {
        $('editFileIn').value = '';
        pendingEditFile = null;
        syncEditFileUI();
    });

    async function openText(rawKey) {
        if (busy) return;
        busy = true;

        closeEditMode();
        $('result').hidden = true;
        activeRootKey = null;
        activeAuthKeyB64 = '';
        activeFile = null;
        setMsg('recv', 'info', '<span class="spinner"></span>Đang tìm văn bản / tệp trên server…');

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

            // Bước 3: giải mã tại máy (hỗ trợ cả gói v1 chỉ text và gói v2 có file đính kèm)
            setMsg('recv', 'info', '<span class="spinner"></span>Đang giải mã trên máy bạn…');
            const payload = await ZKCrypto.decryptPayload(container, rootKey);

            activeRootKey = rootKey;
            activeAuthKeyB64 = derived.authKeyB64;
            renderDecryptedResult(payload.text, payload.file);
            $('result').hidden = false;
            setMsg('recv', null);
        } catch (err) {
            $('result').hidden = true;
            setMsg('recv', 'err', esc(err.message));
        } finally {
            busy = false;
        }
    }

    $('editBtn').addEventListener('click', () => {
        if (!activeRootKey) return;
        $('editPlain').value = $('textOut').textContent;
        $('editFileIn').value = '';
        pendingEditFile = activeFile
            ? { name: activeFile.name, type: activeFile.type, size: activeFile.size, data: activeFile.data }
            : null;
        syncEditFileUI();
        $('resultActions').hidden = true;
        $('editBox').hidden = false;
        setMsg('recv', null);
        $('editPlain').focus();
    });

    $('cancelEditBtn').addEventListener('click', () => {
        closeEditMode();
        setMsg('recv', null);
    });

    async function saveEditedText() {
        if (busy || !activeRootKey) return;

        const text = $('editPlain').value.trim();
        const words = countWords(text);

        if (!text && !pendingEditFile) {
            return setMsg('recv', 'err', 'Hãy nhập văn bản hoặc đính kèm tệp.');
        }
        if (words > MAX_WORDS) {
            return setMsg('recv', 'err', 'Vượt quá ' + MAX_WORDS + ' từ.');
        }

        busy = true;
        $('saveEditBtn').disabled = true;
        $('cancelEditBtn').disabled = true;
        setMsg('recv', 'info', '<span class="spinner"></span>Đang mã hoá lại và cập nhật lên server…');

        try {
            // Mã hoá lại với cùng rootKey nhưng IV 12 byte ngẫu nhiên mới hoàn toàn
            const sealed = pendingEditFile
                ? await ZKCrypto.encryptPayload({ text, file: pendingEditFile }, activeRootKey)
                : await ZKCrypto.encryptText(text, activeRootKey);

            const res = await fetch('/api/secret', {
                method: 'PUT',
                headers: {
                    'Authorization': 'Bearer ' + sealed.authKeyB64,
                    'Content-Type': 'application/octet-stream'
                },
                body: sealed.container
            });

            if (!res.ok) {
                const info = await res.json().catch(() => ({}));
                throw new Error(info.message || ('Cập nhật thất bại (HTTP ' + res.status + ').'));
            }

            renderDecryptedResult(text, pendingEditFile);
            closeEditMode();
            setMsg('recv', 'ok', 'Đã cập nhật nội dung văn bản (key giữ nguyên).');
        } catch (err) {
            setMsg('recv', 'err', esc(err.message));
        } finally {
            busy = false;
            $('cancelEditBtn').disabled = false;
            refreshEditCounter();
        }
    }

    $('saveEditBtn').addEventListener('click', saveEditedText);
    $('editPlain').addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') saveEditedText();
    });

    $('delBtn').addEventListener('click', async () => {
        if (busy || !activeAuthKeyB64) return;

        busy = true;
        $('delBtn').disabled = true;
        $('editBtn').disabled = true;
        setMsg('recv', 'info', '<span class="spinner"></span>Đang xoá văn bản khỏi server…');

        try {
            const res = await fetch('/api/secret', {
                method: 'DELETE',
                headers: { 'Authorization': 'Bearer ' + activeAuthKeyB64 }
            });

            if (!res.ok) {
                const info = await res.json().catch(() => ({}));
                throw new Error(info.message || ('Xoá thất bại (HTTP ' + res.status + ').'));
            }

            closeEditMode();
            $('result').hidden = true;
            activeRootKey = null;
            activeAuthKeyB64 = '';
            activeFile = null;
            lastKey = '';
            setMsg('recv', 'ok', 'Đã xoá văn bản khỏi server. Key này không còn mở được nữa.');
        } catch (err) {
            setMsg('recv', 'err', esc(err.message));
        } finally {
            busy = false;
            $('delBtn').disabled = false;
            $('editBtn').disabled = false;
        }
    });

    $('keyIn').addEventListener('input', () => {
        clearTimeout(debounce);

        const value = $('keyIn').value;

        if (!ZKKeycode.isValid(value)) {
            closeEditMode();
            $('result').hidden = true;
            activeRootKey = null;
            activeAuthKeyB64 = '';
            activeFile = null;
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
