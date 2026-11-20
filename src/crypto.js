/*!
 * crypto.js — lõi mã hoá của ZK-Vault.
 *
 * Toàn bộ việc mã hoá diễn ra trên máy người dùng. Server chỉ nhận bản mã.
 *
 * ── TỪ MỘT KEY DUY NHẤT SINH RA BA GIÁ TRỊ ──────────────────────────────
 *
 *   K (32 byte, người dùng giữ — chính là "key" ZKV1-…)
 *    │
 *    ├─ HKDF-SHA256(K, "zkv1/enc")  → encKey  32B  → AES-256-GCM, KHÔNG rời máy
 *    ├─ HKDF-SHA256(K, "zkv1/auth") → authKey 32B  → gửi server trong header
 *    └─ SHA-256("zkv1/id" ‖ authKey)[0..15] → id   → server dùng để tra cứu
 *
 * Server nhận `id` và `authKey`, KHÔNG BAO GIỜ nhận `encKey` hay `K`.
 * Vì `id` là ảnh một chiều của authKey nên biết id cũng không tải được bản mã.
 *
 * ── GÓI TIN (version 1) ────────────────────────────────────────────────
 *
 *   +---------+-----------+------------------+----------+
 *   | 0x01    | IV 12 B   | bản mã           | tag 16 B |
 *   +---------+-----------+------------------+----------+
 *   version   nonce       ciphertext          thẻ GCM
 *
 *   AAD = byte version  → không thể đổi phiên bản định dạng mà không hỏng thẻ.
 *
 * Với văn bản ngắn (≤ 200 từ ≈ 2 KB) chỉ cần một khối GCM là đủ; không cần
 * chia khối như khi mã hoá tệp lớn.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    } else {
        root.ZKCrypto = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const VERSION = 0x01;
    const VERSION_PAYLOAD = 0x02; // gói tin v2: hỗ trợ cả văn bản + tệp đính kèm (mã hoá cả tên/kiểu tệp)
    const KEY_BYTES = 32;   // AES-256
    const IV_BYTES = 12;    // 96 bit — kích thước nonce khuyến nghị cho GCM
    const TAG_BYTES = 16;   // thẻ xác thực 128 bit
    const HEADER_BYTES = 1 + IV_BYTES;
    const MIN_CONTAINER_BYTES = HEADER_BYTES + TAG_BYTES;

    const HKDF_INFO_ENC = 'zkv1/enc';
    const HKDF_INFO_AUTH = 'zkv1/auth';
    const ID_DOMAIN = 'zkv1/id';

    class VaultError extends Error {
        constructor(message, code) {
            super(message);
            this.name = 'VaultError';
            this.code = code || 'VAULT_ERROR';
        }
    }

    /* ------------------------------------------------------------------ */
    /* Tiện ích                                                            */
    /* ------------------------------------------------------------------ */

    function subtle() {
        const c = typeof globalThis !== 'undefined' ? globalThis.crypto : undefined;
        if (!c || !c.subtle) {
            throw new VaultError(
                'Trình duyệt không cấp Web Crypto API. Cần chạy trên https:// hoặc http://localhost.',
                'NO_WEBCRYPTO'
            );
        }
        return c;
    }

    function toBytes(value, label) {
        if (value instanceof Uint8Array) return value;
        if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(value)) {
            return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        }
        if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) return new Uint8Array(value);
        throw new TypeError((label || 'Giá trị') + ' phải là Uint8Array/ArrayBuffer.');
    }

    function concatBytes(parts) {
        let total = 0;
        for (const p of parts) total += p.length;
        const out = new Uint8Array(total);
        let off = 0;
        for (const p of parts) {
            out.set(p, off);
            off += p.length;
        }
        return out;
    }

    const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const LOOKUP = new Map(Array.from(ALPHABET, (ch, i) => [ch, i]));

    /** Uint8Array -> Base64URL (không có '='). */
    function bytesToBase64Url(bytes) {
        const src = toBytes(bytes, 'dữ liệu');
        let out = '';
        let i = 0;

        for (; i + 3 <= src.length; i += 3) {
            const b0 = src[i], b1 = src[i + 1], b2 = src[i + 2];
            out += ALPHABET[b0 >> 2];
            out += ALPHABET[((b0 & 3) << 4) | (b1 >> 4)];
            out += ALPHABET[((b1 & 15) << 2) | (b2 >> 6)];
            out += ALPHABET[b2 & 63];
        }

        const remain = src.length - i;
        if (remain === 1) {
            const b0 = src[i];
            out += ALPHABET[b0 >> 2];
            out += ALPHABET[(b0 & 3) << 4];
        } else if (remain === 2) {
            const b0 = src[i], b1 = src[i + 1];
            out += ALPHABET[b0 >> 2];
            out += ALPHABET[((b0 & 3) << 4) | (b1 >> 4)];
            out += ALPHABET[(b1 & 15) << 2];
        }
        return out;
    }

    /** Base64URL -> Uint8Array, kiểm tra nghiêm ngặt (không padding, không bit thừa). */
    function base64UrlToBytes(text) {
        const s = String(text).trim();
        if (s.length % 4 === 1) throw new VaultError('Chuỗi Base64URL có độ dài không hợp lệ.', 'BAD_BASE64');

        const out = new Uint8Array(Math.floor((s.length * 3) / 4));
        let acc = 0;
        let bits = 0;
        let o = 0;

        for (let i = 0; i < s.length; i++) {
            const v = LOOKUP.get(s[i]);
            if (v === undefined) throw new VaultError('Ký tự Base64URL không hợp lệ: "' + s[i] + '".', 'BAD_BASE64');
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[o++] = (acc >> bits) & 0xff;
                acc &= (1 << bits) - 1;
            }
        }
        if (bits > 0 && acc !== 0) throw new VaultError('Base64URL không canonical.', 'BAD_BASE64');
        return out.slice(0, o);
    }

    function toHex(bytes) {
        let out = '';
        for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
        return out;
    }

    /** 32 byte ngẫu nhiên từ CSPRNG của hệ điều hành. */
    function randomKey() {
        return subtle().getRandomValues(new Uint8Array(KEY_BYTES));
    }

    /* ------------------------------------------------------------------ */
    /* Dẫn xuất khoá                                                       */
    /* ------------------------------------------------------------------ */

    /**
     * K -> { encKey, authKey, authKeyB64, id }
     *
     * @param {Uint8Array} rootKey 32 byte (chính là key người dùng giữ)
     * @returns {Promise<{encKey: CryptoKey, authKey: Uint8Array, authKeyB64: string, id: string}>}
     */
    async function deriveKeys(rootKey) {
        const c = subtle();
        const keyBytes = toBytes(rootKey, 'Key');

        if (keyBytes.length !== KEY_BYTES) {
            throw new VaultError('Key phải dài đúng ' + KEY_BYTES + ' byte, nhận ' + keyBytes.length + '.', 'BAD_KEY');
        }

        const hkdfKey = await c.subtle.importKey('raw', keyBytes, 'HKDF', false, ['deriveBits']);

        const derive = (info) => c.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new Uint8Array(0),
                info: new TextEncoder().encode(info)
            },
            hkdfKey,
            KEY_BYTES * 8
        );

        // Hai "nhánh" độc lập: lộ nhánh này không suy ra được nhánh kia
        const [encBits, authBits] = await Promise.all([
            derive(HKDF_INFO_ENC),
            derive(HKDF_INFO_AUTH)
        ]);

        const authKey = new Uint8Array(authBits);
        const encKey = await c.subtle.importKey(
            'raw',
            new Uint8Array(encBits),
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );

        // id = 16 byte đầu của SHA-256("zkv1/id" ‖ authKey)
        const digest = await c.subtle.digest(
            'SHA-256',
            concatBytes([new TextEncoder().encode(ID_DOMAIN), authKey])
        );
        const id = toHex(new Uint8Array(digest).slice(0, 16));

        return { encKey, authKey, authKeyB64: bytesToBase64Url(authKey), id };
    }

    /* ------------------------------------------------------------------ */
    /* Mã hoá / giải mã văn bản                                            */
    /* ------------------------------------------------------------------ */

    /**
     * @param {string} text văn bản cần mã hoá
     * @param {Uint8Array} rootKey 32 byte
     * @returns {Promise<{container: Uint8Array, authKeyB64: string, id: string}>}
     */
    async function encryptText(text, rootKey) {
        if (typeof text !== 'string') throw new TypeError('encryptText() cần một string.');

        const c = subtle();
        const derived = await deriveKeys(rootKey);

        const iv = c.getRandomValues(new Uint8Array(IV_BYTES));
        const plaintext = new TextEncoder().encode(text);

        // WebCrypto trả về [ciphertext ‖ tag] gộp chung
        const sealed = new Uint8Array(await c.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv,
                additionalData: Uint8Array.of(VERSION),
                tagLength: TAG_BYTES * 8
            },
            derived.encKey,
            plaintext
        ));

        const container = new Uint8Array(HEADER_BYTES + sealed.length);
        container[0] = VERSION;
        container.set(iv, 1);
        container.set(sealed, HEADER_BYTES);

        return { container, authKeyB64: derived.authKeyB64, id: derived.id };
    }

    /**
     * @param {Uint8Array} container gói tin tải về từ server
     * @param {Uint8Array} rootKey
     * @returns {Promise<string>} văn bản gốc
     */
    async function decryptText(container, rootKey) {
        const c = subtle();
        const raw = toBytes(container, 'Dữ liệu');

        if (raw.length < MIN_CONTAINER_BYTES) {
            throw new VaultError('Dữ liệu quá ngắn để là một gói tin ZK-Vault.', 'BAD_CONTAINER');
        }
        if (raw[0] !== VERSION) {
            throw new VaultError(
                'Phiên bản định dạng không hỗ trợ: 0x' + raw[0].toString(16).padStart(2, '0') + '.',
                'BAD_VERSION'
            );
        }

        const derived = await deriveKeys(rootKey);
        const iv = raw.slice(1, HEADER_BYTES);
        const sealed = raw.slice(HEADER_BYTES);

        let plaintext;
        try {
            plaintext = await c.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv,
                    additionalData: Uint8Array.of(VERSION),
                    tagLength: TAG_BYTES * 8
                },
                derived.encKey,
                sealed
            );
        } catch {
            // GCM không phân biệt được "sai khoá" và "bị sửa" — cả hai đều là lỗi xác thực
            throw new VaultError('Sai key hoặc dữ liệu đã bị thay đổi (thẻ xác thực không khớp).', 'AUTH_FAILED');
        }

        return new TextDecoder().decode(plaintext);
    }

    /* ------------------------------------------------------------------ */
    /* Mã hoá / giải mã gói tin đa phương tiện (Văn bản + File đính kèm)   */
    /* ------------------------------------------------------------------ */

    /**
     * Đóng gói cả văn bản và tệp đính kèm (cùng tên file, MIME type) vào một
     * khối plaintext duy nhất rồi mã hoá bằng AES-256-GCM (VERSION_PAYLOAD = 0x02).
     * Server và MinIO hoàn toàn không biết tên file hay định dạng file.
     *
     * Cấu trúc plaintext bên trong bản mã v2:
     *   [4 byte uint32 BE: độ dài JSON metadata]
     *   [JSON UTF-8: { text: string, file: { name, type, size } | null }]
     *   [Bytes nhị phân của file (nếu có)]
     *
     * @param {{ text?: string, file?: { name: string, type?: string, data: Uint8Array|ArrayBuffer } | null }} payload
     * @param {Uint8Array} rootKey 32 byte
     */
    async function encryptPayload(payload, rootKey) {
        if (!payload || typeof payload !== 'object') {
            throw new TypeError('encryptPayload() cần một object { text, file }.');
        }

        const text = typeof payload.text === 'string' ? payload.text : '';
        let fileBytes = new Uint8Array(0);
        let fileMeta = null;

        if (payload.file != null) {
            if (!payload.file.name || typeof payload.file.name !== 'string') {
                throw new TypeError('file.name phải là chuỗi tên tệp hợp lệ.');
            }
            fileBytes = toBytes(payload.file.data, 'Nội dung tệp');
            fileMeta = {
                name: payload.file.name,
                type: payload.file.type || 'application/octet-stream',
                size: fileBytes.length
            };
        }

        const c = subtle();
        const derived = await deriveKeys(rootKey);
        const iv = c.getRandomValues(new Uint8Array(IV_BYTES));

        const metaBytes = new TextEncoder().encode(JSON.stringify({ text, file: fileMeta }));
        const lenBuf = new Uint8Array(4);
        new DataView(lenBuf.buffer).setUint32(0, metaBytes.length, false);

        const plaintext = concatBytes([lenBuf, metaBytes, fileBytes]);

        const sealed = new Uint8Array(await c.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv,
                additionalData: Uint8Array.of(VERSION_PAYLOAD),
                tagLength: TAG_BYTES * 8
            },
            derived.encKey,
            plaintext
        ));

        const container = new Uint8Array(HEADER_BYTES + sealed.length);
        container[0] = VERSION_PAYLOAD;
        container.set(iv, 1);
        container.set(sealed, HEADER_BYTES);

        return { container, authKeyB64: derived.authKeyB64, id: derived.id };
    }

    /**
     * Giải mã gói tin v1 (chỉ văn bản) hoặc v2 (văn bản + file đính kèm).
     *
     * @param {Uint8Array} container
     * @param {Uint8Array} rootKey
     * @returns {Promise<{ text: string, file: { name: string, type: string, size: number, data: Uint8Array } | null }>}
     */
    async function decryptPayload(container, rootKey) {
        const raw = toBytes(container, 'Dữ liệu');
        if (raw.length < MIN_CONTAINER_BYTES) {
            throw new VaultError('Dữ liệu quá ngắn để là một gói tin ZK-Vault.', 'BAD_CONTAINER');
        }

        if (raw[0] === VERSION) {
            const text = await decryptText(raw, rootKey);
            return { text, file: null };
        }

        if (raw[0] !== VERSION_PAYLOAD) {
            throw new VaultError(
                'Phiên bản định dạng không hỗ trợ: 0x' + raw[0].toString(16).padStart(2, '0') + '.',
                'BAD_VERSION'
            );
        }

        const c = subtle();
        const derived = await deriveKeys(rootKey);
        const iv = raw.slice(1, HEADER_BYTES);
        const sealed = raw.slice(HEADER_BYTES);

        let decryptedBuf;
        try {
            decryptedBuf = await c.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv,
                    additionalData: Uint8Array.of(VERSION_PAYLOAD),
                    tagLength: TAG_BYTES * 8
                },
                derived.encKey,
                sealed
            );
        } catch {
            throw new VaultError('Sai key hoặc dữ liệu đã bị thay đổi (thẻ xác thực không khớp).', 'AUTH_FAILED');
        }

        const plain = new Uint8Array(decryptedBuf);
        if (plain.length < 4) {
            throw new VaultError('Cấu trúc dữ liệu giải mã không hợp lệ.', 'BAD_CONTAINER');
        }

        const metaLen = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint32(0, false);
        if (4 + metaLen > plain.length) {
            throw new VaultError('Header metadata của tệp bị hỏng.', 'BAD_CONTAINER');
        }

        let meta;
        try {
            meta = JSON.parse(new TextDecoder().decode(plain.slice(4, 4 + metaLen)));
        } catch {
            throw new VaultError('Metadata JSON sau giải mã không hợp lệ.', 'BAD_CONTAINER');
        }

        const fileBytes = plain.slice(4 + metaLen);
        const file = meta.file
            ? {
                name: String(meta.file.name || 'file.bin'),
                type: String(meta.file.type || 'application/octet-stream'),
                size: fileBytes.length,
                data: fileBytes
            }
            : null;

        return {
            text: typeof meta.text === 'string' ? meta.text : '',
            file
        };
    }

    return {
        VERSION,
        VERSION_PAYLOAD,
        KEY_BYTES,
        IV_BYTES,
        TAG_BYTES,
        MIN_CONTAINER_BYTES,
        VaultError,
        randomKey,
        deriveKeys,
        encryptText,
        decryptText,
        encryptPayload,
        decryptPayload,
        bytesToBase64Url,
        base64UrlToBytes
    };
});
