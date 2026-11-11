/*!
 * ZK-Vault — lõi mã hoá v2: dẫn xuất khoá + mã hoá tệp theo từng khối.
 *
 * Khác với PoC tuần 1 (một khối GCM cho cả văn bản), bản này chia tệp thành
 * nhiều khối để mã hoá được tệp lớn mà không cần giải mã toàn bộ trong RAM,
 * đồng thời chống được cắt bớt tệp (truncation) và đảo thứ tự khối.
 *
 * ── TỪ MỘT KEY DUY NHẤT ────────────────────────────────────────────────
 *
 *   K (32 byte, người dùng giữ)
 *    ├─ HKDF-SHA256(K, "zkv1/enc")  -> encKey  32B : AES-256-GCM, KHÔNG rời máy
 *    ├─ HKDF-SHA256(K, "zkv1/auth") -> authKey 32B : gửi server làm Bearer
 *    └─ SHA-256("zkv1/id" ‖ authKey)[0..16] -> id  : server dùng để định vị blob
 *
 * Server chỉ thấy `id` và `authKey`; không có encKey nên không giải mã được,
 * và vì id là ảnh một chiều của authKey nên biết id cũng không tải được blob.
 *
 * ── ĐỊNH DẠNG V2 ──────────────────────────────────────────────────────
 *
 *   offset  size  nội dung
 *   0       4     magic "ZKV2"
 *   4       1     version = 2
 *   5       1     flags (dự phòng)
 *   6       4     chunkSize   (u32 BE)
 *   10      4     chunkCount  (u32 BE)
 *   14      8     noncePrefix
 *   22      2     metaLen     (u16 BE, đã gồm 16B tag)
 *   24      12    metaNonce
 *   36      metaLen  metadata đã mã hoá: {name, type, size}
 *   ..      *     [khối 0][khối 1]...[khối n-1], mỗi khối = bản mã ‖ 16B tag
 *
 *   AAD(meta)   = header ‖ "meta"
 *   AAD(khối i) = header ‖ "chk" ‖ u32BE(i)
 *   nonce(i)    = noncePrefix ‖ u32BE(i)
 *
 * Nhờ vậy: cắt bớt tệp -> số khối ít hơn chunkCount đã xác thực -> lỗi;
 * đảo khối -> AAD lệch -> lỗi; ghép khối từ tệp khác -> header lệch -> lỗi.
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

    const MAGIC = Uint8Array.of(0x5A, 0x4B, 0x56, 0x32); // "ZKV2"
    const VERSION = 2;
    const HEADER_LEN = 36;
    const KEY_BYTES = 32;
    const TAG_BYTES = 16;
    const NONCE_PREFIX_BYTES = 8;
    const META_NONCE_BYTES = 12;
    const DEFAULT_CHUNK_SIZE = 256 * 1024; // 256 KiB
    const MIN_CHUNK_SIZE = 1024;
    const MAX_CHUNK_SIZE = 4 * 1024 * 1024;
    const MAX_CHUNKS = 1 << 20;

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

    /* ---------------- tiện ích ---------------- */

    function subtle() {
        const c = typeof globalThis !== 'undefined' ? globalThis.crypto : undefined;
        if (!c || !c.subtle) {
            throw new VaultError('Không có Web Crypto API. Cần chạy trên https:// hoặc http://localhost.', 'NO_WEBCRYPTO');
        }
        return c;
    }

    const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const LOOKUP = new Map(Array.from(ALPHABET, (ch, i) => [ch, i]));

    function toBytes(value, label) {
        if (value instanceof Uint8Array) return value;
        if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(value)) {
            return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        }
        if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) return new Uint8Array(value);
        throw new TypeError((label || 'Giá trị') + ' phải là Uint8Array/ArrayBuffer.');
    }

    function coerceBytes(value, label) {
        if (typeof value === 'string') return base64UrlToBytes(value);
        return toBytes(value, label);
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

    function randomKey() {
        return subtle().getRandomValues(new Uint8Array(KEY_BYTES));
    }

    function u32be(n) {
        return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
    }

    function toHex(bytes) {
        let out = '';
        for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
        return out;
    }

    /* ---------------- dẫn xuất khoá ---------------- */

    /**
     * K -> { encKey (CryptoKey), authKey, id }
     * @param {Uint8Array|string} rootKey 32 byte (hoặc Base64URL)
     */
    async function deriveKeys(rootKey) {
        const c = subtle();
        const keyBytes = coerceBytes(rootKey, 'Key');

        if (keyBytes.length !== KEY_BYTES) {
            throw new VaultError('Key phải dài đúng ' + KEY_BYTES + ' byte, nhận ' + keyBytes.length + '.', 'BAD_KEY');
        }

        const hkdf = await c.subtle.importKey('raw', keyBytes, 'HKDF', false, ['deriveBits']);
        const derive = (info) => c.subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(info) },
            hkdf,
            KEY_BYTES * 8
        );

        const [encBits, authBits] = await Promise.all([derive(HKDF_INFO_ENC), derive(HKDF_INFO_AUTH)]);

        const encKeyBytes = new Uint8Array(encBits);
        const authKey = new Uint8Array(authBits);

        const encKey = await c.subtle.importKey('raw', encKeyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

        const idDigest = await c.subtle.digest(
            'SHA-256',
            concatBytes([new TextEncoder().encode(ID_DOMAIN), authKey])
        );
        const id = toHex(new Uint8Array(idDigest).slice(0, 16));

        return { encKey, encKeyBytes, authKey, id };
    }

    /* ---------------- header ---------------- */

    function buildHeader({ chunkSize, chunkCount, noncePrefix, metaLen, metaNonce }) {
        const header = new Uint8Array(HEADER_LEN);
        header.set(MAGIC, 0);
        header[4] = VERSION;
        header[5] = 0;
        const dv = new DataView(header.buffer);
        dv.setUint32(6, chunkSize, false);
        dv.setUint32(10, chunkCount, false);
        header.set(noncePrefix, 14);
        dv.setUint16(22, metaLen, false);
        header.set(metaNonce, 24);
        return header;
    }

    function readHeader(container) {
        if (container.length < HEADER_LEN) {
            throw new VaultError('Dữ liệu quá ngắn để là một tệp ZK-Vault.', 'BAD_CONTAINER');
        }
        for (let i = 0; i < 4; i++) {
            if (container[i] !== MAGIC[i]) {
                throw new VaultError('Không phải tệp ZK-Vault (sai magic).', 'BAD_CONTAINER');
            }
        }
        if (container[4] !== VERSION) {
            throw new VaultError('Phiên bản định dạng không hỗ trợ: ' + container[4] + '.', 'BAD_VERSION');
        }

        const dv = new DataView(container.buffer, container.byteOffset, container.byteLength);
        const chunkSize = dv.getUint32(6, false);
        const chunkCount = dv.getUint32(10, false);
        const noncePrefix = container.slice(14, 22);
        const metaLen = dv.getUint16(22, false);
        const metaNonce = container.slice(24, 36);

        if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) {
            throw new VaultError('Kích thước khối không hợp lệ: ' + chunkSize + '.', 'BAD_CONTAINER');
        }
        if (chunkCount > MAX_CHUNKS) {
            throw new VaultError('Số khối quá lớn: ' + chunkCount + '.', 'BAD_CONTAINER');
        }
        if (metaLen < TAG_BYTES + 1 || HEADER_LEN + metaLen > container.length) {
            throw new VaultError('Độ dài metadata không hợp lệ.', 'BAD_CONTAINER');
        }

        return { chunkSize, chunkCount, noncePrefix, metaLen, metaNonce };
    }

    /* ---------------- mã hoá ---------------- */

    /**
     * @param {object} opts
     * @param {Uint8Array} opts.bytes  nội dung tệp
     * @param {string} opts.name      tên tệp (sẽ được mã hoá, server không thấy)
     * @param {string} opts.type      MIME type (sẽ được mã hoá)
     * @param {Uint8Array} opts.rootKey 32 byte
     * @param {number} [opts.chunkSize]
     */
    async function encryptFile({ bytes, name, type, rootKey, chunkSize = DEFAULT_CHUNK_SIZE }) {
        const c = subtle();
        const data = toBytes(bytes, 'Nội dung tệp');
        const keys = await deriveKeys(rootKey);

        const chunkCount = Math.ceil(data.length / chunkSize);
        if (chunkCount > MAX_CHUNKS) {
            throw new VaultError('Tệp quá lớn để mã hoá (' + chunkCount + ' khối).', 'TOO_LARGE');
        }

        const noncePrefix = c.getRandomValues(new Uint8Array(NONCE_PREFIX_BYTES));
        const metaNonce = c.getRandomValues(new Uint8Array(META_NONCE_BYTES));

        const metaJson = new TextEncoder().encode(JSON.stringify({
            name: String(name || 'tep-khong-ten'),
            type: String(type || 'application/octet-stream'),
            size: data.length
        }));
        const metaLen = metaJson.length + TAG_BYTES;

        const header = buildHeader({ chunkSize, chunkCount, noncePrefix, metaLen, metaNonce });
        const headerAAD = header;

        const metaCt = new Uint8Array(await c.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: metaNonce,
                additionalData: concatBytes([headerAAD, new TextEncoder().encode('meta')]),
                tagLength: 128
            },
            keys.encKey,
            metaJson
        ));

        const total = HEADER_LEN + metaLen + data.length + chunkCount * TAG_BYTES;
        const out = new Uint8Array(total);
        out.set(header, 0);
        out.set(metaCt, HEADER_LEN);

        let inOff = 0;
        let outOff = HEADER_LEN + metaLen;

        for (let i = 0; i < chunkCount; i++) {
            const end = Math.min(inOff + chunkSize, data.length);
            const chunk = data.subarray(inOff, end);
            const nonce = concatBytes([noncePrefix, u32be(i)]);

            const ct = new Uint8Array(await c.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: nonce,
                    additionalData: concatBytes([headerAAD, new TextEncoder().encode('chk'), u32be(i)]),
                    tagLength: 128
                },
                keys.encKey,
                chunk
            ));

            out.set(ct, outOff);
            outOff += ct.length;
            inOff = end;
        }

        return {
            container: out,
            id: keys.id,
            authKey: bytesToBase64Url(keys.authKey),
            chunkCount,
            chunkSize: DEFAULT_CHUNK_SIZE
        };
    }

    /* ---------------- giải mã ---------------- */

    /**
     * @param {object} opts
     * @param {Uint8Array|string} opts.container  container hoặc Base64URL
     * @param {Uint8Array} opts.rootKey
     * @returns {Promise<{bytes:Uint8Array, name:string, type:string, size:number}>}
     */
    async function decryptFile({ container, rootKey }) {
        const c = subtle();
        const raw = coerceBytes(container, 'Dữ liệu');
        const headerInfo = readHeader(raw);
        const { chunkSize, chunkCount, noncePrefix, metaLen, metaNonce } = headerInfo;

        const keys = await deriveKeys(rootKey);
        const header = raw.slice(0, HEADER_LEN);

        // --- metadata ---
        const metaCt = raw.slice(HEADER_LEN, HEADER_LEN + metaLen);
        let metaJson;
        try {
            const plain = await c.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: metaNonce,
                    additionalData: concatBytes([header, new TextEncoder().encode('meta')]),
                    tagLength: 128
                },
                keys.encKey,
                metaCt
            );
            metaJson = JSON.parse(new TextDecoder().decode(plain));
        } catch (err) {
            throw new VaultError('Sai key hoặc dữ liệu đã bị sửa (metadata không xác thực được).', 'AUTH_FAILED');
        }

        if (!metaJson || typeof metaJson.size !== 'number' || metaJson.size < 0) {
            throw new VaultError('Metadata không hợp lệ.', 'BAD_META');
        }

        // --- các khối ---
        const chunkAreaStart = HEADER_LEN + metaLen;
        const chunkAreaLen = raw.length - chunkAreaStart;
        const out = new Uint8Array(metaJson.size);

        let off = 0;
        let cursor = chunkAreaStart;

        for (let i = 0; i < chunkCount; i++) {
            const isLast = i === chunkCount - 1;
            const ctLen = isLast
                ? chunkAreaLen - (chunkCount - 1) * (chunkSize + TAG_BYTES)
                : chunkSize + TAG_BYTES;

            if (ctLen <= TAG_BYTES || ctLen > chunkSize + TAG_BYTES || cursor + ctLen > raw.length) {
                throw new VaultError('Tệp bị cắt ngắn hoặc hỏng ở khối ' + i + '.', 'TRUNCATED');
            }

            const nonce = concatBytes([noncePrefix, u32be(i)]);
            let plain;
            try {
                plain = new Uint8Array(await c.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: nonce,
                        additionalData: concatBytes([header, new TextEncoder().encode('chk'), u32be(i)]),
                        tagLength: 128
                    },
                    keys.encKey,
                    raw.subarray(cursor, cursor + ctLen)
                ));
            } catch (err) {
                throw new VaultError('Sai key hoặc tệp đã bị sửa (khối ' + i + ' không xác thực được).', 'AUTH_FAILED');
            }

            if (off + plain.length > out.length) {
                throw new VaultError('Kích thước giải mã vượt quá khai báo trong metadata.', 'BAD_SIZE');
            }

            out.set(plain, off);
            off += plain.length;
            cursor += ctLen;
        }

        if (cursor !== raw.length) {
            throw new VaultError('Còn dữ liệu thừa sau khối cuối (tệp bị ghép thêm).', 'TRAILING_DATA');
        }
        if (off !== metaJson.size) {
            throw new VaultError('Kích thước thực tế không khớp metadata (tệp bị cắt ngắn).', 'BAD_SIZE');
        }

        return {
            bytes: out,
            name: typeof metaJson.name === 'string' ? metaJson.name : 'tep-khong-ten',
            type: typeof metaJson.type === 'string' ? metaJson.type : 'application/octet-stream',
            size: metaJson.size
        };
    }

    return {
        MAGIC,
        VERSION,
        HEADER_LEN,
        KEY_BYTES,
        TAG_BYTES,
        DEFAULT_CHUNK_SIZE,
        VaultError,
        deriveKeys,
        encryptFile,
        decryptFile,
        readHeader,
        randomKey,
        bytesToBase64Url,
        base64UrlToBytes,
        toHex
    };
});
