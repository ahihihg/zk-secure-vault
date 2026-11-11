/*!
 * ZK-Vault — PoC tuần 1: nguyên thuỷ mã hoá văn bản (AES-256-GCM).
 *
 * File này chạy được ở cả 2 môi trường:
 *   - Trình duyệt:  <script src="crypto.js"></script>  ->  window.ZKVault
 *   - Node.js:      require('./crypto.js')             ->  module.exports
 *
 * ĐỊNH DẠNG GÓI TIN (version 1):
 *
 *   +--------+------------+-------------------+--------------+
 *   | 0x01   |  IV (12B)  |   bản mã (nB)     |  tag (16B)   |
 *   +--------+------------+-------------------+--------------+
 *     version   nonce ngẫu nhiên              thẻ xác thực GCM
 *
 * Ghi chú thiết kế:
 *   - Byte version được đưa vào AAD nên kẻ tấn công không thể hạ cấp / đổi
 *     định dạng mà không làm hỏng thẻ xác thực.
 *   - IV 96-bit sinh ngẫu nhiên cho MỖI lần mã hoá. Tuyệt đối không tái sử
 *     dụng cặp (khoá, IV): với GCM, tái sử dụng IV sẽ làm lộ XOR của hai bản
 *     rõ và phá luôn khoá xác thực.
 *   - Base64URL được cài đặt thủ công (không dùng btoa/atob) để tránh giới
 *     hạn độ dài đối số của String.fromCharCode — bản PoC cũ chết ở ~121 KB.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    } else {
        root.ZKVault = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const VERSION = 0x01;
    const KEY_BYTES = 32;  // AES-256
    const IV_BYTES = 12;   // 96-bit, kích thước khuyến nghị cho GCM
    const TAG_BYTES = 16;  // thẻ xác thực 128-bit
    const HEADER_BYTES = 1 + IV_BYTES;
    const MIN_PACKED_BYTES = HEADER_BYTES + TAG_BYTES;

    const FORMAT_DESCRIPTION =
        '[0x01 version][12B IV][bản mã][16B tag] — Base64URL khi đóng gói vào URL';

    const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const LOOKUP = new Map(Array.from(ALPHABET, (ch, i) => [ch, i]));

    /* ------------------------------------------------------------------ */
    /* Truy cập Web Crypto (lazy, để require() không ném lỗi khi import)  */
    /* ------------------------------------------------------------------ */

    function webcrypto() {
        const c = typeof globalThis !== 'undefined' ? globalThis.crypto : undefined;
        if (!c || !c.subtle) {
            throw new Error(
                'Không tìm thấy Web Crypto API. Hãy mở trang qua http://localhost hoặc https:// (không dùng file://).'
            );
        }
        return c;
    }

    /* ------------------------------------------------------------------ */
    /* Base64URL — cài đặt thủ công, không phụ thuộc btoa/atob            */
    /* ------------------------------------------------------------------ */

    function bytesToBase64Url(bytes) {
        const src = toUint8Array(bytes, 'dữ liệu');
        let out = '';
        let i = 0;

        for (; i + 3 <= src.length; i += 3) {
            const b0 = src[i], b1 = src[i + 1], b2 = src[i + 2];
            out += ALPHABET[b0 >> 2];
            out += ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)];
            out += ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)];
            out += ALPHABET[b2 & 0x3f];
        }

        const remain = src.length - i;
        if (remain === 1) {
            const b0 = src[i];
            out += ALPHABET[b0 >> 2];
            out += ALPHABET[(b0 & 0x03) << 4];
        } else if (remain === 2) {
            const b0 = src[i], b1 = src[i + 1];
            out += ALPHABET[b0 >> 2];
            out += ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)];
            out += ALPHABET[(b1 & 0x0f) << 2];
        }

        return out;
    }

    /**
     * Giải mã Base64URL ở chế độ NGHIÊM NGẶT:
     *   - từ chối ký tự ngoài bảng chữ cái (kể cả '=' padding)
     *   - từ chối độ dài không hợp lệ (len % 4 === 1)
     *   - từ chối bit thừa khác 0  -> mỗi gói tin chỉ có MỘT biểu diễn duy nhất
     * Nhờ vậy không thể tạo ra hai chuỗi URL khác nhau cùng trỏ về một payload.
     */
    function base64UrlToBytes(text) {
        if (typeof text !== 'string') {
            throw new TypeError('Chuỗi Base64URL phải là string.');
        }
        if (text.length % 4 === 1) {
            throw new Error('Độ dài chuỗi Base64URL không hợp lệ (' + text.length + ' ký tự).');
        }

        const out = new Uint8Array(Math.floor((text.length * 3) / 4));
        let acc = 0;
        let bits = 0;
        let o = 0;

        for (let i = 0; i < text.length; i++) {
            const v = LOOKUP.get(text[i]);
            if (v === undefined) {
                throw new Error('Ký tự không hợp lệ trong Base64URL: "' + text[i] + '" tại vị trí ' + i + '.');
            }
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[o++] = (acc >> bits) & 0xff;
                acc &= (1 << bits) - 1;
            }
        }

        if (bits > 0 && acc !== 0) {
            throw new Error('Chuỗi Base64URL không canonical: bit thừa phải bằng 0.');
        }

        return out.slice(0, o);
    }

    /* ------------------------------------------------------------------ */
    /* Tiện ích                                                           */
    /* ------------------------------------------------------------------ */

    function toUint8Array(value, label) {
        if (value instanceof Uint8Array) return value;
        if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(value)) {
            return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        }
        if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
            return new Uint8Array(value);
        }
        throw new TypeError((label || 'Giá trị') + ' phải là Uint8Array/ArrayBuffer.');
    }

    /** Chấp nhận Uint8Array hoặc chuỗi Base64URL -> luôn trả về Uint8Array. */
    function coerceBytes(value, label) {
        if (typeof value === 'string') return base64UrlToBytes(value.trim());
        return toUint8Array(value, label);
    }

    function bytesToHex(bytes, options) {
        const src = toUint8Array(bytes, 'dữ liệu');
        const max = (options && Number.isFinite(options.max)) ? options.max : Infinity;
        const shown = src.subarray(0, max);
        let out = '';
        for (let i = 0; i < shown.length; i++) {
            if (i > 0) out += ' ';
            out += shown[i].toString(16).padStart(2, '0');
        }
        if (src.length > shown.length) out += ' … (+' + (src.length - shown.length) + ' byte)';
        return out;
    }

    function hexToBytes(hex) {
        const clean = String(hex).replace(/[^0-9a-fA-F]/g, '');
        if (clean.length % 2 !== 0) throw new Error('Chuỗi hex có độ dài lẻ.');
        const out = new Uint8Array(clean.length / 2);
        for (let i = 0; i < out.length; i++) {
            out[i] = parseInt(clean.substr(i * 2, 2), 16);
        }
        return out;
    }

    function concatBytes(parts) {
        const total = parts.reduce((n, p) => n + p.length, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const part of parts) {
            out.set(part, offset);
            offset += part.length;
        }
        return out;
    }

    /** Đảo 1 bit — dùng cho bài kiểm tra tính toàn vẹn. Nhận cả Uint8Array lẫn Base64URL. */
    function flipBit(bytes, index) {
        const copy = new Uint8Array(coerceBytes(bytes, 'dữ liệu'));
        const i = index < 0 ? copy.length + index : index;
        if (i < 0 || i >= copy.length) throw new RangeError('Vị trí đảo bit nằm ngoài dữ liệu.');
        copy[i] ^= 0x01;
        return copy;
    }

    function randomKey() {
        return webcrypto().getRandomValues(new Uint8Array(KEY_BYTES));
    }

    /* ------------------------------------------------------------------ */
    /* Mã hoá                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Mã hoá văn bản.
     * @param {string} text
     * @returns {Promise<object>} toàn bộ giá trị trung gian để hiển thị lên UI
     */
    async function encryptText(text) {
        if (typeof text !== 'string') {
            throw new TypeError('encryptText() nhận vào một string.');
        }

        const crypto = webcrypto();
        const plaintextBytes = new TextEncoder().encode(text);
        const keyBytes = crypto.getRandomValues(new Uint8Array(KEY_BYTES));
        const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

        // Khoá chỉ cần quyền 'encrypt' ở phía gửi và được đánh dấu non-extractable.
        const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);

        const sealed = new Uint8Array(
            await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv,
                    additionalData: Uint8Array.of(VERSION), // ràng buộc byte version vào thẻ
                    tagLength: TAG_BYTES * 8
                },
                key,
                plaintextBytes
            )
        );

        // WebCrypto trả về [bản mã || tag] gộp chung 16 byte cuối.
        const ciphertext = sealed.slice(0, sealed.length - TAG_BYTES);
        const tag = sealed.slice(sealed.length - TAG_BYTES);

        const packed = concatBytes([Uint8Array.of(VERSION), iv, sealed]);

        return {
            version: VERSION,
            plaintext: text,
            plaintextBytes,
            plaintextHex: bytesToHex(plaintextBytes),
            keyBytes,
            keyBase64Url: bytesToBase64Url(keyBytes),
            iv,
            ivHex: bytesToHex(iv),
            ciphertext,
            ciphertextHex: bytesToHex(ciphertext),
            tag,
            tagHex: bytesToHex(tag),
            sealed,
            packed,
            packedHex: bytesToHex(packed),
            packedBase64Url: bytesToBase64Url(packed)
        };
    }

    /* ------------------------------------------------------------------ */
    /* Giải mã                                                            */
    /* ------------------------------------------------------------------ */

    /** Tách gói tin thành các thành phần, có kiểm tra cấu trúc. */
    function parsePacked(input) {
        const packed = coerceBytes(input, 'Gói tin');

        if (packed.length < MIN_PACKED_BYTES) {
            throw new Error(
                'Gói tin quá ngắn: cần tối thiểu ' + MIN_PACKED_BYTES + ' byte, nhận ' + packed.length + '.'
            );
        }
        if (packed[0] !== VERSION) {
            throw new Error(
                'Phiên bản định dạng không hỗ trợ: 0x' + packed[0].toString(16).padStart(2, '0') +
                ' (chỉ hỗ trợ 0x' + VERSION.toString(16).padStart(2, '0') + ').'
            );
        }

        const iv = packed.slice(1, HEADER_BYTES);
        const sealed = packed.slice(HEADER_BYTES);
        const ciphertext = sealed.slice(0, sealed.length - TAG_BYTES);
        const tag = sealed.slice(sealed.length - TAG_BYTES);

        return { version: packed[0], iv, sealed, ciphertext, tag };
    }

    /**
     * Giải mã gói tin.
     * @param {Uint8Array|string} packed  gói tin (Base64URL hoặc bytes)
     * @param {Uint8Array|string} key     khoá 32 byte (Base64URL hoặc bytes)
     * @returns {Promise<{plaintext:string, bytes:Uint8Array, version:number}>}
     */
    async function decryptPacked(packed, key) {
        const crypto = webcrypto();
        const keyBytes = coerceBytes(key, 'Khoá');

        if (keyBytes.length !== KEY_BYTES) {
            throw new Error('Khoá phải dài đúng ' + KEY_BYTES + ' byte, nhận ' + keyBytes.length + '.');
        }

        const { version, iv, sealed } = parsePacked(packed);

        const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);

        let plaintextBytes;
        try {
            plaintextBytes = new Uint8Array(
                await crypto.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv,
                        additionalData: Uint8Array.of(version),
                        tagLength: TAG_BYTES * 8
                    },
                    cryptoKey,
                    sealed
                )
            );
        } catch (err) {
            // GCM không phân biệt được "sai khoá" và "bị sửa" — cả hai đều là lỗi xác thực.
            const e = new Error('Giải mã thất bại: sai khoá hoặc dữ liệu đã bị thay đổi (thẻ GCM không khớp).');
            e.cause = err;
            e.code = 'AUTH_FAILED';
            throw e;
        }

        return {
            plaintext: new TextDecoder('utf-8').decode(plaintextBytes),
            bytes: plaintextBytes,
            version
        };
    }

    return {
        VERSION,
        KEY_BYTES,
        IV_BYTES,
        TAG_BYTES,
        MIN_PACKED_BYTES,
        FORMAT_DESCRIPTION,
        bytesToBase64Url,
        base64UrlToBytes,
        bytesToHex,
        hexToBytes,
        concatBytes,
        flipBit,
        randomKey,
        encryptText,
        parsePacked,
        decryptPacked
    };
});
