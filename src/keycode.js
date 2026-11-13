/*!
 * keycode.js — biến 32 byte ngẫu nhiên thành chuỗi key cho người dùng.
 *
 *   ZKV1-3q2F9mW0tYb8sKcVx1nQzR7pJdLh4gAeUoXiT6NyP5w
 *   └──┘ └──────────── 43 ký tự Base64URL ────────────┘
 *   tiền tố        32 byte = 256 bit
 *
 * Dùng Base64URL (RFC 4648 §5): bảng chữ cái A–Z a–z 0–9 - _ , không có '='.
 * 32 byte -> 43 ký tự (43 × 6 = 258 bit, dư 2 bit đệm phải bằng 0).
 *
 * Lưu ý: Base64URL PHÂN BIỆT hoa thường và có chứa dấu '-' nên chuỗi không
 * được chia nhóm bằng gạch nối. Tiền tố "ZKV1-" chỉ để nhận ra đây là key.
 *
 * Chạy được ở cả trình duyệt (window.ZKKeycode) và Node (module.exports).
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    } else {
        root.ZKKeycode = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const LOOKUP = new Map(Array.from(ALPHABET, (ch, i) => [ch, i]));

    const PREFIX = 'ZKV1';
    const KEY_BYTES = 32;
    const TOTAL_CHARS = 43;      // ceil(256 / 6)

    class KeyFormatError extends Error {
        constructor(message) {
            super(message);
            this.name = 'KeyFormatError';
            this.code = 'BAD_KEY_FORMAT';
        }
    }

    /* ------------------------------------------------------------------ */
    /* Base64URL                                                           */
    /* ------------------------------------------------------------------ */

    function toUint8Array(value, label) {
        if (value instanceof Uint8Array) return value;
        if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(value)) {
            return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        }
        if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) return new Uint8Array(value);
        throw new KeyFormatError((label || 'Giá trị') + ' phải là Uint8Array.');
    }

    function encodeBase64Url(bytes) {
        let out = '';
        let i = 0;

        for (; i + 3 <= bytes.length; i += 3) {
            const b0 = bytes[i], b1 = bytes[i + 1], b2 = bytes[i + 2];
            out += ALPHABET[b0 >> 2];
            out += ALPHABET[((b0 & 3) << 4) | (b1 >> 4)];
            out += ALPHABET[((b1 & 15) << 2) | (b2 >> 6)];
            out += ALPHABET[b2 & 63];
        }

        const remain = bytes.length - i;
        if (remain === 1) {
            const b0 = bytes[i];
            out += ALPHABET[b0 >> 2];
            out += ALPHABET[(b0 & 3) << 4];
        } else if (remain === 2) {
            const b0 = bytes[i], b1 = bytes[i + 1];
            out += ALPHABET[b0 >> 2];
            out += ALPHABET[((b0 & 3) << 4) | (b1 >> 4)];
            out += ALPHABET[(b1 & 15) << 2];
        }

        return out;
    }

    function decodeBase64Url(text) {
        const out = new Uint8Array(Math.floor((text.length * 6) / 8));
        let acc = 0;
        let bits = 0;
        let o = 0;

        for (let i = 0; i < text.length; i++) {
            const v = LOOKUP.get(text[i]);
            if (v === undefined) {
                throw new KeyFormatError('Ký tự không hợp lệ trong key: "' + text[i] + '".');
            }
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[o++] = (acc >> bits) & 0xFF;
                acc &= (1 << bits) - 1;
            }
        }

        // 2 bit đệm cuối phải bằng 0, nếu không thì đây không phải key do hệ thống sinh ra
        if (bits > 0 && acc !== 0) {
            throw new KeyFormatError(
                'Key bị sai ở ký tự cuối (hoặc đã bị cắt cụt). Hãy dán lại nguyên key thay vì gõ tay.'
            );
        }
        return out.slice(0, o);
    }

    /* ------------------------------------------------------------------ */
    /* API công khai                                                       */
    /* ------------------------------------------------------------------ */

    /** 32 byte -> "ZKV1-<43 ký tự Base64URL>" */
    function encode(keyBytes) {
        const bytes = toUint8Array(keyBytes, 'Key');
        if (bytes.length !== KEY_BYTES) {
            throw new KeyFormatError('Key phải dài đúng ' + KEY_BYTES + ' byte, nhận ' + bytes.length + '.');
        }
        return PREFIX + '-' + encodeBase64Url(bytes);
    }

    /**
     * Chuẩn hoá những gì người dùng dán vào:
     *   - bỏ khoảng trắng (xuống dòng khi copy từ đâu đó)
     *   - bỏ tiền tố "ZKV1-" nếu có
     * KHÔNG đổi hoa/thường và KHÔNG bỏ dấu '-', vì cả hai đều mang dữ liệu.
     */
    function normalize(input) {
        let s = String(input == null ? '' : input).replace(/\s+/g, '');

        if (s.length > TOTAL_CHARS && s.slice(0, PREFIX.length).toUpperCase() === PREFIX) {
            s = s.slice(PREFIX.length);
            if (s.indexOf('-') === 0) s = s.slice(1);
        }

        return s;
    }

    /** "ZKV1-…" -> 32 byte. */
    function decode(input) {
        const s = normalize(input);

        if (!s) throw new KeyFormatError('Chưa nhập key.');
        if (s.length !== TOTAL_CHARS) {
            throw new KeyFormatError(
                'Key phải có ' + TOTAL_CHARS + ' ký tự (không tính tiền tố), bạn nhập ' + s.length +
                '. Kiểm tra xem có bị thiếu đoạn nào không.'
            );
        }

        const bytes = decodeBase64Url(s);
        if (bytes.length !== KEY_BYTES) {
            throw new KeyFormatError('Key không hợp lệ: sau giải mã chỉ còn ' + bytes.length + ' byte.');
        }
        return bytes;
    }

    function isValid(input) {
        try {
            decode(input);
            return true;
        } catch {
            return false;
        }
    }

    return {
        PREFIX,
        KEY_BYTES,
        TOTAL_CHARS,
        KeyFormatError,
        encode,
        decode,
        isValid,
        normalize
    };
});
