/*!
 * keycode.js — biến 32 byte ngẫu nhiên thành một "key" người đọc được.
 *
 *   ZKV1-7F3K-9QW2-M4TB-K8XR-2N5D-J6HY-0P3V-K1AC-8W6E
 *   └──┘ └──────────── 14 nhóm × 4 ký tự ─────────────┘
 *   tiền tố      52 ký tự dữ liệu (256 bit) + 4 ký tự checksum
 *
 * Vì sao không dùng Base64URL cho key?
 *   Base64URL có cặp ký tự dễ nhầm khi đọc hoặc gõ tay: 0 với O, 1 với l/I.
 *   Crockford Base32 loại bỏ I, L, O, U nên còn 32 ký tự không nhập nhằng.
 *   4 ký tự checksum (20 bit) giúp báo "key gõ sai" ngay, thay vì để người
 *   dùng nhận thông báo mơ hồ "sai key hoặc dữ liệu hỏng".
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

    const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // 32 ký tự, không có I L O U
    const PREFIX = 'ZKV1';
    const KEY_BYTES = 32;

    // 256 bit / 5 bit = 51,2 -> cần 52 ký tự; 4 bit đệm ở ký tự cuối phải bằng 0
    const DATA_CHARS = 52;
    const CHECK_CHARS = 4;
    const TOTAL_CHARS = DATA_CHARS + CHECK_CHARS;
    const GROUP_SIZE = 4;

    class KeyFormatError extends Error {
        constructor(message) {
            super(message);
            this.name = 'KeyFormatError';
            this.code = 'BAD_KEY_FORMAT';
        }
    }

    /* ------------------------------------------------------------------ */
    /* CRC-32 — chỉ để bắt lỗi gõ tay, không liên quan tới bảo mật        */
    /* ------------------------------------------------------------------ */

    let CRC_TABLE = null;

    function crc32(bytes) {
        if (!CRC_TABLE) {
            CRC_TABLE = new Int32Array(256);
            for (let n = 0; n < 256; n++) {
                let c = n;
                for (let k = 0; k < 8; k++) {
                    c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
                }
                CRC_TABLE[n] = c;
            }
        }
        let crc = -1;
        for (let i = 0; i < bytes.length; i++) {
            crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ bytes[i]) & 0xFF];
        }
        return (crc ^ -1) >>> 0;
    }

    /** 20 bit đầu của CRC-32, mã hoá thành 4 ký tự Base32. */
    function checksumChars(dataChars) {
        const crc = crc32(new TextEncoder().encode('zkv1/check:' + dataChars));
        let out = '';
        for (let i = 0; i < CHECK_CHARS; i++) {
            out += ALPHABET[(crc >>> (27 - i * 5)) & 31];
        }
        return out;
    }

    /* ------------------------------------------------------------------ */
    /* Base32                                                              */
    /* ------------------------------------------------------------------ */

    function encodeBase32(bytes) {
        let acc = 0;
        let bits = 0;
        let out = '';

        for (let i = 0; i < bytes.length; i++) {
            acc = (acc << 8) | bytes[i];
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                out += ALPHABET[(acc >>> bits) & 31];
            }
        }
        if (bits > 0) out += ALPHABET[(acc << (5 - bits)) & 31]; // đệm 0 vào cuối
        return out;
    }

    function decodeBase32(text) {
        const out = new Uint8Array(Math.floor((text.length * 5) / 8));
        let acc = 0;
        let bits = 0;
        let o = 0;

        for (let i = 0; i < text.length; i++) {
            const v = ALPHABET.indexOf(text[i]);
            if (v < 0) throw new KeyFormatError('Ký tự không hợp lệ trong key: "' + text[i] + '".');
            acc = (acc << 5) | v;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out[o++] = (acc >>> bits) & 0xFF;
                acc &= (1 << bits) - 1;
            }
        }
        // Bit đệm phải bằng 0, nếu không thì đây không phải key do hệ thống sinh ra
        if (bits > 0 && acc !== 0) throw new KeyFormatError('Key không hợp lệ: bit đệm phải bằng 0.');
        return out.slice(0, o);
    }

    /* ------------------------------------------------------------------ */
    /* API công khai                                                       */
    /* ------------------------------------------------------------------ */

    function toUint8Array(value, label) {
        if (value instanceof Uint8Array) return value;
        if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(value)) {
            return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        }
        if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) return new Uint8Array(value);
        throw new KeyFormatError((label || 'Giá trị') + ' phải là Uint8Array.');
    }

    /** 32 byte -> "ZKV1-XXXX-XXXX-…-XXXX" */
    function encode(keyBytes) {
        const bytes = toUint8Array(keyBytes, 'Key');
        if (bytes.length !== KEY_BYTES) {
            throw new KeyFormatError('Key phải dài đúng ' + KEY_BYTES + ' byte, nhận ' + bytes.length + '.');
        }
        const data = encodeBase32(bytes);
        const full = data + checksumChars(data);

        const groups = [];
        for (let i = 0; i < full.length; i += GROUP_SIZE) groups.push(full.substr(i, GROUP_SIZE));
        return PREFIX + '-' + groups.join('-');
    }

    /**
     * Chuẩn hoá những gì người dùng dán vào:
     *   - bỏ khoảng trắng, gạch nối, dấu chấm; chuyển về chữ hoa
     *   - sửa nhầm lẫn O -> 0, I/L -> 1 (phải làm TRƯỚC khi bỏ tiền tố,
     *     để "ZKVL-…" vẫn được hiểu là "ZKV1-…")
     *   - bỏ tiền tố ZKV1 nếu có
     */
    function normalize(input) {
        let s = String(input == null ? '' : input)
            .toUpperCase()
            .replace(/[\s\-_.]/g, '');

        s = s.replace(/O/g, '0').replace(/[IL]/g, '1');

        // Chỉ cắt tiền tố khi chuỗi dài hơn phần thân, tránh cắt nhầm dữ liệu thật
        if (s.startsWith(PREFIX) && s.length > TOTAL_CHARS) s = s.slice(PREFIX.length);

        return s;
    }

    /** "ZKV1-…" -> 32 byte. */
    function decode(input) {
        const s = normalize(input);

        if (!s) throw new KeyFormatError('Chưa nhập key.');
        if (s.length !== TOTAL_CHARS) {
            throw new KeyFormatError(
                'Key phải có ' + TOTAL_CHARS + ' ký tự, bạn nhập ' + s.length +
                '. Kiểm tra xem có bị thiếu đoạn nào không.'
            );
        }

        const data = s.slice(0, DATA_CHARS);
        const check = s.slice(DATA_CHARS);

        if (checksumChars(data) !== check) {
            throw new KeyFormatError('Key bị gõ sai (checksum không khớp). Kiểm tra lại các ký tự đã nhập.');
        }

        const bytes = decodeBase32(data);
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
