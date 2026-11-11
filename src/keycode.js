/*!
 * ZK-Vault — mã hoá key dạng người đọc được (Crockford Base32 + checksum).
 *
 *   ZKV1-7F3K-9QW2-M4TB-K8XR-2N5D-J6HY-0P3V-...
 *   └──┘ └──────────────── 14 nhóm × 4 ký tự ────────────────┘
 *   prefix      52 ký tự dữ liệu (256-bit) + 4 ký tự checksum
 *
 * Vì sao không dùng Base64URL cho key?
 *   - Base64URL có "0/O", "1/l/I" — gõ tay hoặc đọc qua điện thoại rất dễ sai.
 *   - Crockford Base32 loại bỏ I, L, O, U nên tự sửa được các nhầm lẫn phổ biến.
 *   - 4 ký tự checksum (20 bit) đủ để báo "key gõ sai" ngay, thay vì để người
 *     dùng nhận thông báo mơ hồ "sai key hoặc file hỏng".
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

    const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // 32 ký tự, bỏ I L O U
    const PREFIX = 'ZKV1';
    const KEY_BYTES = 32;
    const DATA_CHARS = 52;      // ceil(256 / 5)
    const CHECK_CHARS = 4;      // 20 bit checksum
    const TOTAL_CHARS = DATA_CHARS + CHECK_CHARS;
    const GROUP_SIZE = 4;

    class KeyFormatError extends Error {
        constructor(message) {
            super(message);
            this.name = 'KeyFormatError';
            this.code = 'BAD_KEY_FORMAT';
        }
    }

    /* ---------------- CRC-32 (chỉ để bắt lỗi gõ tay) ---------------- */

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

    function checksumChars(dataChars) {
        const bytes = new TextEncoder().encode('zkv1/check:' + dataChars);
        const c = crc32(bytes);
        let out = '';
        for (let i = 0; i < CHECK_CHARS; i++) {
            out += ALPHABET[(c >>> (27 - i * 5)) & 31];
        }
        return out;
    }

    /* ---------------- mã hoá / giải mã ---------------- */

    function toUint8Array(value, label) {
        if (value instanceof Uint8Array) return value;
        if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(value)) {
            return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        }
        if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) return new Uint8Array(value);
        throw new KeyFormatError((label || 'Giá trị') + ' phải là Uint8Array.');
    }

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
        if (bits > 0) out += ALPHABET[(acc << (5 - bits)) & 31];
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
        if (bits > 0 && acc !== 0) {
            throw new KeyFormatError('Key không hợp lệ: bit thừa phải bằng 0.');
        }
        return out.slice(0, o);
    }

    function group(text) {
        const parts = [];
        for (let i = 0; i < text.length; i += GROUP_SIZE) parts.push(text.substr(i, GROUP_SIZE));
        return parts.join('-');
    }

    /** Chuẩn hoá input người dùng dán vào: bỏ khoảng trắng, gạch, prefix, sửa nhầm lẫn. */
    function normalize(input) {
        let s = String(input == null ? '' : input)
            .toUpperCase()
            .replace(/[\s\-_.]/g, '');

        // Sửa nhầm lẫn phổ biến TRƯỚC khi bỏ prefix, để "ZKVL"/"ZKVI" vẫn được hiểu là "ZKV1"
        s = s.replace(/O/g, '0').replace(/[IL]/g, '1');

        // Chỉ bỏ prefix khi chuỗi dài hơn phần thân - tránh cắt nhầm dữ liệu thật
        if (s.startsWith(PREFIX) && s.length > TOTAL_CHARS) s = s.slice(PREFIX.length);

        return s;
    }

    /** 32 byte -> "ZKV1-XXXX-XXXX-...-XXXX" */
    function encode(keyBytes) {
        const bytes = toUint8Array(keyBytes, 'Key');
        if (bytes.length !== KEY_BYTES) {
            throw new KeyFormatError('Key phải dài đúng ' + KEY_BYTES + ' byte, nhận ' + bytes.length + '.');
        }
        const data = encodeBase32(bytes);
        return PREFIX + '-' + group(data + checksumChars(data));
    }

    /** "ZKV1-xxxx-..." -> 32 byte. Ném KeyFormatError với thông báo tiếng Việt. */
    function decode(input) {
        const s = normalize(input);

        if (!s) throw new KeyFormatError('Chưa nhập key.');
        if (s.length !== TOTAL_CHARS) {
            throw new KeyFormatError(
                'Key phải có ' + TOTAL_CHARS + ' ký tự, bạn nhập ' + s.length + ' ký tự. Kiểm tra xem có bị thiếu đoạn nào không.'
            );
        }

        const data = s.slice(0, DATA_CHARS);
        const check = s.slice(DATA_CHARS);

        if (checksumChars(data) !== check) {
            throw new KeyFormatError('Key bị gõ sai (checksum không khớp). Kiểm tra lại các ký tự đã nhập.');
        }

        const bytes = decodeBase32(data);
        if (bytes.length !== KEY_BYTES) {
            throw new KeyFormatError('Key không hợp lệ: độ dài sau giải mã là ' + bytes.length + ' byte.');
        }
        return bytes;
    }

    function isValid(input) {
        try {
            decode(input);
            return true;
        } catch (err) {
            return false;
        }
    }

    return {
        ALPHABET,
        PREFIX,
        KEY_BYTES,
        TOTAL_CHARS,
        KeyFormatError,
        encode,
        decode,
        isValid,
        normalize,
        group
    };
});
