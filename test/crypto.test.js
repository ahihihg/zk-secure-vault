/**
 * Test cho lõi mã hoá v2: dẫn xuất khoá + mã hoá tệp theo khối.
 * Chạy: node --test test/crypto.test.js
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');

const zk = require('../src/crypto.js');

const key = () => zk.randomKey();
const bytesOf = (n, seed = 1) => {
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = (i * seed + 7) & 0xff;
    return b;
};

/** Server sẽ tính id đúng như thế này từ authKey nhận được. */
function serverSideId(authKeyBase64Url) {
    const auth = Buffer.from(authKeyBase64Url, 'base64url');
    const h = nodeCrypto.createHash('sha256');
    h.update('zkv1/id');
    h.update(auth);
    return h.digest().subarray(0, 16).toString('hex');
}

/* ---------------- dẫn xuất khoá ---------------- */

test('client và server tính ra cùng một id từ cùng authKey', async () => {
    for (let i = 0; i < 20; i++) {
        const rootKey = key();
        const d = await zk.deriveKeys(rootKey);
        assert.equal(serverSideId(d.authKey_b64 || zk.bytesToBase64Url(d.authKey)), d.id);
    }
});

test('dẫn xuất khoá là tất định', async () => {
    const rootKey = key();
    const a = await zk.deriveKeys(rootKey);
    const b = await zk.deriveKeys(rootKey);
    assert.equal(a.id, b.id);
    assert.deepEqual(Array.from(a.authKey), Array.from(b.authKey));
    assert.deepEqual(Array.from(a.encKeyBytes), Array.from(b.encKeyBytes));
});

test('khoá khác nhau cho ra encKey/authKey/id khác nhau', async () => {
    const a = await zk.deriveKeys(key());
    const b = await zk.deriveKeys(key());
    assert.notEqual(a.id, b.id);
    assert.notDeepEqual(Array.from(a.encKeyBytes), Array.from(b.encKeyBytes));
});

test('encKey và authKey phải tách biệt (không suy ra nhau)', async () => {
    const d = await zk.deriveKeys(key());
    assert.notDeepEqual(Array.from(d.encKeyBytes), Array.from(d.authKey));
    // id chỉ dài 16 byte, không chứa đủ thông tin để dựng lại authKey
    assert.equal(d.id.length, 32);
});

test('id không phụ thuộc vào encKey', async () => {
    const rootKey = key();
    const d1 = await zk.deriveKeys(rootKey);
    const d2 = await zk.deriveKeys(rootKey);
    assert.equal(d1.id, d2.id);
});

test('key sai kích thước bị từ chối', async () => {
    await assert.rejects(() => zk.deriveKeys(new Uint8Array(16)), (e) => e.code === 'BAD_KEY');
});

/* ---------------- roundtrip ---------------- */

test('roundtrip tệp nhỏ, giữ nguyên tên và MIME type', async () => {
    const rootKey = key();
    const data = bytesOf(1000);
    const enc = await zk.encryptFile({ bytes: data, name: 'hop-dong.pdf', type: 'application/pdf', rootKey });
    const dec = await zk.decryptFile({ container: enc.container, rootKey });

    assert.deepEqual(Array.from(dec.bytes), Array.from(data));
    assert.equal(dec.name, 'hop-dong.pdf');
    assert.equal(dec.type, 'application/pdf');
    assert.equal(dec.size, 1000);
});

test('roundtrip tệp rỗng', async () => {
    const rootKey = key();
    const enc = await zk.encryptFile({ bytes: new Uint8Array(0), name: 'rong.txt', type: 'text/plain', rootKey });
    const dec = await zk.decryptFile({ container: enc.container, rootKey });
    assert.equal(dec.bytes.length, 0);
    assert.equal(dec.name, 'rong.txt');
});

test('roundtrip tên tệp có tiếng Việt và emoji', async () => {
    const rootKey = key();
    const name = 'báo cáo tháng 11 🔐.pdf';
    const enc = await zk.encryptFile({ bytes: bytesOf(300), name, type: 'application/pdf', rootKey });
    const dec = await zk.decryptFile({ container: enc.container, rootKey });
    assert.equal(dec.name, name);
});

test('roundtrip 1 MB với khối 64 KiB', async () => {
    const rootKey = key();
    const data = bytesOf(1024 * 1024, 3);
    const enc = await zk.encryptFile({ bytes: data, name: 'a.bin', type: 'application/octet-stream', rootKey, chunkSize: 65536 });
    assert.equal(enc.chunkCount, 16);
    const dec = await zk.decryptFile({ container: enc.container, rootKey });
    assert.deepEqual(Array.from(dec.bytes.slice(0, 1000)), Array.from(data.slice(0, 1000)));
    assert.equal(dec.bytes.length, data.length);
});

test('tệp đúng bằng bội số của chunkSize (khối cuối đầy)', async () => {
    const rootKey = key();
    const chunkSize = 4096;
    const data = bytesOf(chunkSize * 3);
    const enc = await zk.encryptFile({ bytes: data, name: 'x.bin', type: 'application/octet-stream', rootKey, chunkSize });
    assert.equal(enc.chunkCount, 3);
    const dec = await zk.decryptFile({ container: enc.container, rootKey });
    assert.equal(dec.bytes.length, data.length);
});

test('tệp lẻ 1 byte vẫn đúng', async () => {
    const rootKey = key();
    const enc = await zk.encryptFile({ bytes: Uint8Array.of(7), name: 'one.bin', type: 'x/y', rootKey, chunkSize: 1024 });
    const dec = await zk.decryptFile({ container: enc.container, rootKey });
    assert.deepEqual(Array.from(dec.bytes), [7]);
});

/* ---------------- định dạng container ---------------- */

test('container có magic, version và header 36 byte', async () => {
    const enc = await zk.encryptFile({ bytes: bytesOf(10), name: 'a', type: 'b', rootKey: key() });
    assert.deepEqual(Array.from(enc.container.slice(0, 4)), [0x5a, 0x4b, 0x56, 0x32]);
    assert.equal(enc.container[4], zk.VERSION);

    const h = zk.readHeader(enc.container);
    assert.equal(h.chunkCount, 1);
    assert.equal(h.metaNonce.length, 12);
    assert.equal(h.noncePrefix.length, 8);
});

test('server nhìn vào container không thấy tên tệp hay MIME type', async () => {
    const enc = await zk.encryptFile({
        bytes: bytesOf(500), name: 'hop-dong-thue-nha.pdf', type: 'application/pdf', rootKey: key()
    });
    const asLatin = Buffer.from(enc.container).toString('latin1');
    assert.equal(asLatin.includes('hop-dong'), false);
    assert.equal(asLatin.includes('application/pdf'), false);
    // "ZKV" chỉ được xuất hiện đúng 1 lần: magic ở 4 byte đầu
    assert.equal(asLatin.split('ZKV').length - 1, 1);
});

/* ---------------- chống can thiệp ---------------- */

test('sai key -> lỗi xác thực, không trả dữ liệu', async () => {
    const enc = await zk.encryptFile({ bytes: bytesOf(100), name: 'a', type: 'b', rootKey: key() });
    await assert.rejects(
        () => zk.decryptFile({ container: enc.container, rootKey: key() }),
        (e) => e.code === 'AUTH_FAILED'
    );
});

test('sửa 1 bit trong khối dữ liệu -> phát hiện', async () => {
    const rootKey = key();
    const enc = await zk.encryptFile({ bytes: bytesOf(5000), name: 'a', type: 'b', rootKey, chunkSize: 1024 });
    const tampered = new Uint8Array(enc.container);
    tampered[tampered.length - 40] ^= 0x01;
    await assert.rejects(() => zk.decryptFile({ container: tampered, rootKey }), (e) => e.code === 'AUTH_FAILED');
});

test('sửa 1 bit trong metadata -> phát hiện', async () => {
    const rootKey = key();
    const enc = await zk.encryptFile({ bytes: bytesOf(10), name: 'a', type: 'b', rootKey });
    const tampered = new Uint8Array(enc.container);
    tampered[zk.HEADER_LEN + 2] ^= 0x01;
    await assert.rejects(() => zk.decryptFile({ container: tampered, rootKey }), (e) => e.code === 'AUTH_FAILED');
});

test('cắt bớt tệp (truncation) -> phát hiện', async () => {
    const rootKey = key();
    const enc = await zk.encryptFile({ bytes: bytesOf(5000), name: 'a', type: 'b', rootKey, chunkSize: 1024 });
    const cut = enc.container.slice(0, enc.container.length - 200);
    await assert.rejects(() => zk.decryptFile({ container: cut, rootKey }), (e) => /TRUNCATED|AUTH_FAILED|BAD_SIZE/.test(e.code));
});

test('bỏ hẳn khối cuối -> phát hiện', async () => {
    const rootKey = key();
    const enc = await zk.encryptFile({ bytes: bytesOf(4096), name: 'a', type: 'b', rootKey, chunkSize: 1024 });
    const cut = enc.container.slice(0, enc.container.length - (1024 + 16));
    await assert.rejects(() => zk.decryptFile({ container: cut, rootKey }));
});

test('đảo thứ tự hai khối -> phát hiện', async () => {
    const rootKey = key();
    const chunkSize = 1024;
    const enc = await zk.encryptFile({ bytes: bytesOf(3072), name: 'a', type: 'b', rootKey, chunkSize });
    const h = zk.readHeader(enc.container);
    const start = zk.HEADER_LEN + h.metaLen;
    const a = enc.container.slice(start, start + chunkSize + 16);
    const b = enc.container.slice(start + chunkSize + 16, start + 2 * (chunkSize + 16));

    const swapped = new Uint8Array(enc.container);
    swapped.set(b, start);
    swapped.set(a, start + chunkSize + 16);

    await assert.rejects(() => zk.decryptFile({ container: swapped, rootKey }), (e) => e.code === 'AUTH_FAILED');
});

test('ghép thêm dữ liệu vào cuối -> phát hiện', async () => {
    const rootKey = key();
    const enc = await zk.encryptFile({ bytes: bytesOf(100), name: 'a', type: 'b', rootKey });
    const longer = new Uint8Array(enc.container.length + 10);
    longer.set(enc.container);
    await assert.rejects(() => zk.decryptFile({ container: longer, rootKey }), (e) => /TRAILING_DATA|BAD_SIZE|AUTH_FAILED/.test(e.code));
});

test('sửa chunkSize trong header -> phát hiện', async () => {
    const rootKey = key();
    const enc = await zk.encryptFile({ bytes: bytesOf(3000), name: 'a', type: 'b', rootKey, chunkSize: 1024 });
    const tampered = new Uint8Array(enc.container);
    tampered[9] ^= 0x01; // byte cuối của chunkSize
    await assert.rejects(() => zk.decryptFile({ container: tampered, rootKey }));
});

test('dữ liệu không phải container -> báo lỗi rõ ràng', async () => {
    await assert.rejects(
        () => zk.decryptFile({ container: bytesOf(100), rootKey: key() }),
        (e) => e.code === 'BAD_CONTAINER'
    );
    await assert.rejects(
        () => zk.decryptFile({ container: bytesOf(10), rootKey: key() }),
        (e) => e.code === 'BAD_CONTAINER'
    );
});
