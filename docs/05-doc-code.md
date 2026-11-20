# 05 — Đọc code

Tài liệu này dẫn bạn đi qua từng file theo đúng thứ tự nên đọc.

## Cây file

```
src/crypto.js     270 dòng   lõi mã hoá — đọc trước
src/keycode.js    205 dòng   định dạng key — đọc sau
src/server.js     370 dòng   HTTP + SQLite
public/app.js     225 dòng   luồng giao diện
public/index.html            2 cột: Gửi / Nhận
public/style.css             giao diện
```

## Thứ tự đọc đề xuất

1. `src/crypto.js` — hiểu dữ liệu được mã hoá thế nào.
2. `src/keycode.js` — hiểu vì sao key trông như vậy.
3. `src/server.js` — hiểu server làm gì (rất ít).
4. `public/app.js` — hiểu hai luồng giao diện.
5. Quay lại `test/*.test.js` — thấy mỗi khẳng định trong tài liệu được kiểm chứng ở đâu.

---

## src/crypto.js

### Hằng số (dòng 39–51)

```js
const VERSION = 0x01;
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = 1 + IV_BYTES;   // 13
```

`HEADER_BYTES` là chỗ hay bị sửa nhầm nhất. Nó là `version + IV` vì cả hai đều nằm trước
phần bản mã trong gói tin.

### `deriveKeys(rootKey)` — [src/crypto.js:171](../src/crypto.js#L171)

Đây là hàm quan trọng nhất của dự án. Nó nhận 32 byte và trả về ba thứ:

```js
{ encKey, authKey, authKeyB64, id }
```

Đoạn đáng chú ý:

```js
const [encBits, authBits] = await Promise.all([
    derive(HKDF_INFO_ENC),    // info = "zkv1/enc"
    derive(HKDF_INFO_AUTH)    // info = "zkv1/auth"
]);
```

Hai lần gọi `deriveBits` với `info` khác nhau cho ra hai khoá **không liên quan gì tới
nhau**. Đây là lý do lộ `authKey` không kéo theo lộ `encKey`.

`id` được tính bằng `digest('SHA-256', "zkv1/id" ‖ authKey)` rồi lấy 16 byte đầu — xem
dòng 208–212.

### `encryptText(text, rootKey)` — [src/crypto.js:226](../src/crypto.js#L226)

Ba việc, theo thứ tự:

1. `deriveKeys()` để lấy `encKey`.
2. Sinh IV 12 byte ngẫu nhiên **mỗi lần gọi**.
3. `subtle.encrypt` với `additionalData: Uint8Array.of(VERSION)`.

Lưu ý `sealed` mà WebCrypto trả về là `bản mã ‖ tag` gộp chung. Ta không tách thẻ ra ngoài;
khi giải mã chỉ cần đưa cả cục vào `subtle.decrypt`.

Cuối hàm ghép gói tin:

```js
const container = new Uint8Array(HEADER_BYTES + sealed.length);
container[0] = VERSION;
container.set(iv, 1);
container.set(sealed, HEADER_BYTES);
```

### `decryptText(container, rootKey)` — [src/crypto.js:260](../src/crypto.js#L260)

Thứ tự kiểm tra quan trọng:

1. Độ dài tối thiểu (`29` byte) → `BAD_CONTAINER`.
2. Byte version → `BAD_VERSION`.
3. Gọi `subtle.decrypt`; **mọi lỗi** đều quy về `AUTH_FAILED`.

Bước 3 cố tình không phân biệt "sai khoá" với "dữ liệu bị sửa", vì GCM cũng không phân
biệt được — và việc tách hai thông báo khác nhau sẽ tạo ra một oracle nhỏ cho kẻ tấn công.

---

## src/keycode.js

### `encode(bytes)` — [src/keycode.js:113](../src/keycode.js#L113)

```
32 byte → Base64URL (43 ký tự) → gắn tiền tố → "ZKV1-…"
```

### `decode(text)` — [src/keycode.js:139](../src/keycode.js#L139)

Kiểm tra theo thứ tự:

| Bước | Nếu sai |
|---|---|
| rỗng | "Chưa nhập key." |
| độ dài ≠ 43 | "Key phải có 43 ký tự (không tính tiền tố)…" |
| ký tự ngoài bảng Base64URL | "Ký tự không hợp lệ trong key…" |
| bit đệm ≠ 0 | "Key bị sai ở ký tự cuối (hoặc đã bị cắt cụt)…" |

### `normalize(input)` — [src/keycode.js:127](../src/keycode.js#L127)

Chỉ làm hai việc: bỏ khoảng trắng (kể cả xuống dòng khi copy) và bỏ tiền tố `ZKV1-`.

Điều **không** làm: không đổi hoa/thường và không bỏ dấu `-` trong phần dữ liệu,
vì cả hai đều mang thông tin. Đó cũng là lý do key không chia nhóm bằng gạch nối
như các định dạng thân thiện với người đọc khác.

---

## src/server.js

### `idFromAuthKey(token)` — [src/server.js:118](../src/server.js#L118)

```js
crypto.createHash('sha256').update('zkv1/id').update(auth).digest().subarray(0, 16)
```

Phải khớp **chính xác** với client ([src/crypto.js:209](../src/crypto.js#L209)): cùng chuỗi
miền `"zkv1/id"`, cùng thứ tự nối. Lệch một byte là server tính ra `id` khác và không bao
giờ tìm thấy dữ liệu.

### `handlePost` — [src/server.js:209](../src/server.js#L209)

```
rate limit → kiểm Authorization → đọc body (≤ maxBytes) → kiểm độ dài → ghi DB (hoặc MinIO S3)
```

Điểm cần nhớ: **không có tham số `id` từ client**. Server tự suy ra.

### `handleGet` — [src/server.js:258](../src/server.js#L258)

```
rate limit → Authorization → id → tìm trong DB → kiểm hạn → trả bytes
```

Ba nhánh trả về, và chúng cố tình giống nhau ở tầng HTTP (đều `404`), chỉ khác `message`:
không tìm thấy, hết hạn, hoặc không tồn tại.

### `handlePut` — [src/server.js:299](../src/server.js#L299)

```
rate limit → Authorization → id → kiểm bản ghi tồn tại & còn hạn → đọc body → kiểm độ dài → ghi đè + gia hạn TTL
```

Khác với `POST`: `PUT` đòi hỏi bản ghi đã tồn tại và chưa hết hạn, nếu không trả `404`.
Server vẫn không biết nội dung mới là gì — chỉ thay cục byte bản mã theo cùng `id`.

### `handleDelete` — [src/server.js:358](../src/server.js#L358)

```
rate limit → Authorization → id → kiểm tồn tại & còn hạn → xoá khỏi S3 (nếu có) & SQLite → trả 200
```

Xoá xong trả `{ ok: true, id }`. Nếu gọi lại lần nữa với cùng key sẽ trả `404`.

### `readBody` — [src/server.js:179](../src/server.js#L179)

Đọc body theo từng chunk, cộng dồn kích thước và cắt ngay khi vượt hạn mức. Chú ý: khi vượt
giới hạn, hàm **không huỷ socket ngay** mà để router còn kịp trả `413` cho client — huỷ sớm
thì client chỉ thấy "connection reset" thay vì một thông báo tử tế.

### Router — [src/server.js:424](../src/server.js#L424)

Rất ngắn: hai đường API (`/api/health`, `/api/secret` với `GET`/`POST`/`PUT`/`DELETE`), còn lại là file tĩnh. File tĩnh được chặn thoát thư mục bằng
`file.startsWith(path.resolve(publicDir))` ([src/server.js:397](../src/server.js#L397)).

---

## public/app.js

### `refreshCounter()` — [public/app.js:56](../public/app.js#L56)

Đếm từ bằng `text.trim().split(/\s+/).length` và khoá nút gửi khi vượt 200.
Đây là **giới hạn phía client**; server không kiểm tra số từ (xem "Giới hạn" ở README).

### `sendText()` — [public/app.js:103](../public/app.js#L103)

```js
const rootKey = ZKCrypto.randomKey();
const sealed = await ZKCrypto.encryptText(text, rootKey);
await fetch('/api/secret', { method: 'POST', headers: { Authorization: 'Bearer ' + sealed.authKeyB64 }, body: sealed.container });
$('keyOut').textContent = ZKKeycode.encode(rootKey);
```

Toàn bộ luồng gửi nằm trong 4 dòng này. `rootKey` chỉ sống trong biến cục bộ.

### `openText(rawKey)` — [public/app.js:310](../public/app.js#L310)

```js
const rootKey = ZKKeycode.decode(rawKey);              // 1. key -> 32 byte
const derived = await ZKCrypto.deriveKeys(rootKey);    // 2. -> authKey, id
// 3. GET /api/secret
const container = new Uint8Array(await res.arrayBuffer());
const payload = await ZKCrypto.decryptPayload(container, rootKey); // 4. giải mã
```

Khi giải mã thành công, `activeRootKey` và `activeAuthKeyB64` được giữ trong RAM của trang
để phục vụ ngay cho thao tác **Sửa** và **Xoá** (và bị xoá sạch khi đổi key hoặc xoá xong).

### `saveEditedText()` — [public/app.js:374](../public/app.js#L374)

Khi người dùng bấm **Sửa nội dung** → **Lưu thay đổi**:

```js
const sealed = pendingEditFile
    ? await ZKCrypto.encryptPayload({ text, file: pendingEditFile }, activeRootKey)
    : await ZKCrypto.encryptText(text, activeRootKey);
await fetch('/api/secret', { method: 'PUT', headers: { Authorization: 'Bearer ' + sealed.authKeyB64 }, body: sealed.container });
```

Hàm mã hoá lại dùng đúng `activeRootKey` nhưng luôn sinh **IV 12 byte ngẫu nhiên mới**,
nhờ đó key cũ vẫn giữ nguyên mà không vi phạm yêu cầu duy nhất của nonce AES-GCM.

### Xử lý nút Xoá (`#delBtn`) — [public/app.js:429](../public/app.js#L429)

Gửi `DELETE /api/secret` kèm `Authorization: Bearer <activeAuthKeyB64>`. Khi thành công,
ẩn khung kết quả, xoá `activeRootKey`/`activeAuthKeyB64` khỏi bộ nhớ và thông báo key
không còn mở được nữa.

### Xử lý ô nhập key — [public/app.js:464](../public/app.js#L464)

Không có nút "Mở": mỗi lần người dùng gõ/dán, ta kiểm tra định dạng; nếu hợp lệ thì hẹn
250 ms rồi tự động gọi `openText`. Nhờ vậy dán key là thấy kết quả ngay.

Biến `lastKey` chặn việc gọi lại API liên tục khi văn bản trong ô không đổi.

---

## Chỗ dễ sửa hỏng

| Nếu sửa chỗ này | Phải sửa kèm |
|---|---|
| Chuỗi miền `"zkv1/id"` | cùng lúc ở client và server, nếu không sẽ không tìm thấy dữ liệu |
| `HEADER_BYTES` | phần ghép và tách IV trong `encryptText` / `decryptText` |
| Đổi bảng chữ cái của key | key dài thêm 13 ký tự nếu quay lại Base32; phải sửa `encode`/`decode` và mọi chỗ hiển thị key |
| Đổi `additionalData` | cả `encryptText` và `decryptText` phải đổi giống nhau |
| Thêm endpoint mới | nhớ kiểm `Authorization` và rate limit trước khi đọc body |
