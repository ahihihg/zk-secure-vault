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

### `idFromAuthKey(token)` — [src/server.js:114](../src/server.js#L114)

```js
crypto.createHash('sha256').update('zkv1/id').update(auth).digest().subarray(0, 16)
```

Phải khớp **chính xác** với client ([src/crypto.js:208](../src/crypto.js#L208)): cùng chuỗi
miền `"zkv1/id"`, cùng thứ tự nối. Lệch một byte là server tính ra `id` khác và không bao
giờ tìm thấy dữ liệu.

### `handlePost` — [src/server.js:202](../src/server.js#L202)

```
rate limit → kiểm Authorization → đọc body (≤ 64 KB) → kiểm độ dài → ghi DB
```

Điểm cần nhớ: **không có tham số `id` từ client**. Server tự suy ra.

### `handleGet` — [src/server.js:239](../src/server.js#L239)

```
rate limit → Authorization → id → tìm trong DB → kiểm hạn → trả bytes
```

Ba nhánh trả về, và chúng cố tình giống nhau ở tầng HTTP (đều `404`), chỉ khác `message`:
không tìm thấy, hết hạn, hoặc không tồn tại.

### `readBody` — [src/server.js:172](../src/server.js#L172)

Đọc body theo từng chunk, cộng dồn kích thước và cắt ngay khi vượt hạn mức. Chú ý: khi vượt
giới hạn, hàm **không huỷ socket ngay** mà để router còn kịp trả `413` cho client — huỷ sớm
thì client chỉ thấy "connection reset" thay vì một thông báo tử tế.

### Router — [src/server.js:311](../src/server.js#L311)

Rất ngắn: ba đường API, còn lại là file tĩnh. File tĩnh được chặn thoát thư mục bằng
`file.startsWith(path.resolve(publicDir))` ([src/server.js:278](../src/server.js#L278)).

---

## public/app.js

### `refreshCounter()` — [public/app.js:49](../public/app.js#L49)

Đếm từ bằng `text.trim().split(/\s+/).length` và khoá nút gửi khi vượt 200.
Đây là **giới hạn phía client**; server không kiểm tra số từ (xem "Giới hạn" ở README).

### `sendText()` — [public/app.js:64](../public/app.js#L64)

```js
const rootKey = ZKCrypto.randomKey();
const sealed = await ZKCrypto.encryptText(text, rootKey);
await fetch('/api/secret', { method: 'POST', headers: { Authorization: 'Bearer ' + sealed.authKeyB64 }, body: sealed.container });
$('keyOut').textContent = ZKKeycode.encode(rootKey);
```

Toàn bộ luồng gửi nằm trong 4 dòng này. `rootKey` chỉ sống trong biến cục bộ.

### `openText(rawKey)` — [public/app.js:148](../public/app.js#L148)

```js
const rootKey = ZKKeycode.decode(rawKey);          // 1. key -> 32 byte
const derived = await ZKCrypto.deriveKeys(rootKey); // 2. -> authKey, id
// 3. GET /api/secret
const container = new Uint8Array(await res.arrayBuffer());
const text = await ZKCrypto.decryptText(container, rootKey); // 4. giải mã
```

### Xử lý ô nhập key — [public/app.js:187](../public/app.js#L187)

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
