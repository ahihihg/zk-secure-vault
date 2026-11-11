# 06 — Kiểm thử

## Chạy toàn bộ

```bash
node --test test/keycode.test.js test/crypto.test.js test/server.test.js
```

```
ℹ tests 42
ℹ pass 42
ℹ fail 0
```

Và kiểm thử end-to-end trên trình duyệt thật:

```bash
node test/e2e.cjs       # cần Chrome hoặc Edge
```

`e2e.cjs` tự bật một server tạm trên cổng ngẫu nhiên, mở Chrome headless, thao tác như
người dùng (gõ text, bấm nút, dán key ở tab khác) rồi chụp ảnh vào `docs/`.

## Ba nhóm test

### `test/keycode.test.js` — 10 test

Kiểm tra cách key được sinh và đọc lại.

| Test | Bảo vệ điều gì |
|---|---|
| hình dạng `ZKV1-xxxx-…` | giao diện người dùng không đổi ngoài ý muốn |
| roundtrip 200 key ngẫu nhiên | encode/decode không mất bit |
| đủ kiểu định dạng lộn xộn | dán từ đâu cũng đọc được (chữ hoa, có dấu cách, thiếu gạch) |
| tự sửa `O→0`, `I/L→1` | người đọc key từ giấy không bị chặn oan |
| gõ sai 1 ký tự | checksum bắt được |
| thiếu ký tự | báo đúng số lượng |
| ký tự lạ | nằm ngoài bảng Crockford thì từ chối |
| key rỗng / `null` | không ném lỗi khó hiểu |
| `isValid` | không ném exception ra ngoài |
| key sai độ dài | `encode` từ chối |

### `test/crypto.test.js` — 19 test

| Nhóm | Test | Bảo vệ điều gì |
|---|---|---|
| Dẫn xuất khoá | client và server ra cùng `id` | hai bên không lệch công thức |
| | tất định | cùng key luôn ra cùng `id` |
| | key khác → `id` khác | không đụng nhau |
| | `id` chỉ 16 byte | không thể dựng lại `authKey` |
| Mã hoá | roundtrip ngắn / Unicode / 2 KB / xuống dòng | dữ liệu không bị biến dạng |
| Định dạng | `1 + 12 + n + 16` | đúng đặc tả ở tài liệu 02 |
| | IV khác nhau mỗi lần | không tái sử dụng nonce |
| | bản mã không chứa văn bản gốc | kiểm chứng "server không đọc được" |
| Chống can thiệp | sai key | `AUTH_FAILED` |
| | sửa bản mã / IV / tag | `AUTH_FAILED` |
| | đổi version | `BAD_VERSION` |
| | cắt bớt / dữ liệu rác | lỗi rõ ràng, không trả rác |

### `test/server.test.js` — 13 test

| Test | Bảo vệ điều gì |
|---|---|
| health check | server sống |
| gửi rồi lấy lại | dữ liệu nhị phân không bị biến dạng |
| đi trọn vòng A→B | máy B chỉ có key vẫn mở được |
| server không đọc được nội dung | bảng `secrets` chỉ có `id` và `body` |
| key khác → 404 | không có oracle để dò |
| thiếu Authorization → 401 | không ai gọi được khi chưa chứng minh |
| hết hạn TTL | dữ liệu bị xoá thật khỏi DB |
| quá 64 KB → 413 | chống làm đầy ổ đĩa |
| gói tin quá ngắn → 400 | dữ liệu rác bị chặn sớm |
| rate limit | 3 lượt đầu 201, sau đó 429 |
| thoát thư mục | path traversal bị chặn |
| CSP | header bảo mật còn nguyên |
| thư viện dùng chung | `/crypto.js`, `/keycode.js` phục vụ đúng |

Mỗi test đều chạy trên **thư mục dữ liệu tạm** và **cổng ngẫu nhiên**, nên chạy song song
hay chạy lại nhiều lần đều không ảnh hưởng `data/` thật.

## Tự tay kiểm chứng (làm được trong 3 phút)

### 1. Server không đọc được nội dung

```bash
node src/server.js          # terminal 1
```

Mở http://127.0.0.1:8787, gửi thử một đoạn text, rồi ở terminal khác:

```bash
node -e "
const {DatabaseSync} = require('node:sqlite');
const db = new DatabaseSync('data/vault.db');
for (const r of db.prepare('SELECT id, length(body) AS n, body FROM secrets').all()) {
  console.log('id :', r.id);
  console.log('dài:', r.n, 'byte');
  console.log('nội dung lưu trong DB:', Buffer.from(r.body).toString('latin1').slice(0, 60));
}
"
```

Bạn sẽ thấy `id` là chuỗi hex vô nghĩa và `body` là ký tự rác. Không có cột nào chứa key.

### 2. Sửa một byte trong database thì không mở được

```bash
node -e "
const {DatabaseSync} = require('node:sqlite');
const db = new DatabaseSync('data/vault.db');
const r = db.prepare('SELECT id, body FROM secrets').get();
const b = Buffer.from(r.body);
b[20] ^= 1;                       // đảo 1 bit trong phần bản mã
db.prepare('UPDATE secrets SET body = ? WHERE id = ?').run(b, r.id);
console.log('đã sửa 1 bit của', r.id);
"
```

Mở lại đúng key đó trên trình duyệt → *"Sai key hoặc dữ liệu đã bị thay đổi (thẻ xác thực
không khớp)."* Đây là GHASH đang làm việc.

### 3. Key gõ sai bị bắt trước khi gửi request

Dán key vào ô nhưng xoá 1 ký tự → báo *"checksum không khớp"* **ngay lập tức**, không có
request nào được gửi (kiểm tra ở tab Network của DevTools).

### 4. Chỉ request mã hoá rời khỏi máy

Mở DevTools → Network → gửi một đoạn text. Request `POST /api/secret` chỉ có:

- Header `Authorization: Bearer …` (là `authKey`, không phải key người dùng)
- Body là byte nhị phân

Không có trường nào chứa văn bản gốc.

## Điều các test này **chưa** kiểm tra

Trung thực mà nói, còn những khoảng trống:

- **Không có test tải đồng thời** (race condition khi hai người dùng cùng `id`).
- **Không có fuzz test** cho bộ giải mã container — dữ liệu hỏng bất kỳ được thử thủ công,
  không phủ toàn bộ không gian đầu vào.
- **Không kiểm tra phụ thuộc phiên bản** `node:sqlite` (chỉ chạy trên Node ≥ 22.5).
- **E2E không thử tệp quá dài**, chỉ thử vượt 200 từ ở tầng giao diện.
