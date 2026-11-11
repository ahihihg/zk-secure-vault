# Zero-Knowledge Secure Vault

Gửi tệp bằng một key duy nhất — không tài khoản, không mật khẩu, không server nào đọc được nội dung.

Kéo thả PDF / ảnh / bất kỳ tệp nào → nhận về một key dạng `ZKV1-XXXX-XXXX-…` →
mở lại web, dán key, tải tệp về. Server chỉ giữ bản mã.

---

## Kiến trúc: một key, ba dẫn xuất

Điểm mấu chốt là **key không bao giờ được gửi lên server**. Client tự dẫn xuất ra ba thứ
khác nhau, mỗi thứ dùng cho một việc:

```
K  = 32 byte ngẫu nhiên  (đây là key duy nhất người dùng giữ)
│
├── HKDF-SHA256(K, "zkv1/enc")   → encKey  32B  → AES-256-GCM mã hoá tệp (không rời máy)
├── HKDF-SHA256(K, "zkv1/auth")  → authKey 32B  → gửi server trong header Authorization
└── SHA-256("zkv1/id" ‖ authKey)[0..16] = id    → server dùng để định vị blob
```

Server chỉ giữ `id`, không có `encKey`, và `id` là ảnh một chiều của `authKey` nên
biết `id` cũng không tải được blob. Kể cả khi toàn bộ database bị dump, kẻ tấn công
chỉ có một đống ciphertext.

## Chạy thử

```bash
node src/server.js
# ZK-Vault đang chạy tại http://127.0.0.1:8787
```

Hai lối vào:

| Đường dẫn | Dùng để |
|---|---|
| `/poc-text/` | **PoC văn bản**: dán text (≤ 200 từ) → nhận key → dán key là tự hiện lại text |
| `/` | Ứng dụng đầy đủ: kéo thả tệp PDF/ảnh, TTL, tự huỷ sau 1 lần tải |

Không cần `npm install`. Server chỉ dùng module có sẵn của Node 24 (`node:http`,
`node:sqlite`, `node:crypto`).

Biến môi trường: `PORT`, `HOST`, `DATA_DIR`.

## Cấu trúc

```
src/
├── crypto.js       # lõi mã hoá: HKDF + AES-256-GCM theo khối (client & Node dùng chung)
├── keycode.js      # Crockford Base32 + checksum: key người đọc được
└── server.js       # HTTP API + lưu blob + TTL + rate limit (zero-dependency)
poc-text/           # PoC tối giản: gửi văn bản bằng key (dùng chung src/crypto.js)
public/
├── index.html      # giao diện Kéo thả / Mở bằng key
├── app.js          # luồng client, khoá chỉ nằm trong biến JS
└── style.css
test/
├── keycode.test.js # 11 test
├── crypto.test.js  # 22 test
├── server.test.js  # 13 test
└── e2e.cjs         # 19 kiểm tra end-to-end bằng Chrome headless
poc-week1/          # PoC tuần 1: minh hoạ thuật toán từng bước với văn bản
docs/               # ảnh chụp màn hình
```

## Định dạng tệp (`ZKV2`)

```
offset  size      nội dung
0       4         magic "ZKV2"
4       1         version = 2
5       1         flags
6       4         chunkSize   (u32 BE)
10      4         chunkCount  (u32 BE)
14      8         noncePrefix
22      2         metaLen     (u16 BE)
24      12        metaNonce
36      metaLen   metadata đã mã hoá: { name, type, size }
...               [khối 0]…[khối n-1], mỗi khối = bản mã ‖ 16B tag

AAD(meta)   = header ‖ "meta"
AAD(khối i) = header ‖ "chk" ‖ u32BE(i)
nonce(i)    = noncePrefix ‖ u32BE(i)
```

Tên tệp và MIME type nằm **trong metadata đã mã hoá** — server không biết bạn đang
gửi PDF hay ảnh. Header được đưa vào AAD nên không thể cắt bớt, đảo khối hay ghép
khối từ tệp khác mà không làm hỏng thẻ GCM.

## API

| Method | Đường dẫn | Header | Mô tả |
|---|---|---|---|
| `POST` | `/api/blob?ttl=<giây>&burn=0\|1` | `Authorization: Bearer <authKey>` | Lưu blob mã hoá, trả `{id, size, expiresAt}` |
| `GET` | `/api/blob` | `Authorization: Bearer <authKey>` | Tải blob; trả `X-ZKV-Expires`, `X-ZKV-Remaining` |
| `DELETE` | `/api/blob` | `Authorization: Bearer <authKey>` | Xoá blob |
| `GET` | `/api/health` | — | Kiểm tra server sống |

Không có endpoint nào trả về danh sách tệp: muốn có `id` thì phải có `authKey`.

## Mô hình bảo mật

| Được bảo vệ | Hệ quả cần chấp nhận |
|---|---|
| Nội dung tệp: AES-256-GCM, khoá dẫn xuất tại client | Mất key = **mất tệp vĩnh viễn**, không có khôi phục |
| Tên tệp, MIME type: mã hoá trong metadata | Ai có key = có tệp. Key là chìa khoá vật lý, không phải mật khẩu |
| Server không có `encKey`; dump DB cũng vô dụng | Server vẫn thấy metadata vận hành: kích thước, giờ, IP, số lượt tải |
| `id` là hash một chiều của `authKey` | Server có thể xoá hoặc từ chối phục vụ (mất availability) |
| Không có user DB, không mật khẩu để brute force | Trang bị chèn script lạ thì key bị lấy → CSP chặt, không dùng CDN ngoài |

## Giới hạn đã biết

- **Lưu trữ ẩn danh sẽ bị lạm dụng.** Đây là lý do Firefox Send bị đóng cửa năm 2020.
  Hiện có TTL tối đa 7 ngày, 25 MB/tệp, rate limit theo IP. Nếu mở cho công chúng
  thật thì cần thêm CAPTCHA hoặc proof-of-work, và nên chặn vài MIME nguy hiểm.
- **Chưa streaming.** Client đọc cả tệp vào RAM (`arrayBuffer()`) rồi mới mã hoá.
  25 MB ổn, nhưng muốn lên 500 MB thì phải chuyển sang `Blob.stream()` + đọc/ghi
  từng khối.
- **Một instance.** SQLite + blob trên đĩa, chưa hỗ trợ nhiều server.
- **Không có log/audit.** Cố ý: log càng ít càng tốt cho mô hình zero-knowledge.

## Chạy test

```bash
node --test test/keycode.test.js test/crypto.test.js test/server.test.js
node test/e2e.cjs
```

E2E dùng Chrome/Edge headless (đặt `CHROME=/đường/dẫn` nếu cần), thao tác thật:
kéo thả tệp, mã hoá, mở tab khác dán key, giải mã, kiểm tra ảnh xem trước, thử key
gõ sai, và kiểm tra chế độ tự huỷ ở lần tải thứ hai.

## PoC tuần 1

Thư mục `poc-week1/` là bản minh hoạ thuật toán từng bước (byte UTF-8 → khoá/IV →
bản mã + tag → giải mã), dùng để trình bày trên lớp. Chạy bằng
`python -m http.server 8080` rồi mở `http://localhost:8080/poc-week1/`.
