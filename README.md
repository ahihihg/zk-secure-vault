# ZK-Vault

Gửi một đoạn văn bản bằng **một key duy nhất** — không tài khoản, không mật khẩu, và server
không có khả năng đọc nội dung.

```
soạn text  ──►  mã hoá tại trình duyệt  ──►  server lưu bản mã  ──►  trả về key ZKV1-…
dán key    ──►  tìm bản mã theo key     ──►  giải mã tại trình duyệt  ──►  hiện / sửa / xoá text
```

## Chạy thử

Mở Docker Desktop, sau đó chạy đúng **một lệnh duy nhất**:

```bash
node src/server.js
# Tự động bật MinIO (docker compose up -d) nếu chưa chạy,
# tạo bucket zk-vault và chạy ZK-Vault tại http://127.0.0.1:8787
```

Không cần `npm install`. Server chỉ dùng module có sẵn trong Node 24:
`node:http`, `node:sqlite`, `node:crypto`, `node:child_process`.
Hệ thống lưu trữ theo mô hình **Hybrid toàn thời gian**:
- **SQLite** (`data/vault.db`): chỉ lưu metadata (`id`, `created_at`, `expires_at`).
- **MinIO S3** (bucket `zk-vault`): lưu 100% gói bản mã (`<id>.zkv`).

![Gửi văn bản và nhận key](docs/screenshot-send.png)

![Dán key là tự động mở lại văn bản](docs/screenshot-open.png)

## Điều gì khiến nó "zero-knowledge"

| Client giữ | Server giữ |
|---|---|
| key 32 byte (đưa cho người dùng) | `id` = ảnh một chiều của `authKey` |
| `encKey` — khoá mã hoá, **không bao giờ gửi đi** | bản mã (không giải mã được) |
| `authKey` — chỉ dùng để chứng minh quyền truy cập | thời điểm hết hạn |

Server không có `encKey` và không có key gốc. Dump toàn bộ database cũng chỉ thu được
ciphertext vô nghĩa.

## Cấu trúc

```
src/
├── crypto.js     # lõi: HKDF dẫn xuất khoá + AES-256-GCM (gói v1 & v2)
├── keycode.js    # key ZKV1-… : Base64URL, 43 ký tự
├── s3.js         # client MinIO S3 thuần Node.js (AWS Signature v4)
└── server.js     # HTTP API + SQLite (metadata) + MinIO S3 (bản mã)
public/
├── index.html    # giao diện hai cột: Gửi / Nhận
├── app.js        # luồng client
└── style.css
test/
├── keycode.test.js  # 11 test
├── crypto.test.js   # 21 test
├── server.test.js   # 18 test
└── e2e.cjs          # 16 kiểm tra trên Chrome thật
docs/               # tài liệu đọc hiểu dự án
```

## Tài liệu

| File | Nội dung |
|---|---|
| [01-kiến trúc](docs/01-kien-truc.md) | Các thành phần, luồng dữ liệu, ai giữ cái gì |
| [02-thuật toán](docs/02-thuat-toan.md) | HKDF, AES-256-GCM, định dạng gói tin — có ví dụ số thật |
| [03-bảo mật](docs/03-bao-mat.md) | Mô hình mối đe doạ: chặn được gì, không chặn được gì |
| [04-API](docs/04-api.md) | Đặc tả endpoint, mã lỗi |
| [05-đọc code](docs/05-doc-code.md) | Đi từng file, từng hàm, kèm số dòng |
| [06-kiểm thử](docs/06-kiem-thu.md) | Test làm gì và cách tự tay kiểm chứng |

## Kiểm thử

```bash
node --test test/keycode.test.js test/crypto.test.js test/server.test.js
node test/e2e.cjs        # cần Chrome hoặc Edge
```

## Giới hạn đã biết

- **Mất key là mất văn bản.** Không có khôi phục, không có hỗ trợ — đây là hệ quả trực tiếp
  của việc không cần tài khoản.
- **Ai có key là đọc, sửa và xoá được.** Key là chìa khoá vật lý, không phải mật khẩu.
- **Giới hạn 200 từ** đang chặn ở client. Muốn chắc chắn thì phải chặn cả ở server.
- Văn bản tự xoá sau **7 ngày**; server vẫn thấy kích thước, thời điểm gửi và IP.
