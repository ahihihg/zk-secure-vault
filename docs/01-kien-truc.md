# 01 — Kiến trúc

## Ba thành phần

```
┌────────────────────────┐        ┌────────────────────────┐
│  TRÌNH DUYỆT           │        │  SERVER (Node.js)      │
│                        │  HTTPS │                        │
│  public/index.html     │◄──────►│  src/server.js         │
│  public/app.js         │        │  ├─ POST /api/secret   │
│  src/crypto.js  ───────┤        │  ├─ GET  /api/secret   │
│  src/keycode.js        │        │  └─ file tĩnh          │
│                        │        │                        │
│  sinh key, mã hoá,     │        │  SQLite: data/vault.db │
│  giải mã — TẤT CẢ ở đây│        │  (chỉ có bản mã)       │
└────────────────────────┘        └────────────────────────┘
```

Điểm cốt lõi: **không có thành phần nào ở giữa biết nội dung**. Server là một cái tủ có
khoá số, chỉ giữ hộp đã niêm phong và trả lại đúng cái hộp đó cho ai trình đúng "vé".

## Luồng gửi

```
Người gửi                                                  Server
──────────────────────────────────────────────────────────────────────
1. gõ đoạn text (≤ 200 từ)
2. bấm "Mã hoá & lưu"
   ├─ sinh K = 32 byte ngẫu nhiên
   ├─ encKey = HKDF(K, "enc")
   ├─ authKey = HKDF(K, "auth")
   ├─ id = SHA-256("id" ‖ authKey)[0..15]
   ├─ bản mã = AES-256-GCM(encKey, text)
   └─ POST bản mã, header Authorization: Bearer authKey
                              ────────────────────►
                                                       3. tính lại id từ authKey
                                                          lưu (id, bản mã, hạn)
                              ◄────────────────────
                                                       { id, size, expiresAt }
4. hiện key ZKV1-… cho người dùng
```

Chú ý bước 3: server **tự tính lại `id`** từ `authKey` mà nó nhận được, chứ không tin `id`
do client gửi lên. Nếu không, kẻ tấn công có thể ghi đè bản mã của người khác.

## Luồng nhận

```
Người nhận                                                 Server
──────────────────────────────────────────────────────────────────────
1. dán key ZKV1-… vào ô
   ├─ giải Base64URL, đòi đúng 43 ký tự (sai -> báo ngay, chưa gửi request)
   ├─ authKey = HKDF(K, "auth")
   └─ GET /api/secret, Bearer authKey
                              ────────────────────►
                                                       2. id = SHA-256(...)
                                                          tìm bản mã, kiểm hạn
                              ◄────────────────────
3. nhận bản mã
   ├─ encKey = HKDF(K, "enc")
   ├─ text = AES-256-GCM⁻¹(encKey, bản mã)
   └─ hiện text
```

## Ai giữ gì

| Giá trị | Ai tạo | Client có | Server có | Có trong database |
|---|---|---|---|---|
| `K` (key người dùng) | client | ✅ (trong RAM) | ❌ | ❌ |
| `encKey` | client | ✅ | ❌ | ❌ |
| `authKey` | client | ✅ | ✅ (qua header) | ❌ (chỉ có hash) |
| `id` = SHA-256("id"‖authKey) | cả hai tính độc lập | ✅ | ✅ | ✅ (khoá chính) |
| bản mã | client | ✅ | ✅ | ✅ |
| văn bản gốc | client | chỉ khi giải mã | ❌ | ❌ |

## Vì sao cần server, dù đoạn text chỉ vài trăm byte?

Có ba lý do thực tế:

1. **Văn bản phải tồn tại sau khi người gửi đóng tab.** Nếu chỉ để trong URL thì khi người
   nhận mở máy khác, dữ liệu phải đi theo link — mà link có giới hạn.
2. **Cần chỗ đặt thời hạn.** TTL 7 ngày nghĩa là có ai đó phải xoá dữ liệu. Không có server
   thì không có "tự huỷ".
3. **URL dài bao nhiêu là đủ?** Giới hạn thực tế của hạ tầng khoảng **8 KB** cho một URL
   (nginx mặc định 8 KB, Apache ~8190 byte). Bản mã của 200 từ ≈ 1,4 KB sau Base64 — vừa
   khít, nhưng chỉ cần thêm 1 ảnh là vỡ. Tách dữ liệu ra khỏi URL giữ được kiến trúc mở rộng
   về sau.

## Vòng đời một văn bản

```
tạo ──► tồn tại (tối đa 7 ngày) ──► hết hạn ──► bị xoá khỏi SQLite
```

- Hạn tính từ lúc upload.
- Có hàm dọn dẹp chạy mỗi 10 phút ([src/server.js:161](../src/server.js#L161)).
- Hạn cũng được kiểm tra lúc đọc ([src/server.js:239](../src/server.js#L239)), nên không
  phụ thuộc vào việc hàm dọn có chạy hay không.

## Những quyết định thiết kế và lý do

| Quyết định | Vì sao |
|---|---|
| Mã hoá ở client, không ở server | Server giữ khoá thì không còn zero-knowledge; một lần lộ DB là lộ tất |
| `id` suy ra từ `authKey` | Server tra cứu được mà không cần biết key; không có bảng ánh xạ "key → id" để rò rỉ |
| Một key, nhiều nhánh HKDF | Người dùng chỉ phải giữ một chuỗi, nhưng khoá mã hoá và khoá truy cập là hai thứ độc lập |
| Key dạng Base64URL | Ngắn (43 ký tự), cùng bảng chữ cái với header `Authorization`, đúng chuẩn RFC 4648 |
| Dùng SQLite chứ không dùng file JSON | Cần xoá theo hạn, và BLOB tiện cho dữ liệu nhị phân |
| Một khối GCM duy nhất | Với ≤ 200 từ (≈ 2 KB) chia khối chỉ làm code khó hiểu mà không thêm lợi ích |
