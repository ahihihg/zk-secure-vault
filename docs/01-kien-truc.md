# 01 — Kiến trúc

## Ba thành phần

```
┌────────────────────────┐        ┌────────────────────────┐
│  TRÌNH DUYỆT           │        │  SERVER (Node.js)      │
│                        │  HTTPS │                        │
│  public/index.html     │◄──────►│  src/server.js         │
│  public/app.js         │        │  ├─ POST   /api/secret │
│  src/crypto.js  ───────┤        │  ├─ GET    /api/secret │
│  src/keycode.js        │        │  ├─ PUT    /api/secret │
│                        │        │  ├─ DELETE /api/secret │
│  sinh key, mã hoá,     │        │  └─ file tĩnh          │
│  giải mã — TẤT CẢ ở đây│        │                        │
│                        │        │  SQLite: data/vault.db │
│                        │        │  (hoặc MinIO S3)       │
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

## Luồng sửa (giữ nguyên key)

```
Người giữ key                                              Server
──────────────────────────────────────────────────────────────────────
1. đã mở văn bản bằng key ZKV1-… → bấm "Sửa nội dung"
2. nhập nội dung mới → bấm "Lưu thay đổi"
   ├─ dùng lại K và encKey cũ
   ├─ sinh IV 12 byte ngẫu nhiên MỚI (không tái sử dụng nonce GCM)
   ├─ bản mã mới = AES-256-GCM(encKey, text mới, IV mới)
   └─ PUT /api/secret, header Authorization: Bearer authKey
                              ────────────────────►
                                                       3. tính lại id từ authKey
                                                          kiểm tra bản ghi tồn tại & còn hạn
                                                          ghi đè bản mã mới, làm mới hạn 7 ngày
                              ◄────────────────────
                                                       { ok: true, id, size, expiresAt }
4. cập nhật hiển thị — key ZKV1-… giữ nguyên
```

Điểm quan trọng: cùng một `encKey` nhưng **bắt buộc sinh IV mới** cho mỗi lần `PUT`.
Nếu dùng lại IV cũ với cùng `encKey` trong AES-GCM, hai bản mã sẽ làm lộ XOR của hai
bản rõ và phá hỏng khoá xác thực GHASH.

## Luồng xoá theo key

```
Người giữ key                                              Server
──────────────────────────────────────────────────────────────────────
1. đã mở văn bản bằng key ZKV1-… → bấm "Xoá văn bản"
2. gửi DELETE /api/secret, header Authorization: Bearer authKey
                              ────────────────────►
                                                       3. tính lại id từ authKey
                                                          kiểm tra tồn tại & còn hạn
                                                          xoá khỏi SQLite (và MinIO S3 nếu bật)
                              ◄────────────────────
                                                       { ok: true, id }
4. ẩn khung kết quả — key cũ không còn mở được nữa (trả 404)
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
tạo (POST) ──► tồn tại (tối đa 7 ngày) ──► xoá theo key (DELETE) / hết hạn ──► bị xoá
                    │            ▲
                    └─ sửa (PUT) ┘ (làm mới hạn 7 ngày, giữ nguyên key)
```

- Hạn tính từ lúc upload (và được làm mới 7 ngày sau mỗi lần sửa `PUT`).
- Có hàm dọn dẹp chạy mỗi 10 phút ([src/server.js:165](../src/server.js#L165)).
- Hạn cũng được kiểm tra lúc đọc, sửa và xoá ([src/server.js:272](../src/server.js#L272), [src/server.js:313](../src/server.js#L313), [src/server.js:372](../src/server.js#L372)), nên không
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
