# 01 — Kiến trúc

## Ba thành phần

```
┌────────────────────────┐        ┌───────────────────────────┐
│  TRÌNH DUYỆT           │        │  SERVER (Node.js)         │
│                        │  HTTPS │                           │
│  public/index.html     │◄──────►│  src/server.js            │
│  public/app.js         │        │  ├─ POST   /api/secret    │
│  src/crypto.js  ───────┤        │  ├─ GET    /api/secret    │
│  src/keycode.js        │        │  ├─ PUT    /api/secret    │
│                        │        │  ├─ DELETE /api/secret    │
│  sinh key, mã hoá v1/v2│        │  ├─ GET    /api/health    │
│  giải mã — TẤT CẢ ở đây│        │  └─ file tĩnh             │
│  (text + tệp ≤ 20 MB)  │        │                           │
└────────────────────────┘        │  SQLite: data/vault.db    │
                                  │  MinIO S3: src/s3.js      │
                                  │  (object <id>.zkv, SigV4) │
                                  └───────────────────────────┘
```

Điểm cốt lõi: **không có thành phần nào ở giữa biết nội dung**. Server là một cái tủ có
khoá số, chỉ giữ hộp đã niêm phong và trả lại đúng cái hộp đó cho ai trình đúng "vé".

## Luồng gửi

```
Người gửi                                                  Server
──────────────────────────────────────────────────────────────────────
1. gõ đoạn text (≤ 200 từ) và/hoặc chọn tệp đính kèm (≤ 20 MB)
2. bấm "Mã hoá & lưu"
   ├─ sinh K = 32 byte ngẫu nhiên
   ├─ encKey = HKDF(K, "zkv1/enc")
   ├─ authKey = HKDF(K, "zkv1/auth")
   ├─ id = SHA-256("zkv1/id" ‖ authKey)[0..15]
   ├─ bản mã = AES-256-GCM(encKey, gói v1 nếu chỉ text / gói v2 nếu có tệp)
   └─ POST bản mã, header Authorization: Bearer authKey
                              ────────────────────►
                                                       3. tính lại id từ authKey
                                                          PUT <id>.zkv lên MinIO S3
                                                          lưu metadata (id, created_at, expires_at) vào SQLite
                              ◄────────────────────
                                                       { ok, id, size, expiresAt, storage: "minio-s3" }
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
   ├─ authKey = HKDF(K, "zkv1/auth")
   └─ (sau 250 ms debounce) GET /api/secret, Bearer authKey
                              ────────────────────►
                                                       2. id = SHA-256(...)
                                                          tìm metadata trong SQLite, kiểm hạn
                                                          GET <id>.zkv từ MinIO S3
                              ◄────────────────────
3. nhận bản mã
   ├─ encKey = HKDF(K, "zkv1/enc")
   ├─ decryptPayload(): tự nhận diện gói v1 (0x01) hoặc v2 (0x02)
   └─ hiện văn bản gốc và/hoặc thẻ tải tệp đính kèm (tạo Blob trên RAM)
```

## Luồng sửa (giữ nguyên key)

```
Người giữ key                                              Server
──────────────────────────────────────────────────────────────────────
1. đã mở nội dung bằng key ZKV1-… → bấm "Sửa nội dung"
2. sửa text và/hoặc đổi/xoá tệp đính kèm → bấm "Lưu thay đổi"
   ├─ dùng lại K và encKey cũ
   ├─ sinh IV 12 byte ngẫu nhiên MỚI (không tái sử dụng nonce GCM)
   ├─ bản mã mới = AES-256-GCM(encKey, gói v1 hoặc v2, IV mới)
   └─ PUT /api/secret, header Authorization: Bearer authKey
                              ────────────────────►
                                                       3. tính lại id từ authKey
                                                          kiểm tra bản ghi tồn tại & còn hạn
                                                          ghi đè <id>.zkv mới trên MinIO, làm mới hạn 7 ngày trong SQLite
                              ◄────────────────────
                                                       { ok: true, id, size, expiresAt, storage }
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
                                                          xoá <id>.zkv khỏi MinIO S3 và metadata khỏi SQLite
                              ◄────────────────────
                                                       { ok: true, id }
4. ẩn khung kết quả — key cũ không còn mở được nữa (trả 404)
```

## Ai giữ gì

| Giá trị | Ai tạo | Client có | Server có | Có trong database / MinIO |
|---|---|---|---|---|
| `K` (key người dùng) | client | ✅ (trong RAM) | ❌ | ❌ |
| `encKey` | client | ✅ | ❌ | ❌ |
| `authKey` | client | ✅ | ✅ (qua header) | ❌ (chỉ có hash) |
| `id` = SHA-256("zkv1/id"‖authKey) | cả hai tính độc lập | ✅ | ✅ | ✅ (khoá chính / tên object `<id>.zkv`) |
| bản mã (gói v1/v2) | client | ✅ | ✅ | ✅ (chỉ trên MinIO `<id>.zkv`, SQLite không lưu BLOB) |
| văn bản gốc, tên tệp, MIME, dữ liệu tệp | client | chỉ khi giải mã | ❌ | ❌ |

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
- Có hàm dọn dẹp chạy mỗi 10 phút ([src/server.js:193](../src/server.js#L193)).
- Hạn cũng được kiểm tra lúc đọc, sửa và xoá ([src/server.js:296](../src/server.js#L296), [src/server.js:333](../src/server.js#L333), [src/server.js:388](../src/server.js#L388)), nên không
  phụ thuộc vào việc hàm dọn có chạy hay không.

## Những quyết định thiết kế và lý do

| Quyết định | Vì sao |
|---|---|
| Mã hoá ở client, không ở server | Server giữ khoá thì không còn zero-knowledge; một lần lộ DB là lộ tất |
| `id` suy ra từ `authKey` | Server tra cứu được mà không cần biết key; không có bảng ánh xạ "key → id" để rò rỉ |
| Một key, nhiều nhánh HKDF | Người dùng chỉ phải giữ một chuỗi, nhưng khoá mã hoá và khoá truy cập là hai thứ độc lập |
| Key dạng Base64URL | Ngắn (43 ký tự), cùng bảng chữ cái với header `Authorization`, đúng chuẩn RFC 4648 |
| Mô hình Hybrid toàn thời gian (SQLite + MinIO S3) | SQLite cực nhẹ chỉ giữ metadata `(id, created_at, expires_at)` để tra cứu và quét TTL; MinIO S3 giữ 100% bản mã `<id>.zkv` qua AWS Signature v4. Chạy `node src/server.js` tự động bật MinIO bằng `docker compose up -d` |
| Một khối GCM duy nhất (v1 & v2) | Đơn giản, vừa đủ cho văn bản ≤ 200 từ và tệp đính kèm ≤ 20 MB; hỗ trợ gói v2 mã hoá kín cả tên tệp lẫn MIME type |
