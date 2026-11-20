# 04 — API

Base URL: `http://127.0.0.1:8787`

Mọi endpoint dữ liệu đều yêu cầu header:

```
Authorization: Bearer <authKey Base64URL, 43 ký tự>
```

`authKey` là giá trị dẫn xuất từ key người dùng (xem [02-thuật toán](02-thuat-toan.md#bước-2--dẫn-xuất-ba-giá-trị-bằng-hkdf)),
**không phải** key `ZKV1-…`. Người dùng không bao giờ nhìn thấy `authKey`.

## Tổng quan

| Method | Đường dẫn | Body | Trả về |
|---|---|---|---|
| `POST` | `/api/secret` | gói tin nhị phân v1 hoặc v2 (29 byte – 25 MB) | `201` + JSON |
| `GET` | `/api/secret` | — | `200` + bytes gói tin |
| `PUT` | `/api/secret` | gói tin nhị phân mới v1 hoặc v2 (29 byte – 25 MB) | `200` + JSON |
| `DELETE` | `/api/secret` | — | `200` + JSON |
| `GET` | `/api/health` | — | `200` + JSON |

## POST /api/secret

Lưu một gói tin. Server băm `authKey` để ra `id` rồi ghi đè nếu `id` đã tồn tại.

**Header**

| Header | Giá trị |
|---|---|
| `Authorization` | `Bearer <authKey>` |
| `Content-Type` | `application/octet-stream` |

**Response `201`**

```json
{
  "ok": true,
  "id": "110ceb4b4b5810c5fe78756e32c6f7a5",
  "size": 49,
  "expiresAt": 1763513021000,
  "storage": "minio-s3"
}
```

`expiresAt` là mốc thời gian Unix (mili giây). Bản mã luôn được lưu trên MinIO S3 (`<id>.zkv`), còn SQLite chỉ giữ metadata (`id`, `created_at`, `expires_at`).

**Giới hạn**

- Tối đa **25 MB** mỗi lần gửi (`maxBytes` trong [src/server.js:33](../src/server.js#L33)) — đủ chứa văn bản + tệp đính kèm ≤ 20 MB.
- Tối đa **20 lượt ghi (`POST`/`PUT`/`DELETE`) / phút / IP**.
- TTL cố định 7 ngày, đặt trong `DEFAULTS.ttlSeconds`.

## GET /api/secret

Trả lại đúng bytes đã lưu.

**Response `200`**

| Header | Ý nghĩa |
|---|---|
| `Content-Type` | `application/octet-stream` |
| `Content-Length` | độ dài gói tin |
| `X-ZKV-Expires` | mốc hết hạn (mili giây) |
| `Cache-Control` | `no-store` |

**Lưu ý:** với key sai, server trả `404` chứ không `403`. Lý do: server không có "danh sách
chủ sở hữu" để mà phân biệt — nó chỉ băm ra một `id` rồi tra bảng. Không tìm thấy và không
có quyền là **một vài trường hợp giống hệt nhau**, nên không rò rỉ thông tin.

## PUT /api/secret

Cập nhật bản mã mới cho một văn bản **đã tồn tại** theo đúng key cũ (giữ nguyên key `ZKV1-…`).
Client tự mã hoá lại bằng cùng `rootKey` với **IV 12 byte ngẫu nhiên mới** trước khi gửi lên.

**Header**

| Header | Giá trị |
|---|---|
| `Authorization` | `Bearer <authKey>` |
| `Content-Type` | `application/octet-stream` |

**Response `200`**

```json
{
  "ok": true,
  "id": "110ceb4b4b5810c5fe78756e32c6f7a5",
  "size": 62,
  "expiresAt": 1763513621000,
  "storage": "minio-s3"
}
```

**Hành vi & giới hạn**

- Nếu `id` chưa tồn tại hoặc đã hết hạn → trả `404` (`NOT_FOUND` hoặc `EXPIRED`), **không** tự tạo mới như `POST`.
- Cập nhật thành công sẽ làm mới `expiresAt` thêm 7 ngày kể từ thời điểm sửa.
- Dùng chung hạn mức ghi (`20` lượt `POST`/`PUT`/`DELETE` / phút / IP) và giới hạn kích thước `maxBytes`.

## DELETE /api/secret

Xoá ngay văn bản gắn với key khỏi server (xoá cả bản ghi SQLite và object `<id>.zkv` trên MinIO S3 nếu đang bật).

**Header**

| Header | Giá trị |
|---|---|
| `Authorization` | `Bearer <authKey>` |

**Response `200`**

```json
{
  "ok": true,
  "id": "110ceb4b4b5810c5fe78756e32c6f7a5"
}
```

**Hành vi & giới hạn**

- Nếu `id` chưa tồn tại hoặc đã hết hạn → trả `404` (`NOT_FOUND` hoặc `EXPIRED`).
- Sau khi xoá, mọi yêu cầu `GET` / `PUT` / `DELETE` tiếp theo với cùng key đều trả `404`.
- Dùng chung hạn mức ghi (`20` lượt / phút / IP).

## GET /api/health

```json
{ "ok": true, "service": "zk-vault", "storage": "minio-s3", "time": 1762900000000 }
```

## Mã lỗi

| HTTP | `error` | Khi nào |
|---|---|---|
| `400` | `BAD_CONTAINER` | body ngắn hơn 29 byte |
| `401` | `UNAUTHORIZED` | thiếu/sai header `Authorization: Bearer …` hoặc `authKey` không hợp lệ |
| `403` | `FORBIDDEN` | đường dẫn thoát khỏi thư mục public |
| `404` | `NOT_FOUND` | không có `id` này |
| `404` | `EXPIRED` | có nhưng đã quá hạn |
| `405` | `METHOD_NOT_ALLOWED` | dùng phương thức khác |
| `413` | `PAYLOAD_TOO_LARGE` | body vượt 25 MB |
| `429` | `RATE_LIMITED` | vượt hạn mức mỗi phút |
| `500` | `INTERNAL` | lỗi không lường trước |

Mọi lỗi đều có dạng:

```json
{ "error": "NOT_FOUND", "message": "Không tìm thấy văn bản với key này (hoặc đã hết hạn)." }
```

## Ví dụ chạy thật

Dùng đúng gói tin 49 byte ở [02-thuật toán](02-thuat-toan.md#ví-dụ-số-thật):

```js
// ví dụ-gửi.js
const container = Buffer.from(
    '01a171075618ebda8508cc4104156fc26280f24bdf1cb3d12291bb218a3706ef6c' +
    '8dbffe8653c09d3d53b87a3bfcbebf2e',
    'hex'
);

const res = await fetch('http://127.0.0.1:8787/api/secret', {
    method: 'POST',
    headers: {
        // authKey ứng với key ZKV1-AAECAwQF… ở tài liệu 02
        'Authorization': 'Bearer lN7bd6Uxz7lU9DE3BNoZn0P4aD2SvfrfdDM73ZEU5tg',
        'Content-Type': 'application/octet-stream'
    },
    body: container
});

console.log(res.status, await res.json());
// 201 { ok: true, id: '110ceb4b4b5810c5fe78756e32c6f7a5', size: 49, expiresAt: … }
```

Đọc lại:

```js
const res = await fetch('http://127.0.0.1:8787/api/secret', {
    headers: { 'Authorization': 'Bearer lN7bd6Uxz7lU9DE3BNoZn0P4aD2SvfrfdDM73ZEU5tg' }
});
const bytes = new Uint8Array(await res.arrayBuffer());
```

Sửa nội dung (gửi gói tin mới đã mã hoá lại cùng key, với IV mới):

```js
const res = await fetch('http://127.0.0.1:8787/api/secret', {
    method: 'PUT',
    headers: {
        'Authorization': 'Bearer lN7bd6Uxz7lU9DE3BNoZn0P4aD2SvfrfdDM73ZEU5tg',
        'Content-Type': 'application/octet-stream'
    },
    body: newContainer
});
console.log(res.status, await res.json());
// 200 { ok: true, id: '110ceb4b4b5810c5fe78756e32c6f7a5', size: …, expiresAt: …, storage: 'sqlite' }
```

Xoá văn bản theo key:

```js
const res = await fetch('http://127.0.0.1:8787/api/secret', {
    method: 'DELETE',
    headers: { 'Authorization': 'Bearer lN7bd6Uxz7lU9DE3BNoZn0P4aD2SvfrfdDM73ZEU5tg' }
});
console.log(res.status, await res.json());
// 200 { ok: true, id: '110ceb4b4b5810c5fe78756e32c6f7a5' }
```

Kiểm tra server sống bằng curl:

```bash
curl http://127.0.0.1:8787/api/health
```

## Header bảo mật trên mọi response

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';
  img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none';
  form-action 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

CSP nghiêm tới mức **cấm cả `<style>` và `<script>` viết inline** — đó là lý do giao diện
phải tách thành file `app.js` và `style.css` riêng. Đổi lại, một lỗ hổng XSS (nếu có) cũng
khó chèn được script lạ để đánh cắp key.
