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
| `POST` | `/api/secret` | gói tin nhị phân (13 + n + 16 byte) | `201` + JSON |
| `GET` | `/api/secret` | — | `200` + bytes gói tin |
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
  "expiresAt": 1763513021000
}
```

`expiresAt` là mốc thời gian Unix (mili giây).

**Giới hạn**

- Tối đa **64 KB** mỗi lần gửi (`maxBytes` trong [src/server.js:30](../src/server.js#L30)).
- Tối đa **20 lượt POST / phút / IP**.
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

## GET /api/health

```json
{ "ok": true, "service": "zk-vault", "time": 1762900000000 }
```

## Mã lỗi

| HTTP | `error` | Khi nào |
|---|---|---|
| `400` | `BAD_CONTAINER` | body ngắn hơn 29 byte |
| `403` | `FORBIDDEN` | đường dẫn thoát khỏi thư mục public |
| `404` | `NOT_FOUND` | không có `id` này |
| `404` | `EXPIRED` | có nhưng đã quá hạn |
| `405` | `METHOD_NOT_ALLOWED` | dùng phương thức khác |
| `413` | `PAYLOAD_TOO_LARGE` | body vượt 64 KB |
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
        // authKey ứng với key ZKV1-000G-40R4-… ở tài liệu 02
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
