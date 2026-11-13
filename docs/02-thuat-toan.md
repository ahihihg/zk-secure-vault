# 02 — Thuật toán

Tài liệu này giải thích chính xác từng bước biến một đoạn văn bản thành bản mã và một key,
kèm **ví dụ số thật** để bạn đối chiếu.

## Bức tranh tổng thể

```
K (32 byte ngẫu nhiên)
 │
 ├── HKDF(K, "zkv1/enc")  ──► encKey  ──► AES-256-GCM ──► bản mã
 ├── HKDF(K, "zkv1/auth") ──► authKey ──► gửi server (định danh người giữ key)
 └── SHA-256("zkv1/id" ‖ authKey) ──► id ──► server dùng để tra cứu
```

## Bước 1 — Sinh key

```js
const K = crypto.getRandomValues(new Uint8Array(32));
```

`crypto.getRandomValues` lấy ngẫu nhiên từ CSPRNG của hệ điều hành (trên Windows là
`BCryptGenRandom`). 32 byte = 256 bit.

Vì sao 256 bit: để đoán được key phải thử 2²⁵⁶ khả năng. Ngay cả khi kẻ tấn công có
một triệu máy, mỗi máy thử một tỉ key mỗi giây, vẫn cần nhiều tỉ năm.

> Không dùng `Math.random()`. Hàm đó là PRNG tất định, đoán được trạng thái.

## Bước 2 — Dẫn xuất ba giá trị bằng HKDF

Một key phải phục vụ hai mục đích khác nhau: **mã hoá** và **định danh với server**. Nếu
dùng chung một giá trị cho cả hai thì lộ nhánh này là lộ nhánh kia, và nguy hiểm hơn là
"dùng lại khoá cho hai mục đích" — một lỗi kinh điển. HKDF tách ra ba nhánh độc lập:

```
encKey  = HKDF-SHA256(ikm = K, salt = ∅, info = "zkv1/enc",  L = 32)
authKey = HKDF-SHA256(ikm = K, salt = ∅, info = "zkv1/auth", L = 32)
id      = SHA-256("zkv1/id" ‖ authKey)[0..15]
```

**HKDF** gồm hai pha:

1. *Extract*: `PRK = HMAC-SHA256(salt, K)` — nén key về một giá trị 256 bit, loại bỏ mọi
   thiên lệch phân bố.
2. *Expand*: `OKM = HMAC-SHA256(PRK, info ‖ 0x01)` lặp tới đủ 32 byte — `info` khác nhau
   sinh ra những giá trị không liên quan gì tới nhau.

Vì `info` được đưa vào HMAC, biết `encKey` không cho phép tính `authKey` (phải làm lại
HMAC với khoá `PRK`, mà `PRK` chưa bao giờ lộ).

Mã nguồn: [src/crypto.js:171](../src/crypto.js#L171) — hàm `deriveKeys()`.

## Bước 3 — id để server tra cứu

```js
id = hex( SHA-256("zkv1/id" ‖ authKey)[0..15] )   // 16 byte -> 32 ký tự hex
```

Vì sao không gửi thẳng `authKey` xuống làm khoá chính của bảng? Hai lý do:

- Nếu client gửi `id` tuỳ ý, kẻ xấu có thể ghi đè bản mã của người khác. Server tự tính lại
  `id` từ `authKey` nên không thể giả mạo.
- `id` chỉ 128 bit, không đủ để dựng lại `authKey` 256 bit.

Đây cũng là lý do **không có endpoint liệt kê**: muốn biết `id` thì phải có `authKey`.

## Bước 4 — Mã hoá bằng AES-256-GCM

```js
const iv = crypto.getRandomValues(new Uint8Array(12));
const sealed = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv, additionalData: Uint8Array.of(0x01), tagLength: 128 },
  encKey,
  plaintext
);
// sealed = bản mã ‖ tag 16 byte
```

**AES-GCM** là mã hoá có xác thực (AEAD), gồm hai phần:

- **CTR**: sinh dòng khoá từ `encKey` và IV, XOR với bản rõ để ra bản mã.
- **GHASH**: tính thẻ 128 bit trên `AAD ‖ bản mã ‖ độ dài`. Thẻ được mã hoá bằng một khoá
  dẫn xuất từ `encKey` và IV.

Ba tham số quan trọng:

| Tham số | Giá trị ở đây | Vì sao |
|---|---|---|
| **IV** | 12 byte ngẫu nhiên **mỗi lần** | Dùng lại IV với cùng khoá sẽ làm lộ XOR hai bản rõ và phá luôn khoá xác thực. 12 byte là kích thước GCM tối ưu (96 bit). |
| **AAD** | 1 byte version (`0x01`) | Dữ liệu được xác thực nhưng không mã hoá. Nhờ đó không thể đổi phiên bản định dạng mà không làm hỏng thẻ. |
| **tagLength** | 128 bit (16 byte) | Cắt ngắn thẻ làm giảm độ an toàn theo cấp số nhân; 128 bit là chuẩn. |

Vì sao IV cũng chống được sửa đổi: IV là đầu vào khi tính thẻ (qua `J0 = IV ‖ 0³¹1`). Đổi
IV thì thẻ không còn khớp.

Mã nguồn: [src/crypto.js:226](../src/crypto.js#L226) — `encryptText()`,
[src/crypto.js:260](../src/crypto.js#L260) — `decryptText()`.

## Bước 5 — Định dạng gói tin

Khi lưu và truyền, ta cần biết IV để giải mã, nên gói tin gồm ba phần:

```
 offset  kích thước        nội dung
 ──────  ──────────        ─────────────────────────────
   0         1             version = 0x01
   1        12             IV (nonce)
  13     n + 16            bản mã (n byte) ‖ tag (16 byte)
```

Tổng kích thước = `13 + độ dài UTF-8 của văn bản + 16`.

## Ví dụ số thật

Lấy `K` cố định là `00 01 02 … 1f` và văn bản `"Mã két sắt: 4821"` (20 byte UTF-8):

```
K      : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
key    : ZKV1-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8

encKey : 1b0e366b948dee6ddb01b0fe49a8b78b8b02fa483ec48e9724b86737f18ec82c
authKey: 94dedb77a531cfb954f4313704da199f43f8683d92bdfadf74333bdd9114e6d8
id     : 110ceb4b4b5810c5fe78756e32c6f7a5

bản rõ : 4d c3 a3 20 6b c3 a9 74 20 73 e1 ba af 74 3a 20 34 38 32 31
```

Gói tin 49 byte (`1 + 12 + 20 + 16`):

```
01                                   version
a1 71 07 56 18 eb da 85 08 cc 41 04   IV (ngẫu nhiên cho lần mã hoá này)
15 6f c2 62 80 f2 4b df 1c b3 d1 22   bản mã (20 byte)
91 bb 21 8a 37 06 ef 6c
8d bf fe 86 53 c0 9d 3d 53 b8 7a 3b   tag (16 byte)
fc be bf 2e
```

Có thể tự kiểm chứng: [test/crypto.test.js](../test/crypto.test.js) có test khẳng định
`encKey` dẫn xuất đúng, và `id` do client tính khớp với `id` do server tính.

> Lưu ý: `encKey`/`authKey` ở trên là do HKDF tính từ một `K` cố định nên tái lập được.
> Trong sản phẩm, `K` luôn ngẫu nhiên nên các giá trị này đổi mỗi lần.

## Bước 6 — Key người dùng nhìn thấy

32 byte được mã hoá sang **Base64URL** (RFC 4648 §5) rồi gắn tiền tố cho dễ nhận ra:

```
ZKV1-3q2F9mW0tYb8sKcVx1nQzR7pJdLh4gAeUoXiT6NyP5w
└──┘ └──────────── 43 ký tự Base64URL ────────────┘
tiền tố               32 byte = 256 bit
```

Bảng chữ cái `A–Z a–z 0–9 - _`, bỏ dấu `=` đệm. 32 byte cho ra 43 ký tự
(43 × 6 = 258 bit, dư 2 bit đệm phải bằng 0 — điều kiện "canonical" của chuỗi).

**Hai điều phải nhớ khi dùng Base64URL cho key:**

1. Chuỗi **phân biệt hoa thường** — đổi `a` thành `A` là ra một key khác hoàn toàn.
2. Bảng chữ cái đã chứa `-` và `_`, nên **không thể chia nhóm bằng gạch nối**.
   Tiền tố `ZKV1-` chỉ để nhận ra đây là key, không phải dấu phân cách.

**Không có checksum.** Key gõ sai nhưng vẫn đủ 43 ký tự hợp lệ sẽ giải mã ra một key
khác, và máy chủ trả `404`. Đây là đánh đổi có chủ ý: lấy key ngắn hơn 13 ký tự và
bớt một thuật toán.

Mã nguồn: [src/keycode.js:113](../src/keycode.js#L113) — `encode()`,
[src/keycode.js:139](../src/keycode.js#L139) — `decode()`.

## Những gì KHÔNG làm

| Không làm | Vì sao |
|---|---|
| Tự viết AES/CTR | Web Crypto API đã được kiểm định; tự cài đặt là cách nhanh nhất để có lỗi kênh phụ |
| Dùng AES-ECB hay CBC không có MAC | ECB lộ mẫu; CBC không chống sửa đổi (padding oracle) |
| Dùng cùng khoá cho mã hoá và xác thực | HKDF tách nhánh để tránh đúng chuyện này |
| Lưu key trong localStorage | XSS một phát là lộ; key chỉ nằm trong biến RAM của trang |
| IV cố định / đếm từ 0 dùng lại | GCM tái sử dụng IV là thảm hoạ |
