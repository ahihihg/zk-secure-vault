# 03 — Bảo mật

## "Zero-knowledge" ở đây nghĩa là gì

Chính xác: **server không có khả năng đọc nội dung**, kể cả khi toàn bộ dữ liệu của nó bị
lộ. Không phải "server hứa không đọc", mà là "server không có phương tiện để đọc".

Ba điều kiện tạo nên tính chất đó:

1. Bản rõ chỉ tồn tại ở trình duyệt.
2. `encKey` (khoá giải mã) không bao giờ được gửi đi — không có trong request, không có
   trong cookie, không có trong log.
3. Server tra cứu bằng `id` là **ảnh một chiều** của `authKey`, nên không thể đảo ngược.

## Kẻ tấn công là ai

| Kẻ tấn công | Có trong tay | Mục tiêu |
|---|---|---|
| **A. Quản trị server tò mò** | toàn bộ database, log, file | đọc nội dung văn bản |
| **B. Kẻ trộm database** | bản sao `vault.db` | như trên |
| **C. Người dùng khác** | tài khoản không có, chỉ có HTTP | dò ra văn bản của người khác |
| **D. Người có key** | key của một văn bản | đọc, sửa và xoá văn bản đó — **được phép** |

## Kết quả từng loại tấn công

| Tấn công | Kết quả | Cơ chế chặn |
|---|---|---|
| A/B đọc `vault.db` | Chỉ thấy `id` (hex), bản mã, mốc thời gian | Không có `encKey` ở bất kỳ đâu |
| A đọc log | Không thấy gì thêm ngoài `id`, kích thước, IP | Server không log body, không log `Authorization` |
| A dùng `authKey` thu được để tải bản mã | Tải được, **không giải mã được** | `authKey ≠ encKey`, và HKDF không cho phép suy ngược |
| C đoán `authKey` | Vô vọng: 2²⁵⁶ khả năng | 256 bit + rate limit 120 GET/phút |
| C đoán `id` để tải | Vô ích: API không nhận `id`, server tự tính từ `authKey` | thiết kế endpoint |
| Sửa 1 byte trong bản mã | Giải mã thất bại, không trả dữ liệu rác | thẻ GCM 128 bit |
| Sửa IV | Như trên | IV là đầu vào tính thẻ |
| Cắt bớt / nối thêm dữ liệu | `AUTH_FAILED` | GCM xác thực toàn bộ |
| Đổi byte version để "hạ cấp" định dạng | Bị chặn | version nằm trong AAD |
| Ghi đè / sửa / xoá bản mã của người khác | Không làm được | Server tự tính `id` từ `authKey`, không tin `id` client gửi; `PUT`/`DELETE` trả `404` nếu sai key |
| Tái sử dụng nonce khi sửa nhiều lần cùng key | Không xảy ra | Mỗi lần `PUT`, trình duyệt gọi `getRandomValues(12 byte)` sinh IV hoàn toàn mới |
| Chèn script để lấy key | Bị chặn | CSP `script-src 'self'`, không có script ngoài, render bằng `textContent` |
| Gửi dồn dập làm đầy ổ đĩa | Chặn một phần | rate limit 20 POST/phút + TTL 7 ngày + 64 KB/lần |
| Dò key bằng thời gian phản hồi | Không áp dụng | Không có so sánh từng byte; sai key = không tìm thấy `id` |

## Những gì hệ thống **không** bảo vệ

Đây là phần quan trọng nhất của tài liệu bảo mật — biết giới hạn mới biết mình đang ở đâu.

| Rủi ro | Vì sao không chặn được | Giảm thiểu |
|---|---|---|
| **Mất key** | Không có bản sao nào của key ngoài chỗ người dùng giữ | Người dùng tự lưu: password manager, bản in |
| **Ai có key là đọc, sửa và xoá được** | Bản chất mô hình capability dùng 1 key duy nhất, chưa tách key read-only và key quản trị | Cảnh báo trong UI; coi key như chìa khoá vật lý |
| **Máy người dùng bị nhiễm mã độc** | Malware đọc được RAM khi đang giải mã | Không có cách chặn ở tầng web |
| **Server xoá hoặc từ chối phục vụ** | Zero-knowledge không bảo vệ tính sẵn sàng | Backup, hoặc chấp nhận rủi ro |
| **Metadata** | Server buộc phải biết để vận hành: kích thước, thời điểm, IP, số lần đọc | Chấp nhận; hoặc thêm padding/onion routing |
| **HTTPS bị chặn** | Nếu triển khai không có TLS thì `authKey` lộ trên đường truyền | Bắt buộc HTTPS khi lên production |
| **Key bị chụp màn hình / camera** | Ngoài phạm vi phần mềm | Khuyến nghị dùng password manager |

## Vì sao mô hình này an toàn hơn mật khẩu

| | Mật khẩu | Key 256-bit |
|---|---|---|
| Kẻ tấn công biết "định dạng" | Có thể dò từ điển | Không có cấu trúc để dò |
| Số lần thử | Hữu hạn, thực tế vài triệu | 2²⁵⁶ |
| Lỗi phía người dùng | Dùng lại, đặt yếu, ghi ra giấy dán màn hình | Chỉ có một loại lỗi: mất key |
| Server biết bí mật | Có (hash hay plaintext) | **Không** |
| Khôi phục khi mất | Qua email/SMS | Không có |

Đánh đổi: mật khẩu có thể quên rồi đặt lại; key thì không. Đây là cái giá phải trả để
không cần tài khoản.

## Những việc cần làm nếu triển khai thật

1. **Bắt buộc HTTPS** (HSTS), vì `authKey` đi qua header mỗi request.
2. **Chặn giới hạn ở server**, không chỉ ở client: hiện 200 từ chỉ được kiểm tra trong
   trình duyệt, còn server nhận tới 64 KB.
3. **CAPTCHA hoặc proof-of-work** chống lạm dụng upload ẩn danh — đây chính là lý do
   Firefox Send phải đóng cửa năm 2020.
4. **Backup có mã hoá** cho `vault.db`, và quy trình xoá dữ liệu đúng hạn.
5. **Không thêm analytics/CDN** vào trang chứa key.
6. **Cân nhắc padding** để che kích thước văn bản.
