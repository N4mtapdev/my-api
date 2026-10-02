# Vòng đời

Chuyện gì xảy ra giữa lúc shell tạo khung và khung hình đầu tiên của app, và cách kết nối kết thúc.

## Kết nối, rồi render, rồi ready

```ts
import { os } from '@doan-labs/duo-sdk'

await os.connect()          // hello → welcome → ack; xong thì os.view, os.owner, os.session đã có
createRoot(document.body).render(<App />)
requestAnimationFrame(() => os.ready())   // sau khi khung hình đầu tiên được vẽ
```

`connect()` gửi `hello` tới shell kèm phiên bản giao thức, phiên bản SDK và nonce dùng một lần mà khung nhận được qua `window.name`, thử lại mỗi giây. Shell trả lời `welcome` với khung nhìn, session và một `MessagePort` chuyển giao, hoặc `refused` khi phiên bản SDK không tương thích, giao thức sai hoặc khung bị chặn. Mọi tin nhắn sau đó đi qua cổng này.

Gọi `connect()` một lần, trước khi render. Gọi thêm lần nữa vẫn trả về cùng promise cũ. `ready()` báo cho shell biết khung hình đầu đã lên kính để nó gỡ màn hình che lúc khởi động; trước đó người dùng chỉ thấy icon của app.

## `welcome` mang theo gì

| | |
| --- | --- |
| `os.view` | Màn hình mà tài liệu này đang chạy. Xem [Màn hình và nếp gấp](displays.md). |
| `os.owner` | `{ epoch }` nếu khung nhìn này là chủ sở hữu các effect, ngược lại `null`. |
| `os.session.arg` | Tham số mà app khác hoặc một link đã mở bạn, nếu có. `os.session.onArg` bắn ra khi nó đổi. |
| `os.session.migration` | `{ from }` khi chủ sở hữu cần chuyển đổi dữ liệu do phiên bản cũ ghi. |
| `os.storage.limits` | Các giới hạn dưới đây. |

## Request và lỗi

Mọi phương thức SDK là một request qua cổng với một id. Các request được trả lời đúng thứ tự, và một thao tác ghi chỉ được xác nhận sau khi transaction của cơ sở dữ liệu shell hoàn tất. Request không nhận được trả lời trong năm giây được thử lại một lần với cùng id, để shell có thể khử trùng lặp; nếu lần thử lại cũng hết giờ, promise từ chối với `E_TIMEOUT`. Hết giờ không chứng minh việc ghi đã thất bại: đọc lại trước khi ghi tiếp.

Lỗi từ chối với `PlatformError`, trong đó `code` là một trong:

| Mã | Ý nghĩa |
| --- | --- |
| `E_ARGS` | Key sai, giá trị quá lớn, quá nhiều request đang chờ. |
| `E_QUOTA` | Hạn mức storage hoặc lệnh đã cạn. |
| `E_RATE` | Bị giới hạn tốc độ; cần chậm lại. |
| `E_DENIED` | Một quyền mà manifest không khai báo. |
| `E_STALE` | Lệnh chỉ dành cho chủ sở hữu được gọi từ khung không còn là chủ sở hữu. |
| `E_TIMEOUT` | Không có trả lời sau lần thử lại. |
| `E_CLOSED`, `E_GONE` | Khung nhìn bị thu hồi hoặc app bị gỡ. |
| `E_PROTOCOL` | Dữ liệu trao đổi sai dạng; shell đóng khung nhìn. |
| `E_STORAGE` | Cơ sở dữ liệu gặp sự cố. |

## Giới hạn

| | |
| --- | --- |
| Key | 128 byte, chỉ ký tự in được |
| Giá trị | 256 KiB, chỉ chuỗi |
| Key mỗi app | 4096 |
| Storage bền vững | 5 MiB mỗi app |
| Storage phiên | 64 KiB mỗi phiên |
| Payload lệnh | 16 KiB; 32 lệnh chờ cùng lúc |
| Request đang bay | 64; 200/giây duy trì, 400 đột phát |
| Phong bì tin nhắn | 300 KiB |

## Kết thúc

Shell gửi `bye` kèm lý do (`closed`, `uninstalled`, `updating`, `error`, `revoked`) rồi đóng cổng. Các promise đang chờ từ chối với `E_CLOSED`. Không có hook nào để chạy code sau đó: thứ gì phải sống sót thì đưa vào storage trước khi chuyện đó xảy ra. Khung bị lỗi chưa bắt sẽ báo lên shell; phím Escape bấm trong khung được chuyển tiếp và đưa người dùng về màn hình chính.
