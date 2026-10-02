# Quyền

App chỉ dùng được đúng những gì manifest khai báo. Không có prompt lúc chạy và không có màn hình cài đặt: chủ catalog review danh sách, dòng trong store hiển thị nó, và shell thi hành nó.

## Bảng quyền

| Tên | Loại | Cấp được gì |
| --- | --- | --- |
| `geolocation` | tính năng trình duyệt | `navigator.geolocation` trong khung. Trình duyệt hoặc hệ điều hành vẫn hiện prompt riêng của nó. |
| `clipboard-read` | tính năng trình duyệt | Đọc clipboard. |
| `clipboard-write` | tính năng trình duyệt | Ghi clipboard. |
| `photos` | dịch vụ của máy chủ | `os.photos.list()`, `os.photos.get(id)`, `os.photos.add(blob)`: thư viện ảnh của simulator. `add` chỉ dành cho chủ sở hữu. |

Tính năng trình duyệt được ủy quyền qua thuộc tính `allow` của khung, liệt kê mọi tính năng kiểm soát theo chính sách và đặt từng cái về `'none'` trừ khi được khai báo. Dịch vụ của máy chủ là các phương thức bridge mà shell chặn theo manifest: lệnh gọi chưa khai báo thất bại với `E_DENIED` trước khi bất kỳ tham số nào được đọc.

Camera và microphone luôn bị từ chối. Bắt hình ảnh từ origin mờ chưa khả dụng cho app; app Camera của shell là một component của shell, không phải app cài được. Chụp màn hình, fullscreen, thanh toán, USB, MIDI, autoplay, wake lock và XR cũng bị từ chối.

## Mạng

```json
"network": ["https://api.example.com", "https://tiles.example.org:8443"]
```

Origin chính xác: scheme, host, port tùy chọn. Không path, không wildcard, không thông tin đăng nhập. `build` ghi chúng vào Content Security Policy của tài liệu thành `connect-src` và `media-src`, nên trình duyệt từ chối kết nối tới bất kỳ origin nào bạn chưa khai báo. Request đi ra với `Origin: null` và không kèm thông tin đăng nhập; API phía kia phải cho phép `*`.

Bản development chấp nhận origin `http://` loopback để bạn nói chuyện với server chạy trên máy mình.

## Sandbox tự làm gì

Độc lập với mọi thứ bạn khai báo, khung chạy với `sandbox="allow-scripts"` và không có `allow-same-origin`. Nó không đọc được tài liệu hay storage của shell, không với tới app khác, không mở được khung, worker hay form, và không nạp được script hay style nào không nằm trong tài liệu đã build. Chính sách của nó được cố định lúc khung được tạo và băm vào bản phát hành, nên tài liệu đã được review chính là tài liệu được chạy.
