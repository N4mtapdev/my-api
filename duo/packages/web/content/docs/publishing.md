# Phát hành

Có hai đường để phát hành một app Duo: gửi vào catalog tuyển chọn qua pull request, hoặc tự host một catalog. Cả hai đường đều không cần tạo tài khoản.

## Tự host catalog của bạn

1. `bun run build` trong app. `dist/` là một catalog hoàn chỉnh có một app.
2. Đặt `dist/` lên bất kỳ host tĩnh nào phục vụ file với CORS (`Access-Control-Allow-Origin: *`) và cache ngắn cho `index.json`. GitHub Pages, object bucket, server riêng của bạn: bất cứ thứ gì trả đúng byte và không fallback về trang HTML cho path nào bị thiếu.
3. Chia sẻ URL của `index.json`. Ai đang chạy Duo dán nó vào ô Developer catalog trong App Store.

Muốn phát hành bản cập nhật: tăng `version`, thêm một dòng changelog, build, tải lên thư mục phát hành mới, rồi tải lên `index.json` mới. Không bao giờ sửa thư mục phát hành đã công bố.

## Các lane

| | Community | Official |
| --- | --- | --- |
| Ai | Bất kỳ ai | Chủ catalog, hoặc được thăng từ community |
| Môi trường chạy | Cùng một sandbox | Cùng một sandbox |
| Store | Huy hiệu community, hiện tác giả | Không huy hiệu |

Lane là trạng thái review, không phải khả năng. App official có đúng số quyền truy cập bằng app community. `check` từ chối `official` cho app mà danh sách tin cậy của repository không nêu tên.

## Catalog chính thức

Catalog tuyển chọn được build từ mã nguồn trong repository. Một app là một thư mục dưới `community-apps/<app-slug>/` chứa manifest, mã nguồn, icon, ảnh chụp màn hình, readme, changelog và giấy phép MIT, kèm một mục trong `community-apps/registry.json` nêu các tài khoản GitHub được phép giữ mã nguồn.

Bạn thêm thư mục đó trong pull request mở bằng mẫu `app-submission`. CI chạy `bun scripts/check-submissions.ts` trên nó; check đạt nghĩa là bài gửi đủ điều kiện để được review, chưa phải là được chấp nhận. Merge mới là chấp nhận. Sau merge, workflow publish build bản phát hành bất biến và ghi vào catalog tại `https://duo.doan-labs.com/catalog/index.json` - app chỉ thực sự sống sau khi lần chạy đó thành công.

Hướng dẫn đầy đủ, bao gồm các điều kiện chấp nhận cho lần phát hành đầu tiên, nằm ở [/publish](/publish).

## Telemetry

Shell chỉ báo cáo việc mở và đóng app theo id, và không lấy gì từ bên trong app. Một khung sandbox không thể bị quan sát sâu hơn - do chính thiết kế của nó.
