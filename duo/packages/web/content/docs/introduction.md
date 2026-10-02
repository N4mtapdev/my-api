# Giới thiệu

Duo là bản mô phỏng iPhone Duo của Apple chạy trên trang web và trong cửa sổ desktop. Nó có đầy đủ hai màn hình của máy, bản lề kéo được, màn hình chính và một App Store. Bạn có thể viết app cho nó.

Một app Duo là một ứng dụng web nhỏ. Bạn viết bằng TypeScript và React, trang trí bằng StyleX và token của bộ kit, rồi CLI biên dịch tất cả thành một tài liệu HTML bất biến duy nhất. Shell chạy tài liệu đó trong một khung sandbox, cấp hai màn hình qua SDK, lưu dữ liệu, và cài app từ một catalog do bạn tự host.

## Ba gói chính

- **SDK**, `@doan-labs/duo-sdk`. Cây cầu nối giữa app và shell: màn hình, độ gập, storage, lệnh, widget và link. Một client duy nhất tên `os`, kèm `useKV` cho React.
- **UI kit**, `@doan-labs/duo-uikit`. Component và design token sinh ra đã hiểu màn hình ngoài và màn hình trong: `Screen`, `NavigationStack`, `List`, `Row`, `Button`, `Toggle`, `Text` và nhiều hơn nữa, cùng `useDisplay`.
- **CLI**, `@doan-labs/duo-cli`. `create`, `check`, `build`, `dev`, `preview` và `serve`.

App gói sẵn phiên bản SDK và kit mà nó biên dịch cùng. Phiên bản SDK lúc build là yêu cầu tối thiểu của máy chủ; phiên bản kit không bao giờ chặn gì.

## App chạy thế nào

```
mã nguồn → duo build → release.json + app.html + icon
                        (script, style và asset nhúng ngay trong file)

index.json → App Store → tải về đã xác minh → IndexedDB
                        → <iframe sandbox="allow-scripts">
```

Khung chạy app có origin mờ (opaque): không đọc được shell, không đọc được app khác, không có `localStorage`. Mọi thứ nó cần đi qua một `MessagePort` mà shell trao trong bắt tay ba bước: `hello`, `welcome`, `ack`. SDK lo phần bắt tay đó trong `os.connect()`.

Mỗi màn hình chạy một bản riêng của app, nên trong lúc máy gập thì màn hình kia vẫn giữ một khung nhìn đang sống. Cả hai bản dùng chung storage và session qua shell, và một trong hai được chỉ định là chủ sở hữu các effect. Đây là ý tưởng khiến developer vấp nhiều nhất; trang [Màn hình và nếp gấp](displays.md) nói kỹ về nó.

## Đọc tiếp

- [Bắt đầu](getting-started.md): chạy simulator trên máy bạn và đưa app lên màn hình chính.
- [App đầu tiên](your-first-app.md): dự án sinh ra làm gì, giải thích từng dòng.
- [Manifest](manifest.md), [Vòng đời](lifecycle.md), [Storage](storage.md), [Quyền](permissions.md): hợp đồng giữa app và hệ thống.
- [CLI](cli.md) và [Catalog](catalogs.md): build, phục vụ và cài đặt.
- [Tham chiếu SDK](/docs/sdk) và [tham chiếu UI kit](/kit) được sinh tự động từ mã nguồn.
