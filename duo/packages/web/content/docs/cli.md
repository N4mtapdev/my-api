# CLI

`@doan-labs/duo-cli`, một công cụ Bun nhỏ gọn. Cho tới khi được phát hành chính thức, chạy nó từ repository dưới dạng `bun packages/cli/index.mjs <lệnh>`, hoặc qua các script mà `create` ghi vào `package.json` của app.

```sh
bun scripts/package-platform.ts                  # bản nén + artifacts.json vào .cache/platform-packages/
bun packages/cli/index.mjs create <ten> --packages .cache/platform-packages/artifacts.json
bun packages/cli/index.mjs check   <thu-muc>
bun packages/cli/index.mjs build   <thu-muc> [--out <dir>]
bun packages/cli/index.mjs dev     <thu-muc> [--port 5173] [--simulator http://localhost:3000]
bun packages/cli/index.mjs preview <thu-muc> [--port 5173]
bun packages/cli/index.mjs serve   <dir>    [--port 5173]
```

## create

Ghi `manifest.json`, `main.tsx`, một `icon.png` tạm, `CHANGELOG.md` và `package.json` vào thư mục mới trong thư mục hiện tại. Tên là kebab-case, tối đa mười hai ký tự; nó thành tên thư mục, tên hiển thị và đoạn cuối của `dev.example.<ten>`.

`--packages <artifacts.json>` trỏ `package.json` sinh ra vào bản nén cục bộ của SDK, kit và CLI thay vì phiên bản đã phát hành. Bắt buộc trong thời gian các gói chưa lên npm.

Các script được sinh ra là `bun run check`, `bun run build` và `bun run dev`.

## check

Mọi thứ máy móc quyết định được trước khi con người nhìn vào:

- manifest hợp lệ, phiên bản có dòng changelog, lane `official` có danh sách tin cậy chống lưng;
- import nằm gọn trong app: không import tương đối vượt lên trên thư mục, không import tính toán, không module từ xa, không symlink nguồn, không lấy gì từ shell hay app khác;
- TypeScript strict đối chiếu với các export của SDK và kit;
- tài liệu build ra dưới 4 MiB.

Kết quả tạm được dọn sau đó. Lượt đạt in ra app id, dung lượng và các quyền bằng lời.

## build

Biên dịch `entry` với plugin StyleX thành một `app.html`, băm mọi file, và ghi ra một bản phát hành bất biến cùng catalog:

```
dist/
  index.json
  apps/<id>/<version>+<hash>/release.json
  apps/<id>/<version>+<hash>/app.html
  apps/<id>/<version>+<hash>/icon-1024.png
```

`build` từ chối ghi vào thư mục phát hành đã tồn tại. Tăng version, hoặc đổi byte để nhận mã băm mới.

## dev và preview

Cả hai build app vào một thư mục tạm và phục vụ trên loopback với CORS. `dev` còn theo dõi mã nguồn và build lại; mỗi lần build là một bản phát hành bất biến mới, và bạn nạp lại simulator để chọn nó. Cả hai in ra URL simulator với `?dev=` và `&app=` điền sẵn.

Shell tải `release.json` từ origin đó, xác minh tài liệu một lần, và chạy các byte của nó từ Blob URL trong đúng sandbox mà app cài đặt nhận được, dưới không gian lưu trữ `dev:` kèm nhãn DEV. Nhúng một URL tùy ý không phải là chế độ development; tài liệu phải là thứ do CLI build ra.

Ctrl-C dừng server và watcher, rồi xóa kết quả tạm.

## serve

Hosting tĩnh cho một catalog đã build trên loopback với CORS và không cache. Dán URL `/index.json` của nó vào ô Developer catalog trong App Store. Dùng nó để thử đúng đường cài đặt mà người dùng trải nghiệm, hoặc trao catalog cho máy khác trong mạng của bạn.
