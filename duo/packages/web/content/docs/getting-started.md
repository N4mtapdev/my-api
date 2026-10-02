# Bắt đầu

Muốn viết app ngay trong trình duyệt, mở [Build](/build), kết nối key OpenRouter hoặc một endpoint tương thích OpenAI chạy được trên trình duyệt, rồi mô tả app bạn muốn. Không cần công cụ gì trên máy. Provider nhận request trực tiếp; Duo không proxy key hay prompt của bạn.

Quy trình dev cục bộ dưới đây vẫn dùng được cho dự án nguồn đầy đủ và catalog riêng.

Mười phút: simulator chạy trên máy, một app mới nằm trên màn hình trong, rồi được cài từ catalog như mọi app khác.

Bạn cần [Bun](https://bun.sh) và Python 3 kèm `pip`. Các gói chưa lên npm; repository build sẵn bản nén cục bộ cho CLI dùng thay thế.

## 1. Chạy simulator

```sh
git clone https://github.com/doan-labs/duo.git && cd duo
bun install
pip install usd-core && python3 scripts/prepare-model.py   # model của Apple vào public/model, làm một lần
bun run dev                                                # http://localhost:3000
```

Mở `http://localhost:3000/?deg=180` để xem máy mở phẳng, hoặc `?deg=0` để xem màn hình ngoài. Thanh trượt bên phải gập máy trực tiếp.

## 2. Tạo một app

Từ thư mục gốc repository:

```sh
bun scripts/package-platform.ts          # bản nén SDK, kit và CLI → .cache/platform-packages/
bun packages/cli/index.mjs create my-app --packages .cache/platform-packages/artifacts.json
cd my-app && bun install
```

Tên là kebab-case, tối đa mười hai ký tự. Bạn nhận được `manifest.json`, `main.tsx`, `icon.png`, `CHANGELOG.md` và một `package.json` nối sẵn vào bản nén cục bộ. Thư mục app đặt đâu cũng được; không nhất thiết nằm trong repository.

## 3. Chạy app trên điện thoại

```sh
bun run check   # biên giới import, TypeScript strict, trần 4 MiB
bun run dev     # build, theo dõi file, in ra link
```

`dev` in ra đường dẫn dạng `http://localhost:3000/?dev=http://localhost:5173&app=dev.example.my-app`. Mở nó. App của bạn nằm trên màn hình chính với nhãn DEV, chạy trong đúng sandbox mà app cài đặt nhận được. Sửa `main.tsx`, lưu lại, nạp lại simulator để nhận bản build mới.

## 4. Cài nó vào máy

```sh
bun run build                                        # dist/: index.json kèm bản phát hành
bun packages/cli/index.mjs serve dist --port 5173    # chạy từ thư mục gốc repository
```

Trong simulator, mở App Store, dán `http://localhost:5173/index.json` vào ô Developer catalog, rồi bấm Get và Open. Từ giờ app cài đúng đường mà mọi app Duo đi: được xác minh, có mã băm, nằm trong cơ sở dữ liệu của shell, khởi động từ đó.

## Thứ gì nằm ở đâu

| | |
| --- | --- |
| Dữ liệu app | IndexedDB của shell, dưới app id. App chạy qua `?dev=` dùng không gian `dev:` riêng; dòng DEV trong App Store xóa được nó. |
| Bản phát hành | `dist/apps/<id>/<version>+<hash>/`: `release.json`, `app.html`, `icon-1024.png`. Bất biến; rebuild làm đổi byte là một định danh mới. |
| Catalog | `dist/index.json`. App Store đọc file này. |

Tiếp theo: [App đầu tiên](your-first-app.md).
