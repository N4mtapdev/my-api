# Manifest

Mỗi app một `manifest.json`. Bạn chỉ viết đúng file này về bản phát hành; `build` suy ra phần còn lại thành `release.json`, thứ mà shell, store và loader đọc. Cả hai kiểu dữ liệu được SDK export thành `Manifest` và `Release`.

```json
{
  "id": "dev.example.tides",
  "name": "Tides",
  "version": "1.2.0",
  "lane": "community",
  "entry": "./main.tsx",
  "icon": "./icon.png",
  "light": true,
  "edge": false,
  "widgets": ["small", "medium"],
  "network": ["https://api.example.com"],
  "permissions": ["geolocation"],
  "author": "Ada",
  "repo": "https://github.com/ada/tides",
  "license": "MIT"
}
```

## Các trường

| Trường | Bắt buộc | Ý nghĩa |
| --- | --- | --- |
| `id` | có | Reverse-DNS, chữ thường, tối đa 64 ký tự, bất biến. Khóa cho dữ liệu app, các bản phát hành và `os.open`. Hai app được trùng tên, không bao giờ trùng id. |
| `name` | có | Nhãn màn hình chính và tên trong store. Tối đa 12 ký tự, nếu không sẽ bị cắt trên màn hình ngoài. |
| `version` | có | Semver nghiêm ngặt. Bản prerelease chỉ chạy dưới `?dev=`. |
| `lane` | có | `community` hoặc `official`. Official là trạng thái review do chủ catalog đặt, không phải thứ tác giả tự cấp cho mình; `check` từ chối `official` cho id nằm ngoài `OFFICIAL.txt` của repository. |
| `entry` | có | Module khởi động, tính tương đối từ manifest. Được build thành một `app.html` với script, style và asset nhúng ngay trong file. |
| `icon` | có | PNG vuông 1024 px. Được copy thành `icon-1024.png`. |
| `light` | không | Thanh trạng thái vẽ màu tối trên app này. |
| `edge` | không | App vẽ tràn dưới dải trạng thái. |
| `widgets` | không | Các cỡ mà bạn phát hành snapshot qua `os.widget.set`: `small`, `medium`. Shell vẽ snapshot; không có mã app nào chạy ngoài khung. |
| `network` | không | Các origin HTTPS chính xác mà tài liệu được kết nối: scheme và host, port tùy chọn, không path, không wildcard. Chúng trở thành `connect-src` và `media-src` của tài liệu. Origin `http://` loopback chỉ được chấp nhận ở bản development. |
| `permissions` | không | Tên trong [bảng quyền](permissions.md): `geolocation`, `clipboard-read`, `clipboard-write`, `photos`. Không khai báo nghĩa là bị từ chối khi chạy. |
| `author`, `repo`, `license` | có | Hiển thị trong store. `repo` là URL `https://`. `license` phải là `MIT`. |

## Quy tắc

- `id` không bao giờ đổi. Đổi tên app chỉ đổi `name`. Id mới là một app mới, không có dữ liệu gì.
- `version` tăng ở mọi bản phát hành, và `CHANGELOG.md` phải nhắc tới nó; `check` đọc cả hai.
- Layout responsive là yêu cầu bắt buộc. Không có cờ nào để thoát khỏi màn hình ngoài: mọi app đều chạy ở bề rộng 387 điểm.

## release.json

```json
{
  "manifest": { "...": "file ở trên" },
  "build": { "sdk": "0.0.0", "kit": "0.1.0", "at": "2026-09-18T09:12:00Z", "commit": "…", "hash": "9f3ab21c" },
  "files": [
    { "path": "app.html", "bytes": 412000, "sha256": "…" },
    { "path": "icon-1024.png", "bytes": 15100, "sha256": "…" }
  ]
}
```

`build.sdk` là phiên bản SDK mà app biên dịch cùng và là yêu cầu tối thiểu của máy chủ: shell chỉ chạy bản phát hành khi SDK của nó thỏa `^build.sdk` theo quy tắc caret của npm, và khi SDK còn 0.x thì nghĩa là phải đúng phiên bản đó. `build.kit` được ghi lại cho trang store và không bao giờ chặn. Định danh bản phát hành là `version+hash`, nên một lần rebuild làm đổi bất kỳ byte nào cũng tạo ra định danh mới, và đường dẫn đã phát hành không bao giờ bị ghi đè.
