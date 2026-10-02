# Catalog

App không được đóng sẵn trong Duo. Chúng cài từ một catalog: một `index.json` tĩnh đặt cạnh các thư mục phát hành bất biến, phục vụ với CORS từ bất kỳ origin nào. Bạn có thể tự host một cái ngay hôm nay.

## index.json

```json
{
  "apps": {
    "dev.example.tides": {
      "name": "Tides",
      "lane": "community",
      "author": "Ada",
      "repo": "https://github.com/ada/tides",
      "permissions": ["geolocation"],
      "releases": [
        { "release": "1.2.0+9f3ab21c", "sdk": "0.0.0", "bytes": 412000, "sha256": "…", "note": "Bảng thủy triều offline" },
        { "release": "1.1.0+02cc7e10", "sdk": "0.0.0", "bytes": 398000, "sha256": "…" }
      ]
    }
  }
}
```

Mỗi app một mục, bản phát hành mới nhất lên đầu. Mỗi bản phát hành nêu định danh, yêu cầu SDK của nó, dung lượng `app.html` và mã băm của `release.json`. `build` viết file này giúp bạn; muốn phát hành nhiều app, gộp các mục lại.

## Cấu trúc

```
index.json                                    được thay đổi; giữ cache ngắn
apps/<id>/<version>+<hash>/release.json       bất biến
apps/<id>/<version>+<hash>/app.html           bất biến
apps/<id>/<version>+<hash>/icon-1024.png      bất biến
```

Phát hành bản phát hành hoàn chỉnh trước khi index trỏ tới nó. Không bao giờ viết lại thư mục phát hành đã công bố; định danh bao gồm cả mã băm, nên một lần rebuild là một thư mục mới.

## Store làm gì

Dán URL index vào ô Developer catalog. Store tải nó một lần và khi bạn bấm Refresh thủ công; không có cơ chế hỏi ngầm. Với mỗi app, nó chọn bản phát hành mới nhất mà shell đang chạy thỏa mãn `sdk`. Không có bản nào tương thích thì dòng app ghi "Yêu cầu phiên bản nền tảng mới hơn".

Bấm Get sẽ tải `release.json`, đối chiếu mã băm với index, kiểm tra hợp lệ, tải `app.html` theo luồng với thanh tiến độ và trần dung lượng, xác minh mã băm với bản phát hành, tải icon, rồi ghi bản phát hành và bản ghi cài đặt trong một transaction duy nhất. Bị ngắt trước lúc commit thì không có gì được ghi. Bấm Open khởi chạy các byte đã lưu; catalog không được hỏi lại cho tới khi bạn refresh.

## Cập nhật

Một bản phát hành tương thích mới hơn trong cùng catalog hiện lên dưới dạng cập nhật. Cập nhật gắn với origin catalog mà app được cài từ đó. Bản cập nhật đã tải về được cài chờ trong khi app còn một khung nhìn đang mở, và kích hoạt khi không còn khung nào; bản cập nhật khởi động thất bại hai lần bị giữ lại và hiển thị nút Thử lại. Remove xóa bản phát hành, dữ liệu app và các widget của nó.

## App đóng sẵn

Simulator nạp Notes và Weather từ catalog preinstalled của chính nó trong lần chạy đầu để store không bao giờ trống trơn. Chúng là app đã cài như mọi app khác và có thể gỡ được.
