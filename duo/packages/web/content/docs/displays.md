# Màn hình và nếp gấp

Duo có màn hình ngoài 387 điểm và màn hình trong 790 điểm, cùng cao 850. Màn hình trong chứa một app tràn bề rộng hoặc hai app đứng cạnh nhau. App của bạn chạy trên màn nào đang sáng, và trong lúc máy gập thì màn hình kia vẫn đang chạy một bản sao, nên việc bàn giao không phải remount và không chớp hình.

## Khung nhìn

```ts
os.view          // { display, placement, width, height, visible, active, focused, angle }
os.onView(cb)    // tối đa một sự kiện mỗi khung hình, chỉ khi có thay đổi

// React
const view = useDisplay()   // từ @doan-labs/duo-uikit
```

| Trường | Giá trị | Dùng cho |
| --- | --- | --- |
| `display` | `cover`, `inner` | Hành vi khác nhau theo từng mặt kính, ví dụ bố cục bỏ túi. |
| `placement` | `full`, `left`, `right` | Nửa nào của màn hình trong mà khung split đang chiếm. |
| `width`, `height` | điểm | Dàn trang. Một nửa split hẹp như màn hình ngoài, nên dàn theo hộp, đừng dàn theo `display`. |
| `angle` | 0 đến 180 | Góc bản lề, cập nhật sống. 0 là gập kín, 180 là mở phẳng. |
| `visible` | | Khung nhìn này có đang trên kính không. |
| `active` | | Có phải khung nhìn mà người dùng đang tương tác không. |
| `focused` | | Có giữ tiêu điểm bàn phím không. |

## Thiết kế cho màn hình ngoài trước

Bố cục đọc tốt ở 387 điểm thì khi mở ra có nơi để thở: danh sách thành danh sách đứng cạnh phần chi tiết, thanh công cụ trải ra, biểu đồ lấy lại nhãn trục. Chiều ngược không bao giờ ổn. Đừng bao giờ giấu một tính năng nào khỏi màn hình ngoài; người dùng có thể chẳng bao giờ mở máy ra để tìm nó.

Component của kit tự co lại ở độ rộng màn hình ngoài. Component của bạn cũng nên vậy.

## App của bạn chạy hai bản

Mỗi màn hình là một tài liệu riêng với cây React riêng. Trạng thái module không dùng chung. Thứ mà cả hai bản phải thống nhất nằm trong shell:

- `os.storage`: bền vững, riêng tư theo app id, sống sót qua mọi thứ.
- `os.session`: tạm thời, dùng chung giữa mọi khung nhìn của app đang mở, biến mất khi app đóng.

Cả hai là không gian key-value có đánh số phiên bản; xem [Storage](storage.md).

## Một chủ sở hữu duy nhất

Shell chỉ định một khung nhìn làm **chủ sở hữu**: người kết nối đầu tiên, giữ vai đến khi khung đó đóng, xác định bằng một epoch.

```ts
os.owner                       // { epoch } hoặc null
os.onOwner(cb)                 // bàn giao khi chủ sở hữu đóng

os.commands.send('refresh', '')          // khung nào cũng gửi được; xong khi chủ sở hữu xác nhận
os.commands.onCommand(async (c) => …)    // chỉ chạy ở chủ sở hữu
os.widget.set('small', { lines: [{ text: 'Thủy triều 1.2 m', role: 'value' }] })   // chỉ chủ sở hữu
```

Bản chiếu vẽ lại tất cả nhưng không khởi động gì: không âm thanh, không gọi mạng, không bộ đếm của riêng nó. Ý định chỉ được xảy ra một lần đi dưới dạng lệnh; chủ sở hữu chạy nó và xác nhận, promise của bên gửi mới hoàn tất. Lệnh được thử lại đến khi được xác nhận và khử trùng lặp theo id, nên việc bàn giao quyền sở hữu giữa chừng không làm mất hay nhân đôi lệnh. Lệnh chỉ dành cho chủ sở hữu mà gọi từ khung đã mất quyền sẽ thất bại với `E_STALE`.

Thử là biết: mở app, gập máy hết cỡ, mở ra. Cùng nội dung, cùng vị trí cuộn, đúng một lần.

## Widget

Khai báo `widgets` trong manifest và phát hành snapshot từ chủ sở hữu. Shell vẽ nó và hiển thị tuổi của ảnh chụp; không có mã app nào chạy trên màn hình chính.

```ts
os.widget.set('medium', {
  lines: [
    { text: 'Thủy triều cao tiếp theo', role: 'label' },
    { text: '14:32', role: 'value' },
    { text: 'trong 2 giờ 10 phút', role: 'caption' }
  ],
  tint: 'glass',
  arg: 'tide=next'     // chuyển vào os.session.arg khi widget mở app
})
```

Tối đa tám dòng, mỗi dòng 64 ký tự. `arg` tối đa 256 ký tự.

## Link giữa các app

```ts
os.open('labs.doan.ipduo.maps', 'q=tides')   // theo id, kèm tham số tùy chọn
os.home()
```

App đích nhận tham số trong `os.session.arg`. Shell sở hữu scheme; app không tự đăng ký scheme riêng được.
