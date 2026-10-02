# Storage

Hai không gian key-value, đều chỉ chứa chuỗi, đều không đồng bộ, đều có đánh số phiên bản. Khung app không có `localStorage`; đây là toàn bộ câu chuyện lưu trữ.

| | `os.storage` | `os.session` |
| --- | --- | --- |
| Tuổi thọ | Cho tới khi app bị gỡ | Trong lúc app đang mở |
| Dùng chung bởi | Mọi khung nhìn, mọi phiên, trong IndexedDB của shell dưới app id | Mọi khung nhìn của app đang mở này |
| Kích thước | 5 MiB, 4096 key | 64 KiB |
| Dùng cho | Tài liệu, cài đặt, thứ gì người dùng sẽ tiếc nếu mất | Vị trí cuộn, mục đang chọn, bản nháp đang dở |

## API

```ts
await os.storage.get('lastTab')                       // string | null
const { rev } = await os.storage.set('lastTab', 'today')   // bền vững khi dòng này hoàn tất
await os.storage.del('lastTab')
const { keys, cursor } = await os.storage.keys()      // 256 mỗi trang; truyền cursor để lấy trang sau

const snap = await os.storage.snapshot()              // { rev, entries: [k, v][] }
const stop = os.storage.watch(snap.rev, (change) => { // { rev, k, v }; v là null khi xóa
  // áp dụng theo đúng thứ tự
})
```

Số phiên bản tính riêng từng không gian và tăng một sau mỗi thay đổi. Lấy một snapshot, rồi watch từ `rev` của nó: bạn nhận mọi thay đổi sau đó, đúng thứ tự, từ bất kỳ khung nhìn nào. Một khoảng trống trong `rev` nghĩa là bạn đã bỏ sót; lấy snapshot mới. Watch bị shell từ chối sẽ gọi lại một lần với `rev: -1`.

Cả hai khung nhìn của app thấy cùng số phiên bản, nên bản chiếu luôn cập nhật mà không cần bạn viết dòng code nào.

## React

```tsx
import { useKV } from '@doan-labs/duo-sdk/react'

const { value, status, error, set, del } = useKV(os.storage, 'note')
```

`status` là `hydrating` cho đến khi lần đọc đầu tiên về đích, rồi `ready`, `saving` khi đang ghi, hoặc `error`. Chỉnh sửa trong lúc hydrate được giữ lại và áp dụng sau đó. Ghi chép được xếp hàng theo từng key, và thay đổi đến từ khung kia sẽ ghi đè `value`. Một bản chiếu được dùng chung bởi mọi `useKV` trên cùng không gian, nên snapshot và watch chỉ xảy ra một lần mỗi tài liệu.

## Hết giờ

Thao tác ghi không được xác nhận trong năm giây được thử lại một lần với cùng request id, và shell khử trùng lặp. Nếu lần thử lại cũng hết giờ, promise từ chối với `E_TIMEOUT`. Hết giờ không phải bằng chứng việc ghi thất bại: đọc lại key trước khi ghi tiếp.

## Chuyển đổi dữ liệu

Giữ một key `schema`. Khi `os.session.migration` có giá trị ở chủ sở hữu, app đang khởi động trên dữ liệu do phiên bản `from` ghi: chuyển đổi tiến lên, chấp nhận key lạ, và hoàn tất trước `os.ready()`. Shell chỉ trao ngữ cảnh chuyển đổi cho chủ sở hữu, và không bao giờ cho app chạy qua `?dev=`.

## Gỡ bỏ

Gỡ app xóa sạch storage, session, widget snapshot và bản sao phục hồi trong một lượt. Dữ liệu của app development nằm dưới `dev:<origin>:<id>` và xóa từ dòng DEV trong App Store; nó không bao giờ đụng tới app đã cài cùng id.
