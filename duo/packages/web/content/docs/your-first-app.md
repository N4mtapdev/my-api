# App đầu tiên

`create` viết ra năm file. Đây là chức năng từng file và chỗ nên sửa trước tiên.

## manifest.json

```json
{
  "id": "dev.example.my-app",
  "name": "my-app",
  "version": "1.0.0",
  "lane": "community",
  "entry": "main.tsx",
  "icon": "icon.png",
  "author": "Tên bạn",
  "repo": "https://github.com/ten-ban/ten-app",
  "license": "MIT"
}
```

Đổi `id` trước khi chia sẻ cho ai: nó là reverse-DNS, bất biến, và là khóa cho dữ liệu của app. `name` là nhãn trên màn hình chính, phải vừa trong mười hai ký tự. Mọi trường được liệt kê trong [Manifest](manifest.md).

## main.tsx

```tsx
import { os } from '@doan-labs/duo-sdk'
import { Nav, Page } from '@doan-labs/duo-uikit/nav.tsx'
import { colors } from '@doan-labs/duo-uikit/tokens.stylex.ts'
import * as stylex from '@stylexjs/stylex'
import { useEffect } from 'react'
import { createRoot } from 'react-dom/client'

function App() {
  useEffect(() => { requestAnimationFrame(() => os.ready()) }, [])
  return (
    <main {...stylex.props(styles.root)}>
      <Nav><Page title="my-app"><ul><li>App Duo đầu tiên của bạn</li></ul></Page></Nav>
    </main>
  )
}

const styles = stylex.create({
  root: { position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', color: colors.white, backgroundColor: colors.black }
})

await os.connect()
createRoot(document.body).render(<App />)
```

Có hai dòng quyết định. `await os.connect()` chạy trước mọi thứ được vẽ: nó bắt tay với shell và điền `os.view`, `os.owner`, `os.session`. `os.ready()` sau khung hình đầu tiên bảo shell gỡ màn hình che lúc khởi động. Mọi thứ còn lại chỉ là React.

Màu sắc lấy từ token của kit, không bao giờ ghi số cứng. Hai màn hình có mật độ điểm khác nhau và shell tinh chỉnh bảng màu cho từng màn; một giá trị hex sẽ nhìn sai ở một trong hai bên.

## Đọc độ gập

```tsx
import { useDisplay } from '@doan-labs/duo-uikit'

function Layout() {
  const view = useDisplay()   // { display, placement, width, height, visible, active, focused, angle }
  return <Grid columns={view.display === 'cover' ? 1 : 2} />
}
```

`display` là `cover` hoặc `inner`. `width` là kích thước hộp bạn thật sự có, và cũng là đúng thứ cần dựa vào để dàn trang: một nửa split của màn hình trong hẹp như màn hình ngoài. `angle` là góc bản lề theo độ, cập nhật sống trong khi người dùng gập máy. [Màn hình và nếp gấp](displays.md) có phần còn lại.

## Ghi nhớ một thứ gì đó

```tsx
import { useKV } from '@doan-labs/duo-sdk/react'

function Note() {
  const note = useKV(os.storage, 'field-note')   // { value, status, set, del }
  return <input value={note.value ?? ''} onChange={(e) => note.set(e.target.value)} />
}
```

Storage không đồng bộ, chỉ chứa chuỗi, và riêng tư theo từng app. `status` là `hydrating`, `ready`, `saving` hoặc `error`. Chỉnh sửa trong lúc hydrate được giữ lại, ghi chép được xếp hàng tuần tự, và cả hai màn hình thấy cùng một giá trị. [Storage](storage.md) giải thích cơ chế revision bên dưới.

## Một ví dụ hoàn chỉnh

[Fold Compass](https://github.com/doan-labs/duo/blob/main/examples/fold-compass/main.tsx) là một app độc lập chừng một trăm dòng: đọc góc bản lề, chuyển qua lại giữa thẻ bỏ túi trên màn hình ngoài và bảng điều khiển trên màn hình trong, và giữ một ghi chú nhỏ trong storage. [Bộ sưu tập developer](https://github.com/doan-labs/duo/blob/main/examples/developer/main.tsx) vẽ mọi component của kit ở cả hai độ rộng.
