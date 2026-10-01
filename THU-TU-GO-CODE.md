# 📝 Thứ tự gõ file - hướng dẫn chi tiết từng bước cho dự án iPhone Duo

> File này trả lời đúng một câu hỏi: **"Bây giờ tôi mở file nào, gõ gì vào đó, xong rồi thì sang file nào tiếp theo?"**
> Kèm theo là toàn bộ lưu ý bắt buộc để code bạn gõ vào không bị lỗi, không bị từ chối merge, và không phá vỡ chuẩn của repo.
> Nếu bạn chưa cài xong môi trường, quay lại đọc `HUONG-DAN-SETUP.md` trước, rồi mới đọc file này.

---

## Mục lục

1. [Cách đọc file này](#1-cách-đọc-file-này)
2. [Bản đồ dự án - code sống ở đâu](#2-bản-đồ-dự-án-code-sống-ở-đâu)
3. [5 nguyên tắc phải nhớ trước khi gõ dòng code đầu tiên](#3-5-nguyên-tắc-phải-nhớ-trước-khi-gõ-dòng-code-đầu-tiên)
4. [Lộ trình A - Sửa trang web giới thiệu (dễ nhất, nên bắt đầu)](#4-lộ-trình-a-sửa-trang-web-giới-thiệu)
5. [Lộ trình B - Viết một app chạy thật trong simulator](#5-lộ-trình-b-viết-một-app-chạy-thật-trong-simulator)
6. [Lộ trình C - Viết app cộng đồng (community-apps)](#6-lộ-trình-c-viết-app-cộng-đồng)
7. [Lộ trình D - Sửa lõi simulator (nâng cao)](#7-lộ-trình-d-sửa-lõi-simulator-nâng-cao)
8. [Bảng tổng hợp thứ tự gõ file - in ra dán cạnh màn hình](#8-bảng-tổng-hợp-thứ-tự-gõ-file)
9. [20 lưu ý bắt buộc khi gõ code](#9-20-lưu-ý-bắt-buộc-khi-gõ-code)
10. [Bảng xử lý lỗi thường gặp khi gõ code](#10-bảng-xử-lý-lỗi-thường-gặp)
11. [Tóm tắt 30 giây](#11-tóm-tắt-30-giây)

---

## 1. Cách đọc file này

**Quy ước dùng trong toàn bộ tài liệu:**

- Đường dẫn như `packages/web/src/home/hero.tsx` là **đường dẫn tính từ thư mục `duo/`**, trừ khi ghi rõ "gốc repo" (thì tính từ `my-api/`).
- "Lưu lại" nghĩa là nhấn `Ctrl+S` trong VS Code. Biome extension đã cài theo hướng dẫn sẽ tự format file ngay khi lưu, bạn không cần can thiệp.
- Mỗi bước đều có dòng "Thành công trông thế nào". Đó là dấu hiệu để bạn biết được bước đó đúng rồi, mới được sang bước kế tiếp. **Không nhảy bước.**
- Khó dễ tăng dần: Lộ trình A chỉ sửa chữ và màu, khoảng 30 phút. Lộ trình B viết một app hoàn chỉnh, khoảng 2-3 tiết học. Lộ trình C làm app phát hành được, khoảng 1 buổi. Lộ trình D là việc của người giữ repo, chỉ đọc tham khảo.

**Quy tắc vàng:** sau mỗi bước có gõ code, chạy `bun run typecheck` trong thư mục `duo/`. Lỗi TypeScript hiện càng sớm càng dễ sửa. Đừng đợi gõ xong 5 file rồi mới kiểm tra, khi đó lỗi chồng lỗi rất khó tìm.

---

## 2. Bản đồ dự án - code sống ở đâu

Trước khi biết gõ file nào, phải biết mỗi việc nằm ở đâu. Đây là cây thư mục, chỉ giữ lại phần bạn sẽ động tới:

```
my-api/                          ← gốc repo
├── HUONG-DAN-SETUP.md           ← cài môi trường (đã đọc)
├── THU-TU-GO-CODE.md            ← file bạn đang đọc
├── duo-preview.mjs              ← server preview 1 cổng, tự live reload
└── duo/                         ← MỌI code nằm trong đây
    ├── package.json             ← scripts chung: dev, typecheck, build
    ├── serve.ts                 ← dev server của simulator (cổng 3000)
    ├── scripts/
    │   ├── prepare-model.py     ← tải model 3D của Apple (chạy 1 lần)
    │   ├── build-app.ts         ← đóng gói app cộng đồng thành release
    │   └── simulator.ts         ← copy simulator vào trang web khi build
    ├── packages/
    │   ├── shell/               ← LÕI SIMULATOR: iPhone 3D, màn hình, hệ điều hành giả
    │   │   ├── main.ts          ← điểm khởi động, kết nối bridge với trang web
    │   │   ├── device.ts        ← thân máy, bản lề, trạng thái gập
    │   │   ├── screen.ts        ← "chụp" màn hình home thành texture
    │   │   ├── os.tsx           ← hệ điều hành giả: mở app, task, màn hình trong/ngoài
    │   │   ├── apps.ts          ← ⭐ danh sách app hiện trên màn hình chính
    │   │   ├── springboard/     ← màn hình chính, Control Center, khóa máy
    │   │   ├── runtime/         ← nơi chạy app bên ngoài (sandbox, storage...)
    │   │   ├── shaders/         ← shader WebGL của màn hình gập
    │   │   └── index.html       ← khung HTML của simulator
    │   ├── apps/                ← ⭐ 30 app "nướng sẵn" viết React + StyleX
    │   │   ├── notes/           ← app Ghi chú - ví dụ mẫu tốt nhất để học theo
    │   │   ├── calculator/      ← app Máy tính - ví dụ đơn hơn notes
    │   │   ├── weather/         ← app Thời tiết - ví dụ có gọi API ngoài
    │   │   └── <tên-app>/       ← app mới của bạn sẽ nằm ở đây
    │   ├── sdk/                 ← bộ API mà app dùng (storage, mirror...)
    │   ├── uikit/               ← bộ giao diện: Button, Nav, VStack, Screen...
    │   │   ├── tokens.stylex.ts ← ⭐ mọi màu/chữ/khoảng cách lấy từ đây
    │   │   └── icons/index.ts   ← danh sách icon SF Symbol
    │   └── web/                 ← TRANG WEB GIỚI THIỆU (TanStack Start + Vite)
    │       ├── src/
    │       │   ├── home/        ← ⭐ các section trang chủ: hero, works, fold...
    │       │   ├── routes/      ← ⭐ mỗi file là 1 route: /, /docs, /kit...
    │       │   ├── simulator.tsx← khung nhúng simulator vào trang web
    │       │   ├── nav.tsx      ← thanh điều hướng trên cùng
    │       │   ├── footer.tsx   ← chân trang
    │       │   ├── site.ts      ← tên, mô tả site dùng cho meta/SEO
    │       │   └── generated/   ← ❌ KHÔNG sửa tay, code sinh tự động
    │       ├── content/docs/    ← bài docs dạng markdown, 1 file = 1 trang
    │       └── scripts/         ← sinh api.ts, tokens.ts trước khi chạy web
    ├── community-apps/          ← ⭐ app cộng đồng, mỗi thư mục 1 app
    │   ├── pomodoro-timer/      ← ví dụ app cộng đồng hoàn chỉnh, nhỏ gọn
    │   └── <slug>/              ← app của bạn (nếu đi đường cộng đồng)
    └── docs/                    ← tài liệu kỹ thuật của repo gốc (tiếng Anh)
        ├── working.md           ← quy tắc làm việc chính thức
        ├── architecture.md      ← kiến trúc tổng thể
        └── debug.md             ← công cụ gỡ lỗi (?debug, state probe)
```

**Ba ngôi sao (⭐) cần nhớ:**

- `packages/shell/apps.ts` - nơi "đăng ký" app để nó xuất hiện trên màn hình chính.
- `packages/uikit/tokens.stylex.ts` - kho màu, cỡ chữ, khoảng cách. Mọi số liệu dùng trong app phải lấy từ đây.
- `packages/web/src/home/` và `packages/web/src/routes/` - nơi sửa giao diện trang web.

**Một dấu ❌:** `packages/web/src/generated/` và mọi file đuôi `.gen.ts`. Chúng được sinh tự động khi chạy dev/build. Sửa tay sẽ bị ghi đè mất, và reviewer sẽ bắt bạn làm lại.

---

## 3. 5 nguyên tắc phải nhớ trước khi gõ dòng code đầu tiên

### Nguyên tắc 1: Format do Biome lo, bạn lo nội dung

Repo dùng Biome với cấu hình cố định: nháy đơn `'`, không dấu chấm phẩy cuối dòng, thụt lề 2 dấu cách, tối đa 120 cột. Extension Biome đã đặt làm formatter mặc định nên **bạn không cần bận tâm đến format**. Tệ nhất bạn có thể làm là cài thêm Prettier hoặc tự sửa tay kiểu cách, làm git diff loạn. Gõ code của bạn đi, `Ctrl+S`, extension tự dọn.

### Nguyên tắc 2: Style là StyleX, không phải Tailwind, không phải style attribute

Toàn bộ styling viết bằng `stylex.create({...})` đặt ở **cuối file**, rồi gắn qua `stylex.props(styles.ten)`. Tuyệt đối không:

- Dùng `className` hoặc `style` cạnh `stylex.props`.
- Dùng thuộc tính viết tắt (`font`, `margin`, `padding`) - chỉ dùng viết dài (`fontSize`, `marginBottom`).
- Dùng selector con cháu, `!important`.
- Chế số màu lạ - lấy token từ `packages/uikit/tokens.stylex.ts`.

Viết tắt thường vẫn chạy qua TypeScript nhưng sẽ **lỗi ngay ở bước build** khi Babel dịch StyleX. Lỗi đó khó tìm hơn nhiều so với viết đúng từ đầu.

### Nguyên tắc 3: Tên file kebab-case

`ve-tay-app.tsx` đúng. `VeTayApp.tsx` sai. Riêng thư mục `packages/web/src/routes/` được miễn vì file route phải theo quy ước của TanStack (`__root.tsx`, `docs.$.tsx`).

### Nguyên tắc 4: Cấm ký tự gạch ngang dài "—" (em dash)

Trong **toàn repo**, kể cả file markdown tiếng Việt, chỉ dùng gạch ngang thường `-`. Đây là quy tắc của repo gốc doan-labs/duo, CI sẽ quét.

### Nguyên tắc 5: Không tự thêm package mới

`package.json` của repo bị giới hạn dependencies. Muốn thêm thư viện nào, hỏi thầy/cô hoặc người giữ repo trước. App của bạn gần như chắc chắn chỉ cần: `@doan-labs/duo-sdk`, `@doan-labs/duo-uikit`, `@stylexjs/stylex`, `react`.

---

## 4. Lộ trình A - Sửa trang web giới thiệu

Đối tượng: người mới, muốn thấy kết quả ngay. Toàn bộ trong `duo/packages/web/src/`.

### Bước A1. Làm quen với luồng dev có live reload

```bash
# từ gốc repo
cd duo
bun ../duo-preview.mjs
```

Mở `http://localhost:3000`. Server này tự bật cả simulator (cổng 3370) lẫn web Vite (cổng 3371) rồi chuyển tiếp qua một cổng duy nhất. **Sửa file nào trong `duo/`, lưu lại là trình duyệt tự cập nhật**, không cần F5, không cần build lại. Đây là "Live Server" thật sự của dự án.

Thành công trông thế nào: trang web tiếng Việt hiện ra, có chiếc iPhone 3D. Thử sửa chữ trong `hero.tsx` (bước A2) và thấy trang tự đổi.

### Bước A2. Sửa hero - dòng chữ đầu tiên khách thấy

File: `packages/web/src/home/hero.tsx`

1. Mở file, tìm đến thẻ `<motion.h1 ...>` chứa tiêu đề hiện tại ("iPhone gập của Apple, mô phỏng thật...").
2. Sửa chữ bên trong thẻ thành nội dung lớp bạn muốn. Chỉ đổi **văn bản giữa các thẻ**, đừng đổi thuộc tính trong lần đầu.
3. Lưu lại (`Ctrl+S`), nhìn trình duyệt: chữ đổi ngay, còn giữ animation mượt.

Thành công trông thế nào: chữ mới hiện đúng, không lỗi gì trong terminal.

Lưu ý riêng cho file này: các biến `MID`, `SMALL` ở đầu file là **điểm dừng responsive cục bộ**. StyleX 0.19 không nhận được media query qua chuỗi import nên mỗi file tự khai báo. Khi copy style từ file khác sang file khác, kiểm tra media query dùng biến cục bộ của chính file đó.

### Bước A3. Sửa nội dung các section còn lại

Trang chủ ghép từ các file trong `packages/web/src/home/`, mỗi file một section:

| File | Phần của trang | Gợi ý sửa |
| --- | --- | --- |
| `hero.tsx` | Đầu trang, tên + nút | Chữ tiêu đề, dòng phụ |
| `works.tsx` | Cảnh kể chuyện khi cuộn | Tên app, mô tả từng bước |
| `fold.tsx` | Phần về màn hình gập | Số liệu, chữ |
| `sdk.tsx` | Phần giới thiệu SDK | Đoạn code mẫu, chữ |
| `apps.tsx` | Phần về các app | Danh sách app |
| `open.tsx` | Phần mã nguồn mở | Link, chữ |
| `cta.tsx` | Kết trang, lời mời | Nút và chữ |

Cách gõ an toàn: **một file một lần lưu một lần nhìn trình duyệt**. Vite HMR cập nhật tức thì, nếu chữ bạn gõ làm vỡ bố cục là biết ngay tại file nào.

### Bước A4. Đổi màu theo chủ đề của lớp

File: `packages/uikit/tokens.stylex.ts`

Đây là file chi phối cả simulator lẫn website. Muốn đổi tông màu trang web, tìm nhóm `colors` (hoặc token màu mà web dùng) và sửa giá trị hex. Lưu ý:

- Sửa **một token một lần lưu** rồi xem lại toàn bộ trang. Một token có thể được dùng ở 20 chỗ, đổi xấu là phải đổi lại.
- Token đặt tên theo vai trò (`background`, `text`, `accent`) chứ không theo màu (`blue`, `red`). Giữ nguyên cách đặt tên.
- App nào có màu riêng thì khai báo dưới dòng `// <app>` trong `appAppearance`, không dùng chéo.

### Bước A5. Sửa tên site và meta SEO

File: `packages/web/src/site.ts`. Đây là tên ngắn, mô tả, đường dẫn hình dùng cho thẻ meta. Sửa chuỗi ở đây là title tab, mô tả khi share Facebook/Zalo, favicon chữ đều đổi theo. Sửa file này không cần đụng HTML.

### Bước A6. Sửa nav và footer

- `packages/web/src/nav.tsx`: các mục menu trên cùng. Mỗi mục là một link + chữ. Thêm mục mới trỏ về route có sẵn (`/docs`, `/kit`, `/simulator`) trước khi nghĩ đến route mới.
- `packages/web/src/footer.tsx`: chân trang, chữ và link.

### Bước A7. Thêm hoặc sửa một trang route (nâng hạng nhẹ)

Mỗi route là một file trong `packages/web/src/routes/`. Ví dụ `simulator.tsx` chính là trang `/simulator`. Muốn sửa trang đó, mở file, sửa JSX bên trong. Muốn thêm route mới: tạo file theo đúng quy ước tên của TanStack rồi **để Vite tự sinh lại `route-tree.gen.ts`** (file này tự cập nhật khi dev server đang chạy; đừng sửa tay nó).

### Bước A8. Kiểm tra đóng hàng lộ trình A

```bash
cd duo
bun run typecheck            # phải sạch lỗi
cd packages/web
bun run build                # build cả web + simulator, phải hết sạch
```

Thành công trông thế nào: typecheck không in lỗi nào, build xong không đỏ. Nếu build lỗi mà typecheck sạch, khả năng cao bạn dùng cú pháp StyleX không hợp lệ (viết tắt, media query lạ) - quay lại file vừa sửa gần nhất.

---

## 5. Lộ trình B - Viết một app chạy thật trong simulator

Đối tượng: đã xong lộ trình A, muốn có app của mình nằm trên màn hình iPhone. Đây là con đường "trusted baked app" - app nướng sẵn trong máy, được viết trong `packages/apps/`.

**Chuẩn bị bắt buộc trước khi gõ:** mở và lướt qua 2 file mẫu, không cần hiểu hết:
- `packages/apps/calculator/index.tsx` - app đơn giản nhất, khoảng vài trăm dòng.
- `packages/apps/notes/index.tsx` - app đầy đủ nhất, có storage, có layout rộng/hẹp.

### Bước B1. Tạo khung thư mục app (4 file khai sinh)

Tạo thư mục `packages/apps/<ten-app>/` với `<ten-app>` là tên kebab-case, ví dụ `bang-diem`. Bên trong tạo **4 file theo đúng thứ tự dưới đây**:

**File 1: `package.json`** - khai báo app là một workspace package:

```json
{
  "name": "@doan-labs/duo-app-bang-diem",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "exports": {
    ".": "./index.tsx",
    "./*": "./*"
  },
  "scripts": {
    "typecheck": "tsc --noEmit -p tsconfig.json"
  },
  "dependencies": {
    "@doan-labs/duo-sdk": "workspace:*",
    "@doan-labs/duo-uikit": "workspace:*",
    "@stylexjs/stylex": "0.19.0",
    "react": "^19"
  }
}
```

Chỉ đổi phần `bang-diem` trong tên. Còn lại giữ nguyên mẫu của `packages/apps/calculator/package.json`.

**File 2: `tsconfig.json`** - copy nguyên xi từ `packages/apps/calculator/tsconfig.json` (app nào cũng dùng chung cấu hình dẫn từ root).

**File 3: `manifest.json`** - thông tin app:

```json
{
  "id": "labs.doan.ipduo.bang-diem",
  "name": "Bảng điểm",
  "version": "0.1.0",
  "entry": "./index.tsx",
  "icon": "./icon.png"
}
```

`id` phải có dạng `labs.doan.ipduo.<ten>` - đây là định danh app dùng trong storage và catalog, đặt xong **không đổi nữa**.

**File 4: `icon.png`** - tạm dùng icon của app khác (`packages/apps/calculator/icon.png`), sau này thay hình riêng. Kích thước vuông, 192x192 trở lên.

### Bước B2. Gõ `index.tsx` - component chính

Đây là trái tim của app. Dàn khung tối thiểu:

```tsx
import * as stylex from '@stylexjs/stylex'
import { Screen, Text } from '@doan-labs/duo-uikit'
import type { Os } from '@doan-labs/duo-sdk'

export function BangDiem({ os }: { os: Os }) {
  return (
    <Screen>
      <Text>Bảng điểm của tôi</Text>
    </Screen>
  )
}
```

Ba quy tắc khi gõ file này:

1. **Chỉ import từ `@doan-labs/duo-sdk` và `@doan-labs/duo-uikit`.** Cấm import từ shell (`packages/shell/`) hoặc từ app khác. App nào lén nhìn code app khác sẽ bị tách ra khi build sandbox.
2. **Props `os` là cửa sổ ra thế giới ngoài**: `os.storage` để lưu dữ liệu, `os.mirror` để thấy trạng thái máy, `os.display` để biết đang ở màn hình trong hay ngoài. Xem app notes dùng thế nào rồi học theo.
3. **Layout phải đo khung chứa, không đo màn hình.** App có thể chạy ở màn hình trong (rộng), màn hình ngoài khi gập (hẹp), hoặc nửa màn hình khi split. Dùng component `Screen`, `VStack`, `HStack` của uikit - chúng tự co giãn theo chỗ được cấp.

### Bước B3. Gõ `styles.ts` - mọi style của app

Tạo `styles.ts` cùng cấp, nội dung kiểu:

```ts
import * as stylex from '@stylexjs/stylex'
import { colors, radius, space } from '@doan-labs/duo-uikit/tokens.stylex.ts'

export const styles = stylex.create({
  card: {
    backgroundColor: colors.background,
    borderRadius: radius.md,
    padding: space.lg
  }
})
```

Lưu ý bắt buộc:

- Import token từ đường dẫn token của uikit, không ghi số cứng `#ffffff`, `12px`.
- Nếu app cần màu riêng, khai báo dưới dòng `// <app>` trong `appAppearance` của `tokens.stylex.ts`, đặt tên theo vai trò.
- Script `bun scripts/check-app-tokens.ts` là cổng kiểm tra: chạy nó, nó sẽ chỉ đúng chỗ nào dùng số cứng chưa được phép. `screen.ts`, `main.ts`, `device.ts` và shader được miễn vì chúng vẽ canvas/WebGL - app của bạn thì không được miễn.

### Bước B4. Gõ `main.tsx` - kết nối SDK (khi app cần lưu dữ liệu)

App nào lưu dữ liệu theo mẫu notes/weather thì cần `main.tsx` khởi tạo kết nối SDK trước khi render `index.tsx`. Mở `packages/apps/notes/main.tsx`, copy cấu trúc, đổi tên export. App thuần hiển thị không cần file này.

### Bước B5. Cài app vào máy ảo - 2 file phải chạm tay

Đây là bước sinh viên hay quên nhất. App gõ xong mà không làm bước này thì **không bao giờ hiện trên màn hình chính**.

**File 1: `packages/shell/package.json`** - thêm 1 dòng vào `dependencies`:

```json
"@doan-labs/duo-app-bang-diem": "workspace:*",
```

Sau đó chạy `bun install` trong thư mục `duo/` để Bun nối workspace. Chưa có bước này, bước sau import sẽ lỗi "Cannot find module".

**File 2: `packages/shell/apps.ts`** - đăng ký app lên màn hình chính:

1. Thêm import đầu file: `import { BangDiem } from '@doan-labs/duo-app-bang-diem/index.tsx'`
2. Thêm entry vào danh sách phù hợp:
   - `LEFT` - hiện trên **màn hình ngoài khi gập máy** (hàng 3-6).
   - `RIGHT` - chỉ hiện khi **mở máy trên màn hình trong**.
   - `DOCK` - thanh dock dưới cùng (chỉ 4 chỗ, thường không thêm).
   - `APPS` - chỉ mở được qua Spotlight tìm kiếm.

   ```ts
   { name: 'Bảng điểm', id: 'labs.doan.ipduo.bang-diem', view: BangDiem }
   ```

   `name` chính là tên hiện trên home screen và là tên dùng để mở qua `?app=Bảng điểm`.

3. Nếu app là bản release đóng gói (đi qua catalog) thì thay `view` bằng `id` + `...RELEASE` như Calendar, Photos đang viết. App học tập để chạy trực tiếp thì dùng `view`.

### Bước B6. Chạy và xem app sống

```bash
cd duo
bun ../duo-preview.mjs
```

Mở `http://localhost:3000/device/` (simulator full màn hình), hoặc thêm `?app=Bảng điểm` vào URL để mở thẳng app, bỏ qua màn hình khóa.

Thành công trông thế nào: icon app nằm trên màn hình chính, bấm vào là mở, nội dung hiện đúng ở cả 3 tư thế: mở máy, gập máy (màn hình ngoài), split.

**Ba tư thế bắt buộc phải test** (quy tắc của repo gốc): wide (mở máy), cover (gập máy), split (kéo app sang nửa màn hình). App chạy đẹp ở wide mà vỡ ở cover là chưa xong.

### Bước B7. Đóng hàng: typecheck + build

```bash
cd duo
bun run typecheck
bun run build
```

Cả hai phải sạch. HMR của Bun đôi khi để lại trạng thái cũ của module không phải React (thuộc danh sách hạn chế của repo) - nếu app behaves lạ, restart dev server trước khi nghi ngờ code.

---

## 6. Lộ trình C - Viết app cộng đồng (community-apps)

Đối tượng: muốn làm một app **đóng gói, phát hành được** - đúng mô hình repo gốc dùng để nhận app từ cộng đồng. Khác biệt với lộ trình B: app không nằm trong máy ảo, mà là một gói độc lập chạy trong sandbox.

### Bước C1. Tạo thư mục app theo slug

`community-apps/<slug>/` với slug là kebab-case, ví dụ `community-apps/diem-so-lop/`. **Không thêm thư mục này vào `workspaces` ở root** - nó không phải workspace, nó resolve các package `@doan-labs/*` qua fallback của `scripts/build-app.ts`. Thêm vào sẽ phá cấu trúc.

### Bước C2. Gõ `manifest.json` trước tiên

Sao chép mẫu từ `community-apps/pomodoro-timer/manifest.json`:

```json
{
  "id": "com.<tenban>.duo.diem-so-lop",
  "name": "Điểm số lớp",
  "version": "0.1.0",
  "lane": "community",
  "entry": "./main.tsx",
  "icon": "./icon.png",
  "author": "<tên bạn>",
  "repo": "<link GitHub tới app>",
  "license": "MIT"
}
```

Thứ tự gõ: manifest xong rồi mới gõ code, vì build-app đọc manifest để tìm entry point.

### Bước C3. Gõ `main.tsx`

Component mặc định export từ `main.tsx`, import chỉ từ `@doan-labs/duo-sdk` + `@doan-labs/duo-uikit` + React. App cộng đồng chạy trong **sandbox tách biệt**: không camera, không micro, storage qua SDK host. Thiết kế app từ đầu với giới hạn đó (xem bảng hạn chế ở mục 9).

### Bước C4. Icon, README, CHANGELOG

- `icon.png`: vuông, nền đặc, không trong suốt.
- `README.md`: app làm gì, 2-3 đoạn (xem pomodoro-timer/README.md làm mẫu - ngắn gọn, đúng trọng tâm).
- `CHANGELOG.md`: ghi lại version đầu tiên.

### Bước C5. Đóng gói và thử

```bash
cd duo
bun scripts/build-app.ts community-apps/diem-so-lop
```

Kết quả phát ra dưới `dist/cdn/`. Script sẽ kiểm tra manifest, entry, icon. Lỗi nào nó chặn đúng lỗi đó, sửa rồi chạy lại.

### Bước C6. Nộp app

Gửi PR vào repo gốc doan-labs/duo theo đúng luồng review (`duo/docs/platform/review.md`). Repo học tập của lớp thì commit thẳng, nhưng cứ giữ cấu trúc chuẩn để sau này nộp thật không phải làm lại.

---

## 7. Lộ trình D - Sửa lõi simulator (nâng cao)

Đây là việc của người giữ repo, học sinh lớp chỉ đọc để hiểu. Toàn bộ trong `packages/shell/`. Nếu vẫn muốn nghịch, thứ tự đọc file là một lộ trình học tốt:

1. `index.html` - khung HTML, layer CSS reset.
2. `main.ts` - điểm khởi động, scene Three.js, bridge postMessage với website.
3. `device.ts` - thân máy 3D, bản lề, độ gập (đơn vị **centimet**, camera mặc định `z=40` - không dịch camera).
4. `screen.ts` - bakes màn hình 2D thành texture dán lên model.
5. `os.tsx` - "hệ điều hành": quản lý scene app, màn hình trong/ngoài, task switcher.
6. `apps.ts` - đã gặp ở lộ trình B.
7. `springboard/` - home screen, khóa máy, Control Center, wallpaper.
8. `shaders/fold.ts`, `shaders/screen.ts` - shader chuồn nhẹ qua phần bóng đổ bản lề.

Lưu ý khi chạm vào lõi: mỗi thay đổi phải test cả pose gập 120 độ và pose phẳng; HUD (`hud.tsx`) tự ẩn khi nhúng trong iframe; sau khi đổi bridge phải chạy lại `bun scripts/simulator.ts` để copy shell mới vào trang web.

---

## 8. Bảng tổng hợp thứ tự gõ file

In trang này ra, dán cạnh màn hình. Tick từng dòng khi xong.

**Lộ trình A - sửa web (mỗi dòng một file, thứ tự từ trên xuống):**

- [ ] 1. `bun ../duo-preview.mjs` (bật live reload)
- [ ] 2. `packages/web/src/home/hero.tsx` - chữ hero
- [ ] 3. `packages/web/src/home/*.tsx` - các section còn lại
- [ ] 4. `packages/uikit/tokens.stylex.ts` - màu chủ đề
- [ ] 5. `packages/web/src/site.ts` - tên + meta
- [ ] 6. `packages/web/src/nav.tsx`, `footer.tsx`
- [ ] 7. `packages/web/src/routes/*.tsx` - trang riêng (tùy chọn)
- [ ] 8. `bun run typecheck` + `cd packages/web && bun run build`

**Lộ trình B - app trong máy (thứ tự bắt buộc, không đảo):**

- [ ] 1. `packages/apps/<ten>/package.json`
- [ ] 2. `packages/apps/<ten>/tsconfig.json`
- [ ] 3. `packages/apps/<ten>/manifest.json`
- [ ] 4. `packages/apps/<ten>/icon.png` (mượn tạm)
- [ ] 5. `packages/apps/<ten>/index.tsx` (chỉ import SDK/uikit)
- [ ] 6. `packages/apps/<ten>/styles.ts` (token, không số cứng)
- [ ] 7. `packages/apps/<ten>/main.tsx` (nếu cần SDK storage)
- [ ] 8. `packages/shell/package.json` - thêm dependency
- [ ] 9. `bun install` trong `duo/`
- [ ] 10. `packages/shell/apps.ts` - import + đăng ký vào LEFT/RIGHT
- [ ] 11. `bun ../duo-preview.mjs` - test 3 tư thế wide/cover/split
- [ ] 12. `bun run typecheck` + `bun run build`

**Lộ trình C - app cộng đồng (thứ tự bắt buộc):**

- [ ] 1. `community-apps/<slug>/manifest.json`
- [ ] 2. `community-apps/<slug>/main.tsx`
- [ ] 3. `community-apps/<slug>/icon.png`
- [ ] 4. `community-apps/<slug>/README.md`
- [ ] 5. `community-apps/<slug>/CHANGELOG.md`
- [ ] 6. `bun scripts/build-app.ts community-apps/<slug>`
- [ ] 7. Nộp/commit

**Lộ trình D - lõi simulator:** đọc theo thứ tự `index.html` → `main.ts` → `device.ts` → `screen.ts` → `os.tsx` → `apps.ts` → `springboard/` → `shaders/`.

---

## 9. 20 lưu ý bắt buộc khi gõ code

1. **Typecheck trước khi nói "xong".** `bun run typecheck` trong `duo/` phải sạch. Đây cũng là quy tắc số 1 của `duo/docs/working.md`.
2. **Không sửa file sinh tự động**: `packages/web/src/generated/*`, `route-tree.gen.ts`, mọi thứ dưới `dist/`, `public/model/`. Sinh lại bằng cách chạy dev/build.
3. **Model 3D không vào Git.** `duo/public/model/` đã gitignore vì model là tài sản Apple. Mỗi máy clone tự chạy `python scripts/prepare-model.py`.
4. **Token là pháp luật.** Mọi màu, cỡ chữ, bo góc, bóng, khoảng cách lấy từ `tokens.stylex.ts`. Không có bước phù hợp thì snap sang bước gần nhất, không tự chế số. Chạy `bun scripts/check-app-tokens.ts` để được nhắc.
5. **Media query là biến cục bộ** của từng file (`MID`, `NARROW`, `SMALL`), không import chéo. StyleX 0.19 với chuỗi import sẽ ném "Invalid pseudo or at-rule".
6. **Keyframes khai báo trong file sử dụng nó.** Animation tái sử dụng là cả block style nguyên vẹn, không phải tên keyframe dùng chung.
7. **Home bar chiếm 180x22px ở đáy giữa, z-index 8.** Nút bấm, thanh công cụ của app phải né vùng chạm này. Các layer hệ điều hành z-index tối đa 10, dưới ramp bản lề ở 11.
8. **Đo tọa độ đúng hệ:** `getBoundingClientRect()` là tọa độ màn hình; panel trong app dùng chuỗi offset của `spot()`, đặc biệt khi nằm trong home page có transform.
9. **Đơn vị 3D là centimet, camera mặc định `z=40`.** Không dịch camera trong `device.ts`/`main.ts` nếu chưa đọc `docs/architecture.md`.
10. **Không camera/micro trong sandbox app.** App cộng đồng và preview bên ngoài bị từ chối quyền thiết bị - đừng thêm `allow-same-origin` để "chữa", đó là lỗi bảo mật bị chặn review.
11. **Dữ liệu app lưu qua `os.storage` (SDK).** Không dùng localStorage trực tiếp trong app nướng sẵn - notes/weather đều đi qua SDK storage để đồng bộ giữa màn hình trong/ngoài.
12. **App về Home là được park, không phải tắt.** App vẫn mounted với `display: none`. Dọn timer/media khi unmount, nhưng đừng giết state ngỡ rằng app đóng hẳn.
13. **HMR có giới hạn.** Đổi module không phải React có thể để lại trạng thái cũ. Thấy hành vi lạ: restart dev server, đừng vội sửa code theo hiện tượng ảo.
14. **Chỉnh bridge thì build lại web.** Sửa `packages/shell/main.ts` (postMessage, `?bg=`, cues) xong phải chạy `bun scripts/simulator.ts` trong `packages/web` để copy bản shell mới vào `/device/`.
15. **Docs markdown có renderer riêng.** Bài mới trong `packages/web/content/docs/*.md` phải dùng đúng cú pháp renderer hỗ trợ; thêm slug vào `ORDER` trong `src/docs.ts` để vào sidebar; link giữa các bài docs dùng đường dẫn tương đối.
16. **Breakpoint đúng chuẩn repo:** MID 1068, NARROW 833, SMALL 734 - khai báo trong từng file.
17. **Kiểm tra reduced motion.** Animation phải tôn trọng `useReducedMotion()`; gate `initial` theo reduced motion sẽ làm hydration vỡ - giảm duration, không đổi pose khởi đầu.
18. **Tải trang nặng trước mắt thì đừng mở Camera.** Never open the Camera app in a frame that mounts early: browser sẽ xin quyền webcam trước khi người dùng hiểu vì sao.
19. **Em dash "—" cấm tuyệt đối.** Gạch ngang thường `-` thôi, cả trong code lẫn markdown tiếng Việt.
20. **Biome format khi lưu; pre-commit kiểm tra lại.** Nếu commit bị từ chối vì format, chạy không được tay: mở lại file, `Ctrl+S`, commit lại.

---

## 10. Bảng xử lý lỗi thường gặp

| Hiện tượng | Nguyên nhân khả dĩ nhất | Xử lý |
| --- | --- | --- |
| `Cannot find module '@doan-labs/duo-app-...'` | Chưa thêm dependency vào `packages/shell/package.json` hoặc chưa `bun install` | Làm lại B5, chạy `bun install` |
| App không hiện trên màn hình chính | Chưa đăng ký trong `apps.ts`, hoặc đăng ký vào danh sách sai (LEFT/RIGHT) | Xem lại B5 file 2; thử `?app=Tên app` trên URL |
| Build lỗi mà typecheck sạch | Cú pháp StyleX sai ở build: thuộc tính viết tắt, media query chuỗi import | Tìm file vừa sửa; rải token/longhand đúng chuẩn |
| `Unexpected 'stylex.defineVars' call at runtime` | Đang mở web bằng server khác, không phải dev server Bun/Vite chính thức | Chỉ chạy qua `bun ../duo-preview.mjs` hoặc `bun run dev` |
| `Blocked: Host header does not match` | Gọi simulator qua host lạ; shell chặn DNS rebinding | Truy cập qua preview relay hoặc `localhost` trên chính máy |
| Trang trắng sau khi sửa web | Lỗi TS/JSX trong route vừa sửa; HMR kẹt | Nhìn terminal relay; restart `freebuff-preview restart` nếu relay chết |
| Model không hiện, console báo 404 `/model/...` | Chưa chạy prepare-model | `pip install usd-core && python scripts/prepare-model.py` trong `duo/` |
| Ảnh icon app trắng/ sai | Icon chưa nằm đúng chỗ, hoặc chưa đăng ký trong ICONS | Đối chiếu cách app khác khai báo icon trong `apps.ts` |
| `Invalid pseudo or at-rule` | Media query dùng chuỗi import từ file khác | Khai báo biến breakpoint cục bộ trong chính file đó |
| Style xịn nhưng trang nhạt nhòa, margin sai | Reset CSS bị mất thứ tự layer | Kiểm tra `src/reset.css` được import trước `virtual:stylex.css` trong `__root.tsx` |
| Commit bị chặn, diff loạn | Prettier/ESLint giành nhau với Biome | Gỡ extension cấm theo HUONG-DAN-SETUP.md, để Biome format |
| Bun compile lỗi media query sau nhiều lần | Bug Bun 1.4.0 với FTL JIT | Repo đã tắt FTL sẵn; nếu còn, `bun upgrade` |

---

## 11. Tóm tắt 30 giây

```
SỬA WEB       : bun ../duo-preview.mjs → sửa file trong packages/web/src/home/ → lưu → trang tự đổi
THÊM APP MỚI  : packages/apps/<ten>/ (4 file khai sinh) → index.tsx + styles.ts
                → shell/package.json + bun install → shell/apps.ts đăng ký
                → test wide/cover/split → typecheck + build
APP CỘNG ĐỒNG : community-apps/<slug>/ → manifest.json → main.tsx → icon/README/CHANGELOG
                → bun scripts/build-app.ts community-apps/<slug>
LÕI SIMULATOR : đọc theo index.html → main.ts → device.ts → screen.ts → os.tsx
LUÔN LUÔN     : typecheck trước khi nói xong, token từ tokens.stylex.ts, kebab-case,
                không em dash, không sửa file generated, không thêm package khi chưa hỏi
```

Chúc lớp code vui! Khi gặp tình huống ngoài bảng trên, mở `duo/docs/working.md` (tiếng Anh) - nó là nguồn chính thức của mọi quy tắc mà file này đã tóm tắt.
