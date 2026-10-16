# G4. `packages/apps/` (116 file TS, 17.980 dòng, 38 app)

## Thứ tự file trong MỌI app (đã đối chiếu layer thật)

```
1. package.json      <- gõ trước, không thì không tìm thấy uikit
2. tsconfig.json
3. manifest.json     (chỉ 9 app có)
4. CHANGELOG.md      (chỉ 9 app có)
5. styles.ts         <- layer 1, StyleX, không import component
6. data.ts           <- layer 1, seed dữ liệu, không import gì
7. file con          <- layer 2-3 (editor, sidebar, map, bookmarks, store, ...)
8. index.tsx         <- layer 3-5, gom mọi thứ ở đây
9. main.tsx          <- layer 3-6, entry, chỉ import index
```

Layer thật của `packages/apps` xác nhận đúng trật tự trên: `L1` = toàn bộ `styles.ts`
và `data.ts`, `L2` = file con và `index.tsx` của app 2 file, `L3-L4` = trang con và
`index.tsx` của app nhiều file, `L5` = `notes/main.tsx`, `L6` = `calendar/main.tsx`.

## Thứ tự các app, theo độ khó tăng dần

| Nhóm | App | File `.ts` | Ghi chú |
| --- | --- | ---: | --- |
| A. Gõ đầu tiên | `calculator` | 3 | có `manifest.json` + `main.tsx`, mẫu chuẩn cho app release |
| B. Lặp lại mẫu A | `clock` `freeform` `news` `reminders` | 3 mỗi app | y hệt calculator, gõ 4 lần |
| C. App 2 file đơn giản nhất | `appstore` `books` `camera` `contacts` `facetime` `files` `findmy` `fitness` `health` `home` `itunes` `mail` `memos` `messages` `music` `phone` `podcasts` `preview` `shortcuts` `siri` `stocks` `tips` `tv` `wallet` `watch` `youtube` | 2 mỗi app (26 app) | chỉ `styles.ts` + `index.tsx`, mỗi app ~100 dòng |
| D. App nhiều trang | `safari` (3) `photos` (5) `maps` (6) `settings` (6) | 20 | `index` tách sidebar + trang |
| E. App có store/data lớn | `weather` (7) `notes` (8) | 15 | có store riêng, file con |
| F. App lớn nhất | `calendar` | 14 | 14 file, gõ sau cùng, mất nhiều nhất |

Nhóm C nên gõ **sau** vì là lao động lặp: 26 app chỉ chiếm **6.338 dòng** (91 dòng
`health` đến 1.292 dòng `appstore`). Mỗi app là 1 workspace nên sau mỗi `package.json`
phải `bun install` một lần.

Checkpoint: `bunx tsc --noEmit` xanh. Nếu báo
`Cannot find module '@doan-labs/duo-uikit'` là do chưa `bun install`.
