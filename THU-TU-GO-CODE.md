# THU TỰ GÕ CODE: iPhone Duo (bản đầy đủ)

Đây là bản chi tiết của lộ trình đã có: gõ rõ từng file, theo đúng thứ tự import thật của repo.
Không cần 100% repo, nhưng nếu gõ giống, đây là thứ tự giúp bạn gõ hết mà vẫn luôn `tsc` xanh.

Toàn bộ số dưới đây được lấy trực tiếp từ `duo/` (chạy thật, không ước lượng):

| Khối | File `.ts/.tsx` | Dòng (tất cả file trong khối) |
| --- | ---: | ---: |
| Cấu trúc gốc (package/tsconfig/biome/serve/build) | 3 | 266 |
| `scripts/` | 9 | 902 |
| `packages/uikit/` | 39 | 3.233 |
| `packages/sdk/` | 17 | 1.232 |
| `packages/cli/` + `packages/fixtures/` | 4 | 238 |
| `packages/apps/` | 116 | 17.980 |
| `packages/shell/` | 48 | 10.016 |
| `packages/web/` | 108 | 17.397 |
| `community-apps/` + `examples/` | 23 | 4.929 |
| `docs/` + `content/docs/` (Markdown) | 0 | 5.431 |
| **Tổng** | **367** | **~61.600** |

Trong đó **52.966 dòng là TypeScript**, phần còn lại là `package.json` / `manifest.json` /
`README` / `docs` bạn vẫn phải gõ hoặc chỉnh tay.

Repo chỉ có **4 file test**: `sdk/contract.test.ts`, `sdk/mirror.test.ts`,
`fixtures/tracks.test.ts`, `web/src/builder/provider.test.ts`.

---

## 0. Quy tắc đọc chung (áp dụng cho mọi giai đoạn)

### 0.1. Import là kế hoạch thứ tự

Trong mọi file, thứ tự đi lên là: `styles` -> `data` -> file con -> `index` -> `main`.
Để ra thứ tự thật của một thư mục, chạy lệnh này (đã chạy thử, in ra `L1` là layer không
import gì, `L2` chỉ import file ở `L1`, cứ thế đến hết):

```sh
cd duo && bun -e 'const{readFile,readdir}=require("fs/promises");const{join}=require("path");
async function walk(d){const out=[];for(const e of await readdir(d,{withFileTypes:true})){const p=join(d,e.name);if(e.isDirectory())out.push(...await walk(p));else if(/\.(ts|tsx)$/.test(e.name))out.push(p);}return out}
const files=await walk("packages");
const src=await Promise.all(files.map(async f=>[f,await readFile(f,"utf8").catch(()=>"")]));
const has=new Set(src.map(([f])=>f));
const mod=new Map(src.map(([f,s])=>{const deps=new Set();for(const m of s.matchAll(/from\s+["\x27]([^"\x27]+)["\x27]/g)){if(!m[1].startsWith("."))continue;const r=join(f,"..",m[1]).replace(/\\/g,"/");for(const c of[r,`${r}.ts`,`${r}.tsx`,join(r,"index.ts"),join(r,"index.tsx")])if(has.has(c)){deps.add(c);break}}return[f,deps]}));
const seen=new Map();let layer=0;
for(;;){const cur=[...mod.keys()].filter(f=>!seen.has(f)&&[...mod.get(f)].every(g=>seen.has(g)));if(!cur.length)break;for(const f of cur)seen.set(f,layer);layer++;}
console.log("files:",files.length,"layers:",layer,"chua resolve:",[...mod.keys()].filter(f=>!seen.has(f)).map(f=>f.replace("packages/","")));
for(let i=0;i<layer;i++)console.log(`L${i+1}: `+[...seen].filter(([,v])=>v===i).map(([f])=>f.replace("packages/","")).join("  "));'
```

Kết quả thật hôm nay: `files: 332 layers: 14 chua resolve: ["web/src/route-tree.gen.ts", "web/src/router.tsx"]`.
Hai file còn lại là vòng lặp `router.tsx` <-> `route-tree.gen.ts`, xem mục G7.

> Lưu ý: repo này ghi import bằng **quote đơn** (`import x from './y.ts'`),
> nên regex phải nhận cả `'` lẫn `"` và phải xét chính đường dẫn đã có đuôi `.ts`.
>
> Lệnh này **chỉ đi theo import relative**. Các cạnh giữa package với nhau
> (`shell/apps.ts` gọi app bằng tên gói `@doan-labs/duo-app-*`) nó không thấy,
> nên thứ tự G1 -> G9 ở dưới chính là chỗ phân giải các cạnh đó.

### 0.2. Mỗi thư mục có `package.json` là 1 workspace

Xong file đó phải `bun install` thì `tsc` mới thấy các tên gói `@doan-labs/duo-uikit`,
`@doan-labs/duo-sdk`. Workspaces là `packages/*` và `packages/apps/*`.
`community-apps/` **không** phải workspace, vẫn build độc lập bằng `bunx duo check`.

### 0.3. Import

- Trong cùng package: relative có đuôi `./button.tsx` (`allowImportingTsExtensions` đang bật).
- Sang package khác: tên gói `@doan-labs/duo-uikit`, `@doan-labs/duo-sdk`.
- Không có path alias, không có import vòng ngoài `packages/`.

### 0.4. StyleX

Không viết CSS chay. Mọi style nằm trong `createStyles(...)` của các file `*.stylex.ts`,
`uikit`, `apps/*/styles.ts`, `web/vite-stylex.ts`. Token màu ở `duo/design/tokens.json`
và `uikit/tokens.stylex.ts`. Sửa gì xong cứ chạy `bun run format` (Biome), nó tự gộp
`stylex.props(...)` lại cho.

### 0.5. Test

`tsconfig.json` gốc `exclude` `packages/**/*.test.ts`, nên `tsc` không kiểm tra test.
Vẫn gõ test, kiểm tra bằng `bun test`.

---

## 1. Bảng checkpoint

| Sau khi gõ xong | Chạy | Thành công |
| --- | --- | --- |
| G0 | `cd duo && bun install` | có `bun.lock` |
| G0 -> G6 (trước khi có `packages/web/tsconfig.json`) | `bunx tsc --noEmit` | 0 lỗi |
| G7 trở đi | `bun run typecheck` | 2 lần tsc xanh |
| Muốn xem thứ tự file bất kỳ | lệnh mục 0.1 | ra layer |
| Muốn xem giao diện | `freebuff-preview restart` | `127.0.0.1:3000` |

**Chốt:** sau mỗi bước nhỏ mới chạy `bun run typecheck`. Chạy lần lượt ở cuối nghĩa là
bạn gõ quá nhanh và lỗi sẽ chồng nhau.

---

## G0. Cấu trúc gốc (8 file, 266 dòng) - gõ trước tất cả

| # | File | Dòng | Ghi chú |
| ---: | --- | ---: | --- |
| 1 | `package.json` | 42 | tên `@n4mtapdev/duo`, scripts `dev/build/typecheck`, `workspaces` |
| 2 | `tsconfig.json` | 17 | `strict`, `noUncheckedIndexedAccess`, include `packages`, exclude `packages/web` |
| 3 | `bunfig.toml` | 2 | đăng ký StyleX plugin cho serve |
| 4 | `biome.json` | 101 | format + lint |
| 5 | `stylex-plugin.ts` | 49 | Bun plugin, giống `web/vite-stylex.ts` |
| 6 | `serve.ts` | 23 | dev server |
| 7 | `build.ts` | 24 | build gốc |
| 8 | `wrangler.jsonc` | 8 | Pages config |

Checkpoint: `bun install` chạy thẳng. Sau đó `bunx tsc --noEmit` vẫn có thể báo lỗi vì
chưa có thư mục con, điều đó bình thường.

---

## G1. `packages/uikit/` (39 file TS, 3.233 dòng)

Gõ khối này trước vì shell, apps và web đều import nó. Layer thật:

```
L1 (10)  sandbox-stylex.ts  stack.ts  app.ts  wide.ts  icons/index.ts
         tokens.stylex.ts(561)  presence.ts  num.tsx  display.ts  assets.d.ts
L2 (3)   sym.tsx  styles.ts(474)  rings.tsx
L3 (3)   widget.tsx  animations.ts  nav.tsx
L4 (1)   primitive.ts
L5 (19)  section  placeholder  screen  v-stack  row  segmented  text-field  title
         h-stack  list  icon-button  menu  text  widget-label  sheet  toggle
         button  large-title  checkbox          (các file .tsx)
L6 (2)   navigation-link.tsx  select.tsx
L7 (1)   index.ts                              <- chỉ xuất hình cuối cùng
```

Thêm 4 file không phải `.ts`: `package.json`, `tsconfig.json`, `README.md`, `CHANGELOG.md`.

Gõ xong `L4` là đã có `primitive.ts` + `styles.ts`, phần còn lại là component độc lập,
thả ga gõ song song.

Checkpoint: `bunx tsc --noEmit` xanh là đi tiếp được.

---

## G2. `packages/sdk/` (17 file TS, 1.232 dòng)

Nhỏ, đọc nho, và là gốc lỗi của không gian thi giới (React context bị bỏ ngoài root).

```
L1 (7)   compat.ts  preview-features.ts  transition.ts
         document-policy.ts  permissions.ts  legacy.ts  store.ts
L2 (2)   protocol.ts  manifest.ts
L3 (2)   guards.ts  builder-preview.ts
L4 (3)   client.ts(318)  mirror.ts  contract.test.ts
L5 (3)   index.ts  react.ts  mirror.test.ts
```

Thêm `package.json`, `tsconfig.json`, `README.md`.

Đây là phần đọc quan trọng nhất repo: `contract.test.ts` và `mirror.test.ts` mô tả toàn bộ
giao diện host-app.

Checkpoint: `bun test packages/sdk` qua cả 2 test.

---

## G3. `packages/fixtures/` + `packages/cli/` (4 file TS, 238 dòng)

```
fixtures:  package.json -> tsconfig.json -> tracks.ts -> index.ts -> tracks.test.ts
cli:       package.json -> tsconfig.json -> index.ts -> README.md
```

`cli/index.ts` là wrapper đọc `src/services`: `dev/create/build/serve/preview/check`
(check này dùng test fixtures). Không có phụ thuộc nên gõ là chạy.

---

## G4. `packages/apps/` (116 file TS, 17.980 dòng, 38 app)

### Thứ tự file trong MỌI app (đã đối chiếu layer thật)

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

### Thứ tự các app, theo độ khó tăng dần

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

---

## G5. `packages/shell/` (48 file TS, 10.016 dòng)

Phải đặt **sau G4**: `shell/apps.ts` import 29 app bằng tên gói
`@doan-labs/duo-app-<ten>/index.tsx` (29 dòng `import` đầu file), nên G4 xong mới gõ được.
Layer thật:

```
L1 (16)  hud.tsx  shaders/screen.ts  shaders/fold.ts  runtime/database.ts
         runtime/preview-events.ts  runtime/photos.ts  runtime/display.ts  device.ts
         springboard/gestures.ts  springboard/toggles.ts  springboard/clock.ts
         springboard/wallpaper.ts  springboard/power.tsx  native.ts  buttons.ts  assets.d.ts
L2 (9)   runtime/widgets.tsx  runtime/storage.ts  runtime/releases.ts  runtime/erase.ts
         springboard/control-center.tsx(992)  springboard/wallpaper-sheet.tsx
         springboard/status-bar.tsx  springboard/system-hud.tsx  device-buttons.ts
L3 (3)   runtime/lifecycle.ts  runtime/development.ts  apps.ts
L4 (3)   runtime/sessions.ts  runtime/catalog.ts  springboard/tile.tsx
L5 (4)   runtime/registry.ts  runtime/bridge.ts  springboard/scenes.ts  springboard/spotlight.tsx
L6 (5)   runtime/sandbox.tsx  runtime/builder-preview.ts
         springboard/switcher.tsx  springboard/home-bar.tsx  springboard/grid.ts
L7 (4)   screen.ts  cues.ts  springboard/folder.tsx  springboard/lock-screen.tsx
L8 (1)   springboard/home-screen.tsx
L9 (1)   springboard/springboard.tsx(498)
L10 (1)  os.tsx
L11 (1)  main.ts(788)   <- entry của toàn shell
```

Thêm: `package.json`, `tsconfig.json`, `index.html`.
Chưa cần `desktop/` (tauri.conf.json, Cargo.toml, capabilities, src-tauri) - gõ thêm nếu
muốn `bun run desktop`, không thì bỏ qua cả thư mục này.

Checkpoint: `bunx tsc --noEmit` xanh. Đây là bước lớn nhất, đừng coi thường `L1/L2`
vì đó là các file được mọi thứ khác import.

---

## G6. `scripts/` (9 file TS, 902 dòng)

```
L1 (8)   check-app-tokens.ts  generate-kit-docs.ts  build-app.ts
         build-preinstalled.ts  package-platform.ts  check-platform.ts
         publish-catalog.ts  checks/stage2/notes-store.ts
L2 (1)   check-submissions.ts     <- import các check ở trên
```

Đặt sau `uikit` vì `generate-kit-docs.ts` và `check-app-tokens.ts` đọc API của uikit.

---

## G7. `packages/web/` (108 file TS, 17.397 dòng)

Từ đây chạy `bun run typecheck` (nó chạy 2 lần tsc, lần hai là `-p packages/web`).

### 7.1. Cấu hình (6 file)

`package.json` -> `tsconfig.json` -> `vite.config.ts` -> `vite-stylex.ts` -> `index.html` -> `src/index.ts`

### 7.2. Script sinh code (6 file, layer 1-3)

`scripts/tokens.ts` `scripts/simulator.ts` `scripts/catalog.ts` (L1)
-> `scripts/builder-runtime.ts` `scripts/api.ts` (L2) -> `scripts/builder/assets.ts` (L3)
Các file này sinh `src/generated/*` và `docs/platform/api/uikit.json`.
Chạy `bun run build` trong `packages/web` **sau** bước 7.9 để chúng sinh ra.

### 7.3. Foundation của `src/` (L1)

`src/tokens.stylex.ts` -> `src/reset.css` -> `src/theme.ts` (L2) -> `src/media.ts` ->
`src/motion.ts` -> `src/site.ts` -> `src/docs.ts` -> `src/api-types.ts` ->
`src/virtual.d.ts` `src/vite-env.d.ts` `src/builder/vendor.d.ts`

### 7.4. Component chung (từ leaf lên)

```
L1  src/smooth-scroll.tsx  src/safari-scroll-bridge.tsx
L2  src/footer.tsx  src/layout.tsx  src/segmented.tsx  src/highlight.tsx  src/side-nav.tsx
L3  src/nav.tsx(606)  src/page-parts.tsx  src/kit-preview.tsx  src/simulator.tsx
L4  src/markdown.tsx(527)  src/kit/data.ts
L5  src/doc-body.tsx  src/api-card.tsx  src/kit/hero.tsx
```

### 7.5. `home/` (10 file)

`parts.tsx` (L2) -> `apps.tsx`(556) `cta.tsx` `open.tsx` `sdk.tsx` (L3)
-> `fold.tsx` `hero.tsx` `works.tsx` (L4)

### 7.6. `guidelines/` (7 file)

`tabs.tsx` `group.tsx` `rules.tsx` (L2) -> `colour.tsx` `geometry.tsx` `easing.tsx` `typography.tsx` (L3)

### 7.7. `kit-demos/` (18 file)

Tất cả đều là leaf (L1), bất cứ thứ tự. Mỗi file khoảng 50-100 dòng.

### 7.8. `builder/` (9 file)

```
L1  types.ts  preview-client.ts  provider.ts  vendor.d.ts
L2  compiler.ts  compiler-worker.ts  example.ts  prompt.ts
L3  projects.ts  provider.test.ts
L4  workspace.tsx(1088)
```

### 7.9. `routes/` (18 file, gõ sau mọi thứ còn lại)

```
L1  get-started.tsx  kit.tsx  build.tsx
L2  sdk.tsx
L3  docs.tsx
L4  apps.tsx  docs.index.tsx  guidelines.tsx  publish.tsx  __root.tsx
L5  changelog.tsx  kit.docs.tsx  kit.docs.index.tsx  simulator.tsx  index.tsx
L6  docs.sdk.tsx  kit.index.tsx  docs.$.tsx  kit.docs.$name.tsx
```

Lưu ý `__root.tsx` ở L4 chứ không phải cuối, vì nó chỉ import `layout` + `smooth-scroll`
đã gõ ở 7.4. Các route `L5/L6` import thêm `markdown`/`doc-body`.

### 7.10. Vòng lặp bắt buộc: `router.tsx` <-> `route-tree.gen.ts`

`src/router.tsx` import `routeTree` từ `./route-tree.gen`, còn `route-tree.gen.ts` lại
`import type { getRouter } from './router.tsx'`. Hai file này **vòng lặp**, nên không thể
gõ theo kiểu leaf-first được. Cách xử lý:

1. Gõ `router.tsx` cuối cùng của `src/`.
2. `route-tree.gen.ts` là file sinh ra bởi TanStack Router (plugin của vite), **không gõ tay**.
   Chạy `bun run build` trong `packages/web` một lần để nó tự ra, rồi mới chạy typecheck.

### 7.11. `content/docs/*.md` (11 file)

Chỉ cần tồn tại, `extends` nhau: `base.md` -> `build-*.md` `install.md` `localize.md`
`lifecycle.md` `storage.md` `widget.md` `customize.md` `displays.md`.

Checkpoint cuối: `bun run typecheck` xanh, rồi `cd packages/web && bun run build` chạy hết script.

---

## G8. `community-apps/` + `examples/` (23 file TS, 4.929 dòng)

```
L1  community-apps/*/styles.ts  audio.ts  config.ts  avatars.ts  game.ts
    fold-compass/main.tsx  memory-match/main.tsx  wordle-mini/main.tsx
    pomodoro-timer/main.tsx  habit-streaks/main.tsx  tic-tac-toe/main.tsx
L2  flappy-duo/world.ts  2048/styles.ts  snake/duo-logo.tsx
L3  flappy-duo/main.tsx  2048/board.tsx  snake/game-board.tsx
L4  2048/main.tsx  snake/main.tsx
```

Thứ tự cụ thể: `community-apps/registry.json` -> `fold-compass/` (7 file, ví dụ mẫu)
-> `apple-calc/` và 8 app còn lại -> `examples/developer/` -> `examples/fold-compass/`.

`examples/` chỉ có 2 file `.tsx` (`developer/main.tsx`, `fold-compass/main.tsx`), cực nhẹ.
Mỗi app ngoài này là 1 project độc lập, `package.json` trước, `index.tsx` sau.
Đây là sàn chạy `bunx duo check`, không tính vào tsc của gốc.

---

## G9. `docs/` + README (cuối cùng)

`docs/README.md` -> `architecture.md` `working.md` `debug.md` `decisions.md` `CONTRIBUTING.md`
-> `docs/platform/*` -> `docs/platform/api/uikit.json` (đánh số, sinh bởi G6)
`README.md` và `duo/community-apps/README.md` gõ sau vì chứa link đến mọi thứ.

---

## Không cần gõ (tranh phí công sức)

- `bun.lock`, `node_modules/` - sinh bởi `bun install`
- `dist/`, `packages/web/public/*` - sinh bởi build/scripts
- `packages/web/src/route-tree.gen.ts`, `packages/web/src/generated/*` - sinh bởi TanStack Router và `web/scripts/`
- `public/model/**` - asset Apple, không phải tài nguyên, gitignored
- `docs/platform/api/uikit.json` - sinh bởi `scripts/generate-kit-docs.ts`
- `design/*.blend` - file Blender, thuộc nhóm riêng
- `.cache/`, `.claude/`, `.codex/`, `.agents/`, `.github/`, `.mcp.json` - tooling
- `CHANGELOG.md`, `README.md`, `LICENSE` - không cần gõ, chỉ đọc

---

## Ước lượng thời gian (trừ các mục trên)

| Mục | Dòng | Thời gian gõ liên tục (~100 dòng/phút) |
| --- | ---: | ---: |
| G0 + G1 + G2 + G3 | 4.969 | ~50 phút |
| G4 (38 app) | 17.980 | ~3 giờ |
| G5 + G6 | 10.918 | ~1,8 giờ |
| G7 (web) | 17.397 | ~3 giờ |
| G8 + G9 | 10.360 | ~1,7 giờ |
| **Tổng** | **61.624** | **~10,3 giờ gõ thật, thực tế 3-5 ngày** |

Nếu bạn muốn gõ **100%** rồi đo: mỗi lần `bun install` xong thì chạy `bun run typecheck`
ngay trong bước nhỏ; nếu đỏ thì fix trước khi qua bước tiếp. Đó là chốt, còn lại chỉ là công sức.

---

## Nếu chỉ gõ 1 phần

1. Chỉ cần `duo` chạy được: gõ **G0 -> G1 -> G2 -> G3 -> G4 -> G5** (33.000 dòng, ra simulator trọn vẹn).
2. Cần cả website: thêm **G6 -> G7**.
3. Chỉ muốn làm app mới: **G0 -> G1 -> G2 -> G4 nhóm A**, rồi tạo `packages/apps/<ten-app>`
   theo đúng thứ tự file ở mục G4.
