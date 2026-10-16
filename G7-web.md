# G7. `packages/web/` (108 file TS, 17.397 dòng)

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
