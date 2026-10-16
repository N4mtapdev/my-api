# G5. `packages/shell/` (48 file TS, 10.016 dòng)

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
