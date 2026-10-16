# G2. `packages/sdk/` (17 file TS, 1.232 dòng)

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
