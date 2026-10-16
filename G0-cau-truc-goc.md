# G0. Cấu trúc gốc (8 file, 266 dòng) — gõ trước tất cả

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
