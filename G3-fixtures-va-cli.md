# G3. `packages/fixtures/` + `packages/cli/` (4 file TS, 238 dòng)

```
fixtures:  package.json -> tsconfig.json -> tracks.ts -> index.ts -> tracks.test.ts
cli:       package.json -> tsconfig.json -> index.ts -> README.md
```

`cli/index.ts` là wrapper đọc `src/services`: `dev/create/build/serve/preview/check`
(check này dùng test fixtures). Không có phụ thuộc nên gõ là chạy.
