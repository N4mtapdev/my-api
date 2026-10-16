# THU TỰ GÕ CODE: iPhone Duo — hướng dẫn chi tiết

Nhánh này **chỉ chứa md hướng dẫn**, tách lộ trình gõ code thành từng mục, **mỗi mục 1 file**.
Toàn bộ số liệu lấy trực tiếp từ `duo/` (367 file TypeScript, 52.966 dòng TypeScript,
tổng ~61.600 dòng tính cả JSON/Markdown).

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

## Mục lục — mỗi mục 1 file

| Mục | File |
| --- | --- |
| 0 + 1. Quy tắc đọc chung, lệnh xem layer, bảng checkpoint | [00-quy-tac-chung-va-checkpoint.md](00-quy-tac-chung-va-checkpoint.md) |
| G0. Cấu trúc gốc — gõ trước tất cả | [G0-cau-truc-goc.md](G0-cau-truc-goc.md) |
| G1. `packages/uikit/` | [G1-uikit.md](G1-uikit.md) |
| G2. `packages/sdk/` | [G2-sdk.md](G2-sdk.md) |
| G3. `packages/fixtures/` + `packages/cli/` | [G3-fixtures-va-cli.md](G3-fixtures-va-cli.md) |
| G4. `packages/apps/` — 38 app | [G4-apps.md](G4-apps.md) |
| G5. `packages/shell/` | [G5-shell.md](G5-shell.md) |
| G6. `scripts/` | [G6-scripts.md](G6-scripts.md) |
| G7. `packages/web/` — website + builder | [G7-web.md](G7-web.md) |
| G8. `community-apps/` + `examples/` | [G8-community-apps-va-examples.md](G8-community-apps-va-examples.md) |
| G9. `docs/` + README | [G9-docs-va-readme.md](G9-docs-va-readme.md) |
| Không cần gõ (tránh phí công sức) | [khong-can-go.md](khong-can-go.md) |
| Ước lượng thời gian + gõ 1 phần | [uoc-luong-va-gon.md](uoc-luong-va-gon.md) |

Đọc theo đúng thứ tự từ trên xuống. Muốn bản gộp trong 1 file duy nhất, xem
`THU-TU-GO-CODE.md` trên nhánh `main`.
