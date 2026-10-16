# Mục 0 + 1. Quy tắc đọc chung và bảng checkpoint

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
