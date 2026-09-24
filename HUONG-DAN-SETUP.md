# 📱 Hướng dẫn setup dự án iPhone Duo ở trường (VS Code + Windows)

> File này dành cho máy tính ở trường (thường là **Windows**, tài khoản hạn chế quyền admin).
> Làm theo tuần tự từ trên xuống là chạy được web mô phỏng iPhone Duo 3D.
> Mất khoảng **10-15 phút** lần đầu. Các lần sau chỉ cần 2 bước ở [mục 6](#6-chạy-dự-án).

---

## 1. Dự án này là gì?

- Repo: `https://github.com/N4mtapdev/my-api` (code nằm trong thư mục **`duo/`**)
- **iPhone Duo** gồm 2 phần:
  - **Web giới thiệu** (`duo/packages/web`): landing page, docs, demo UI kit - có nhúng iPhone 3D tương tác được ngay trong trang
  - **Simulator** (`duo/packages/shell`): mô phỏng iPhone gập bằng **Three.js** - gập/mở máy, màn hình trong - ngoài, home screen, app Notes/Weather/Camera...
- Công nghệ của repo (đọc kỹ để code cho đúng):
  | Thành phần | Công nghệ |
  | --- | --- |
  | Runtime + dev server + bundler | **Bun** (không dùng Node/npm) |
  | Ngôn ngữ | **TypeScript** strict |
  | UI | **React 19 + StyleX** (KHÔNG phải Tailwind, KHÔNG dùng className/style) |
  | 3D | **Three.js** r186, tải model **USDZ của Apple** |
  | Format/lint | **Biome** (KHÔNG phải Prettier/ESLint) |
- Model iPhone là tài sản của Apple, **không được đưa lên Git** → mỗi máy clone xong phải tự chạy 1 script Python để tải model về (mục 5).

---

## 2. Cài công cụ cần thiết

### 2.1. Bun (bắt buộc)

Mở **PowerShell** (không cần admin) và chạy:

```powershell
powershell -c "irm bun.sh/install.ps1 | iex"
```

Xong thì **đóng PowerShell mở lại** rồi kiểm tra:

```powershell
bun --version
```

> Phải hiện `1.4.x` trở lên. Nếu báo "bun is not recognized" → biến PATH chưa nạp lại, đăng xuất/đăng nhập lại máy hoặc restart VS Code.

### 2.2. Python 3 (bắt buộc - chỉ để tải model 3D)

- Tải từ `https://www.python.org/downloads/` (bản 3.10+)
- Khi cài **nhớ tick "Add python.exe to PATH"** (máy trường nếu không tick được thì dùng bản "embeddable" hoặc nhờ thầy/cô cài)
- Kiểm tra:

```powershell
python --version
pip --version
```

> Trên macOS/Linux dùng `python3` thay cho `python`.

### 2.3. Git + VS Code

- Git: `https://git-scm.com/download/win` (Next hết, chọn default)
- VS Code: `https://code.visualstudio.com/` (bản User Installer chạy được không cần admin)

---

## 3. Cài extension VS Code

Mở VS Code → `Ctrl+Shift+X` → gõ tên từng cái bên dưới → Install.
Hoặc nhanh hơn: mở Terminal (`Ctrl+`` `) dán cả lọn vào:

```powershell
code --install-extension biomejs.biome
code --install-extension oven.bun-vscode
code --install-extension ms-python.python
code --install-extension ms-python.vscode-pylance
code --install-extension usernamehw.errorlens
code --install-extension eamodio.gitlens
code --install-extension christian-kohler.path-intellisense
code --install-extension gruntfuggly.todo-tree
code --install-extension PKief.material-icon-theme
code --install-extension streetsidesoftware.code-spell-checker
```

### Danh sách chi tiết - tại sao cần

| # | Extension | ID | Lý do |
| --- | --- | --- | --- |
| 1 | **Biome** | `biomejs.biome` | ⭐ Bắt buộc. Formatter + linter chính thức của repo (single quote, no semicolon, 2-space, 120 cột). Cài xong vào Settings đặt Biome làm **Default Formatter** |
| 2 | **Bun** | `oven.bun-vscode` | ⭐ Bắt buộc. Debug/visualize code Bun, tự nhận biết `bun.lock` |
| 3 | **Python** | `ms-python.python` | ⭐ Bắt buộc. Chạy/tự động hoàn thiện `scripts/prepare-model.py` |
| 4 | **Pylance** | `ms-python.vscode-pylance` | Gợi ý code Python cho script tải model |
| 5 | **Error Lens** | `usernamehw.errorlens` | ⭐ Nên có. Lỗi TypeScript hiện ngay tại dòng code, cực hợp gõ nhanh trên tiết Tin học |
| 6 | **GitLens** | `eamodio.gitlens` | Xem ai sửa dòng nào, lịch sử commit trên GitHub |
| 7 | **Path Intellisense** | `christian-kohler.path-intellisense` | Tự gợi ý đường dẫn import file |
| 8 | **TODO Tree** | `gruntfuggly.todo-tree` | Gom hết các `TODO` trong repo ra 1 panel |
| 9 | **Material Icon Theme** | `PKief.material-icon-theme` | Icon folder file cho dễ nhìn |
| 10 | **Code Spell Checker** | `streetsidesoftware.code-spell-checker` | Gạch đỏ biến tiếng Anh viết sai chính tả |

### ⚠️ KHÔNG cài những extension này (tránh phá format repo)

| Extension | Vì sao tránh |
| --- | --- |
| Prettier | Repo dùng **Biome**, 2 thằng sẽ giành nhau format → git diff loạn |
| ESLint | Repo dùng **Biome** làm linter rồi |
| Tailwind CSS IntelliSense | Dự án dùng **StyleX**, không có Tailwind → gợi ý thừa thãi, dễ nhầm |
| Live Server | Dự án có dev server riêng (`bun run dev`), mở file HTML trực tiếp sẽ lỗi StyleX |

---

## 4. Clone repo về máy

Mở PowerShell tại thư mục muốn chứa code (ví dụ `D:\hoc-tap`), chạy:

```powershell
git clone https://github.com/N4mtapdev/my-api.git
cd my-api
code .
```

VS Code mở lên → **File → Open Folder → chọn đúng thư mục `duo`** bên trong
(khuyên dùng: mọi lệnh Bun, Biome và gợi ý extension sẽ chạy đúng ngữ cảnh repo).

---

## 5. Cài dependencies + tải model 3D (làm 1 lần mỗi máy)

Mở Terminal trong VS Code (`Ctrl+`` `) — đảm bảo đang đứng trong thư mục **`duo/`** (prompt có chữ `duo`), chạy 3 lệnh theo thứ tự:

```powershell
# 1. Cài toàn bộ dependencies (bun.lock có sẵn, install rất nhanh)
bun install

# 2. Thư viện USD của Apple cho Python
pip install usd-core

# 3. Tải model iPhone Duo từ Apple và xử lý thành file 3D cho web
python scripts/prepare-model.py
```

Kết quả mong đợi ở bước 3:

```
Downloading the Apple reference model...
Preparing the unfolded pose...
Model ready in public/model.
```

Kiểm tra thư mục `duo/public/model/` có các file:

- `iPhone_Duo_Render.usdc` ← file 3D mà web load
- `textures/` ← texture trắng của máy

> 💡 Model nặng ~chục MB, cần mạng trường truy cập được `apple.com`. Nếu mạng chặn, tải bằng 4G/hotspot rồi copy vào `duo/public/model/` cho lần sau.
>
> 💡 Không cần commit thư mục `public/model` — nó đã nằm trong `.gitignore` của repo (mỗi máy tự tải, đúng quy định của dự án vì model Apple không được phân phối lại).

---

## 6. Chạy dự án

Dự án có **2 phần**: web giới thiệu (`duo/packages/web` - landing page có nhúng iPhone 3D, docs, /kit...) và **simulator** (mô phỏng iPhone 3D chạy riêng). Cả 2 đều chạy được:

### Cách 1 - Xem web giới thiệu kèm simulator nhúng (chỉ cần xem)

```powershell
cd duo/packages/web
bun run build
bun run preview
```

Mở URL mà Vite in ra (mặc định `http://localhost:4173`):

- Trang chủ giới thiệu có iPhone 3D bay vào theo cuộn chuột, bấm vào là xoay/gập được luôn (iframe nhúng simulator)
- `/device/` = simulator full màn hình
- `/docs/` = tài liệu dự án, `/kit/` = demo UI kit, `/build` = công cụ viết app ngay trên web

### Cách 2 - Chạy simulator ở chế độ dev (khi sửa code)

Vẫn trong thư mục `duo/`:

```powershell
bun run dev
```

Mở trình duyệt (Chrome/Edge tốt nhất) vào: **http://localhost:3000**

- Kéo chuột để **gập/mở** máy, vuốt màn hình, mở app như iPhone thật
- Góc màn hình có slider gập + minimap
- Muốn sửa web giới thiệu: mở terminal thứ 2 chạy `cd packages/web && bun run dev` → vào `localhost:3001` (nó tự nhúng simulator ở cổng 3000)

### Bảng lệnh thường dùng (chạy trong `duo/`)

| Lệnh | Tác dụng |
| --- | --- |
| `bun run dev` | Chạy web simulator ở `localhost:3000` |
| `cd packages/web && bun run dev` | Chạy web giới thiệu ở `localhost:3001` (nhúng simulator 3000) |
| `bun run typecheck` | ⭐ Kiểm tra lỗi TypeScript (**chạy trước khi nói "xong"**) |
| `bun run build` | Build simulator production ra `dist/` |
| `cd packages/web && bun run build` | Build cả website + simulator ra `packages/web/dist/client` (bản deploy Vercel) |
| `bun run format:check` | Kiểm tra format Biome (đừng tự sửa tay, để extension lo) |
| `bun run desktop` | Chạy app desktop Tauri (cần Rust, chính thức chỉ hỗ trợ macOS - bỏ qua trên Windows) |

---

## 7. Quy tắc code BẮT BUỘC của repo (đọc trước khi sửa code)

Repo có `duo/AGENTS.md` và `duo/docs/working.md` ghi rõ chuẩn — tóm tắt nhanh:

1. **Format**: single quotes `'`, KHÔNG dấu `;` cuối dòng, indent 2 space, tối đa 120 cột. Biome extension tự lo khi lưu file.
2. **Style là StyleX**: viết `const styles = stylex.create({...})` ở cuối file, chỉ dùng thuộc tính viết dài (`fontSize`, không `font`), **không bao giờ** dùng `className`/`style` cạnh `stylex.props()`.
3. **Màu/kích thước/timing** lấy từ `packages/uikit/tokens.stylex.ts`, không tự chế số lạ.
4. **Tên file/folder kebab-case**: `my-new-file.tsx`, không `MyNewFile.tsx`.
5. **Cấm dùng ký tự gạch ngang dài** "—" (em dash U+2014) trong toàn bộ repo, chỉ dùng `-` thường.
6. **Không tự thêm package mới** vào `package.json` khi chưa hỏi - repo hạn chế dependencies.
7. Shaders là file TS export chuỗi string, không tạo file `.glsl`.
8. Đơn vị 3D là **centimet**, camera cố định `z=40` - đừng dịch chuyển nó.

---

## 8. Xử lý sự cố thường gặp

### ❌ `Unexpected 'stylex.defineVars' call at runtime`

StyleX phải được **biên dịch bởi plugin của Bun** (`duo/bunfig.toml` + `stylex-plugin.ts`).
→ Bạn đang mở web bằng server khác hoặc mở file `index.html` trực tiếp.
**Chỉ chạy đúng `bun run dev` trong thư mục `duo/`**, không dùng Live Server/nginx/xem file tĩnh.

### ❌ `Blocked: Host header does not match the dev server`

Server Bun chặn truy cập qua domain lạ (DNS rebinding protection) - lỗi này từng gặp khi chạy qua proxy preview.
→ Truy cập bằng `http://localhost:3000` trên chính máy đó. Nếu cần chia sẻ qua mạng LAN khác thì phải đi qua proxy đổi Host, không truy cập thẳng.

### ❌ Trang trắng / model không hiện

```powershell
cd duo
python scripts/prepare-model.py
```

Chạy lại rồi refresh trình duyệt (Ctrl+Shift+R). Kiểm tra `duo/public/model/iPhone_Duo_Render.usdc` có tồn tại.

### ❌ Web giới thiệu (packages/web) báo thiếu `/device/` hoặc simulator trắng trong iframe

Web build nhúng simulator qua thư mục `packages/web/public/device/`. Build lại cả cụm:

```powershell
cd duo/packages/web
bun run build
```

Xem log có dòng `simulator: copied dist/ → public/device/` là thành công.

### ❌ Màn hình 3D đen, console báo WebGL

Trình duyệt trường có thể tắt tăng tốc phần cứng → vào `edge://settings` / `chrome://settings` tìm "hardware acceleration" bật lên, hoặc thử Chrome mới nhất.

### ❌ `pip` không chạy / Python không thấy

Máy trường chưa thêm Python vào PATH. Cài bản portable từ python.org hoặc dùng `py -3 -m pip install usd-core` + `py -3 scripts/prepare-model.py`.

### ❌ Port 3000 bị chiếm

```powershell
$env:PORT=3100
bun run dev
```

### ❌ Lỗi lạ khi compile StyleX media queries (Bun 1.4.0)

Repo đã tắt FTL JIT sẵn (`BUN_JSC_useFTLJIT=false` trong scripts). Nếu vẫn gặp, cập nhật Bun mới nhất: `bun upgrade`.

### ❌ `bun install` chậm/fail ở trường do mạng

Bun download từ npm registry. Nếu bị chặn, thử đổi mirror:

```powershell
bun install --registry https://registry.npmmirror.com
```

---

## 9. Tóm tắt 60 giây (bỏ túi)

```powershell
# LẦN ĐẦU
git clone https://github.com/N4mtapdev/my-api.git
cd my-api/duo
bun install
pip install usd-core
python scripts/prepare-model.py
bun run dev                    # → http://localhost:3000 (simulator)
cd packages/web && bun run build && bun run preview   # → web giới thiệu

# NHỮNG LẦN SAU
cd my-api/duo
bun run dev
```

Chúc code vui! 🎉 Mọi thắc mắc về cấu trúc xem thêm `duo/docs/README.md` (có bản đồ tài liệu đầy đủ của dự án).
