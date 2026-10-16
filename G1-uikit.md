# G1. `packages/uikit/` (39 file TS, 3.233 dòng)

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
