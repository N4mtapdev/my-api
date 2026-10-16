# Không cần gõ (tranh phí công sức)

- `bun.lock`, `node_modules/` - sinh bởi `bun install`
- `dist/`, `packages/web/public/*` - sinh bởi build/scripts
- `packages/web/src/route-tree.gen.ts`, `packages/web/src/generated/*` - sinh bởi TanStack Router và `web/scripts/`
- `public/model/**` - asset Apple, không phải tài nguyên, gitignored
- `docs/platform/api/uikit.json` - sinh bởi `scripts/generate-kit-docs.ts`
- `design/*.blend` - file Blender, thuộc nhóm riêng
- `.cache/`, `.claude/`, `.codex/`, `.agents/`, `.github/`, `.mcp.json` - tooling
- `CHANGELOG.md`, `README.md`, `LICENSE` - không cần gõ, chỉ đọc
