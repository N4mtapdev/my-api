# G8. `community-apps/` + `examples/` (23 file TS, 4.929 dòng)

```
L1  community-apps/*/styles.ts  audio.ts  config.ts  avatars.ts  game.ts
    fold-compass/main.tsx  memory-match/main.tsx  wordle-mini/main.tsx
    pomodoro-timer/main.tsx  habit-streaks/main.tsx  tic-tac-toe/main.tsx
L2  flappy-duo/world.ts  2048/styles.ts  snake/duo-logo.tsx
L3  flappy-duo/main.tsx  2048/board.tsx  snake/game-board.tsx
L4  2048/main.tsx  snake/main.tsx
```

Thứ tự cụ thể: `community-apps/registry.json` -> `fold-compass/` (7 file, ví dụ mẫu)
-> `apple-calc/` và 8 app còn lại -> `examples/developer/` -> `examples/fold-compass/`.

`examples/` chỉ có 2 file `.tsx` (`developer/main.tsx`, `fold-compass/main.tsx`), cực nhẹ.
Mỗi app ngoài này là 1 project độc lập, `package.json` trước, `index.tsx` sau.
Đây là sàn chạy `bunx duo check`, không tính vào tsc của gốc.
