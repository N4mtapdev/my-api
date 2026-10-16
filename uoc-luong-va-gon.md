# Ước lượng thời gian (trừ các mục trên)

| Mục | Dòng | Thời gian gõ liên tục (~100 dòng/phút) |
| --- | ---: | ---: |
| G0 + G1 + G2 + G3 | 4.969 | ~50 phút |
| G4 (38 app) | 17.980 | ~3 giờ |
| G5 + G6 | 10.918 | ~1,8 giờ |
| G7 (web) | 17.397 | ~3 giờ |
| G8 + G9 | 10.360 | ~1,7 giờ |
| **Tổng** | **61.624** | **~10,3 giờ gõ thật, thực tế 3-5 ngày** |

Nếu bạn muốn gõ **100%** rồi đo: mỗi lần `bun install` xong thì chạy `bun run typecheck`
ngay trong bước nhỏ; nếu đỏ thì fix trước khi qua bước tiếp. Đó là chốt, còn lại chỉ là công sức.

---

# Nếu chỉ gõ 1 phần

1. Chỉ cần `duo` chạy được: gõ **G0 -> G1 -> G2 -> G3 -> G4 -> G5** (33.000 dòng, ra simulator trọn vẹn).
2. Cần cả website: thêm **G6 -> G7**.
3. Chỉ muốn làm app mới: **G0 -> G1 -> G2 -> G4 nhóm A**, rồi tạo `packages/apps/<ten-app>`
   theo đúng thứ tự file ở mục G4.
