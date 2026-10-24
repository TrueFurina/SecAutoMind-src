# 🚨 提交格式（13:50 实锤，所有会话必读）

**平台只认花括号内的裸内容，不要带 `flag{}` / `DASCTF{}` 外壳。**

- 端点：`POST https://ycb-bk.dasctf.com/slab-match/api/v1/player/answer-panel/answer`
- body：`{"exerciseId": <题号>, "flag": "<裸内容>"}`
  - 字段名必须是 `exerciseId`，写 `exercise_id` 会报 `40001 column.exercise_id不能为空`
- 实测（12082）：
  - `flag{e-cdn81.net_...}` → `40001 提交flag错误`
  - `e-cdn81.net_...`（裸）→ **`isCorrect: true`**

## 判据（别再重复踩）
- 题面/README 里的「flag 格式：flag{...}」只描述**逻辑格式**，提交时**去壳**。
- 例外：如果该题 flag 串本身就以 `DASCTF{` 开头（如 12063 的 `DASCTF{3792...}`），那它本身就是裸内容，不要再包一层。
- **连续 5 次失败就停手做通道对照**：拿一个已知正确的串，分别裸/带壳各发一次，看返回码差异。不要在内容上继续枚举。

## 12082 已解出，不要再提交
已通过 flag（裸内容）：
`e-cdn81.net_PAT-9F4K2M-Q3GIT7-CORP4S_107_20260910T1422_asset-inventory-2026Q3.md_corp-fast.net`
