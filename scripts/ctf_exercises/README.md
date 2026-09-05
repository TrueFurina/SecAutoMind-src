# 实战赛 CTF 演练题库（scripts/ctf_exercises/）

> 用途：终审第一环节（人机协同实战赛，占 60%）的赛前演练材料。
> 方法论移植自西湖论剑 CTF-Agent 实战验证过的解题套路；每题附自然语言任务示范，可直接对 SecAutoMind 平台下发。
> 判分：`judge.py`（sha256 对 ground truth，杜绝手工对答案）。

## 题目清单（5 道 · 全部可离线求解 · flag 互异）

| id | 类型 | 考察能力 | 文件 | 对应平台工具 |
|---|---|---|---|---|
| c1_zip_chain | MISC | 嵌套 zip + base64 链式解码 | `c1_zip_chain/challenge.b64` | execute-python-script（zipfile/base64） |
| c2_xor_prefix | CRYPTO | 单字节 XOR + 已知明文前缀攻击 | `c2_xor_prefix/cipher.bin` + hint | execute-python-script |
| c3_rsa_fermat | CRYPTO | RSA 相近素数 → Fermat 分解 | `c3_rsa_fermat/task.txt` | execute-python-script |
| c4_log_forensics | MISC | 200 行日志中定位 3 条外带/异常 | `c4_log_forensics/access.log` | execute-python-script / grep 类 |
| c5_png_lsb | MISC | PNG LSB 逐位隐写提取 | `c5_png_lsb/stego.png` + readme | execute-python-script（PIL） |

## 使用方式

### 1) 判分器
```bash
python judge.py --check                      # 题目文件完整性
python judge.py "flag{...}"                  # 提交 flag 判分（自动判所有题）
```

### 2) 对平台下发的自然语言任务示范（实战赛口吻）

- c1：*"解出 c1_zip_chain/challenge.b64 里的 flag——先 base64 解码，再逐层解 zip 包裹，最内层 secret.txt 就是答案，最后用 judge.py 提交验证。"*
- c2：*"cipher.bin 是单字节 XOR 加密的 flag，已知明文以 flag{ 开头，用已知前缀攻击恢复密钥并解出全文。"*
- c3：*"task.txt 给了 RSA 的 n/e/c，素数生成方式相近，用 Fermat 分解恢复 p、q 解密。"*
- c4：*"access.log 中混入了 3 条含敏感数据外带的可疑请求，找出它们并提取外带的 flag。"*
- c5：*"stego.png 的 LSB 按行序藏了 ASCII 字符串（NUL 结尾），提取出 flag。"*

### 3) 演练记录方式（每次演练必填，赛前复盘用）

| 日期 | 题目 | 人解/Agent解 | 用时 | 失败点 | 改进 |
|------|------|--------------|------|--------|------|

## 重建

```bash
python generate_exercises.py   # 重新生成全部题目与 ground_truth.json（固定种子，可复现）
```

## ⚠️ 边界

- 本题库为**自研练习题**（非真题、非泄露题），用于演练与演示，可随材料提交展示"备战过程"。
- 解题引擎/技能包自动化**不在本目录范围**（按用户决策，11 月决赛前用官方仿真平台打磨）。
- ground_truth.json 含明文 flag——**若随作品材料提交，评委可视为"判分依据"而非泄题；若担心观感，提交前删掉各题 flag 字段只留 sha256**。
