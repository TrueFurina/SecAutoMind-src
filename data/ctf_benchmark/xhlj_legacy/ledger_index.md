# 西湖论剑 真题验证链数据索引（迁移至 SecAutoMind）

> **来源**：`E:\Program\西湖论剑\ctf_agent\REAL_SOLVES_LEDGER.md`（2026-10-23 全读核对的权威快照）
> **用途**：吞并后的只读知识库索引——数据本体保留在西湖论剑（冻结仓库），本文件提供
> 可复现路径、flag_sha256 真值锚与 SecAutoMind 覆盖对照。机器可读版见 `coverage_map.json`。
> **口径**：strict KPI = offline_verified 严格真题 **14 道**（A 类 6 + B 类 8，含 vnctf_cm1）；
> 另有 10732/10735 可机器复现但无官方 sha256 闭环，不进严格 KPI；HGAME×3/西湖 FilterRandom
> 为外部真题不计 KPI。西湖论剑平台 accepted=0（历史事实，保留为对照基线）。
> **验证命令基址**：下表「西湖论剑验证命令」列均为**相对冻结仓 `西湖论剑/ctf_agent/`** 的路径
> （该仓 `scripts/` 下 23 个 verify/regress 脚本，2026-10-24 实测存在）。按路线图
> 「冻结不是删除」，脚本本体留在只读知识库、不迁入本仓——本表只作溯源，本仓 CI 不断言其可执行。

## A 类 · 完整攻击链（6）

| # | id | 题型 | flag_sha256 锚 | 西湖论剑验证命令 | SecAutoMind 覆盖 |
|---|---|---|---|---|---|
| 1 | real_crypto_specialcurve2 | crypto/复数组 RSA | `cd7e815f4a5a378b…` | `scripts/verify_specialcurve2.py` → REGRESS_PASS | ❌ 未覆盖（factordb/DLP 依赖） |
| 2 | 10733 | crypto/高偶指数 RSA+ROT13 | `ac232bd941738e22…` | `scripts/verify_10733.py` | ✅ `rsa_hint_high_exp` |
| 3 | real_misc_vnctf_flag | misc/网格重采样 | `7d9ce4e1a4e7369e…` | `_verify_presolve_truth.py`（15/15） | ✅ `grid_resample`（OCR 视觉兜底） |
| 4 | real_misc_xuanhun_signin | misc/JPEG 尾嵌 PNG | `d5e1894ae1bb4e4d…` | `skills/jpeg_png_embedded.run()` | ⚠️ 部分（`stego_detect` 检测有，提取链路未验证） |
| 5 | real_reverse_sheng | reverse/静态分析 | `d65b30ccdac4d74e…` | `_verify_presolve_truth.py` | ❌ 未覆盖（无实际反汇编执行） |
| 6 | real_reverse_upx | reverse/UPX 脱壳 | `7130218010da8eea…` | `_verify_presolve_truth.py` | ❌ 未覆盖（无 UPX 脱壳执行） |

## B 类 · presolve 确定性变换（8）

| # | id | 题型 | flag_sha256 锚 | 西湖论剑验证命令 | SecAutoMind 覆盖 |
|---|---|---|---|---|---|
| 7 | real_crypto_anwang_crypto1 | 八进制 ASCII+Vigenère | `2e9f80ef4619805c…` | `_verify_presolve_truth.py` | ⚠️ 部分（`encoding_octal`+`vigenere` 均有，链路未验证） |
| 8 | real_crypto_ezrsa | Hastad e=17 | `93be5f3ad422c43e…` | `_regress_one.py real_crypto_ezrsa` | ✅ `hastad_broadcast_attack` |
| 9 | real_crypto_simplelegendre | 勒让德逐位 | `75e6aa4de894faf2…` | `_regress_one.py real_crypto_simplelegendre` | ✅ `legendre_phi` |
| 10 | real_crypto_ezmult | base64+ROT13 | `60b6c2c15e658b87…` | `_verify_presolve_truth.py` | ⚠️ 部分（`b64_caesar_alphabet` 存在，链路未验证） |
| 11 | real_crypto_exciting_inverse | phi+双模逆分解 | `4b84616cccbe84a9…` | `_regress_one.py real_crypto_exciting_inverse` | ✅ `rsa_phi_pinv` |
| 12 | real_crypto_filterrandom | LFSR 噪声恢复 | `768a21b901963eb9…` | `_verify_presolve_truth.py` | ✅ `lfsr_correlation` |
| 13 | real_crypto_qiangwang_classic | 摩斯+单表 | `f4adf0d868f5b0ac…` | `_verify_presolve_truth.py` | ⚠️ 部分（`morse`+`caesar` 均有，链路未验证） |
| 14 | real_reverse_vnctf_cm1 | Android XXTEA | `a9bb88af16508d85…` | `_regress_one.py real_reverse_vnctf_cm1` | ❌ 未覆盖（XXTEA/Android） |

## 可机器复现但不进严格 KPI（2）

| id | 题型 | 说明 |
|---|---|---|
| 10732 | PKCS#1 v1.5+AES | `verify_10732.py` REGRESS_PASS；无题面官方 sha256 锚（自证双运行一致），不进 KPI |
| 10735 | logbool pcap 盲注 | `verify_10735.py` REGRESS_PASS（19s，三重 sha256 锚互证）；同无官方锚点，不进 KPI |

## 覆盖对照小结

- ✅ 已覆盖 **6/14**：10733 / vnctf_flag / ezrsa / simplelegendre / exciting_inverse / filterrandom
- ⚠️ 部分覆盖 **4/14**：xuanhun_signin / anwang_crypto1 / ezmult / qiangwang_classic（求解器原语存在，链路未验证）
- ❌ 未覆盖 **4/14**：specialcurve2 / sheng / upx / vnctf_cm1（reverse 执行层与深度 crypto 为赛后 P1/P2 迁移对象）

> 数据本体（题面 JSON、附件、verify 脚本、重建实例）均保留于西湖论剑冻结仓库原路径，
> 赛前不复制字节、不动 SecAutoMind 基准 JSON（避免基线漂移影响 1024 快闪赛材料口径）。
> 赛后 P0/P1 按 `merge_xhlj_roadmap_20261023.md` 逐链 Go 化并入真实基准。
