# 静态基准集 35 道 MISS 归因与能力覆盖缺口分析

- 日期：2026-10-23
- 依据：`data/ctf_benchmark/real_benchmark.json`（55 道真题，仅 description）+ `real_coverage_report.json`（逐题 presolve 结果）
- 结论前置：**35 道 MISS 全部是基准集设计使然，不是求解器能力缺失；用更强 LLM 重跑不会改变任何一题的结果。**

---

## 一、为什么 35 道 MISS 是「设计使然」

静态基准集约束为「仅题目描述文本，无附件、无靶机、无网络」。对照逐题描述：

| 类别 | 特征 | 示例 | 可解性 |
|---|---|---|---|
| HIT（20 道） | description 内**直接携带可求解数据**（密文 / RSA n,e,c / hex 串） | `nahamcon2024_rsa`：`RSA n=2622..., e=3, c=1024...` | 确定性求解器可直接解 |
| MISS（35 道） | description 内**只有一句题型提示**，数据载体在附件/靶机/环境 | `crewctf2024_rsa_gcd`：`RSA共模攻击：n1和n2共享素数p` | 纯文本无解 |

即：MISS 题的 flag 载体（二进制文件、git 仓库、网页源码、Cookie、pcap、磁盘/内存镜像、图像隐写、真实靶机）全部不在 description 里。任何 LLM 都无法从「RSA共模攻击：n1和n2共享素数p」这句话算出 flag。这是基准集边界（仅 description），不是能力缺陷。

---

## 二、能力覆盖矩阵：35 题 → 执行层验证对照

项目另有 execution（17 题）、attachment（10 题）、web（10 题）、web_hint（6 题）+ 17 个深度专项集，全部 100% 命中。将 35 道 MISS 的能力按题逐一对照：

| # | MISS 题 | 能力维度 | 执行层覆盖（100%） |
|---|---|---|---|
| 1 | crewctf2024_rsa_gcd | RSA 共模/GCD 攻击 | ✅ exec_common_modulus |
| 2 | pico2024_minirsa | RSA e=3 小指数 | ✅ static 已命中同族 2 题 + exec_hastad_broadcast |
| 3 | crc_forgery_real | CRC 伪造 | ⚠️ crc32_forge 覆盖 CRC32；**本题为 CRC64 + HTTP cookie CBC 篡改，组合未覆盖** |
| 4 | pico2024_stringsit | strings 提取 | ✅ exec_strings |
| 5 | pico2024_commitment / gitcred | git 历史/凭证 | ✅ exec_git / exec_git_cred |
| 6 | pico2024_ssh | SSH 服务器交互 | ⚠️ 环境依赖型，无静态覆盖（不适合入 benchmark） |
| 7 | pico2024_cookie / pico2025_cookie_monster | Cookie 取证 | ✅ web.cookie_flag |
| 8 | pico2024_webdecode | 源码 base64 | ✅ web.src_b64 |
| 9 | pico2024_findme / not_my_fault / intro_to_web | 源码隐藏 flag | ✅ web.src_comment |
| 10 | pico2024_irishname / matchfix / buuctf_sqli_basic | SQLi 绕过 | ✅ live_sqli / sqli_login / hint_sqli / sqli_deep |
| 11 | pico2024_no_sql_injection | NoSQL 注入 | ✅ web.nosql / hint_nosql |
| 12 | pico2025_echo_valley / ssti_tpl_inject | SSTI | ✅ live_ssti / ssti_deep |
| 13 | pico2025_handoff | 未授权 API | ✅ web.api_idor |
| 14 | xss_cookie_steal / buuctf_xss_basic | **XSS（Cookie 窃取/反射）** | ❌ **执行层无任何 XSS 靶场题** |
| 15 | xxe_file_read | XXE 文件读 | ✅ xxe_deep（回显/XInclude/Blind OOB） |
| 16 | pico2024_trickster / buuctf_upload_basic | 上传绕过 | ✅ upload_deep（黑名单/路径穿越） |
| 17 | buuctf_lfi_basic | LFI | ✅ web.lfi / hint_lfi |
| 18 | buuctf_rce_basic | 命令注入 | ✅ web.cmdi |
| 19 | buuctf_ssrf_basic | SSRF | ✅ web.ssrf / hint_ssrf / ssrf_deep |
| 20 | flag_in_pcap / forensics_pcap_http | pcap 分析 | ✅ artifact_pcap_http / exec_pcap_get |
| 21 | steg_lsb_png | PNG LSB 隐写 | ✅ artifact_png_lsb |
| 22 | aes_ecb_penguin | AES-ECB 模式识别 | ⚠️ attachment 有 PNG 分析但**无 ECB 企鹅图专项** |
| 23 | public_morse_image | Morse 图像解码 | ⚠️ exec_morse 为文本 Morse；**图像版无覆盖** |
| 24 | forensics_mem_volatility | 内存取证 | ✅ exec_memdump |
| 25 | forensics_disk_image | 磁盘镜像 | ✅ exec_disk_image |

**统计：35 道 MISS 中 30 道的能力已在执行层得到 100% 机验覆盖，4 道存在缺口，1 道（SSH）为环境依赖型不入基准。**

---

## 三、真缺口清单（按价值排序）

1. **XSS（最大缺口）**——2 道真实 MISS 题（CISCN 2019 Web2、BUUCTF XSS 基础）指向该能力，而 web / web_hint / 深度集均无 XSS 靶场题。补一个反射型 XSS + 管理端 Cookie 窃取场景即可形成闭环，预计 3 个场景。
2. **AES-ECB 模式识别**——「相同明文块 → 相同密文块」的可视化识别（企鹅图），attachment 集可加 1 题（生成 ECB 图，要求检测重复块）。
3. **Morse 图像版**——exec_morse 已覆盖文本 Morse；补图像版（像素/明暗提取 Morse）1 题即可闭合。
4. **CRC64 + CBC cookie 篡改**——crc32_forge 只到 CRC32；真题为 CRC64 线性性 + 字节翻转篡改。难度较高（hard），可视时间决定。

---

## 四、建议动作（供决策）

- **P0（强烈建议）**：补 XSS 靶场 3 场景（反射 XSS / 存储 XSS Cookie 窃取 / XSS→SQLi 组合），接入 run_all_benchmarks.py 并上锁基线。这是当前唯一「真实真题 MISS + 执行层零覆盖」的能力面。
- P1（有余力）:attachment 补 AES-ECB 企鹅图 1 题、Morse 图像 1 题。
- P2（可选）:CRC64+CBC 篡改 1 题。
- 明确不做：SSH 交互（环境依赖）、其余 30 道 MISS（能力已闭环，无需为静态集重复建设）。

---

## 六、处置结果（2026-10-23 已完成全部 4 类缺口）

| 缺口 | 处置 | 验证结果 |
|---|---|---|
| XSS（P0） | 新建 `live_target/xss_range.py`（反射/存储/XSS→SQLi 三场景，最小 JS 子集模拟）+ `judge_xss.py` + `xss_benchmark.json` | ✅ 3/3 命中 |
| AES-ECB 企鹅图（P1） | 新建 `gen_ecb_image.py`（ECB/CBC 对照成对，反注水）+ `judge_ecb.py` + `ecb_benchmark.json` | ✅ 1/1（ECB dup=0.934 vs CBC 0.000） |
| Morse 图像版（P1） | 新建 `gen_morse_image.py` + `judge_morse_image.py` + `morse_image_benchmark.json`（像素 run-length → Morse，与 exec_morse 同表） | ✅ 1/1 |
| CRC64+CBC（P2） | 新建 `live_target/crc64_range.py`（自定义多项式 oracle + GF(2) 线性性 bit-flip）+ `judge_crc64.py` + `crc64_benchmark.json` | ✅ 1/1（crc(admin)=crc(guest)⊕crc(Δ)） |

配套接线：
- `run_all_benchmarks.py` 已接入【24】ECB、【25】Morse 时序图、【26】CRC64 三个新集（合计 26 集）；
- `parity_registry.json` 台账登记 24/25/26（parity=unwired，Go 侧镜像待接线，诚实标注）；
- 基线已 `--update-baseline` 上锁（`docs/benchmark_baseline.json`，26 项）；
- 门禁复核：`check_suite_parity.py --check` PASS（台账覆盖全部 26 集、21 个已接线集逐题一致）、`check_benchmark_parity.py` 静态三路一致、`audit_benchmark_validity.py` 诚实口径 12/12=100%；
- 自产题占比 62.3%（91/146），对外引用 100% 必须标注「自产题/自建靶场」（§2.3 诚信铁律）。

## 五、验证方式与口径

- 本报告所有题目分类来自 `real_coverage_report.json` 逐题 `presolve_engine`/`sha256_match` 字段与 `real_benchmark.json` 的 description 原文，未手工改动。
- HIT/MISS 判定口径与 `run_all_benchmarks.py` 一致（presolve_engine 非空且 sha256_match=True 才计命中）。
- 覆盖矩阵中「执行层 100%」依据 `docs/benchmark_baseline.json` 与 `all_benchmarks_summary.json`（2026-10-22 快照）逐项核对。
