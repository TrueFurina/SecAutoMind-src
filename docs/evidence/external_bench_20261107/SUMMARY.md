# 外部赛题池跑批汇总（机器生成）

池：`data/questions_external_bench/external_bench.json`  题数 40  可计分分母 37

## 一、总体

| 轮次 | 模型 | 解出 | rate(全池) | rate(可计分) | API失败 | 截断题 | 空答/无工具 | 平均耗时 |
|---|---|---|---|---|---|---|---|---|
| step_s1 | step-3.5-flash | 0/40 | 0.000 | 0.000 | 0 | 19 | 10 | 79s |
| step_s2_32k | step-3.5-flash | 0/40 | 0.000 | 0.000 | 1 | 19 | 10 | 158s |
| ds_qwen38max | qwen3.8-max-0902 | 0/40 | 0.000 | 0.000 | 29 | 0 | 2 | 120s |
| a8_ds41 | deepseek-v4.1-flash | 0/8 | 0.000 | 0.000 | 0 | 1 | 3 | 75s |
| a8_kimi_v1 | kimi-k3 | 0/8 | 0.000 | - | 8 | 0 | 0 | 37s |
| a8_kimi_v2 | kimi-k3 | 0/8 | 0.000 | 0.000 | 4 | 0 | 3 | 242s |
| a8_qwen24t | qwen3.8-2.4t-a95b | 0/8 | 0.000 | 0.000 | 4 | 0 | 1 | 291s |
| a8_qwenflash | qwen3.8-flash | 0/8 | 0.000 | 0.000 | 4 | 0 | 2 | 316s |
| a8_minimax | MiniMax-M2.5 | 0/8 | 0.000 | 0.000 | 2 | 0 | 2 | 179s |
| a8_qwen27b | qwen3.8-27b | 1/8 | 0.125 | 0.333 | 5 | 0 | 1 | 311s |

### 按模型合计

| 模型 | 解出 | 总题次 | rate |
|---|---|---|---|
| step-3.5-flash | 0 | 80 | 0.000 |
| qwen3.8-max-0902 | 0 | 40 | 0.000 |
| deepseek-v4.1-flash | 0 | 8 | 0.000 |
| kimi-k3 | 0 | 16 | 0.000 |
| qwen3.8-2.4t-a95b | 0 | 8 | 0.000 |
| qwen3.8-flash | 0 | 8 | 0.000 |
| MiniMax-M2.5 | 0 | 8 | 0.000 |
| qwen3.8-27b | 1 | 8 | 0.125 |

## 二、按结构分档

| 轮次 | A 静态数据完备 | B 需自建 oracle | 软受限 |
|---|---|---|---|
| step_s1 | 0/8 (0%) | 0/29 (0%) | 0/11 (0%) |
| step_s2_32k | 0/8 (0%) | 0/29 (0%) | 0/11 (0%) |
| ds_qwen38max | 0/8 (0%) | 0/29 (0%) | 0/11 (0%) |
| a8_ds41 | 0/8 (0%) | - | 0/5 (0%) |
| a8_kimi_v1 | 0/8 (0%) | - | 0/5 (0%) |
| a8_kimi_v2 | 0/8 (0%) | - | 0/5 (0%) |
| a8_qwen24t | 0/8 (0%) | - | 0/5 (0%) |
| a8_qwenflash | 0/8 (0%) | - | 0/5 (0%) |
| a8_minimax | 0/8 (0%) | - | 0/5 (0%) |
| a8_qwen27b | 1/8 (12%) | - | 0/5 (0%) |

## 三、按类别

| 轮次 | crypto | misc |
|---|---|---|
| step_s1 | 0/26 | 0/14 |
| step_s2_32k | 0/26 | 0/14 |
| ds_qwen38max | 0/26 | 0/14 |
| a8_ds41 | 0/7 | 0/1 |
| a8_kimi_v1 | 0/7 | 0/1 |
| a8_kimi_v2 | 0/7 | 0/1 |
| a8_qwen24t | 0/7 | 0/1 |
| a8_qwenflash | 0/7 | 0/1 |
| a8_minimax | 0/7 | 0/1 |
| a8_qwen27b | 1/7 | 0/1 |

## 四、未解分类（逐题）

**step_s1**：EMPTY 9 / NOT_ADMISSIBLE 3 / NO_TOOL 1 / TRUNCATED 19 / WRONG 8

| 题 | 分类 | tool_calls | 耗时 | 截断轮次 |
|---|---|---|---|---|
| ext_gctf2021_david-and-the-tree | EMPTY | 10 | 31s | 0 |
| ext_gctf2021_story | EMPTY | 10 | 17s | 0 |
| ext_gctf2022_appnote-txt | EMPTY | 10 | 32s | 0 |
| ext_gctf2022_cycling | EMPTY | 2 | 91s | 0 |
| ext_gctf2022_electric-mayhem-pqc | EMPTY | 10 | 14s | 0 |
| ext_gctf2022_enigma | EMPTY | 10 | 22s | 0 |
| ext_gctf2023_totally-not-brute-force | EMPTY | 8 | 17s | 0 |
| ext_gctf2024_otp | EMPTY | 10 | 48s | 0 |
| ext_gctf2025_underhanded | EMPTY | 10 | 11s | 0 |
| ext_gctf2021_abc-arm-and-amd | NOT_ADMISSIBLE | 10 | 53s | 0 |
| ext_gctf2022_segfault-labyrinth | NOT_ADMISSIBLE | 10 | 20s | 0 |
| ext_gctf2024_auxin2 | NOT_ADMISSIBLE | 2 | 105s | 1 |
| ext_gctf2025_bpfbox | NO_TOOL | 0 | 4s | 0 |
| ext_gctf2021_filestore | TRUNCATED | 0 | 99s | 1 |
| ext_gctf2021_h1 | TRUNCATED | 8 | 336s | 1 |
| ext_gctf2021_ican-tbelieveit-snotcrypto | TRUNCATED | 4 | 86s | 1 |
| ext_gctf2021_pythia | TRUNCATED | 0 | 93s | 1 |
| ext_gctf2021_tiramisu | TRUNCATED | 11 | 156s | 1 |
| ext_gctf2021_tonality | TRUNCATED | 6 | 90s | 1 |
| ext_gctf2022_custom-protocol | TRUNCATED | 0 | 95s | 1 |
| ext_gctf2022_legit | TRUNCATED | 0 | 77s | 1 |
| ext_gctf2022_maybe-someday | TRUNCATED | 0 | 98s | 1 |
| ext_gctf2022_ocr | TRUNCATED | 0 | 77s | 1 |
| ext_gctf2023_primes | TRUNCATED | 1 | 81s | 1 |
| ext_gctf2024_blinders | TRUNCATED | 0 | 74s | 1 |
| ext_gctf2024_desfunctional | TRUNCATED | 0 | 99s | 1 |
| ext_gctf2024_hwsim | TRUNCATED | 7 | 107s | 1 |
| ext_gctf2024_idea | TRUNCATED | 1 | 173s | 1 |
| ext_gctf2024_mceliece | TRUNCATED | 4 | 114s | 1 |
| ext_gctf2025_filtermaze | TRUNCATED | 1 | 90s | 1 |
| ext_gctf2025_hwsimv2 | TRUNCATED | 9 | 110s | 1 |
| ext_gctf2025_merkurated | TRUNCATED | 0 | 100s | 1 |
| ext_gctf2022_electric-mayhem-cls | WRONG | 10 | 17s | 0 |
| ext_gctf2023_cursved | WRONG | 4 | 144s | 0 |
| ext_gctf2023_least-common-genominator | WRONG | 10 | 72s | 0 |
| ext_gctf2023_mhk2 | WRONG | 11 | 41s | 0 |
| ext_gctf2023_papapapa | WRONG | 10 | 36s | 0 |
| ext_gctf2023_zip | WRONG | 10 | 54s | 0 |
| ext_gctf2024_zkpok | WRONG | 7 | 161s | 0 |
| ext_gctf2025_numerology | WRONG | 10 | 27s | 0 |

**step_s2_32k**：API_ERROR 1 / EMPTY 8 / NOT_ADMISSIBLE 3 / NO_TOOL 2 / TRUNCATED 19 / WRONG 7

| 题 | 分类 | tool_calls | 耗时 | 截断轮次 |
|---|---|---|---|---|
| ext_gctf2024_desfunctional | API_ERROR | 1 | 482s | 0 |
| ext_gctf2021_david-and-the-tree | EMPTY | 12 | 29s | 0 |
| ext_gctf2022_appnote-txt | EMPTY | 12 | 24s | 0 |
| ext_gctf2022_electric-mayhem-cls | EMPTY | 12 | 27s | 0 |
| ext_gctf2022_electric-mayhem-pqc | EMPTY | 12 | 25s | 0 |
| ext_gctf2022_ocr | EMPTY | 12 | 39s | 0 |
| ext_gctf2023_totally-not-brute-force | EMPTY | 5 | 21s | 0 |
| ext_gctf2024_otp | EMPTY | 12 | 49s | 0 |
| ext_gctf2025_numerology | EMPTY | 12 | 26s | 0 |
| ext_gctf2021_abc-arm-and-amd | NOT_ADMISSIBLE | 3 | 33s | 0 |
| ext_gctf2022_segfault-labyrinth | NOT_ADMISSIBLE | 12 | 31s | 0 |
| ext_gctf2024_auxin2 | NOT_ADMISSIBLE | 6 | 463s | 1 |
| ext_gctf2022_maybe-someday | NO_TOOL | 0 | 92s | 0 |
| ext_gctf2025_bpfbox | NO_TOOL | 0 | 60s | 0 |
| ext_gctf2021_filestore | TRUNCATED | 0 | 341s | 1 |
| ext_gctf2021_ican-tbelieveit-snotcrypto | TRUNCATED | 5 | 177s | 1 |
| ext_gctf2021_pythia | TRUNCATED | 0 | 176s | 1 |
| ext_gctf2021_story | TRUNCATED | 5 | 258s | 1 |
| ext_gctf2021_tonality | TRUNCATED | 3 | 172s | 1 |
| ext_gctf2022_custom-protocol | TRUNCATED | 0 | 166s | 1 |
| ext_gctf2022_cycling | TRUNCATED | 0 | 332s | 1 |
| ext_gctf2022_enigma | TRUNCATED | 6 | 167s | 1 |
| ext_gctf2022_legit | TRUNCATED | 0 | 168s | 1 |
| ext_gctf2023_cursved | TRUNCATED | 0 | 150s | 1 |
| ext_gctf2023_papapapa | TRUNCATED | 4 | 165s | 1 |
| ext_gctf2023_primes | TRUNCATED | 5 | 194s | 1 |
| ext_gctf2023_zip | TRUNCATED | 0 | 142s | 1 |
| ext_gctf2024_hwsim | TRUNCATED | 5 | 148s | 1 |
| ext_gctf2024_idea | TRUNCATED | 2 | 257s | 1 |
| ext_gctf2024_mceliece | TRUNCATED | 3 | 151s | 1 |
| ext_gctf2025_filtermaze | TRUNCATED | 2 | 168s | 1 |
| ext_gctf2025_hwsimv2 | TRUNCATED | 7 | 154s | 1 |
| ext_gctf2025_underhanded | TRUNCATED | 10 | 326s | 1 |
| ext_gctf2021_h1 | WRONG | 12 | 315s | 0 |
| ext_gctf2021_tiramisu | WRONG | 12 | 15s | 0 |
| ext_gctf2023_least-common-genominator | WRONG | 12 | 98s | 0 |
| ext_gctf2023_mhk2 | WRONG | 13 | 124s | 0 |
| ext_gctf2024_blinders | WRONG | 1 | 231s | 0 |
| ext_gctf2024_zkpok | WRONG | 8 | 197s | 0 |
| ext_gctf2025_merkurated | WRONG | 1 | 126s | 0 |

**ds_qwen38max**：API_ERROR 29 / EMPTY 2 / NOT_ADMISSIBLE 3 / WRONG 6

| 题 | 分类 | tool_calls | 耗时 | 截断轮次 |
|---|---|---|---|---|
| ext_gctf2021_david-and-the-tree | API_ERROR | 0 | 16s | 0 |
| ext_gctf2021_filestore | API_ERROR | 0 | 36s | 0 |
| ext_gctf2021_h1 | API_ERROR | 0 | 360s | 0 |
| ext_gctf2021_ican-tbelieveit-snotcrypto | API_ERROR | 0 | 44s | 0 |
| ext_gctf2022_appnote-txt | API_ERROR | 0 | 31s | 0 |
| ext_gctf2022_custom-protocol | API_ERROR | 1 | 562s | 0 |
| ext_gctf2022_legit | API_ERROR | 0 | 18s | 0 |
| ext_gctf2022_maybe-someday | API_ERROR | 0 | 360s | 0 |
| ext_gctf2022_ocr | API_ERROR | 0 | 31s | 0 |
| ext_gctf2023_cursved | API_ERROR | 4 | 191s | 0 |
| ext_gctf2023_least-common-genominator | API_ERROR | 1 | 46s | 0 |
| ext_gctf2023_mhk2 | API_ERROR | 0 | 33s | 0 |
| ext_gctf2023_papapapa | API_ERROR | 0 | 15s | 0 |
| ext_gctf2023_primes | API_ERROR | 0 | 16s | 0 |
| ext_gctf2023_totally-not-brute-force | API_ERROR | 0 | 17s | 0 |
| ext_gctf2023_zip | API_ERROR | 0 | 40s | 0 |
| ext_gctf2024_blinders | API_ERROR | 0 | 17s | 0 |
| ext_gctf2024_desfunctional | API_ERROR | 0 | 46s | 0 |
| ext_gctf2024_hwsim | API_ERROR | 0 | 42s | 0 |
| ext_gctf2024_idea | API_ERROR | 0 | 19s | 0 |
| ext_gctf2024_mceliece | API_ERROR | 0 | 33s | 0 |
| ext_gctf2024_otp | API_ERROR | 0 | 39s | 0 |
| ext_gctf2024_zkpok | API_ERROR | 0 | 43s | 0 |
| ext_gctf2025_bpfbox | API_ERROR | 0 | 29s | 0 |
| ext_gctf2025_filtermaze | API_ERROR | 0 | 40s | 0 |
| ext_gctf2025_hwsimv2 | API_ERROR | 0 | 28s | 0 |
| ext_gctf2025_merkurated | API_ERROR | 0 | 23s | 0 |
| ext_gctf2025_numerology | API_ERROR | 0 | 36s | 0 |
| ext_gctf2025_underhanded | API_ERROR | 0 | 40s | 0 |
| ext_gctf2022_electric-mayhem-cls | EMPTY | 12 | 120s | 0 |
| ext_gctf2022_electric-mayhem-pqc | EMPTY | 19 | 165s | 0 |
| ext_gctf2021_abc-arm-and-amd | NOT_ADMISSIBLE | 0 | 29s | 0 |
| ext_gctf2022_segfault-labyrinth | NOT_ADMISSIBLE | 0 | 48s | 0 |
| ext_gctf2024_auxin2 | NOT_ADMISSIBLE | 0 | 19s | 0 |
| ext_gctf2021_pythia | WRONG | 11 | 404s | 0 |
| ext_gctf2021_story | WRONG | 18 | 471s | 0 |
| ext_gctf2021_tiramisu | WRONG | 10 | 331s | 0 |
| ext_gctf2021_tonality | WRONG | 12 | 294s | 0 |
| ext_gctf2022_cycling | WRONG | 11 | 509s | 0 |
| ext_gctf2022_enigma | WRONG | 9 | 159s | 0 |

**a8_ds41**：EMPTY 2 / NO_TOOL 1 / TRUNCATED 1 / WRONG 4

| 题 | 分类 | tool_calls | 耗时 | 截断轮次 |
|---|---|---|---|---|
| ext_gctf2022_appnote-txt | EMPTY | 12 | 35s | 0 |
| ext_gctf2023_mhk2 | EMPTY | 12 | 40s | 0 |
| ext_gctf2021_tiramisu | NO_TOOL | 0 | 40s | 0 |
| ext_gctf2024_mceliece | TRUNCATED | 2 | 135s | 1 |
| ext_gctf2021_h1 | WRONG | 12 | 224s | 0 |
| ext_gctf2022_enigma | WRONG | 3 | 22s | 0 |
| ext_gctf2023_least-common-genominator | WRONG | 12 | 78s | 0 |
| ext_gctf2025_numerology | WRONG | 12 | 28s | 0 |

**a8_kimi_v1**：API_ERROR 8

| 题 | 分类 | tool_calls | 耗时 | 截断轮次 |
|---|---|---|---|---|
| ext_gctf2021_h1 | API_ERROR | 0 | 37s | 0 |
| ext_gctf2021_tiramisu | API_ERROR | 0 | 45s | 0 |
| ext_gctf2022_appnote-txt | API_ERROR | 0 | 32s | 0 |
| ext_gctf2022_enigma | API_ERROR | 0 | 25s | 0 |
| ext_gctf2023_least-common-genominator | API_ERROR | 0 | 23s | 0 |
| ext_gctf2023_mhk2 | API_ERROR | 0 | 34s | 0 |
| ext_gctf2024_mceliece | API_ERROR | 0 | 57s | 0 |
| ext_gctf2025_numerology | API_ERROR | 0 | 44s | 0 |

**a8_kimi_v2**：API_ERROR 4 / EMPTY 2 / NO_TOOL 1 / WRONG 1

| 题 | 分类 | tool_calls | 耗时 | 截断轮次 |
|---|---|---|---|---|
| ext_gctf2021_h1 | API_ERROR | 0 | 360s | 0 |
| ext_gctf2023_least-common-genominator | API_ERROR | 11 | 426s | 0 |
| ext_gctf2023_mhk2 | API_ERROR | 0 | 360s | 0 |
| ext_gctf2024_mceliece | API_ERROR | 0 | 360s | 0 |
| ext_gctf2022_appnote-txt | EMPTY | 12 | 181s | 0 |
| ext_gctf2025_numerology | EMPTY | 12 | 83s | 0 |
| ext_gctf2021_tiramisu | NO_TOOL | 0 | 91s | 0 |
| ext_gctf2022_enigma | WRONG | 1 | 75s | 0 |

**a8_qwen24t**：API_ERROR 4 / EMPTY 1 / WRONG 3

| 题 | 分类 | tool_calls | 耗时 | 截断轮次 |
|---|---|---|---|---|
| ext_gctf2021_h1 | API_ERROR | 2 | 550s | 0 |
| ext_gctf2021_tiramisu | API_ERROR | 8 | 543s | 0 |
| ext_gctf2023_mhk2 | API_ERROR | 0 | 360s | 0 |
| ext_gctf2024_mceliece | API_ERROR | 0 | 360s | 0 |
| ext_gctf2022_appnote-txt | EMPTY | 12 | 80s | 0 |
| ext_gctf2022_enigma | WRONG | 5 | 171s | 0 |
| ext_gctf2023_least-common-genominator | WRONG | 12 | 181s | 0 |
| ext_gctf2025_numerology | WRONG | 13 | 84s | 0 |

**a8_qwenflash**：API_ERROR 4 / EMPTY 2 / WRONG 2

| 题 | 分类 | tool_calls | 耗时 | 截断轮次 |
|---|---|---|---|---|
| ext_gctf2021_h1 | API_ERROR | 0 | 360s | 0 |
| ext_gctf2021_tiramisu | API_ERROR | 10 | 552s | 0 |
| ext_gctf2023_mhk2 | API_ERROR | 4 | 899s | 0 |
| ext_gctf2024_mceliece | API_ERROR | 0 | 360s | 0 |
| ext_gctf2022_appnote-txt | EMPTY | 12 | 81s | 0 |
| ext_gctf2025_numerology | EMPTY | 13 | 20s | 0 |
| ext_gctf2022_enigma | WRONG | 17 | 96s | 0 |
| ext_gctf2023_least-common-genominator | WRONG | 13 | 161s | 0 |

**a8_minimax**：API_ERROR 2 / EMPTY 2 / WRONG 4

| 题 | 分类 | tool_calls | 耗时 | 截断轮次 |
|---|---|---|---|---|
| ext_gctf2021_h1 | API_ERROR | 11 | 296s | 0 |
| ext_gctf2022_enigma | API_ERROR | 11 | 244s | 0 |
| ext_gctf2022_appnote-txt | EMPTY | 12 | 40s | 0 |
| ext_gctf2023_mhk2 | EMPTY | 12 | 52s | 0 |
| ext_gctf2021_tiramisu | WRONG | 8 | 314s | 0 |
| ext_gctf2023_least-common-genominator | WRONG | 12 | 259s | 0 |
| ext_gctf2024_mceliece | WRONG | 12 | 195s | 0 |
| ext_gctf2025_numerology | WRONG | 12 | 34s | 0 |

**a8_qwen27b**：API_ERROR 5 / EMPTY 1 / WRONG 1

| 题 | 分类 | tool_calls | 耗时 | 截断轮次 |
|---|---|---|---|---|
| ext_gctf2021_h1 | API_ERROR | 0 | 360s | 0 |
| ext_gctf2021_tiramisu | API_ERROR | 0 | 360s | 0 |
| ext_gctf2022_enigma | API_ERROR | 7 | 466s | 0 |
| ext_gctf2023_mhk2 | API_ERROR | 0 | 360s | 0 |
| ext_gctf2024_mceliece | API_ERROR | 0 | 360s | 0 |
| ext_gctf2022_appnote-txt | EMPTY | 13 | 153s | 0 |
| ext_gctf2025_numerology | WRONG | 14 | 180s | 0 |

