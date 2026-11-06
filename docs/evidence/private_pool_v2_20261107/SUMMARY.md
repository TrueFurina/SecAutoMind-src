# 私有题池跑批汇总（40 题 × 3 轮）

> 由 `scripts/summarize_private_pool_runs.py` 从结果文件机算；未解已按 EMPTY / REPEAT / WRONG 拆开。REPEAT 为**下界**（只看得到 raw_head 300 字符）。

## 一、每轮总览

| 轮次 | 解出 | 率 | EMPTY | 其中 REPEAT | WRONG | 延迟合计 |
|---|---|---|---|---|---|---|
| s1 | 37/40 | 92.5% | 2 | 1 | 1 | 482s |
| s2 | 33/40 | 82.5% | 5 | 3 | 2 | 374s |
| s3 | 36/40 | 90.0% | 3 | 2 | 1 | 357s |
| **合计** | **106/120** | **88.3%** | | | | |

## 二、按类别

| category | 题数 | s1 | s2 | s3 | 合计率 |
|---|---|---|---|---|---|
| crypto | 20 | 18/20 | 17/20 | 19/20 | 90.0% |
| misc | 8 | 7/8 | 5/8 | 7/8 | 79.2% |
| reverse | 6 | 6/6 | 6/6 | 5/6 | 94.4% |
| web | 2 | 2/2 | 2/2 | 2/2 | 100.0% |
| pwn | 4 | 4/4 | 3/4 | 3/4 | 83.3% |

## 三、按难度

| difficulty | 题数 | s1 | s2 | s3 | 合计率 |
|---|---|---|---|---|---|
| easy | 17 | 16/17 | 13/17 | 16/17 | 88.2% |
| medium | 16 | 15/16 | 14/16 | 14/16 | 89.6% |
| hard | 7 | 6/7 | 6/7 | 6/7 | 85.7% |

## 四、逐题矩阵

| 题 | 类别 | 难度 | s1 | s2 | s3 | 稳定 |
|---|---|---|---|---|---|---|
| `pp_v1_01_xor_single_byte` | crypto | easy | O | X | O | 波动 |
| `pp_v1_02_rsa_low_exponent_cube` | crypto | easy | O | O | O | 稳定命中 |
| `pp_v1_03_vigenere_known_key` | crypto | easy | O | O | O | 稳定命中 |
| `pp_v1_04_lcg_predict_next` | crypto | easy | O | O | O | 稳定命中 |
| `pp_v1_05_weak_seed_prng` | crypto | medium | R | - | O | 波动 |
| `pp_v1_06_encoding_nest` | misc | easy | O | O | O | 稳定命中 |
| `pp_v1_07_licence_constraints` | reverse | medium | O | O | O | 稳定命中 |
| `pp_v1_08_discrete_log_small` | crypto | easy | O | O | O | 稳定命中 |
| `pp_v1_09_ctr_nonce_reuse` | crypto | medium | O | O | O | 稳定命中 |
| `pp_v1_10_rsa_common_modulus` | crypto | hard | O | O | O | 稳定命中 |
| `pp_v2_11_rsa_wiener_small_d` | crypto | hard | O | O | O | 稳定命中 |
| `pp_v2_12_rsa_fermat_close_primes` | crypto | hard | O | O | O | 稳定命中 |
| `pp_v2_13_rsa_hastad_broadcast_e3` | crypto | hard | O | O | O | 稳定命中 |
| `pp_v2_14_rsa_shared_prime_gcd` | crypto | medium | O | O | O | 稳定命中 |
| `pp_v2_15_rsa_small_factor_rho` | crypto | medium | O | O | O | 稳定命中 |
| `pp_v2_16_cbc_iv_bitflip` | crypto | medium | O | O | O | 稳定命中 |
| `pp_v2_17_dsa_nonce_reuse` | crypto | hard | O | O | O | 稳定命中 |
| `pp_v2_18_lcg_unknown_params` | crypto | medium | O | O | O | 稳定命中 |
| `pp_v2_19_mt19937_clone_624` | crypto | hard | - | - | - | 从未命中 |
| `pp_v2_20_affine_bruteforce` | crypto | easy | O | O | O | 稳定命中 |
| `pp_v2_21_crt_three_moduli` | crypto | easy | O | O | O | 稳定命中 |
| `pp_v2_22_dlog_bsgs_2e40` | crypto | hard | O | O | O | 稳定命中 |
| `pp_v2_23_jwt_hs256_forge` | web | medium | O | O | O | 稳定命中 |
| `pp_v2_24_sql_blind_inference` | web | medium | O | O | O | 稳定命中 |
| `pp_v2_25_pwn_stack_offset` | pwn | easy | O | O | O | 稳定命中 |
| `pp_v2_26_fmt_arg_index` | pwn | medium | O | O | O | 稳定命中 |
| `pp_v2_27_rop_address_math` | pwn | easy | O | R | R | 波动 |
| `pp_v2_28_fmt_hn_wrap` | pwn | medium | O | O | O | 稳定命中 |
| `pp_v2_29_licence_xor_table` | reverse | medium | O | O | O | 稳定命中 |
| `pp_v2_30_vm_bytecode_trace` | reverse | medium | O | O | X | 波动 |
| `pp_v2_31_xtea_decrypt` | reverse | medium | O | O | O | 稳定命中 |
| `pp_v2_32_rc4_decrypt` | reverse | easy | O | O | O | 稳定命中 |
| `pp_v2_33_custom_base64` | reverse | easy | O | O | O | 稳定命中 |
| `pp_v2_34_png_ihdr_crc` | misc | medium | O | O | O | 稳定命中 |
| `pp_v2_35_zip_local_header` | misc | medium | O | R | R | 波动 |
| `pp_v2_36_gzip_b64_nest` | misc | easy | O | O | O | 稳定命中 |
| `pp_v2_37_rail_fence_3` | misc | easy | X | X | O | 波动 |
| `pp_v2_38_posix_time_delta` | misc | easy | O | O | O | 稳定命中 |
| `pp_v2_39_elf64_entry` | misc | easy | O | R | O | 波动 |
| `pp_v2_40_ecb_block_detect` | misc | easy | O | O | O | 稳定命中 |

图例：O=解出　X=答错　-=空答　R=空答且文本重复退化

