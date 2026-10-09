# 外部真题基准 · 静态分层结果（自动生成）

> 生成时间：2026-10-10T00:14:51｜题目总数：80
> 方法：纯静态扫描（读附件字节 + SHA-256 比对），**零 LLM 调用、零 token 成本**。

## 一、分层口径与结果

| 层级 | 含义 | 题数 | 占比 | 能否代表推理能力 |
|------|------|------|------|----------------|
| L0_direct_read | 附件里能直接扫到真值 | 66 | 82.5% | ❌ 不能（测的是读文件） |
| L0b_answer_key_attachment | 附件含答案键形态文件（另有真实载荷） | 0 | 0.0% | ❌ 不能（已泄漏） |
| LB_answer_key_only | 附件**只有答案键**、真实载荷缺失 | 0 | 0.0% | ❌ 坏题（必然 0 分，须剔除） |
| L1_single_candidate | 附件有 flag 形态串但非真值（需判断/解码） | 4 | 5.0% | ⚠️ 部分（需排除抄错候选） |
| L2_pure_reasoning | 附件无 flag 形态串，必须真解题 | 10 | 12.5% | ✅ 能 |
| L3_no_payload | 题面声明无附件 | 0 | 0.0% | ✅ 能（但样本少） |
| LX_attachment_unavailable | 声明有附件但本机读不到 | 0 | 0.0% | ⚠️ 不可用（须先补齐载荷） |

题型分布：{'crypto': 21, 'misc': 40, 'pwn': 2, 'reverse': 5, 'web': 12}

## 二、对外报数规则（反注水）

1. **L0 必须剔除**：附件直含真值的题，裸 LLM 一读即中，报出去等于用文件读取冒充推理。
2. **L1 必须标注**：附件含多个 flag 形态候选时，agent 可能抄到错候选（需真值仲裁兜底）。
3. **只有 L2/L3 是有效推理分母**；报数时写「L2+L3 共 N 题，解出 M 题」。
4. 与「求解器体系」口径（如 176 求解器 / 静态确定性 34.5%）**不可相加**：那是不同能力线。

## 三、逐题明细

| 题 id | 题型 | 层级 | 附件 flag 形态串数 | 附件类型 | 已训练 |
|-------|------|------|------------------|---------|--------|
| 10733 | crypto | L2_pure_reasoning | 0 | other | 是 |
| real_crypto_anwang_crypto1 | crypto | L2_pure_reasoning | 0 | text | 是 |
| real_crypto_anxun2020_aes | crypto | L0_direct_read | 2 | text | 否 |
| real_crypto_changan2021_checkin | crypto | L0_direct_read | 2 | text | 否 |
| real_crypto_changan2021_easyrsa | crypto | L0_direct_read | 2 | text | 否 |
| real_crypto_changan2021_ezpy | crypto | L0_direct_read | 2 | text | 否 |
| real_crypto_dnui_keyboard | crypto | L2_pure_reasoning | 0 | text | 否 |
| real_crypto_exciting_inverse | crypto | L2_pure_reasoning | 0 | other | 是 |
| real_crypto_ezmult | crypto | L2_pure_reasoning | 0 | text | 是 |
| real_crypto_ezrsa | crypto | L2_pure_reasoning | 0 | other | 是 |
| real_crypto_filterrandom | crypto | L1_single_candidate | 1 | other | 是 |
| real_crypto_gaoxiao2024_z3 | crypto | L0_direct_read | 2 | text | 否 |
| real_crypto_gkctf2020_che11y | crypto | L0_direct_read | 2 | text | 否 |
| real_crypto_gkctf2020_rsa | crypto | L0_direct_read | 2 | text | 否 |
| real_crypto_isctf2024_decrypt | crypto | L0_direct_read | 2 | text | 否 |
| real_crypto_longjian2023_hd1 | crypto | L0_direct_read | 2 | text | 否 |
| real_crypto_qiangwang_classic | crypto | L2_pure_reasoning | 0 | text | 是 |
| real_crypto_simplelegendre | crypto | L2_pure_reasoning | 0 | other | 是 |
| real_crypto_specialcurve2 | crypto | L2_pure_reasoning | 0 | other | 是 |
| real_crypto_udomctf2022_aes | crypto | L0_direct_read | 2 | text | 否 |
| real_crypto_umdctf2022_vigenere | crypto | L0_direct_read | 2 | text | 否 |
| real_misc_bytectf_flag | misc | L0_direct_read | 2 | text | 否 |
| real_misc_chunqiu2022_checkin | misc | L0_direct_read | 2 | text | 否 |
| real_misc_chunqiu2022_tiger | misc | L0_direct_read | 2 | text | 否 |
| real_misc_gaoxiao2024_cve41773 | misc | L0_direct_read | 2 | text | 否 |
| real_misc_gaoxiao2024_file_extract | misc | L0_direct_read | 2 | text | 否 |
| real_misc_gaoxiao2024_phish_link | misc | L0_direct_read | 2 | text | 否 |
| real_misc_gaoxiao2024_phish_sender | misc | L0_direct_read | 2 | text | 否 |
| real_misc_gaoxiao2024_xiandian | misc | L0_direct_read | 2 | text | 否 |
| real_misc_gkctf2020_pokemon | misc | L0_direct_read | 2 | text | 否 |
| real_misc_hws2022_badpdf | misc | L0_direct_read | 2 | text | 否 |
| real_misc_isctf2024_checkin02 | misc | L0_direct_read | 2 | text | 否 |
| real_misc_isctf2024_park2 | misc | L0_direct_read | 2 | text | 否 |
| real_misc_isctf2024_pixel | misc | L0_direct_read | 2 | text | 否 |
| real_misc_isctf2024_sstv | misc | L0_direct_read | 2 | text | 否 |
| real_misc_isctf2024_win_rar | misc | L0_direct_read | 2 | text | 否 |
| real_misc_longjian2023_baby_forensics3 | misc | L0_direct_read | 2 | text | 否 |
| real_misc_longjian2023_bf | misc | L0_direct_read | 2 | text | 否 |
| real_misc_longjian2023_smallsword3 | misc | L0_direct_read | 2 | text | 否 |
| real_misc_longjian2024_smallsword1 | misc | L0_direct_read | 1 | text | 否 |
| real_misc_longjian2024_smallsword2 | misc | L0_direct_read | 1 | text | 否 |
| real_misc_longjian2024_smallsword3 | misc | L0_direct_read | 2 | text | 否 |
| real_misc_longjian2024_ssw_redis | misc | L0_direct_read | 1 | text | 否 |
| real_misc_longjian2024_telnet | misc | L0_direct_read | 1 | text | 否 |
| real_misc_longjian2025_app_part2 | misc | L0_direct_read | 2 | text | 否 |
| real_misc_longjian2025_data_security1 | misc | L0_direct_read | 2 | text | 否 |
| real_misc_longjian2025_siem | misc | L0_direct_read | 2 | text | 否 |
| real_misc_mjuctf_speak | misc | L0_direct_read | 2 | text | 否 |
| real_misc_mjuctf_this_is_the_flag | misc | L0_direct_read | 2 | text | 否 |
| real_misc_nactf2020_zip_madness | misc | L0_direct_read | 2 | text | 否 |
| real_misc_qiangwang2020_cefang | misc | L0_direct_read | 2 | text | 否 |
| real_misc_qiangwang2020_upload | misc | L0_direct_read | 2 | text | 否 |
| real_misc_sheng2022_traffic_bruteforce_count | misc | L0_direct_read | 1 | text | 否 |
| real_misc_sheng2022_traffic_enable_pwd | misc | L0_direct_read | 1 | text | 否 |
| real_misc_sheng2022_traffic_ftp_dataconn_count | misc | L0_direct_read | 1 | text | 否 |
| real_misc_sheng2022_traffic_ftp_port | misc | L0_direct_read | 1 | text | 否 |
| real_misc_sheng2022_traffic_telnet_pwd | misc | L0_direct_read | 1 | text | 否 |
| real_misc_udomctf2022_morse | misc | L0_direct_read | 2 | text | 否 |
| real_misc_vnctf_flag | misc | L1_single_candidate | 195 | png | 是 |
| real_misc_vnctf_vnloan | misc | L0_direct_read | 2 | text | 否 |
| real_misc_xuanhun_signin | misc | L1_single_candidate | 9 | jpg | 是 |
| real_pwn_changan2021_pwn3 | pwn | L0_direct_read | 2 | text | 否 |
| real_pwn_hws2022_peach | pwn | L0_direct_read | 2 | text | 否 |
| real_reverse_gaoxiao2024_upx | reverse | L0_direct_read | 2 | text | 否 |
| real_reverse_js | reverse | L0_direct_read | 4 | other | 否 |
| real_reverse_sheng | reverse | L2_pure_reasoning | 0 | elf | 是 |
| real_reverse_upx | reverse | L1_single_candidate | 30 | elf | 是 |
| real_reverse_vnctf_timeflies | reverse | L0_direct_read | 2 | text | 否 |
| real_web_changan2021_soeasy | web | L0_direct_read | 2 | text | 否 |
| real_web_dicectf2022_knockknock | web | L0_direct_read | 2 | text | 否 |
| real_web_dicectf2022_point | web | L0_direct_read | 2 | text | 否 |
| real_web_gongye_web2 | web | L0_direct_read | 2 | other | 否 |
| real_web_hacktheboo2022_spookifier | web | L0_direct_read | 2 | text | 否 |
| real_web_linectf2022_ssti_jwt | web | L0_direct_read | 2 | text | 否 |
| real_web_longjian2023_hard_web1 | web | L0_direct_read | 2 | text | 否 |
| real_web_longjian2023_hard_web2 | web | L0_direct_read | 2 | text | 否 |
| real_web_longjian2025_which_sql | web | L0_direct_read | 2 | text | 否 |
| real_web_udomctf2022_cmdinj | web | L0_direct_read | 2 | text | 否 |
| real_web_wgmy2022_christmas_wishlist | web | L0_direct_read | 2 | text | 否 |
| real_web_wgmy2022_christmas_wishlist2 | web | L0_direct_read | 2 | text | 否 |
