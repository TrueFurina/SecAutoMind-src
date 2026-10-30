# AICTF 工件链调查收口报告（2026-10-31）

> 结论先行：原「工件类题因架构双断裂 / 测不出工具能力」的口径**已被证伪为数据层破损**。基础设施（工件注入 + 工件模式守卫）在服务器编排器里早已存在且可用；唯一可修题 `steg_lsb_png` 经三处修复后已实证 `solved=1 / exact=1`。当前全库报 0 的根因是**数据集接线缺失 + 真值失修**，不是 agent 不行、也不是缺功能。

---

## 1. 旧口径（已推翻）

此前结论：「输入链在 `build_prompt` 与 `run_python` 守卫两处断裂 → 补工件路径救不回图片题 → 本评测集当前测不出工具/工件分析能力」。

该口径建立在**默认路径（不启用 `--artifact-dir`）**的 A/B 探针上，是 foregone conclusion，未触及服务器已实现的工件基础设施。

## 2. 实证四阶段（spark-x2.6，复用生产 `run_python` 守卫）

| 组 | 配置 | 结果 | 关键证据 |
|---|---|---|---|
| A | 默认（不注入工件） | MISS | 工件从不进 prompt，agent 自陈「无数据」 |
| B | 注入路径 + 严格守卫 | MISS | 守卫 `open(` → `file-open` 拦死 |
| C(临时) | 真实 `--artifact-dir` + 临时加 `zip` 字段 | agent 解出真 flag（判分仍 false） | 4 次调用全 allowed / 0 blocked；读 PNG→逆滤波→LSB 抽取 |
| **收口** | 真实文件 + `--artifact-dir` + `--max-iter 24` | **solved=1 / exact=1** | `got=flag{lsb_p1x3l_st3g0_2026}` / blocked=0 / artifact_mode=true |

`--max-iter 6` 时 solved=0 是**迭代预算/模型能力信号**（模型卡在调试 PNG 尺寸，调用全 allowed），多给预算即收敛——非架构故障。

## 3. 根因修正：双断裂 → 数据层三处破损

1. **接线缺失**：全库 55 题 **0 题**有 `zip` 字段（批量跑不启用 `--artifact-dir`）；`data/ctf_benchmark/artifacts/` 是散文件非按题 zip → `prepare_artifacts` 永不触发。
2. **真值失修**：`steg_lsb_png` 题库存 `flag_sha256=f5308159…` ≠ 工件真 flag 的 sha `1c6551d5…` → 解对也判 miss。
3. **验证器误显**：`verify_flag` 未命中时回落 `cands[0]`（首个正则命中 = 工具 stdout 的二进制垃圾）→ `got=乱码`（sha 修对后即自愈）。

## 4. 已落地改动（均非破坏性，有备份）

| 文件 | 改动 | 备份 |
|---|---|---|
| `data/ctf_benchmark/real_benchmark.json` | `steg_lsb_png` 加 `zip="steg_lsb_png.zip"` + `flag_sha256` 修正为 `1c6551d5de5a0e66605a626ece85ac41d071368fa6ed0731bc8ef38972235ec9`；其余 54 题原样 | `real_benchmark.json.bak_apply_20261031` |
| `scripts/ctf_stepfun_orchestrator.py` | `verify_flag` 回落改 `cands[-1]`（未命中时显示模型最终答案） | `ctf_stepfun_orchestrator.py.bak_20261031` |
| `artifacts_wired/steg_lsb_png.zip` | `stego_lsb.png` 按题打包（工件落点） | — |

> 无 `--artifact-dir` 时 `zip` 字段被忽略，真实批量跑**不回归**。

## 5. 复现命令（服务器 172.16.222.99）

```bash
# 接线 + 真值修正已写入真实文件；验证：
cd /home/user/SecAutoMind
source ~/.xfyun_env
python3 scripts/ctf_stepfun_orchestrator.py \
  --provider xfyun --artifact-dir /home/user/SecAutoMind/artifacts_wired \
  --benchmark data/ctf_benchmark/real_benchmark.json \
  --only-ids steg_lsb_png --agentic --max-iter 24 \
  --out /tmp/steg_verify.json --slice real-verify
# => solved=1 exact=1 got=flag{lsb_p1x3l_st3g0_2026} blocked=0

# 独立确定性提取（不依赖模型，确认真值）：
python3 - <<'PY'
import struct, zlib, re, hashlib
data=open("data/ctf_benchmark/artifacts/stego_lsb.png","rb").read()
pos=8; idat=b""
while pos<len(data):
    ln=struct.unpack(">I",data[pos:pos+4])[0]; typ=data[pos+4:pos+8]
    if typ==b"IDAT": idat+=data[pos+8:pos+8+ln]
    pos+=12+ln
    if typ==b"IEND": break
raw=zlib.decompress(idat)
stride=1+64*3; prev=bytearray(64*3); out=bytearray()
for y in range(64):
    r=bytearray(raw[y*stride:(y+1)*stride]); f=r[0]; line=bytearray(r[1:])
    for i in range(len(line)):
        a=line[i-3] if i>=3 else 0; b=prev[i]; c=prev[i-3] if i>=3 else 0
        if f==1: line[i]=(line[i]+a)&0xff
        elif f==2: line[i]=(line[i]+b)&0xff
        elif f==3: line[i]=(line[i]+(a+b)//2)&0xff
        elif f==4:
            p=a+b-c; pa,pb,pc=abs(p-a),abs(p-b),abs(p-c)
            line[i]=(line[i]+(a if pa<=pb and pa<=pc else (b if pb<=pc else c)))&0xff
    out+=line; prev=bytearray(line)
bits=[(byte>>0)&1 for byte in out]
res=bytes(((v<<j)|bits[i+j] for j in range(8)) for i in range(0,len(bits)-7,8))
m=re.search(rb"flag\{[^}]*\}", res)
print(m.group().decode(), "sha=", hashlib.sha256(m.group()).hexdigest())
PY
```

## 6. 另 8 道「需工件」题判为数据层不可修（保持原状）

- `traffic.pcap` 仅 **391 B（截断）** → `flag_in_pcap` / `forensics_pcap_http` 工件残缺。
- `mem.raw` / 磁盘镜像 / morse 图片 **不在 `artifacts/`** → 工件缺失。
- `pico2024_commitment` / `pico2024_gitcred` 需 git 仓库、`buuctf_upload_basic` 需在线靶机 → 非本地工件。
- blob 类（`b64_blob.bin` 等）无 manifest 映射、二进制编码无明文 flag → 无法可靠接线。

## 7. 待决策（不在「继续」授权内，需用户明确拍板）

1. git HEAD 8 仓 72 条明文 flag —— 重写历史（破坏性）。
2. 19 份快照共 2.4GB —— 目录级删除（若被安全守卫拦下则停手）。
3. 是否将 `verify_flag` 补丁 + `steg_lsb_png` 接线通过 `git bundle` 部署到服务器（服务器为 non-git 副本，部署走 bundle 而非本地 git）。
