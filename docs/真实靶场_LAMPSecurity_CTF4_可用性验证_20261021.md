# 真实靶场可用性验证：LAMPSecurity CTF4

> 验证日期：2026-10-21 · 环境：本机 Windows + VirtualBox 7.2.14
> 目的：确认本地真实漏洞靶机能否作为 **Web 层 / 执行层** 的实机对照，以及它与基准题库的关系。
> 结论先行：**可用**，但它是 **root 导向、无 flag** 的靶场，**不能**用来补基准题库的缺口。

---

## 1. 资产清单

| 项 | 实测值 |
|---|---|
| 磁盘 | `E:\Code\Cyber range\ctf4\CTF4\CTF4.vmdk` |
| 大小 | 1,927,610,368 字节（1.9 GB），虚拟容量 4 GB（8388608 扇区） |
| 格式 | VMware `monolithicSparse`（单文件稀疏，含内嵌 descriptor） |
| 说明书 | `E:\Code\Cyber range\ctf4\ctf4_instructions.pdf`，66 页 |
| 来源 | LAMPSecurity CTF4，Justin C. Klein Keane，2009-03-10（MadIrish.net） |
| 原配置 | `virtualHW 7` / `guestOS rhel3` / 256 MB / lsilogic SCSI / hostonly |

靶场性质：**CentOS 时代 LAMP 靶机**，目标是从 Web 应用打到 **root shell**，攻击链为
`SQL 注入进后台 → XSS → 文件包含(LFI) 读 /restricted/.htpasswd → 破解 Apache 口令 → 偷 SSH 私钥 → 提权 root`。
**全程没有 flag 字符串**——这正是它与 CTF 题库的根本差异。

---

## 2. 启动方式（本机实测可用）

原 `.vmx` 是 VMware 格式，本机无 VMware，改用 **VirtualBox 直接挂 VMDK**（无需转换）。

### 2.1 为什么不用 host-only

原配置是 host-only，但 VirtualBox 7.2.14 启动报：

```
Failed to open/create the internal network 'HostInterfaceNetworking-VirtualBox Host-Only Ethernet Adapter'
(VERR_INTNET_FLT_IF_NOT_FOUND)
```

真因：host-only 适配器的 **NDIS 过滤驱动未加载**（且该 build 不支持 `VBoxManage hostonlynet` 子命令）。
**不要试图去装驱动**——改用 NAT + 端口转发，效果等价且无需宿主驱动。

### 2.2 一键启停

```bash
bash scripts/ctf4_lab.sh start     # 建 VM（首次）+ 启动 + 端口转发
bash scripts/ctf4_lab.sh status    # 看运行状态与转发规则
bash scripts/ctf4_lab.sh stop      # 关机
```

等价的原始命令（便于排查）：

```bash
VB="/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
"$VB" createvm --name CTF4 --ostype RedHat --register --basefolder "E:/Code/Cyber range/ctf4_work"
"$VB" modifyvm CTF4 --memory 512 --vram 16 --cpus 1 --nic1 nat --nictype1 82540EM
"$VB" storagectl CTF4 --name SCSI --add scsi --controller LSILogic
"$VB" storageattach CTF4 --storagectl SCSI --port 0 --device 0 --type hdd \
      --medium "E:/Code/Cyber range/ctf4_work/CTF4.vmdk"
"$VB" startvm CTF4 --type headless
"$VB" controlvm CTF4 natpf1 "http,tcp,,8080,,80"
"$VB" controlvm CTF4 natpf1 "ssh,tcp,,2222,,22"
```

> ⚠️ 端口转发参数必须用**逗号分隔** `名称,tcp,,宿主端口,,客机端口`；
> 用 `[]:8080:[]:80` 这种方括号写法会报 `Missing or invalid argument to '--natpf'`。
> 运行中的 VM 用 `controlvm ... natpf1`，关机状态用 `modifyvm ... --natpf1`。

### 2.3 访问地址

| 服务 | 地址 |
|---|---|
| HTTP | `http://127.0.0.1:8080/` |
| SSH | `127.0.0.1:2222` |
| MySQL | `127.0.0.1:3307` |

**原始 VMDK 未被改动**：启动前已复制到 `E:/Code/Cyber range/ctf4_work/CTF4.vmdk`，大小逐字节校验一致。

---

## 3. 可用性实测证据

### 3.1 引导与 HTTP

引导日志（截图核对）：`sshd [OK]`、`MySQL [OK]`、`httpd [OK]`；`smartd [FAILED]` 是虚拟机内的磁盘健康监控，无影响。
`eth0` 通过 DHCP 取址成功。

```
HTTP/1.1 200 OK
Server: Apache/2.2.0 (Fedora)
X-Powered-By: PHP/5.1.2
Content-Length: 3479
```

站点标题「Prof. Ehks」，与说明书一致。

### 3.2 文件包含（LFI）确实存在

| 探测 | 结果 |
|---|---|
| `GET /?page=blog&title=Blog` | 200，1718 字节（正常页） |
| `GET /?page=../inc/header` | 200，2173 字节，页面内 `<html` 出现 **2 次** → header 被二次包含，**LFI 成立** |
| `GET /?page=../restricted/.htpasswd%00` | 200，1249 字节，`main` 区出现 **4 条口令哈希** |

说明：`include($page . ".php")` 会补 `.php` 后缀，所以直接读 `.htpasswd` 得到空内容；
必须用 **null byte 截断** `%00` 才能绕过——与说明书 Step 9 描述一致。

读出的 4 条为 **DES crypt**（13 字符，无 `$apr1$` 前缀）。本文档不记录哈希值与口令。

---

## 4. 与本仓 Web 链的对接实测

用**生产链路函数**直接打这个靶机（临时测试文件，跑完即删，未入库）：

| 用例 | 结果 |
|---|---|
| `ExploitURLsInText(ctx, "Challenge target: http://127.0.0.1:8080/")` | 1.522s，**0 命中** |
| `ExploitWebTargetWithHints(ctx, base, WebHints{})` | 2.492s，**0 命中** |
| 给端点线索 `Endpoints=["/"] Types=["lfi"] Params=["page"]` | 2.038s，**0 命中** |
| 再加 null-byte 载荷 `../restricted/.htpasswd%00` | 1.958s，**0 命中** |

### 4.1 为什么 0 命中（代码级结论，已核实）

**不是能力缺失，是判定口径不同。** 两处结构性原因：

1. **空线索直接返回**：`internal/ctfplatform/web_hints.go:241`
   ```go
   eps := h.Endpoints
   if len(eps) == 0 { return }   // 无端点线索 → 整段定向探测跳过
   ```
   所以题目描述里没给端点时，SQLi/SSTI/LFI/cmdi/SSRF 这些定向阶段**一次都不跑**。

2. **只认 flag 形态**：所有探测结果都经 `passiveScan` 过滤
   （`hintProbeGET` → `record(passiveScan(...))`，`web_hints.go:212-221`）。
   靶机回的是 `.htpasswd` 明文哈希，**不含 flag 形态字符串** → 不产生 `WebFinding`。

### 4.2 这个靶机补不了基准缺口

`data/ctf_benchmark/real_benchmark.json` 里未命中的 35 道是 **picoCTF / BUUCTF 的具体题目**，
判分靠 **sha256(flag)**。本靶机既不是那些题，也没有 flag，**两者不可互换**。
详见 `docs/真题数据补齐方案_20261021.md`。

---

## 5. 正确的用法（建议）

| 用途 | 可行性 | 说明 |
|---|---|---|
| **Web 层真实靶机对照** | ✅ 推荐 | 独立于自产题的第三方真实漏洞应用，可验证「请求真的发出去了、漏洞真的被利用」 |
| **执行层 / 提权链演练** | ✅ 推荐 | 拿到 shell 后的提权、横向、文件窃取链，是自产题覆盖不到的场景 |
| 补 35 道基准缺口 | ❌ 不可行 | 题源不同、无 flag、判分口径不符 |
| 直接计入能力数字 | ❌ 不可行 | 无 flag 可校验，计入即属注水（AGENTS.md 第一条 1.5） |

若要把它变成**可判分的对照**，需要定义「非 flag 成功判据」（例如：能否通过 LFI 读到
`/restricted/.htpasswd` 或 `/etc/passwd`）。这属于**新增能力口径**，须由主理人拍板后
再动 `internal/`（当前不在冻结窗口内，但会连锁影响门禁与材料数字）。

---

## 6. 已知限制

- 客机是 2009 年的 CentOS 时代系统，**不要暴露到公网**，仅限本机 NAT。
- `smartd [FAILED]` 为正常现象（虚拟磁盘无 SMART 信息）。
- 本机 host-only 不可用（见 §2.1），如换机器需重新确认。
- 若要重跑，务必用 `scripts/ctf4_lab.sh`，避免手工参数写错导致 VM 起不来。
