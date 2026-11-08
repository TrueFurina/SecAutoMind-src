# 免 root 网络隔离：`unshare -Un` 替掉 iptables（2026-11-08）

## 一句话

工具子进程的「零外网」此前靠 `iptables -m owner --uid-owner 995`，在服务器上**两条死结同时成立**：`sudo -n` 要密码所以规则施不上；规则又不跨重启。现在改成每个子进程一份新的 network namespace（`unshare -Un`，**不需要 root**），出网能力从一开始就不存在。

## 为什么必须换（不是"顺手重构"）

| 旧做法 | 问题 | 实证 |
|---|---|---|
| `iptables -m owner --uid-owner 995` | 需要 root | `sudo -n -l` → `sudo: 需要密码` |
| 同上 | 规则不跨重启 | 第 17 轮跑批前实测只剩 `-P ACCEPT`，上一轮的隔离已不存在，而"已隔离"这句话还留在历史证据里 |
| 状态性证据 | 会腐烂 | 任何"上次施过规则"的断言，都无法证明**这一次**跑批被隔离 |

`unshare -Un` 的性质正好相反：无状态（每个子进程一份）、不需要 root（内核 `unprivileged_userns_clone=1`）、不可跨重启继承（所以不存在"历史状态"这回事）。

## 服务器实测（host `ubantu`, 172.16.222.99）

证据文件：`docs/evidence/netns_isolation_proof_20261108.json`（`--proof` 产出）

逐目标**内外对照**（这是关键，见下一节）：

| 目标 | 普通进程 | netns 内 |
|---|---|---|
| `14.103.2.83:443` | connected | **ENETUNREACH (errno=101)** |
| `8.8.8.8:53` | connected | **ENETUNREACH (errno=101)** |
| `1.1.1.1:443` | 超时（无人应答） | ENETUNREACH (errno=101) |
| loopback | 可用 | 可用（uid=65534） |

`decisive_targets = ['14.103.2.83:443', '8.8.8.8:53']`，`available = true`。

## 🔴 判据的第一版是自证的

第一版只跑「netns 内连不上」就宣布隔离生效。真机一跑就露馅：**`1.1.1.1:443` 在不隔离时也连不上**（超时，`errno=None`）。拿它当"被 netns 挡住"的证据等于没有证据 —— 上游本来就黑洞了这个 IP。

顺带踩到第二个坑：`"errno=%d" % e.errno` 在 `errno=None` 时抛 `TypeError`，把对照组打成 `rc=1 / 空输出`，于是 A/B 结论写成"对照不成立"，而真实原因是**我自己的格式化崩了**。报错文本又一次不是原因。

改成逐目标对照后，判据变成：

- 外面能连 + 里面连不上 ⇒ **有分辨力**，算证据
- 外面也连不上 ⇒ 无分辨力，不算证据（不证有也不证无）
- 里面也能连上 ⇒ 隔离失效，直接不可用（fail-closed）
- 一个 decisive 目标都没有 ⇒ 判「本机无分辨力」，**不**判「已隔离」

## 关键约束：降权到 `nobody`

`unshare -U` 不带 `-r` 时进程 uid=65534（带 `-r` 会写 `/proc/self/uid_map`，服务器上直接 `不允许的操作`）。后果：

- `/home/user` 是 **0750** ⇒ 隔离后**读不到 home 下任何东西**；
- `tempfile.mkdtemp()` 是 **0700** ⇒ 工件目录也读不到。

不做处理的话，表现是「工具调用成功但返回空」—— 一种会被读成"模型不会读文件"的功能性故障。所以 `prepare_cwd()` 把工作目录放开到 0777，且**只允许 `/tmp`、`/var/tmp` 下**（拒绝改 home/题库权限）。

副作用是白赚的：模型就算绕过正则去读题库明文，权限层也读不到。

## 与正则层的关系（这是本轮最硬的一条）

第 13 轮的结论是「正则判据能被绕过，IP 直连仍通」。在服务器上用**同一段代码**做净对照（跳过 `_audit_code`，直接起子进程）：

```
=== 绕过正则层、不隔离 ===        NET-CONNECTED
=== 同一段代码，套 netns ===      NET-BLOCKED errno=101
=== 读工件（隔离内）===           answer=42 | rc: 0
```

即：正则层漏的那条路，netns 关上；而正常的工件读取不受影响。

## 接进编排器

`scripts/ctf_stepfun_orchestrator.py`：

```
--netns-isolate {off,auto,require}   默认 off（不改老行为）
```

- `require`：不可用在**花任何 API 额度之前**退出（fail-closed）
- `auto`：可用就用，不可用把 `why` 写进 `summary.netns_isolation`
- 每次 `run_python_tool` 都 `wrap()`；`wrap()` 失败时返回 `(ISOLATION-UNAVAILABLE: ...)`，**绝不静默降级成"没隔离接着跑"**（那正是第 13 轮跨层假绿的形态）
- 工件目录在使用前 `prepare_cwd()`

`summary.netns_isolation` 保留完整对照表，结果文件能自证「这一批到底隔离了没有、证据是哪几个目标」。它与 `summary.airgap_binding` 互补且互不替代：前者证 iptables/UID 层绑定，后者证「每个工具子进程各自没有路由」。

## 判据自测 7/7（不需要 root、不需要本机支持 userns）

靠注入的假 runner，覆盖：

1. 里面全断 + 外面有一个能连 ⇒ 可用，且 `decisive_targets` 正确
2. 里面有漏 ⇒ 不可用
3. 里外都连不上 ⇒ 不可用，理由含「无分辨力」
4. loopback 挂 ⇒ 不可用（隔离过头同样是故障）
5. 无 `unshare` ⇒ 不可用，且说清是"没装"而非"跑不起来"
6. `wrap()` 不可用时必须抛，不许降级
7. `prepare_cwd()` 拒绝改 home 权限

## 仍缺 / 未验

- 隔离跑批**尚未**用真实 API 跑过一整批（本轮只做机制层与工具调用层烟测，未花额度）。`supports_tools` 在 `PROVIDERS` 里对 stepfun 仍是 `False`，`--agentic` 会被 `resolve_agentic` 降级 ⇒ 要真跑 agentic 批次，仍需 `scripts/run_agentic_stepfun.py` 的那层 patch，或把 `supports_tools` 改成实测值。
- `--netns-isolate` 默认 `off`：历史读数的口径不变，但也意味着**不显式加参数就没有隔离**。跑批脚本应固定加 `require`。
