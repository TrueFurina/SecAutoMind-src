# Incident Response（应急响应）

> 针对已授权环境的安全事件研判与处置方法论：异常确认 → 影响面评估 → 遏制止损 → 取证溯源 → 恢复加固。

## Summary

* [排查清单](#排查清单)
    * [Windows](#windows)
    * [Linux](#linux)
* [常见入侵痕迹](#常见入侵痕迹)
* [时间线取证](#时间线取证)
* [工具清单](#工具清单)
* [References](#references)

## 排查清单

### Windows

* 账号：`net user` / 事件 ID 4720（新建账号）、4728/4732（加入组）；检查隐藏账号（`$` 结尾）与注册表 `SAM` 异常。
* 进程：`tasklist /svc`、Process Explorer——关注无签名、路径异常（Temp/公共目录）、父进程异常（如 office 拉起 powershell）。
* 持久化：注册表 Run/RunOnce 键、计划任务（`schtasks`）、服务（`sc query`）、WMI 订阅、启动文件夹。
* 网络：`netstat -ano` 异常外联；DNS 请求异常域名。
* 日志：Security/Evolution/Sysmon；登录类型 4624/4625（成功/失败登录）、4688（进程创建）。
* Webshell：IIS/Apache/Nginx 日志中异常 POST、`eval|assert|system` 关键词扫描（D 盾/河马）。

### Linux

* 账号：`/etc/passwd`、`/etc/shadow` 异常条目；`last`/`lastlog` 登录记录；`~/.ssh/authorized_keys` 后门公钥。
* 进程：`ps auxf`（注意 CPU 异常与挖矿特征）；`/proc/<pid>/exe` 被删除仍运行的进程。
* 持久化：`crontab -l` 与 `/etc/cron*`、`/etc/rc.local`、`/etc/profile` 与 `~/.bashrc`、systemd 单元、LD_PRELOAD/ld.so.preload 劫持。
* 网络：`ss -antup` 外联；`iptables -L` 是否被篡改。
* 日志：`/var/log/secure|auth.log`、`/var/log/messages`；重点爆破（大量 Failed password）与 Accepted（异常 IP/时间）。
* Rootkit：`rkhunter`/`chkrootkit`；对比包管理器校验（`rpm -Va` / `debsums`）。

## 常见入侵痕迹

* Web 日志中的扫描器 UA（sqlmap/nucleus/fofa）与高频 404/500。
* 可疑定时任务向外部 IP 回连（挖矿/远控）。
* 突发的 DNS TXT / 长域名请求（C2 隧道特征）。
* Webshell 常见特征：`eval($_POST[`、`assert(`、`system(`、`passthru(`、jsp 的 `Runtime.getRuntime()`。
* 挖矿木马特征进程名：`kdevtmpfsi`、`kinsing`、`xmrig`、`minerd`。

## 时间线取证

* 先固定证据再处置：日志/内存/关键文件哈希（`sha256sum`）留存到只读介质。
* 时间线要素：初始访问（漏洞/口令）→ 执行（payload）→ 持久化 → 横向移动（凭据复用）→ 目标达成（数据/勒索）。
* 时区校准：日志时区不一致（UTC vs CST）是时间线错位的常见根因。

## 工具清单

* [CyberChef](https://gchq.github.io/CyberChef/) - 编解码/流量还原瑞士军刀
* [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) - Windows 进程/网络细粒度日志
* [Velociraptor](https://docs.velociraptor.app/) - 端点取证与威胁狩猎
* [D 盾](https://www.d99net.net/) / [河马 WebShell](https://www.shellpub.com/) - Webshell 查杀
* [Volatility](https://github.com/volatilityfoundation/volatility3) - 内存取证
* [rkhunter](https://sourceforge.net/projects/rkhunter/) - Linux Rootkit 检测

## References

* [ATT&CK Framework](https://attack.mitre.org/) - 攻击战术与技术知识库
* [应急响应实战笔记 (Bypass007)](https://github.com/Bypass007/Emergency-Response-Notes)
* [NIST SP 800-61r2](https://csrc.nist.gov/publications/detail/sp/800/61/rev-2/final) - 计算机安全事件处理指南
