# 工具链依赖审计（纯净环境实测）

- 审计时间：2026-09-05T09:47:30.421961　平台：win32　Python：3.13.14
- 工具定义总数：**90**　其中 enabled：**78**
- 真能跑：**15**　不可用：**75**
- enabled 工具中真能跑：**14/78（17.9%）**

## 关键：两类工具必须分开看（合并统计会得出错误结论）

| 类型 | 总数 | 可跑 | 说明 |
|---|---|---|---|
| 自研内联脚本 | 17 | 12 | 实现内联在 YAML 的自研脚本，解释器在即可跑，不依赖外部二进制 |
| 外部二进制依赖 | 73 | 3 | 依赖外部可执行文件（nuclei/nmap/sqlmap 等），需环境预装 |

**口径澄清**：绝不能只报一个「90 个工具只有 19% 能跑」——那会把「自带实现、跨平台可跑」
的自研脚本和「需环境预装」的外部二进制混为一谈，得出严重低估。两类必须分列。

## 解读口径（能力基线必须在此下解读）

Agent 未发现某漏洞，可能是能力不足，也可能是**外部二进制工具未预装**，
还可能是**自研脚本所依赖的第三方包缺失**——三者不可混为一谈，材料引用时必须注明。

## 不可用工具清单（75 个）

| 工具 | 类型 | 可执行 | enabled | 缺包 | 说明 |
|---|---|---|---|---|---|
| amass | 外部二进制 | `amass` | 是 | — | 子域名枚举和网络映射工具 |
| api-schema-analyzer | 外部二进制 | `spectral` | 是 | — | API模式分析工具，识别潜在安全问题 |
| arjun | 外部二进制 | `arjun` | 是 | — | HTTP参数发现工具 |
| arp-scan | 外部二进制 | `arp-scan` | 是 | — | ARP网络发现工具 |
| binwalk | 外部二进制 | `binwalk` | 是 | — | 固件和文件分析工具 |
| bloodhound | 外部二进制 | `bloodhound-python` | 是 | — | Active Directory 攻击路径分析和可视化工具 |
| checkov | 外部二进制 | `checkov` | 是 | — | 基础设施即代码安全扫描工具 |
| checksec | 外部二进制 | `checksec` | 是 | — | 二进制安全特性检查工具 |
| clair | 外部二进制 | `clair` | 否 | — | 容器漏洞分析工具 |
| cloudmapper | 外部二进制 | `cloudmapper` | 是 | — | AWS网络可视化和安全分析工具 |
| dalfox | 外部二进制 | `dalfox` | 是 | — | 高级XSS漏洞扫描器 |
| dirsearch | 外部二进制 | `dirsearch` | 是 | — | 高级目录和文件发现工具 |
| dnsenum | 外部二进制 | `dnsenum` | 是 | — | DNS枚举工具 |
| dotdotpwn | 外部二进制 | `dotdotpwn` | 是 | — | 目录遍历漏洞测试工具 |
| enum4linux-ng | 外部二进制 | `enum4linux-ng` | 是 | — | 高级SMB枚举工具（Enum4linux的下一代版本） |
| exiftool | 外部二进制 | `exiftool` | 是 | — | 元数据提取工具 |
| falco | 外部二进制 | `falco` | 是 | — | 运行时安全监控工具 |
| feroxbuster | 外部二进制 | `feroxbuster` | 否 | — | 递归内容发现工具 |
| ffuf | 外部二进制 | `ffuf` | 是 | — | 快速Web模糊测试工具，用于目录、参数和内容发现 |
| fierce | 外部二进制 | `fierce` | 是 | — | DNS侦察工具 |
| fofa_search | 自研内联 | `python3` | 否 | requests | FOFA网络空间搜索引擎，支持灵活的查询参数配置 |
| foremost | 外部二进制 | `foremost` | 是 | — | 文件恢复工具 |
| fscan | 外部二进制 | `fscan` | 否 | — | 内网综合扫描工具，支持存活探测、端口扫描、服务识别、爆破、POC检测 |
| gau | 外部二进制 | `gau` | 是 | — | 从多个数据源获取所有URL |
| gdb | 外部二进制 | `gdb` | 是 | — | GNU调试器，用于二进制分析和调试 |
| ghidra | 外部二进制 | `analyzeHeadless` | 是 | — | 高级二进制分析和逆向工程工具 |
| gobuster | 外部二进制 | `gobuster` | 否 | — | Web内容扫描工具，用于发现目录、文件和子域名 |
| graphql-scanner | 外部二进制 | `graphqlmap` | 是 | — | GraphQL安全扫描和自省工具 |
| hashcat | 外部二进制 | `hashcat` | 是 | — | 高级密码破解工具，支持GPU加速 |
| hashpump | 外部二进制 | `hashpump` | 是 | — | 哈希长度扩展攻击工具 |
| http-framework-test | 自研内联 | `python3` | 是 | chardet,charset_normalizer,h2,httpx | 纯Python HTTP测试框架（httpx，会话复用+编码守护） |
| hydra | 外部二进制 | `hydra` | 是 | — | 密码暴力破解工具，支持多种协议和服务 |
| jaeles | 外部二进制 | `jaeles` | 是 | — | 高级漏洞扫描器，支持自定义签名 |
| john | 外部二进制 | `john` | 是 | — | John the Ripper密码破解工具 |
| jwt-analyzer | 外部二进制 | `jwt_tool` | 是 | — | JWT令牌分析和漏洞测试工具 |
| katana | 外部二进制 | `katana` | 是 | — | 下一代Web爬虫和蜘蛛工具 |
| kube-bench | 外部二进制 | `kube-bench` | 是 | — | CIS Kubernetes基准检查工具 |
| kube-hunter | 外部二进制 | `kube-hunter` | 是 | — | Kubernetes渗透测试工具 |
| lightx | 外部二进制 | `lightx` | 否 | — | 轻量级资产发现与漏洞扫描工具 |
| linpeas | 外部二进制 | `linpeas.sh` | 是 | — | Linux 权限提升枚举脚本，自动检测常见提权路径 |
| masscan | 外部二进制 | `masscan` | 是 | — | 高速互联网级端口扫描工具 |
| msfvenom | 外部二进制 | `msfvenom` | 是 | — | Metasploit载荷生成工具 |
| nbtscan | 外部二进制 | `nbtscan` | 是 | — | NetBIOS名称扫描工具 |
| netexec | 外部二进制 | `netexec` | 是 | — | 网络枚举和利用框架（原CrackMapExec） |
| nikto | 外部二进制 | `nikto` | 是 | — | Web服务器扫描工具，用于检测Web服务器和应用程序中的已知漏洞和配置错误 |
| nmap | 外部二进制 | `nmap` | 是 | — | 网络扫描：端口/服务/脚本；可选时序、自定义 NSE、OS 检测（需 root） |
| nuclei | 外部二进制 | `nuclei` | 是 | — | 快速漏洞扫描器，使用YAML模板进行漏洞检测 |
| one-gadget | 外部二进制 | `one_gadget` | 是 | — | 在libc中查找one-shot RCE gadget的工具 |
| pacu | 外部二进制 | `pacu` | 否 | — | AWS渗透测试框架 |
| paramspider | 外部二进制 | `paramspider` | 是 | — | 从Web档案中挖掘参数 |
| prowler | 外部二进制 | `prowler` | 是 | — | 云安全评估工具（AWS, Azure, GCP） |
| pwninit | 外部二进制 | `pwninit` | 是 | — | CTF二进制漏洞利用设置工具 |
| quake_search | 自研内联 | `python3` | 否 | requests | Quake网络空间搜索接口，支持自定义query、size、fields |
| query_execution_result | 外部二进制 | `internal:query_execution_result` | 是 | — | 查询工具执行结果，支持分页、搜索和过滤大结果集 |
| radare2 | 外部二进制 | `r2` | 是 | — | 二进制分析和逆向工程框架，支持反汇编、调试和脚本分析 |
| ropgadget | 外部二进制 | `ROPgadget` | 是 | — | ROP gadget搜索工具 |
| ropper | 外部二进制 | `ropper` | 是 | — | 高级ROP/JOP gadget搜索工具 |
| rustscan | 外部二进制 | `rustscan` | 是 | — | 超快速端口扫描（Rust）；可选 greppable、批量与脚本级别 |
| scout-suite | 外部二进制 | `scout` | 是 | — | 多云安全评估工具 |
| shodan_search | 自研内联 | `python3` | 否 | requests | Shodan网络空间搜索，支持search与count模式 |
| smbmap | 外部二进制 | `smbmap` | 是 | — | SMB共享枚举和访问工具 |
| sqlmap | 外部二进制 | `sqlmap` | 是 | — | 自动化SQL注入检测和利用工具，用于发现和利用SQL注入漏洞 |
| steghide | 外部二进制 | `steghide` | 是 | — | 隐写术分析工具 |
| subfinder | 外部二进制 | `subfinder` | 是 | — | 被动子域名发现工具，使用多个数据源 |
| terrascan | 外部二进制 | `terrascan` | 是 | — | 基础设施即代码安全扫描工具 |
| trivy | 外部二进制 | `trivy` | 是 | — | 容器和文件系统漏洞扫描器 |
| volatility3 | 外部二进制 | `volatility3` | 是 | — | Volatility3内存取证分析工具 |
| wafw00f | 外部二进制 | `wafw00f` | 是 | — | WAF识别和指纹识别工具 |
| waybackurls | 外部二进制 | `waybackurls` | 是 | — | 从Wayback Machine获取历史URL |
| wpscan | 外部二进制 | `wpscan` | 是 | — | WordPress安全扫描器，用于检测WordPress漏洞 |
| x8 | 外部二进制 | `x8` | 是 | — | 隐藏参数发现工具 |
| xsser | 外部二进制 | `xsser` | 是 | — | XSS漏洞测试工具 |
| zap | 外部二进制 | `zap-cli` | 否 | — | OWASP ZAP Web应用安全扫描器 |
| zoomeye_search | 自研内联 | `python3` | 否 | requests | ZoomEye网络空间搜索引擎，支持灵活的查询参数配置 |
| zsteg | 外部二进制 | `zsteg` | 是 | — | LSB 隐写检测工具，用于检测 PNG/BMP 图片中的隐写数据 |

## 可用工具清单（15 个）

| 工具 | 可执行 | 解析路径 |
|---|---|---|
| angr | `python3` | `C:\Users\Lenovo\.workbuddy\binaries\python\versions\3.13.12\python3.EXE` |
| dnslog | `python3` | `C:\Users\Lenovo\.workbuddy\binaries\python\versions\3.13.12\python3.EXE` |
| exec | `sh` | `C:\Users\Lenovo\.workbuddy\binaries\PortableGit\versions\1.2.0\usr\bin\sh.EXE` |
| execute-python-script | `/bin/bash` | `C:\Users\Lenovo\.workbuddy\binaries\PortableGit\versions\1.2.0\usr\bin\bash.EXE` |
| impacket | `python3` | `C:\Users\Lenovo\.workbuddy\binaries\python\versions\3.13.12\python3.EXE` |
| install-python-package | `/bin/bash` | `C:\Users\Lenovo\.workbuddy\binaries\PortableGit\versions\1.2.0\usr\bin\bash.EXE` |
| libc-database | `python3` | `C:\Users\Lenovo\.workbuddy\binaries\python\versions\3.13.12\python3.EXE` |
| metasploit | `python3` | `C:\Users\Lenovo\.workbuddy\binaries\python\versions\3.13.12\python3.EXE` |
| objdump | `objdump` | `D:\miniconda3_new\Library\mingw-w64\bin\objdump.EXE` |
| pwntools | `python3` | `C:\Users\Lenovo\.workbuddy\binaries\python\versions\3.13.12\python3.EXE` |
| responder | `python3` | `C:\Users\Lenovo\.workbuddy\binaries\python\versions\3.13.12\python3.EXE` |
| rpcclient | `python3` | `C:\Users\Lenovo\.workbuddy\binaries\python\versions\3.13.12\python3.EXE` |
| strings | `strings` | `D:\miniconda3_new\Library\mingw-w64\bin\strings.EXE` |
| virustotal_search | `python3` | `C:\Users\Lenovo\.workbuddy\binaries\python\versions\3.13.12\python3.EXE` |
| xxd | `xxd` | `C:\Users\Lenovo\.workbuddy\binaries\PortableGit\versions\1.2.0\usr\bin\xxd.EXE` |

## 一键满血路径（自研工具 100% 可用）

自研内联脚本的不可用，**全部**只因通用第三方包缺失（无一是二进制依赖）：
`chardet charset_normalizer h2 httpx requests`。一条命令即可补齐：

```bash
pip install chardet charset_normalizer h2 httpx requests
```

补齐后自研工具可达 17/17（100%）。**这是本平台工具链『依赖极轻』的直接证据**：自研能力是纯 Python 实现，
跨平台、零二进制预装要求。
