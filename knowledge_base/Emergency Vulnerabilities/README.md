# Emergency Vulnerabilities（高危漏洞应急处置）

> 常见"组件级"高危漏洞的应急处置要点：影响范围确认 → 临时缓解 → 升级修复 → 加固复核。面向已授权环境使用。

## Summary

* [Log4j2 (CVE-2021-44228)](#log4j2-cve-2021-44228)
* [Shiro 反序列化 (CVE-2016-4437)](#shiro-反序列化-cve-2016-4437)
* [FastJSON 反序列化](#fastjson-反序列化)
* [Spring 全家桶](#spring-全家桶)
* [通用处置流程](#通用处置流程)
* [References](#references)

## Log4j2 (CVE-2021-44228)

* **影响确认**：`pom.xml`/`gradle` 依赖树中 log4j-core < 2.15.0；jar 包名扫描 `log4j-core-*.jar`。
* **临时缓解**：设置 `-Dlog4j2.formatMsgNoLookups=true` 或环境变量 `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`；移除 `JndiLookup` class。
* **排查入侵痕迹**：日志中 `${jndi:` 关键词；异常出站 LDAP/RMI 连接（389/636/1099 端口）。
* **根修**：升级 log4j-core ≥ 2.17.1。

## Shiro 反序列化 (CVE-2016-4437)

* **影响确认**：Cookie 中出现 `rememberMe` 字段且响应头含 `rememberMe=deleteMe`；shiro-core < 1.2.4 或未更换默认密钥。
* **临时缓解**：更换 `rememberMe` AES 密钥（硬编码 kPH+bIxk5D2deZiIxcaaaA== 必须改）。
* **排查**：大量超长 `rememberMe` Cookie 请求（利用尝试）；异常反序列化告警。
* **根修**：升级 shiro ≥ 1.2.5+ 并随机化密钥。

## FastJSON 反序列化

* **影响确认**：依赖 fastjson < 1.2.83（autoType 绕过链持续更新）；对外提供 JSON 反序列化接口。
* **临时缓解**：关闭 `autoTypeSupport`；WAF 拦截 `@type` 关键词请求体。
* **排查**：请求体含 `@type`、`rmi://`、`ldap://` 的日志；异常出站连接。
* **根修**：升级 ≥ 1.2.83 或迁移 fastjson2 / Jackson。

## Spring 全家桶

* Spring4Shell（CVE-2022-22965）：JDK9+ + Tomcat 部署 + 参数绑定，关注 `class.module.classLoader` 请求特征；升级 5.3.18+/5.2.20+。
* Spring Cloud Gateway（CVE-2022-22947）：`/actuator/gateway/routes` SpEL 注入；排查异常路由新增与内存马痕迹。
* 排查内存马：Filter/Servlet/Listener 数量与名称异常、无源码 Class（`java.net.URLClassLoader` 加载）。

## 通用处置流程

1. **确认暴露面**：FOFA/鹰图/内网 CMDB 双向核对受影响资产清单。
2. **临时缓解优先**：业务不可中断时先上缓解措施（WAF 规则/JVM 参数/密钥更换）。
3. **证据留存**：缓解/升级前留存访问日志与可疑文件样本。
4. **根修升级**：官方渠道取包，校验哈希；灰度→全量。
5. **入侵排查**：漏洞暴露窗口期内的所有请求按 IOC 回溯（Webshell/计划任务/新增账号）。
6. **复核**：升级后复测利用点确认修复；输出事件报告与改进项。

## References

* [Log4Shell 处置手册 (Apache)](https://logging.apache.org/log4j/2.x/security.html)
* [Shiro 官方安全公告](https://shiro.apache.org/security.html)
* [FastJSON 更新日志](https://github.com/alibaba/fastjson/releases)
* [Spring Security Advisories](https://spring.io/security)
