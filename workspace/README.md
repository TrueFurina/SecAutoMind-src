# SecAutoMind 工作区（Workspace）

本目录定义 SecAutoMind 的**可打包工作区**：把「协调主代理 + 专项子代理 + 角色 + 技能 + 人格」打成一个可移植单元，供导入另一个 SecAutoMind 实例，或作为统一分发格式。

## 目录结构

- `manifest.json` —— 工作区清单（字段见下）
- `SOUL.md` —— 人格文件（授权优先 / 证据驱动 / 非破坏 / 诚实）
- 打包内容来自仓库根的 `agents/*.md`、`roles/*.yaml`、`skills/*/SKILL.md`

## 清单字段（manifest.json）

| 字段 | 含义 |
|---|---|
| `schema_version` | 清单格式版本 |
| `id` / `label` / `version` | 工作区标识与版本 |
| `description` | 一句话描述 |
| `welcome` | 首次进入时的欢迎语 |
| `quick_prompts` | 快捷提示词 |
| `task_examples` | 任务示例 |
| `personality` | 人格文件（默认 `SOUL.md`） |
| `assets` | 资产 glob（agents / roles / skills）；实际文件由脚本发现并校验 |
| `prompt_files` | 额外提示词文件 glob |

## 用法

```bash
# 校验资产（不产包）：agent 需 id/name、role 需 name、skill 的 SKILL.md name 须等于目录名
python scripts/package_workspace.py --check

# 预览将纳入的文件
python scripts/package_workspace.py --list

# 产出 dist/secautomind-workspace-<version>.tar.gz
python scripts/package_workspace.py

# 自定义输出路径
python scripts/package_workspace.py --out /path/to/ws.tar.gz
```

退出码：`0` 成功；`1` 资产校验失败 / 人格文件缺失；`2` 清单缺失或解析失败。

## 设计约束

- **加法式**：只读取 `agents/ roles/ skills/` 与 `workspace/`，不改动它们。
- **单一真值源**：清单只声明 glob，实际文件由脚本发现并校验，避免清单与磁盘漂移。
- **fail-closed**：任一资产格式不合法即拒绝出包，绝不产出半成品。
- **确定性**：归档内路径排序、mtime/uid/gid 归零，同一输入产出一致字节（便于哈希与复现）。

## 回归测试

```bash
python scripts/package_workspace_test.py   # 3 例：--check / --list / 归档必含关键文件
```
