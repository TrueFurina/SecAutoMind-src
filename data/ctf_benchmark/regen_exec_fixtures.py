#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""重新生成执行基准集中「不可入库」的嵌套 .git 工件（exec_git_repo / git_cred_repo）。

这两个 git 仓库含真实提交历史，依设计（gen_exec_artifacts*.py 注释「嵌套 .git 不入库，
由本脚本再生成」）不进入版本库；CI 与本地校验前必须重新生成，否则
TestExecSolversAgainstBenchmark（Go）与 judge_exec.py（Python）会因缺少 git 历史而 13/15。

本脚本只调用生成器的 git 仓库构建函数，不重写 execution_benchmark.json，
以保留 live_sqli / live_ssti 等手工题与 v1/v2/v3 已提交的工件。
"""
import gen_exec_artifacts as g1
import gen_exec_artifacts_v2 as g2

g1.gen_git()
g2.gen_git_cred_repo(g2.EXEC_DIR)
print("regenerated execution git fixtures: exec_git_repo, git_cred_repo")
