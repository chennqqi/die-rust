# 需求分析 006 — 上游更新检查与同步评估

日期：2026-10-01

## 用户需求

检查上游 DIE 引擎和规则是否有更新，判断项目是否需要同步上游基线。

## 分析方法

1. 从 `upstream/components.lock.toml` 读取当前锁定的基线 SHA
   （DIE-engine `74eaf50`、Detect-It-Easy `c2c17df`，以及关键组件 gitlink）。
2. 用 `git ls-remote` 获取各上游仓库当前 HEAD。
3. 用 GitHub compare API 统计落后提交数并提取提交摘要。

## 结果摘要

| 仓库 | 锁定 SHA（前 7 位） | 上游 HEAD（前 7 位） | 落后提交 | 最新提交日期 |
| --- | --- | --- | --- | --- |
| DIE-engine | 74eaf50 | 23fec32 | +433 | 2026-09-30 |
| Detect-It-Easy（规则） | c2c17df | 8925358 | +668 | 2026-09-30 |
| die_script | 5d82316 | 3a19ceb | +5 | 2026-08-31 |
| XScanEngine | dfe4a41 | 2550d2d | +39 | 2026-09 下旬 |
| Formats | 1151e72 | 65b04be | +52 | 2026-09-27 |
| SpecAbstract | cdfe107 | 5188e04 | +21 | 2026-09-22 |
| XArchive | 0fcd4e8 | cffced3 | +67 | 2026-09-28 |
| XOptions | 810d78d | 954afe8 | +16 | 2026-09-29 |
| XFileInfo | 88b8e28 | 7fa7027 | +6 | 2026-09-06 |
| StaticScan | fcdcb25 | fcdcb25 | 0 | — |
| signatures | 5d80fb2 | 5d80fb2 | 0 | — |

上游最新正式 release 仍为 3.21（2026-04-21），早于当前基线；master 持续滚动更新。

## 与 diec-rust 相关的实质性变更

- **XScanEngine**：新增 NE_Script 多个方法（isNE16/isDriver/isFont/isDll/
  isResourcesPresent）、Binary_Script::is8()、PDF getPermissions、多个新
  record name；移除 PE.isNET()、移除 rar_script 模块、archive 处理重构、
  新增 `--stoponerror` 选项、Binary_Script::compare() 整数溢出修复、
  loadDatabase 内存泄漏修复。
- **die_script**：新增 CLI assembly 脚本引擎支持；限制文件类型检测范围为
  archives/images；移除 extra database update 支持；Archive_Script 替代
  RAR_Script。
- **Detect-It-Easy 规则**：668 个提交（大量新规则/启发式，如 BorrCod
  cryptor 检测）。

## 结论

上游已大幅领先当前基线（规则库落后约 2 个月）。建议按
`docs/design/upstream-sync.md` 流程同步：先更新 Detect-It-Easy 规则
sibling subtree 并重生成 rule-source-manifest，然后针对 die_script /
XScanEngine 的 host API 语义变更做源码考古与差分验证，最后决定是否升级
DIE-engine 基线 SHA。
