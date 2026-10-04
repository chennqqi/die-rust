# Permanent 项处理分析（2026-10-12）

## 需求
- 归档安全上限应可配置/参数化
- XStyles/InfoDB 差异可接受
- TLSH 有开源参考（C/Python），应落地
- 解释"规则库漂移重同步"

## 发现与决策

1. **TLSH 其实已落地**：`file_info.rs` 的 `HASH_ALGORITHMS` 含
   `"TLSH"`，`compute_named_hash` 经 `tlsh2` v1.1.0（纯 Rust 移植）
   实现，Phase 29 交付——ADR 0042 #11 的"not implemented /
   Conditional"是治理表滞后而非真实缺口。本次补强：以参考实现
   trendmicro/tlsh（pin `ebdec8fd`，tlsh_unittest）为 oracle 生成
   7 条确定性语料摘要 + 3 条 fail-closed 边界（uniform 输入
   "cannot hash"、<50B "file too small"），全部 parity。

2. **ArchiveLimits 设计**：`archive_unpack.rs` 的 8 个模块级常量
   收敛为 serde 结构体（Default = 原值，零行为漂移）。三条调用面
   分别注入：`ScanFlags.archive_limits`（extract_* 扫描路径）、
   `&ArchiveLimits` 显式参数（list/extract_member/zip_member_* 记录
   级 API）、host.rs 规则 host API 走 flags。CLI 4 个
   `--archive-max-*` flag（K/M/G 后缀）；server `ScanFlagsRequest`
   body 字段（`/scan/bytes` 为标量 query 保持默认）；GUI
   `ScanFlagDefaults` + `ScanFlagsDto` 可选字段 + 设置面板数字输入。
   `is_lzma` 检测界固定取默认值——放宽提取上限不得扩大检测面。

3. **前端风险点**：设置面板 `Object.keys(flags)` 布尔循环会因
   `archive_limits` 对象键崩坏——两处（App.tsx、SettingsModal.tsx）
   均加 `typeof === 'boolean'` 过滤。

4. **规则库漂移**：vendor `db/`/`db_extra/` 快照 vs pin submodule
   演进差；上游已删 `PE.isNET` 但旧快照 10 条规则仍在调（兼容别名
   维持中）。重同步=对齐 pin SHA+差分+删别名，属维护项。
