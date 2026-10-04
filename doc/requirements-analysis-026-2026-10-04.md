# 分析记录 026 — 2026-10-04

## 需求：diec-rust → die-rust 改名分析

全仓盘点结果：仓库名硬编码 URL ~20 处（workspace.repository、go.mod、
tauri updater、died.service/spec、release.yml、README）；crate 名
`diec-*`×9 + `die-gui`（前缀混用），`use diec_*` 约 170 处；对外面
`diec_v1_*`/`DIEC_*`/`libdiec_ffi`/env vars/import diec 属 ABI 承诺，
改名即破坏。结论：方案 B 推荐——仓库名+内部 crate 名统一，
二进制 diec/died/die（与上游 die/diec 对齐）与 C ABI 全部保留。
设计文档：docs/design/rename-die-rust.md。
