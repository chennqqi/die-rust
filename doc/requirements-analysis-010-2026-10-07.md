# 需求分析 010 — Phase 19/20 实施（2026-10-07）

## 需求
顺序完成 Phase 19（InfoDB）、Phase 20（静态脱壳）、Phase 21（NFD）。

## 决策记录
- Phase 23 不存在 → 用户澄清按 19→20→21 推进。
- Phase 19 存储选型：旁车 `<file>.diec.json`（纯 Rust、可 diff、
  无 native 依赖），优于 SQLite；ADR 0037 标记 Superseded。
- Phase 20 对齐目标为 DIE `XUPX::_unpackPE`（简化重建模型），
  非 `upx -d` 全部行为；oracle 用真实 `upx -d` 输出节级差分。
- NRV 移植关键 bug：literal 读取与位缓冲 refill 必须共享同一输入
  游标；NRV2E 长度树无公共 `m_len*2+getbit` 步。
- Filter 字节序：上游 `_read_uint32`/`_write_uint32` 默认小端。
- SpecAbstract 许可证审计：MIT，兼容；源码 ~1.5MB C++，Phase 21
  计划为 `diec-nfd` crate + 签名表 codegen + 第二扫描 pass。

## 验证
upx_unpack 7 测试（PE32×NRV2B/NRV2E/LZMA、PE64×NRV2B vs upx -d）、
annotations 4 测试、clippy -D warnings 零警告、workspace 全绿、
前端 build 通过。
