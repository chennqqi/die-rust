# 需求分析 031 — 2026-10-06

## 输入

用户要求获取 GitHub issues，仓库 `chennqqi/die-rust` 有两个 OPEN issue。

## Issue #1: saving settings failed

报错：`invalid args 'settings' for command 'save_settings': missing field 'online_tools'`。

根因链：
- `online_tools` 与 `shortcuts` 在 Phase 11+12（commit fe6199d65）加入 `AppSettings`，无 serde 默认值；
- 更早版本的 `settings.json` 缺少这些字段 → `get_settings` 反序列化失败（SETTINGS_PARSE_ERROR）；
- 前端 `.catch(() => {})` 静默吞掉，`settings` 保持 `defaultSettings`；
- `App.tsx` 的 `AppSettings` 接口/`defaultSettings` 又缺 `online_tools`/`shortcuts`（SettingsModal 有、App.tsx 漏了）；
- `saveSettings`/`advanced` 切换把不完整对象发回 `save_settings` → serde 报缺字段。

修复：
- `crates/die-gui/src/settings.rs`：8 个设置结构体全部加容器级 `#[serde(default)]`，默认值从 `AppSettings::default` 拆分为各结构体 `impl Default`——旧文件缺任意层级字段（含 `scan.flags.no_dedup` 等 leaf 字段）均用语义默认值填充而非报错；
- `frontend/src/App.tsx`：接口与 `defaultSettings` 补 `online_tools`、`shortcuts`，即使 `get_settings` 失败兜底对象也完整；
- 新增 2 个单元测试覆盖"旧文件缺新字段"与"空对象"。

## Issue #2: pe.rs:592 out-of-range slice panic

`collect_resources_l` 记录的 `data_off` 来自 `rva_to_off`——其跨度用 `max(raw_size, vsize)`，RVA 落在 vsize 虚尾（vsize>raw_size）时返回 `raw_ptr+delta` 可超过文件长度。`pe.rs:592` 直接 `&d[data_off..data_off+n]`，`saturating_sub` 只把 n 压成 0，range 起点仍越界 → panic。CLI 每文件一次、FFI 每条触及 manifest host API 的规则一次（~317 行/文件）。

修复：`find` 守卫加 `r.data_off < d.len()`（等价上游"读不到→空 manifest"行为）。

审计其余 `ResourceEntry.data_off` 消费点均安全：
- `signature::get_signature`、`parse::find_ansi`/`read_ansi_string`、`windows_installer_vi`（经 find_ansi）边界自检；
- `pe_version::get_resources_version_rec` 全程 `rd_u16/rd_u32` 边界读；
- `engine::resource_parts` 消费方用 `d.get(off..)`；
- `resource_record` 消费方（Inno ldr_off）经 `get_signature`/`rd_u32`；
- host bridge `getResourceOffsetByNumber` 只回传数值，JS `readXxx` 走边界检查读。

回归测试 `pe32_manifest_offset_beyond_eof_no_panic`：放大 .rsrc vsize 使 manifest RVA 映到 EOF 之后，断言 `collect` 不 panic、manifest 为空，且整 scan 不 panic。
