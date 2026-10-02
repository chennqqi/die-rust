# Requirements Analysis 008 — 2026-10-02

## 输入

1. "检查对比、分析上游diec 图形界面和当前实现的差异"
2. "需要，并根据分析结果制定改进计划"（确认落盘 + 出计划）

## 分析过程

- 确认基线：`upstream/components.lock.toml` 固定 `DIE-engine@23fec32`
  （2026-09-30，subtree-squash），dep/* submodule 均为空目录（gitlink
  未 checkout），故上游源码核实分两部分：本地 `src/gui/` 源码 +
  GitHub API 拉取固定 commit 的 `formatswidget.h`/`die_widget.h|cpp`/
  `xdemangle.h`。
- 历史上下文：v3 差距分析（2026-08-08）35 项已在 Phase 12 关闭；
  本次为第四轮复核，故文件名沿用 `gui-gap-analysis-v4.md`。
- 实测方法：枚举 `main.rs` invoke_handler 60 个命令、24 个前端组件、
  各 viewer 后端模块，逐项对照上游 SPE::TYPE/SELF::TYPE/SMACH::TYPE
  清单和 die_widget 按钮清单，不复述 v3 结论。
- 关键新发现（v3 未覆盖或状态已变）：
  - `nfd_enabled` 仅为设置项占位，无后端实现 —— stub 开关。
  - 引擎层已有 ZIP/7Z/RAR 提取（`archive_unpack.rs`，ADR 0029 `rars`），
    GUI `list_archive` 却手写 ZIP/TAR/GZ —— 归档差距是接线问题，
    大幅降低 17.B 工作量。
  - 上游 9-28 XDemangle bump 新增 6 模式后达 20 模式；当前 31 行
    demangle.rs 仅覆盖 2 —— 确定为最大用户可感知差距（V4-10）。
  - `die_widget` 的 Extra Information 是 `ScanItemModel::toFormattedString`
    纯文本导出，实现成本极低（17.E）。
- 计划结构沿用 Phase 11/12 批次惯例：每批独立提交、独立验证；
  架构级缺口（NFD/Unpacker/InfoDB/多语言/自动更新）只产出 ADR
  （0035–0038），不并入实现批次。

## 产出

- `docs/research/gui-gap-analysis-v4.md`（Draft）
- `docs/design/phase17-gui-parity.md`（Draft）
- `docs/research/README.md`、`docs/design/README.md` 索引更新
- `ROADMAP.md` 追加 Phase 17（TODO）

## 追加：Phase 17 实施记录（2026-10-02）

按批次顺序实施。关键决策与修复：

1. **17.A**：`detectMode` 按上游探测顺序逐条移植；`_ZN…17h<hex>E`
   与 `_R`/`__R` 前缀判 Rust；`msvc-demangler` 覆盖 MSVC 四架构；
   Borland(`__Z`/`@std@`)/Watcom(`W?`)/D(`_D`)/Java 自实现精简解码，
   上游其余模式枚举保留返回原串。
2. **17.B**：GUI `list_archive` 重写为引擎 `list_archive_members`
   （ZIP 目录直读、7Z `Archive::read().files`、RAR `members()`）；
   新增 `extract_archive_member`；DOS 时间解码 `format_dos_time`。
3. **17.C**：`compute_named_hash` 分发 17 算法；新增
   `list_hash_algorithms`/`compute_hash` 命令；前端 FileInfo
   "More hashes" 勾选面板；引擎 `struct_mode::hash_algorithms`
   同步扩到 17 项（修复既有 `hash_non_empty_data` 计数断言）。
   版本统一为 RustCrypto 0.10 系避免双版本入 lock。
4. **17.D**：`parse_dex_deep_view` 七表，uleb128/边界钳制/1M 上限。
5. **17.E**：修 `extract_base_and_entry` Mach-O 格式名匹配 bug
   （"MACH-O" vs "Mach-O 32"）；修 App.tsx `base_address !== "0"`
   数字/字符串比较恒真 bug；`format_counts` 多计数信息栏；
   `follow.ts` 总线替代深层 prop 传递；Extra Info 模态框；
   `edit_bytes_at_offset`（.bak + 1MiB 上限 + 越界拒绝）。
6. **17.F**：ADR 0035 NFD deferred（并移除 GUI 中无后端的
   `nfd_enabled` 复选框）；0036 静态脱壳 deferred；0037 InfoDB
   deferred；0038 i18n 增量 Accepted。
7. 修 clippy `collapsible_if`/`manual_is_multiple_of` 若干；
   `cargo fmt/clippy/test` 全绿，前端 `npm run build` 通过，
   `diec --struct "Hash"` 实测输出 17 算法。
