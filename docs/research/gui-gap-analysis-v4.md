# GUI 对齐差距分析 v4 — 基于当前实现实测复核

> 生成日期：2026-10-02
> 基线：上游 `DIE-engine@23fec32cac2a562342c1c2db8e22ce231b58f346`（2026-09-30，
> `upstream/components.lock.toml` 固定，含全部 dep/* submodule 固定 commit）
> 当前实现：`die-gui` v0.6.1（Tauri v2 + React 18），Phase 12 后实测
> 方法：不沿用 v3 结论，逐项核实当前代码（前端组件、Tauri 命令、后端模块）
> 与上游源码（`src/gui/` + 固定 commit 的 `die_widget`/`FormatWidgets`/
> `XDemangle`/`XArchive` 等）的对应关系

参考文档：

- [`gui-gap-analysis-v3.md`](gui-gap-analysis-v3.md) — Phase 11/12 依据（35 项已全部关闭）
- [`upstream-gui-analysis.md`](upstream-gui-analysis.md) — 上游 GUI 源码结构
- [`../design/phase11-gui-parity.md`](../design/phase11-gui-parity.md) — Phase 11 设计
- 设计文档：[`../design/phase17-gui-parity.md`](../design/phase17-gui-parity.md) — 本文对应的改进计划

---

## 1. 当前实现对齐状态总览

Phase 11/12 后，die-gui 已覆盖上游 GUI 的绝大多数功能面。以下为实测确认
已实现的部分（本次逐命令、逐组件核实，非复述 v3 结论）：

| 功能域 | 状态 | 备注 |
|--------|------|------|
| DIE 扫描（文件/目录/停止/profiling/scan_log） | ✅ | `scan_file`/`scan_directory`/`stop_scan`，profiling 与 scan_log 前端展示均在 |
| 签名浏览器（列表/源码/编辑/运行/保存） | ✅ | `list_signatures`/`get_signature_source`/`save_signature_source`/`run_signature` |
| PE 专用视图 | ✅ | 30 个子标签，覆盖上游 46 种 `SPE::TYPE` 全部类别（部分合并） |
| ELF 专用视图 | ✅ | 9 个子视图，interpreter/runpath 在数据模型中 |
| Mach-O 专用视图 | ✅ | 27 个子视图，含 chained fixups/exports trie/SuperBlob/unix_thread |
| MSDOS/NE/LE/DEX | ⚠ 部分 | 仅 header 级字段（`misc_viewer.rs`），见 §3.4 |
| Hex / Disasm / MemoryMap | ✅ | Hex 只读；Disasm x86/x64/ARM/ARM64 + 语法切换 + xref 计数 |
| 字符串搜索 | ✅ | MapMode/FileType/右键菜单（Hex/Disasm/Demangle/Edit String）/CSV/JSON 保存 |
| 可视化 | ✅ | 二维色块 + 7 种 DATAMETHOD + 高亮 + 缩放 + PNG 保存 |
| 提取器 | ✅ | RAW/FORMAT/HEURISTIC 三模式 + 深度扫描 + 分析模式 |
| VirusTotal | ✅ | MD5 + API key 双模式，与上游 `xvirustotalwidget.cpp` 一致 |
| PEiD / YARA | ✅ | `peid_scan`/`yara_scan` |
| Struct 求值 | ✅ | `evaluate_struct`/`list_struct_methods`（对标 XDynStructs） |
| 数据转换器 | ✅ | DataConverter（对标 XDataConvertorWidget） |
| Settings（view/scan/database/engine/online/shortcuts） | ✅ | 含 8 个可配置快捷键、stay_on_top、advanced |
| 拖放 / 命令行打开 / 单实例 / 右键菜单集成 / Recent files | ✅ | `tauri_plugin_single_instance`、`context-menu-file` 事件 |
| Advanced 模式 | ✅ | tab 过滤方式实现 |

## 2. 上游基线新增变化（v3 分析后，2026-08-08 ~ 2026-09-30）

对基线 commit 的 submodule bump 梳理，GUI 相关增量：

| 日期 | 变更 | 对差距的影响 |
|------|------|--------------|
| 09-28 | XDemangle 新增 Swift/Go/Haskell/OCaml/Tru64/SunPro 6 种反混淆器 | **扩大 demangle 差距**（上游 20 模式 vs 当前 2 模式） |
| 09-27 | XScanEngine 新增 native scan helpers / binary primitives / PE bindings | 引擎侧，需核对 host API 覆盖（Phase 16.x 已部分跟进） |
| 09-27 | Formats 新增 `XBinary::find_signatures` 多模式搜索 | 引擎侧 |
| 09-14 | XArchive 新增 decoders/archives/compressors/SFX 模块 | **扩大归档格式差距** |
| 09-19 | XStyles +46 个 QSS 主题 | 样式生态，非功能 |
| 09-22 | FormatDialogs/Formats/XArchive QPointer→裸指针重构 | 无功能影响 |
| 09-29 | XOptions 改用 QSettings + native console API | 无功能影响 |
| 10-01 | die_script / Detect-It-Easy 规则更新 | 规则同步事项，非 GUI |

上游 `die_widget`（`5ae98a5d`）与 `FormatWidget`（`8de1efff`）的按钮/子视图
清单与 v3 分析一致，无新增工具按钮。

## 3. 仍存在的差距清单

### 3.1 完全缺失

| ID | 功能 | 上游位置 | 现状 | 阻塞原因 |
|----|------|---------|------|---------|
| V4-01 | NFD 引擎扫描 | `dep/nfd_widget` + SpecAbstract | 仅 `settings.engine.nfd_enabled` 开关（默认 false），无 `nfd_scan` 命令、无 NFD 引擎绑定 | 需 port SpecAbstract 或接 nfd 数据，工作量大，需 ADR |
| V4-02 | 静态脱壳 | `dep/XStaticUnpacker` + `Unpack` 工具按钮 | 无 | 需独立 ADR（脱壳器逐个移植） |
| V4-03 | Extra Information 对话框 | `die_widget::on_pushButtonDieExtraInformation_clicked`（`DialogTextInfo` 输出 `ScanItemModel::toFormattedString`） | 无独立入口；检测结果树已含同信息 | 低价值，易实现 |
| V4-04 | 自动更新 / 更新检查 | `dep/XUpdate` + `dep/XGithub` | 无 | ADR 0019 已 deferred |
| V4-05 | InfoDB（注释/书签/分析结果持久化） | `dep/XInfoDB` | 无 | 数据库基础设施，上游 Hex/Disasm 书签依赖此 |

### 3.2 广度差距（部分实现）

| ID | 功能 | 上游 | 当前 | 差距 |
|----|------|------|------|------|
| V4-10 | **Demangle** | XDemangle 20 种模式：`MSVC32/64/ARM32/ARM64`、`GNU_V2/V3`、`GCC_WIN/MAC`、`JAVA`、`BORLAND32/64`、`WATCOM`、`RUST`、`GNAT`、`DLANG`、`SWIFT`、`GO`、`HASKELL`、`OCAML`、`TRU64`、`SUN` | `demangle.rs`（31 行）：仅 rustc-demangle + cpp_demangle（Itanium） | **最严重**：PE 场景最常用的 MSVC `?foo@@...` 无法反混淆；缺 Borland/Watcom（旧 Delphi/C++Builder 样本常见） |
| V4-11 | 归档格式 | XArchive：ZIP/RAR/7z/CAB/ARJ/ISO/BZ2/XZ/LZMA/LZIP/ZLIB/APK/JAR/IPA/DEB/RPM/SFX 等 | `list_archive`：ZIP/TAR/TAR.GZ | 差 ~15 种；7z/BZ2/XZ 纯 Rust crate 可用，RAR 需 native 依赖决策 |
| V4-12 | 哈希算法 | XHashWidget：MD4/MD5/SHA1/SHA2 系/SHA3 系/BLAKE2/BLAKE3/CRC 系/Adler32/GOST/Tiger/Whirlpool/RIPEMD/SSDeep/TLSH 等 ~30 种，独立对话框 + 算法勾选 | FileInfo 固定 4 种（MD5/SHA1/SHA256/CRC32）；Struct 模式 7 种 | 无独立 Hash 面板、无算法选择；SHA3/BLAKE 纯 Rust 无阻塞，SSDeep/TLSH 需 native |
| V4-13 | DEX 深视图 | DEX Widget：`dexsectionheaderwidget` + string_ids/type_ids/proto_ids/field_ids/method_ids/class_def/map 列表 | `misc_viewer.rs` 仅 header 字段 + ids size/off 计数 | 差 6+ 张表；MSDOS/NE/LE 同为 header 级（上游 NE/LE widget 也仅头部级，差距小） |
| V4-14 | 反汇编架构 | XCapstone：x86/ARM/ARM64/MIPS/PPC/SPARC/SYSZ/XCORE/M68K/RISCV/WASM 等 | iced-x86（Intel/AT&T/NASM）+ yaxpeax-arm（ARM/ARM64） | 覆盖主流；MIPS/PPC/RISCV 嵌入式样本会缺 |
| V4-15 | 多语言 | 22 个 `die_*.ts` 翻译 | 5 个（en/zh-CN/ru/de/fr） | 差 17 种；XTranslation 在线更新机制也无 |
| V4-16 | 主题生态 | XStyles：46+ QSS 主题 + `DialogSelectStyle` | light/dark/system + 自定义 CSS 名 | 生态差距，非功能阻断 |
| V4-17 | 扫描引擎切换 | `comboBoxScanEngine` 同位置单选切换 DIE/NFD/YARA/PEiD | 独立 Tab + Settings 开关 | 交互形态不同；NFD 缺位使组合不完整 |

### 3.3 交互/行为细节

| ID | 功能 | 上游 | 当前 |
|----|------|------|------|
| V4-20 | Hex 编辑 | XHexEdit/XHexView 上下文菜单含编辑/转储 | `edit_string_at_offset`/`write_binary_file` 后端已有，前端 Hex 只读，无字节级编辑 UI |
| V4-21 | 跨视图 Follow 链 | 所有格式子视图均可 Follow in Hex/Disasm | strings→hex/disasm、disasm→hex 已通；PE/ELF 子视图内跳转不完整 |
| V4-22 | 信息栏字段 | FormatsWidget 顶部始终显示 base address/entry point/各格式计数（PE 节数/导入/导出；ELF phdr/shdr 数；Mach-O cmd/sect/seg/lib 数） | 数据在 header tree 内可查到，无固定信息栏字段 |

### 3.4 各格式子视图逐项核对

**PE（上游 46 项 vs 当前 30 子标签）**：上游所有 `SPE::TYPE` 类别均有对应
（合并项：IMAGE_DOS_HEADER+DOS_STUB、FILE_HEADER+OPTIONAL_HEADER+
DIRECTORY_ENTRIES+NT_HEADERS 拆分展示、.NET 四项齐全）。✅ 类别完备。

**ELF（上游 10 格式项 vs 当前 9）**：Ehdr/Shdr/Phdr/Dynamic/Libraries/
Notes/StringTable/SymbolTable/Rela+Rel（合并） ✅；Interpreter/Runpath 在
overview/dynamic 内而非独立视图（上游为独立 navi 项）。⚠ 信息等价、形态不同。

**Mach-O（上游 28 格式项 vs 当前 27）**：基本逐项对应 ✅。

**DEX**：上游为完整 section header widget（各 ids 表逐行展示），当前仅
header 汇总。❌ 实质差距。

## 4. 风险与依赖评估

| 项 | 依赖风险 | 许可风险 |
|----|---------|---------|
| MSVC/Borland demangle | `msvc-demangler`（MIT/Apache-2.0，纯 Rust，成熟）可覆盖 MSVC；Borland/Watcom 社区 crate 质量参差，可能需自实现精简版 | 低 |
| 7z/BZ2/XZ | `sevenz-rust`（Apache-2.0 纯 Rust）、`bzip2`（C 依赖）或 `bzip2-rs`（纯 Rust）、`xz2`（liblzma native）/ `lzma-rs`（纯 Rust） | 低；native 需 ADR |
| RAR | `unrar`（GPL 兼容层）或 `unrar5` 纯 Rust 移植；上游 unrar 许可限制已知（Phase 13 已调研） | **中** — 需沿用 Phase 13 RAR ADR 结论 |
| SSDeep/TLSH | `ssdeep`/`libtlsh` 均 native；纯 Rust `tlsh2`/`ssdeep-rust` 存在 | 低-中 |
| NFD | SpecAbstract 移植工作量大（与 DIE 规则引擎平级的另一套签名系统） | 低（LGPL？需核对） |
| 静态脱壳 | XStaticUnpacker 逐个脱壳器移植，收益低 | 低 |

## 5. 结论

- Phase 11/12 后 GUI 功能面对齐度已从 ~30% 提升至 **~85%**（按 v3 §6
  清单逐项重估）。
- **最大的用户可感知差距是 Demangle**（V4-10）：上游 20 模式 vs 当前 2，
  且 MSVC 是 PE 分析最常见场景。
- **其次是归档格式广度**（V4-11）与 **DEX 深视图**（V4-13）。
- NFD/静态脱壳/InfoDB/自动更新为架构级缺口，需 ADR 决策，不建议并入
  常规批次。
- 上游基线（9-30）距 v3 基线（8-8）的 GUI 增量主要集中在 demangle 模式
  与 archive 解码器两条线上，与本次识别的 V4-10/V4-11 吻合。

改进计划见 [`../design/phase17-gui-parity.md`](../design/phase17-gui-parity.md)。
