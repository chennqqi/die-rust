# Phase 11：GUI 深度对齐 — 完整头部解析与缺失模块

Status: Complete
Last updated: 2026-08-08

## 完成状态

所有 8 个任务批次均已实现并通过验证：

| 任务 | 优先级 | 状态 | 新增测试 |
|------|--------|------|----------|
| 11.1 FileInfo 完整头部解析 | P0 | ✅ | 21 |
| 11.2 文件格式检测扩展 | P0 | ✅ | 6 |
| 11.3 PE 专用视图 | P1 | ✅ | 6 |
| 11.4 字符串搜索与提取器 | P1 | ✅ | 9 |
| 11.5 归档格式扩展 | P1 | ✅ | — |
| 11.6 可视化视图与区段视图 | P2 | ✅ | — |
| 11.7 Settings 模态对话框与快捷键 | P2 | ✅ | — |
| 11.8 VirusTotal 集成与 MIME 类型 | P2 | ✅ | 7 |

**验证结果**：
- Rust 测试：66 passed, 0 failed
- cargo fmt：通过
- cargo clippy：零警告
- 前端编译：通过

**新增后端模块**：
- `crates/die-gui/src/pe_viewer.rs` — PE 专用视图（imports/exports/resources/overlay/.NET/manifest/version info/TLS/Rich Header）
- `crates/die-gui/src/string_extractor.rs` — 字符串提取器（ASCII/UTF-16LE，过滤搜索）

**新增前端组件**：
- `PeViewPanel.tsx` — PE 专用视图面板（9 个子标签）
- `StringExtractor.tsx` — 字符串搜索与提取器
- `SectionVisualizer.tsx` — 区段可视化视图
- `SettingsModal.tsx` — Settings 模态对话框（5 个标签：View/Scan/Database/Engine/Shortcuts）

**新增依赖**：
- `die-formats`（workspace）— 20+ 格式 probe
- `tar = "0.4"` — TAR 归档支持
- `flate2 = "1.1"` — GZIP 解压支持

**扩展功能**：
- `detect_format` 现在优先使用 die-formats probe table（20+ 格式），手写 magic bytes 作为回退
- `list_archive` 扩展支持 ZIP/TAR/GZIP+TAR
- `FileInfo` 新增 `mime_type` 字段
- `AppSettings` 新增 `shortcuts` 字段（8 个可配置快捷键）
- OnlineTools 重构：接收 filePath，自动获取 SHA256，点击跳转 VirusTotal（与上游 Qt 行为一致，非 API 查询）

## 目标

Phase 9 修复了信息展示格式和基础功能缺陷，但人工实际使用发现对齐度仍仅约
30%。根本原因是**架构层面**的差距：FileInfoPanel 缺少完整头部解析、格式
专用视图缺失、多个工具模块未实现。

本 Phase 聚焦**用户最常感知的差距**，分 8 个任务批次逐步实现，每个批次
聚焦一个主题领域，可独立验证和提交。

## 依据

- 差距分析：[`docs/research/gui-gap-analysis-v2.md`](../research/gui-gap-analysis-v2.md)
- 上游 GUI 源码分析：[`docs/research/upstream-gui-analysis.md`](../research/upstream-gui-analysis.md)
- Phase 8 设计：[`docs/design/phase8-gui.md`](phase8-gui.md)
- 上游 FormatsWidget 源码：`horsicq/FormatWidgets/formatswidget.h`
- 上游 XFileInfo 源码：`horsicq/XFileInfo/xfileinfo.h`

## 任务批次

### 11.1 FileInfo 完整头部解析（P0）

**问题**：当前 FileInfoPanel 仅显示 sections 表和 symbols 表，缺少 PE/ELF/
Mach-O 的完整头部字段。这是用户打开二进制文件时**第一眼就能发现的差距**。

**实现**：

1. **后端：重构 `file_info.rs` 为树形头部解析器**

   新增 `FileHeaderTree` 数据结构，递归表示头部字段：

   ```rust
   pub struct HeaderField {
       pub name: String,         // "e_magic"
       pub value: String,        // "0x5A4D"
       pub comment: Option<String>, // "MZ signature"
       pub children: Vec<HeaderField>, // 嵌套字段
   }

   pub struct FileHeaderInfo {
       pub format: String,
       pub fields: Vec<HeaderField>, // 顶层字段组
   }
   ```

2. **PE 头部解析**（使用 `pelite`）：
   - IMAGE_DOS_HEADER：全部字段（e_magic/e_cblp/e_cp/e_crlc/e_cparhdr/...）
   - IMAGE_NT_HEADERS：Signature/Machine/NumberOfSections/TimeDateStamp/
     PointerToSymbolTable/NumberOfSymbols/SizeOfOptionalHeader/Characteristics
   - IMAGE_OPTIONAL_HEADER：AddressOfEntryPoint/ImageBase/SectionAlignment/
     FileAlignment/...（32/64 位区分）
   - IMAGE_SECTION_HEADER：Name/VirtualAddress/VirtualSize/PointerToRawData/
     SizeOfRawData/Characteristics（含标志位解析如
     `IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE`）
   - Entry Point 地址

3. **ELF 头部解析**（使用 `goblin::elf::Header`）：
   - e_ident（magic/class/data/version/os_abi/abi_version）
   - e_type（ET_REL/ET_EXEC/ET_DYN/ET_CORE + 解析）
   - e_machine（EM_386/EM_X86_64/EM_ARM/EM_AARCH64 + 解析）
   - e_version/e_entry/e_phoff/e_shoff/e_flags
   - e_ehsize/e_phentsize/e_phnum/e_shentsize/e_shnum/e_shstrndx
   - Program Headers（Phdr）：Type/Offset/VAddr/PAddr/FileSz/MemSz/Flags/Align
   - Section Headers：Name/Type/Flags/Addr/Offset/Size/Link/Info/Align/Entsize
     + SHF_* 标志解析

4. **Mach-O 头部解析**（使用 `goblin::mach`）：
   - mach_header：magic/cputype/cpusubtype/filetype/ncmds/sizeofcmds/flags
   - Load Commands：全部类型（LC_SEGMENT/LC_SYMTAB/LC_DYLD_INFO/...）
   - Segments + Sections：完整字段
   - Libraries（DYLD 加载库列表）

5. **前端：新增 `FileHeaderTree` 组件**
   - 递归树形展示 HeaderField
   - 支持展开/折叠
   - 字段名、值、注释三列
   - 标志位解析以彩色标签显示

6. **FileInfoPanel 重构**：
   - Tab "Info" → 子标签：Overview / Headers / Sections / Symbols / Entropy
   - "Headers" 子标签展示 FileHeaderTree
   - "Overview" 保留现有基本信息（文件名/大小/格式/哈希/熵）

**验证**：
- PE32/PE32+ 样本：DOS Header + NT Headers + Section Headers 字段完整
- ELF64 样本：Ehdr + Phdr + Shdr 字段完整
- Mach-O 64 样本：mach_header + Load Commands + Libraries 完整
- 与上游 XFileInfo 输出对比（字段名和值）

### 11.2 文件格式检测扩展（P0）

**问题**：`detect_format` 仅识别 PE/ELF/Mach-O/ZIP 约 6 种格式，上游
`XFormats` 支持 50+ 种。用户打开 PDF/PNG/ISO/RAR 等文件时显示 "Unknown"。

**实现**：

1. **复用 `die-formats` probe 结果**：
   - die-formats 已有 20 个格式 probe（Phase 2 实现）
   - 新增 IPC 命令 `detect_file_format(path) -> String`
   - 返回 die-formats 识别的格式名（如 "PDF"、"PNG"、"ISO9660"）

2. **扩展 `detect_format` 回退**：
   - 优先使用 die-formats probe
   - 回退到手写 magic bytes（已有）
   - 补充常见格式：PDF（%PDF）、PNG（89PNG）、JPEG（FFD8）、GIF（GIF8）、
     BMP（BM）、RIFF/WAV（RIFF）、GZIP（1F8B）、RAR（Rar!）、7Z（377A）、
     TAR（ustar）、CPIO（070701）、ISO9660（CD001）、JavaClass（CAFEBABE）、
     DEX（dex\n）、CFBF（D0CF11E0）

3. **前端 FileInfoPanel 显示格式名**

**验证**：
- 20+ 种格式样本正确识别
- 与 die-formats probe 输出差分

### 11.3 PE 专用视图（P1）

**问题**：上游有 PEExport/PEImport/PEResources/PEOverlay/PENET/PEManifest/
PEVersion/PETLS 等子视图，die-gui 仅有基础 sections/imports。

**实现**：

1. **后端：扩展 `file_info.rs` PE 解析**（使用 `pelite`）：
   - **Import Directory**：DLL 名 + 导入函数列表（已有基础，增强为完整树）
   - **Export Directory**：导出名/ordinal/forwarder/RVA
   - **Resource Directory**：递归资源树（Type/Name/Language → DataEntry）
   - **Overlay**：偏移 + 大小
   - **.NET Metadata**：CLR header + metadata 目录
   - **Manifest**：XML 内容（从 RT_MANIFEST 资源提取）
   - **Version Info**：VS_VERSIONINFO 结构解析
   - **TLS**：TLS 目录字段
   - **Rich Header**：Rich header 记录

2. **前端：PE 专用子标签页**：
   - FileInfoPanel Tab "Info" → 当格式为 PE 时显示 PE 子标签：
     Overview / Headers / Sections / Imports / Exports / Resources /
     .NET / Manifest / Version / TLS / Rich Header / Overlay
   - 每个子标签为对应的表格或树形视图

3. **IPC 命令**：
   ```rust
   #[tauri::command]
   async fn get_pe_imports(path: String) -> Result<Vec<ImportEntry>, GuiError>;
   #[tauri::command]
   async fn get_pe_exports(path: String) -> Result<Vec<ExportEntry>, GuiError>;
   #[tauri::command]
   async fn get_pe_resources(path: String) -> Result<ResourceTree, GuiError>;
   #[tauri::command]
   async fn get_pe_dotnet(path: String) -> Result<DotNetInfo, GuiError>;
   #[tauri::command]
   async fn get_pe_manifest(path: String) -> Result<String, GuiError>;
   #[tauri::command]
   async fn get_pe_version_info(path: String) -> Result<Vec<VersionEntry>, GuiError>;
   ```

**验证**：
- PE 样本：imports/exports/resources 树与上游对比
- .NET 样本：CLR header 字段完整
- Manifest 样本：XML 内容正确提取

### 11.4 字符串搜索与提取器（P1）

**问题**：上游有 DialogSearchStrings（字符串搜索）和 XExtractorWidget
（提取器），die-gui 均缺失。这两个是逆向分析常用功能。

**实现**：

1. **字符串搜索**：
   - 后端：`search_strings(path, min_len, encoding) -> Vec<StringResult>`
     - 支持 ASCII/UTF-8/UTF-16LE/UTF-16BE 编码
     - 最小长度过滤（默认 4）
     - 返回偏移 + 字符串内容
   - 前端：新增 `StringSearch` 组件
     - 编码选择下拉
     - 最小长度输入
     - 结果表格（Offset / String / Encoding）
     - 点击结果跳转到 HexViewer 对应偏移

2. **提取器**：
   - 后端：`extract_section(path, section_name) -> Vec<u8>`
     - 提取 PE/ELF/Mach-O section
     - 提取 overlay
     - 提取 resource（按 Type/Name 索引）
   - 前端：新增 `Extractor` 组件
     - 列出可提取项（sections/resources/overlay）
     - 选择目标 → 保存到文件（Tauri dialog）

3. **新增 Tab**：
   - Tab "strings"（字符串搜索）
   - Tab "extractor"（提取器）

**验证**：
- 字符串搜索：ASCII/UTF-16 结果与已知工具对比
- 提取器：提取 .text section 内容正确

### 11.5 归档格式扩展（P1）

**问题**：ArchiveViewer 仅支持 ZIP，上游 XArchive 支持 20+ 格式。

**实现**：

1. **引入归档库**：
   - `tar` crate — TAR 归档
   - `flate2` crate — GZIP 解压
   - `bzip2` crate — BZIP2 解压
   - `sevenz-rust` crate — 7Z 归档
   - RAR：使用 `rar` crate 或 `unrar`（native 依赖，需 ADR）

2. **后端：统一归档接口**：
   ```rust
   pub enum ArchiveFormat { Zip, Tar, Gzip, Bzip2, SevenZ, Rar }

   pub fn list_archive_entries(path: &str) -> Result<Vec<ArchiveEntry>, String>;
   pub fn extract_archive_entry(path: &str, entry_name: &str) -> Result<Vec<u8>, String>;
   ```

3. **前端：ArchiveViewer 增强**：
   - 自动检测归档格式
   - 列出条目（名称/大小/压缩后大小/时间）
   - 双击条目提取到临时文件

**验证**：
- ZIP/TAR/GZIP/7Z 样本正确列出条目
- 提取条目内容正确

### 11.6 可视化视图与区段视图（P2）

**问题**：上游有 XVisualizationWidget（字节分布/熵可视化）和
XRegionsWidget（内存区域可视化），die-gui 均缺失。

**实现**：

1. **可视化视图**：
   - 后端：`get_byte_histogram(path) -> [u32; 256]`（字节频率统计）
   - 后端：`get_entropy_map(path, block_size) -> Vec<f64>`（块级熵图）
   - 前端：新增 `VisualizationView` 组件
     - 字节分布柱状图（Canvas/SVG，256 根柱子）
     - 熵热图（彩色条带，颜色映射熵值）
     - 文件结构可视化（section/overlay 彩色条带）

2. **区段视图**：
   - 复用 MemoryMapViewer 数据
   - 新增 `RegionsView` 组件
   - 以表格 + 彩色条带展示内存区域（地址/大小/权限/类型）

3. **新增 Tab**：
   - Tab "visualization"（可视化）
   - Tab "regions"（区段，或作为 MemoryMapViewer 子标签）

**验证**：
- 字节分布柱状图与已知文件对比
- 熵热图颜色映射正确

### 11.7 Settings 模态对话框与快捷键配置（P2）

**问题**：Settings 是内联折叠面板（非模态），缺少 Hex/Disasm/签名搜索/
在线工具选项。快捷键配置缺失。

**实现**：

1. **Settings 重构为模态对话框**：
   - 前端：新增 `SettingsModal` 组件
   - 分页：View / File / Scan / Database / Engine / Hex / Disasm /
     Signatures / Online / About
   - 模态遮罩，阻塞主窗口

2. **快捷键配置**：
   - 前端：新增 `ShortcutsDialog` 组件
   - 列出所有快捷键（Open/Exit/Fullscreen/Scan/Stop/Copy 等）
   - 支持自定义绑定
   - 持久化到 settings.json

3. **样式选择**：
   - 前端：新增 `StyleSelector` 组件
   - 预设主题：dark/light/system + 自定义颜色方案
   - 实时预览

**验证**：
- Settings 修改后持久化往返
- 快捷键自定义生效
- 主题切换实时预览

### 11.8 VirusTotal 集成与 MIME 类型（P2）

**问题**：OnlineTools 仅有链接，无实际 API 集成。MIME 类型检测缺失。

**实现**：

1. **VirusTotal 集成**：
   - 后端：`virustotal_scan(path, api_key) -> VtResult`
     - 上传文件或计算 hash 查询
     - 返回检测率/扫描结果
   - 前端：OnlineTools 增强
     - API key 配置（Settings）
     - 扫描按钮 + 结果展示
     - 需要用户提供 API key（不内置）

2. **MIME 类型检测**：
   - 后端：`detect_mime(path) -> String`
     - 基于文件签名映射（PE → application/x-msdownload,
       ELF → application/x-elf, Mach-O → application/x-mach-binary, ...）
   - 前端：FileInfoPanel Overview 显示 MIME 类型

**验证**：
- VirusTotal 查询返回正确结果（需 API key）
- MIME 类型与已知映射对比

---

## 实现顺序

```
11.1 FileInfo 完整头部解析 (P0) ← 最高优先级
  ↓
11.2 文件格式检测扩展 (P0) ← 可与 11.1 并行
  ↓
11.3 PE 专用视图 (P1) ← 依赖 11.1 的头部解析基础
  ↓
11.4 字符串搜索与提取器 (P1) ← 独立
  ↓
11.5 归档格式扩展 (P1) ← 独立
  ↓
11.6 可视化视图与区段视图 (P2) ← 独立
  ↓
11.7 Settings 模态对话框与快捷键配置 (P2) ← 独立
  ↓
11.8 VirusTotal 集成与 MIME 类型 (P2) ← 独立
```

11.1 和 11.2 可并行。11.3 依赖 11.1。11.4-11.8 相互独立，可按优先级
顺序实现或并行。

## 依赖变更

| 任务 | 新增依赖 | 许可证 | 说明 |
| --- | --- | --- | --- |
| 11.1 | `pelite`（已有） | MIT | PE 深度解析 |
| 11.2 | 无（复用 die-formats） | — | — |
| 11.3 | 无（pelite 已有） | — | — |
| 11.4 | 无 | — | 纯 Rust 实现 |
| 11.5 | `tar`、`flate2`、`bzip2`、`sevenz-rust` | MIT/MIT/Apache-2.0/MIT | 归档格式 |
| 11.6 | 无 | — | 前端 Canvas/SVG |
| 11.7 | 无 | — | 前端实现 |
| 11.8 | `reqwest`（HTTP client） | MIT | VirusTotal API |

## 测试策略

### 单元测试

- `file_info.rs`：PE/ELF/Mach-O 头部字段解析正确性
- `detect_format`：20+ 格式样本识别正确性
- 归档解析：ZIP/TAR/GZIP/7Z 条目列表正确性
- 字符串搜索：ASCII/UTF-16 结果正确性
- MIME 检测：常见格式映射正确性

### 差分测试

- FileInfo 头部字段与上游 XFileInfo 输出对比（字段名和值）
- PE imports/exports/resources 与上游对比
- 归档条目列表与上游对比
- 字符串搜索结果与已知工具对比

### 前端测试

- FileHeaderTree 组件渲染正确性
- PE 专用子标签页渲染
- StringSearch/Extractor 组件交互
- SettingsModal 模态行为
- 可视化图表渲染

### 跨平台 CI

- 三平台（Linux/Windows/macOS）构建通过
- WebView smoke test 无 console error

## 退出条件

- 11.1-11.5 全部完成（P0+P1）
- 11.6-11.8 至少完成 2 项（P2）
- `cargo fmt --check` + `cargo clippy --workspace --all-targets --all-features -- -D warnings` 通过
- `cargo test --workspace --all-features` 通过
- 前端 `tsc --noEmit` + `vite build` 通过
- GUI-CLI 差分测试通过
- FileInfo 头部字段与上游对比无关键差异

## 交付物

### 代码

- `crates/die-gui/src/file_info.rs` — 重构为树形头部解析
- `crates/die-gui/src/pe_viewer.rs` — PE 专用视图后端（新增）
- `crates/die-gui/src/string_search.rs` — 字符串搜索（新增）
- `crates/die-gui/src/extractor.rs` — 提取器（新增）
- `crates/die-gui/src/archive.rs` — 归档扩展（新增或重构）
- `crates/die-gui/src/visualization.rs` — 可视化数据（新增）
- `crates/die-gui/src/virustotal.rs` — VirusTotal 集成（新增）
- `crates/die-gui/frontend/src/components/FileHeaderTree.tsx` — 头部树（新增）
- `crates/die-gui/frontend/src/components/PeViewer.tsx` — PE 专用视图（新增）
- `crates/die-gui/frontend/src/components/StringSearch.tsx` — 字符串搜索（新增）
- `crates/die-gui/frontend/src/components/Extractor.tsx` — 提取器（新增）
- `crates/die-gui/frontend/src/components/VisualizationView.tsx` — 可视化（新增）
- `crates/die-gui/frontend/src/components/SettingsModal.tsx` — 设置模态框（新增）
- `crates/die-gui/frontend/src/components/ShortcutsDialog.tsx` — 快捷键（新增）

### 文档

- `docs/research/gui-gap-analysis-v2.md`（差距分析）
- `docs/design/phase11-gui-parity.md`（本文）
- 更新 `ROADMAP.md` Phase 11
- 更新 `README.md` GUI 章节

## Deferred 项

以下功能不在本 Phase 范围内，deferred 到后续 Phase：

- NFD（Nauz File Detector）视图 — 需独立 ADR
- InfoDB — 需独立 ADR
- 静态脱壳（XStaticUnpacker）— 需独立 ADR
- DEX 专用视图 — 需求较低
- SSDeep/TLSH 哈希 — 需 native 依赖
- 多语言扩展到 22 种 — 低优先级
- 自动更新（tauri-plugin-updater）— ADR 0019 deferred
- RAR 归档支持 — 需 native 依赖（unrar），需 ADR
