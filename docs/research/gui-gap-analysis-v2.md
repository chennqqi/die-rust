# die-gui 与上游 Qt GUI 差距分析 v2（Phase 9 后）

Status: Accepted
Upstream: `horsicq/DIE-engine@ab0ea3e2764c9c5616362070be5c85404e3f7756` (master)
FormatWidgets: `horsicq/FormatWidgets` (master, 2026-08-08 fetch)
XFileInfo: `horsicq/XFileInfo` (master, 2026-08-08 fetch)
XArchive: `horsicq/XArchive` (master, 2026-08-08 fetch)
diec-rust die-gui: v0.6.1（Phase 10 后，2026-08-08）
Last updated: 2026-08-08

## 范围

本文在 `gui-upstream-diff.md`（v0.4.0 基线）基础上，重新评估 Phase 9 后的
差距。Phase 9 修复了 20 项 P1/P2/P3 问题，但人工实际使用发现对齐度仍仅约
30%。本文聚焦**架构层面**和**功能模块层面**的差距，而非已修复的信息格式
问题。

参考文档：
- [`upstream-gui-analysis.md`](upstream-gui-analysis.md) — 上游 GUI 源码结构
- [`gui-upstream-diff.md`](gui-upstream-diff.md) — Phase 8 后差距分析（v0.4.0）
- [`../design/phase8-gui.md`](../design/phase8-gui.md) — Phase 8 设计文档
- [`../design/phase11-gui-parity.md`](../design/phase11-gui-parity.md) — Phase 11 设计文档

---

## 1. Phase 9 已修复项确认

以下 20 项在 Phase 9 中已完成，不再列为差距：

| # | 修复项 | 状态 |
| --- | --- | --- |
| 1 | ScanDetection 扩展 id/parentId/file_part/offset/size/is_heuristic/is_a_heuristic/original_name | ✅ |
| 2 | 数据库选择接线（scan_file 接收 database_paths） | ✅ |
| 3 | 文件类型覆盖接线（scan_file 接收 file_type override） | ✅ |
| 4 | options 直接显示（不再显示计数） | ✅ |
| 5 | 启发式标记 (Heur)/(A-Heur) | ✅ |
| 6 | 嵌套结果树（基于 id/parentId） | ✅ |
| 7 | Hex viewer 虚拟滚动 + 搜索 + 跳转 + 复制 | ✅ |
| 8 | Disassembler 移除 break-on-Ret + 多架构（x86/x64/ARM/ARM64） | ✅ |
| 9 | Hex 数据检查器 + Follow in Disasm | ✅ |
| 10 | Disasm 交叉引用 + Analyze All | ✅ |
| 11 | PE imports 提取（goblin pe.imports） | ✅ |
| 12 | Mach-O FAT 识别（0xCAFEBABE magic） | ✅ |
| 13 | 结构化诊断信息（file/line/message/kind） | ✅ |
| 14 | Profiling 数据（SignatureProfile: file/elapsed_ms） | ✅ |
| 15 | 符号表虚拟滚动（移除 500 限制） | ✅ |
| 16 | 扫描进度事件（loading_database/scanning/complete） | ✅ |
| 17 | Hex 数据类型切换（Byte/Word/DWord/QWord） | ✅ |
| 18 | Disasm Follow in Hex 双向联动 | ✅ |
| 19 | CRC32 哈希 | ✅ |
| 20 | 熵块大小可配置（64B-4KB） | ✅ |

---

## 2. 仍存在的差距

### 2.1 FileInfo：完整头部字段解析（最大差距）

**上游 `XFileInfo`**（`xfileinfo.h`）使用 `XFileInfoModel`（树形
`QAbstractItemModel`）展示完整的结构化文件信息。每个头部字段是树节点，
包含字段名、十六进制值、注释、标志位解析。

上游解析的头部（`xfileinfo.h` 方法列表）：

| 格式 | 上游解析的头部 | die-gui FileInfoPanel |
| --- | --- | --- |
| PE | IMAGE_DOS_HEADER（全部字段）、IMAGE_NT_HEADERS（Signature/Machine/NumberOfSections/TimeDateStamp/PointerToSymbolTable/NumberOfSymbols/SizeOfOptionalHeader/Characteristics）、IMAGE_SECTION_HEADER（含 Characteristics 标志解析）、IMAGE_RESOURCE_DIRECTORY（递归）、IMAGE_EXPORT_DIRECTORY、IMAGE_IMPORT_DIRECTORY、Rich Header、TLS、.NET metadata、Manifest、Version Info、Entry Point | sections（name/vaddr/vsize/rawoff/rawsize/entropy）+ symbols + imports（DLL.function） |
| ELF | Elf Ehdr（e_ident/e_type/e_machine/e_version/e_entry/e_phoff/e_shoff/e_flags/e_ehsize/e_phentsize/e_phnum/e_shentsize/e_shnum/e_shstrndx）、Elf Shdr（全部字段 + SHF_* 标志解析）、Elf Phdr、Elf Sym（含版本信息）、Elf Dynamic、Elf Rel/Rela | sections（name/addr/offset/size/entropy）+ symbols（name/value/size/type） |
| Mach-O | mach_header（magic/cputype/cpusubtype/filetype/ncmds/sizeofcmds/flags）、Load Commands（全部类型）、Segments + Sections（完整字段）、Symbols（nlist 完整解析）、Libraries（DYLD 加载库列表）、FAT 多架构 | segments/sections（name/addr/size/offset）+ symbols（name/value/type） |
| DEX | DEX_HEADER（全部字段） | **无** |
| MSDOS | IMAGE_DOS_HEADER | **无** |
| NE/LE | NE/LE 头部 | **无** |

**影响**：用户打开 PE 文件时，上游显示完整的 DOS Header → NT Headers →
Section Headers → Resource Directory → Export Directory → Import Directory
树形结构，每个字段都有值和注释。die-gui 仅显示 sections 表和 symbols 表，
缺少 80% 以上的头部信息。这是**最明显的差距**。

### 2.2 格式专用视图缺失

上游 `FormatsWidget`（`formatswidget.h`）根据文件类型动态显示格式专用
视图。每种格式有独立的 Dialog（DialogPE/DialogELF/DialogMACH/DialogDEX
等），内含多个子视图按钮：

| 格式 | 上游子视图按钮 | die-gui 状态 |
| --- | --- | --- |
| PE | PE（总览）、PEExport、PEImport、PEResources、PEOverlay、PENET、PESections、PEManifest、PEVersion、PETLS | **全部缺失**（FileInfoPanel 有基础 sections/imports） |
| ELF | ELF（总览）、ELFSections、ELFPrograms | **全部缺失** |
| Mach-O | MACH（总览）、MACHSegments、MACHSections、MACHCommands、MACHLibraries | **全部缺失** |
| DEX | DEX（总览） | **缺失** |
| MSDOS | MSDOS、MSDOSOverlay | **缺失** |
| NE/LE | NE、LE | **缺失** |
| Archive | Archive（归档内容） | 有 ArchiveViewer 但仅支持 ZIP |
| Binary | Binary（通用二进制） | **缺失** |

### 2.3 缺失的工具模块

上游 FormatsWidget 的工具按钮（与文件类型无关的通用工具）：

| 功能 | 上游模块 | die-gui 状态 | 影响 |
| --- | --- | --- | --- |
| 字符串搜索 | DialogSearchStrings | **缺失** | 无法搜索文件中的字符串 |
| 签名搜索 | DialogSearchSignatures | **缺失** | 无法在文件中搜索签名 |
| 提取器 | XExtractorWidget + XExtractor | **缺失** | 无法提取 overlay/resource/section |
| 可视化视图 | XVisualizationWidget | **缺失** | 无字节分布/熵可视化图 |
| 区段视图 | XRegionsWidget | **缺失** | 无内存区域可视化 |
| MIME 类型 | XMIMEWidget | **缺失** | 无 MIME 类型检测 |
| VirusTotal | DialogXVirusTotal | **缺失**（OnlineTools 仅链接） | 无法在线查杀 |
| NFD | nfd_widget | **缺失** | 无 Nauz File Detector |
| InfoDB | XInfoDB | **缺失** | 无文件信息数据库 |
| 静态脱壳 | XStaticUnpacker | **缺失** | 无法静态脱壳 |
| 快捷键配置 | DialogShortcuts | **缺失** | 无法自定义快捷键 |
| 样式选择 | DialogSelectStyle | **缺失** | 无法选择 QSS 主题 |
| About 对话框 | DialogAbout | **简化**（仅文本） | 缺少详细信息 |

### 2.4 文件格式检测范围差距

**die-gui `file_info.rs:detect_format`** 使用手写 magic bytes，仅识别：
- PE/PE32/PE32+
- ELF32/ELF64
- Mach-O 32/64/FAT
- ZIP
- 其他均为 "Unknown"

**上游 `XFormats::getFileTypes`** 支持 50+ 文件类型，包括：
ISO9660、RAR、7Z、GZIP、BZIP2、TAR、CAB、AR、CPIO、NSIS、InstallShield、
InnoSetup、PDF、PNG、JPEG、BMP、GIF、RIFF/WAV、JavaClass、DEX、CFBF、
MPEG、AVI、MP4 等。

**影响**：用户打开 PDF/PNG/JPG/ISO/RAR 等文件时，die-gui FileInfoPanel
显示 "Unknown"，上游正确识别格式。这直接影响用户第一印象。

### 2.5 归档格式支持差距

**die-gui** 使用 `zip` crate，仅支持 ZIP 归档。

**上游 `XArchive`** 支持 20+ 归档格式：ZIP、RAR、7Z、TAR、GZIP、BZIP2、
CAB、AR、CPIO、ISO、NSIS、InstallShield、InnoSetup 等。

**影响**：ArchiveViewer 打开 RAR/7Z/TAR 等归档时无法列出内容。

### 2.6 哈希算法差距

| 算法 | die-gui | 上游 |
| --- | --- | --- |
| MD5 | ✅ | ✅ |
| SHA-1 | ✅ | ✅ |
| SHA-256 | ✅ | ✅ |
| CRC32 | ✅ | ✅ |
| SHA-224 | ❌ | ✅ |
| SHA-384 | ❌ | ✅ |
| SHA-512 | ❌ | ✅ |
| SSDeep | ❌ | ✅ |
| TLSH | ❌ | ✅ |

**影响**：缺少 SSDeep/TLSH 影响恶意软件相似性分析。

### 2.7 Settings 对话框差距

**上游 `DialogOptions`** 包含 6 个子选项 widget：
1. XScanEngineOptionsWidget — 扫描引擎选项
2. SearchSignaturesOptionsWidget — 签名搜索选项
3. XHexViewOptionsWidget — Hex 视图选项
4. XDisasmViewOptionsWidget — 反汇编视图选项
5. XOnlineToolsOptionsWidget — 在线工具选项
6. XInfoDBOptionsWidget — InfoDB 选项

**die-gui** Settings 是内联折叠面板，仅包含扫描标志复选框、主题/语言选择、
右键菜单管理。缺少 Hex/Disasm/签名搜索/在线工具/InfoDB 选项。

### 2.8 上游 die-gui 增值功能（die-gui 独有）

| 功能 | 说明 |
| --- | --- |
| Rust 符号 demangle | `rustc-demangle` crate |
| NASM 反汇编语法 | iced-x86 支持 |
| 状态栏 | 底部状态显示 |
| 拖放视觉 overlay | 拖放时全屏遮罩 |
| DataConverter | 数据格式转换 |
| MemoryMapViewer 可视化条 | 虚拟地址布局彩色条形图 |
| 内置 YARA/PEID 规则选择 | 前端下拉选择内置规则 |

---

## 3. 差距分类汇总

### 3.1 按用户影响分类

| 优先级 | 差距 | 用户影响 | 修复复杂度 |
| --- | --- | --- | --- |
| **P0** | FileInfo 缺少完整 PE/ELF/Mach-O 头部字段 | 打开任何二进制文件第一眼就发现 | 高（需重构 FileInfoPanel 为树形） |
| **P0** | 文件格式检测仅 6 种 vs 50+ | 打开非 PE/ELF/Mach-O 文件显示 Unknown | 中（复用 diec-formats probe） |
| **P1** | PE Import/Export/Resource 目录无独立视图 | PE 逆向分析时缺少关键信息 | 中（扩展 file_info.rs） |
| **P1** | 字符串搜索缺失 | 逆向分析常用功能缺失 | 中（新增 IPC + 前端组件） |
| **P1** | 提取器缺失 | 无法提取 overlay/resource/section | 中（新增 IPC + 前端组件） |
| **P1** | 归档仅支持 ZIP | 打开 RAR/7Z/TAR 归档无法查看 | 中（引入 tar/七零归档库） |
| **P2** | 可视化视图缺失 | 缺少字节分布/熵可视化 | 中（前端 Canvas/SVG） |
| **P2** | 区段视图缺失 | 缺少内存区域可视化 | 低（复用 MemoryMapViewer 数据） |
| **P2** | MIME 类型缺失 | 缺少 MIME 检测 | 低（前端映射表） |
| **P2** | .NET/Manifest/Version Info/TLS/Rich Header | PE 高级分析缺失 | 中（扩展 PE 解析） |
| **P2** | ELF Phdr/Dynamic/Relocations | ELF 高级分析缺失 | 中（扩展 ELF 解析） |
| **P2** | Mach-O Load Commands/Libraries | Mach-O 高级分析缺失 | 中（扩展 Mach-O 解析） |
| **P2** | 快捷键配置/样式选择 | UI 自定义能力缺失 | 低（前端实现） |
| **P2** | VirusTotal 集成 | 在线查杀缺失 | 中（API 集成） |
| **P3** | NFD/InfoDB/静态脱壳/DEX 视图 | 小众功能缺失 | 高 |
| **P3** | SSDeep/TLSH/SHA224/384/512 | 高级哈希缺失 | 中 |
| **P3** | 多语言扩展到 22 种 | 国际化完整度 | 低 |

### 3.2 按架构层次分类

| 层次 | 差距 | 修复方向 |
| --- | --- | --- |
| **数据层** | file_info.rs 缺少完整头部解析 | 重构为树形 FileInfoModel，使用 pelite 深度解析 PE |
| **数据层** | detect_format 仅 6 种 | 复用 diec-formats 的 20 个 probe |
| **数据层** | 归档仅 ZIP | 引入 tar crate + 其他归档库 |
| **IPC 层** | 缺少字符串搜索/提取器/签名搜索 IPC | 新增 Tauri commands |
| **前端层** | FileInfoPanel 需重构为树形 | 新增 FileHeaderTree 组件 |
| **前端层** | 缺少格式专用视图 | 新增 PE/ELF/Mach-O 专用 tab 或子面板 |
| **前端层** | 缺少工具模块组件 | 新增 StringSearch/Extractor/Visualization 等组件 |
| **前端层** | Settings 需扩展为模态对话框 | 重构 Settings 为 Modal + 分页 |

---

## 4. 限制

- 上游 `die` 未在本地运行，上游 GUI 展示基于源码静态分析推断。
- FormatWidgets/XFileInfo/XArchive 等 submodule 未在本地检出，分析依据
  GitHub raw 文件获取的 `.h` 头文件。
- die-gui 前端组件的渲染细节基于源码阅读，未做视觉截图对比。
- 上游 GUI 的确切渲染效果（颜色、字体、布局细节）未做像素级对比。
- Phase 9 修复项基于 ROADMAP.md 记录和源码审查确认，未重新运行差分测试。
