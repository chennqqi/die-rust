# 需求分析 005 — GUI 与上游深度对齐

日期：2026-08-08

## 用户需求

Phase 9 完成了 GUI 上游对齐增强，但人工实际使用发现差距仍很大（约 30% 对齐度）：
1. 相同模块展示的数据不一样
2. 很多功能模块还没有实现

要求：再次深入总结差距，制定计划，一个 phase 中多拆分几个任务，用户实际体验最重要。

## 分析过程

### 1. 已有文档审查

- `docs/research/upstream-gui-analysis.md`：上游 GUI 源码结构分析（Phase 8 前编写）
- `docs/research/gui-upstream-diff.md`：Phase 8 后差距分析（v0.4.0 基线）
- `docs/design/phase8-gui.md`：Phase 8 设计文档
- ROADMAP.md Phase 9 记录：P1/P2/P3 共 20 项修复已完成

### 2. Phase 9 已修复项确认

通过审查 App.tsx、commands.rs、各组件源码，确认 Phase 9 已修复：
- ScanDetection 扩展字段（id/parentId/file_part/offset/size/is_heuristic 等）
- 数据库选择接线、文件类型覆盖接线
- options 直接显示（不再显示计数）
- 启发式标记 (Heur)/(A-Heur)
- 嵌套结果树（基于 id/parentId）
- Hex viewer 虚拟滚动 + 搜索 + 跳转 + 复制
- Disassembler 移除 break-on-Ret + 多架构支持
- Hex 数据检查器 + Follow in Disasm/Hex 双向联动
- Disasm 交叉引用 + Analyze All
- PE imports 提取
- Mach-O FAT 支持
- 结构化诊断信息
- Profiling 数据
- 符号表虚拟滚动
- 扫描进度事件
- CRC32 哈希
- 熵块大小可配置

### 3. 仍存在的差距（核心发现）

通过对比上游 FormatsWidget.h（45 个功能按钮）、XFileInfo.h（完整头部解析）、
.gitmodules（57 个 submodule），识别出以下仍存在的差距：

#### A. 相同模块展示数据不一样

| 模块 | 上游展示 | die-gui 展示 | 差距 |
| --- | --- | --- | --- |
| FileInfo | 完整 PE/ELF/Mach-O/DEX 头部字段树（DOS Header、NT Headers、Section Header 含 Characteristics 标志解析、Resource Directory、Export Directory、Import Directory、Rich Header、TLS、.NET metadata、Manifest、Version Info、Entry Point） | 基本信息 + sections（name/vaddr/vsize/rawoff/rawsize/entropy）+ symbols | **缺少 80% 的头部字段** |
| PE 解析 | XPE 完整解析（imports/resources/.NET/rich header/TLS/manifest/version info） | goblin 基础解析（sections + exports + imports） | 缺少 resources/.NET/rich header/TLS/manifest/version info |
| ELF 解析 | XELF 完整（Ehdr/Phdr/Shdr/Sym/Dynamic/Relocations） | goblin 基础（sections + symbols） | 缺少 Phdr/Dynamic/Relocations |
| Mach-O 解析 | XMACH 完整（header/load commands/segments/sections/symbols/libraries） | goblin 基础（segments/sections/symbols） | 缺少 load commands/libraries 完整字段 |
| 文件格式检测 | XFormats 50+ 类型 | 手写 magic bytes 约 6 种 | **大量格式不识别** |
| 归档解析 | XArchive 20+ 格式 | zip crate 仅 ZIP | **仅支持 ZIP** |
| 哈希 | 8+ 种（MD5/SHA1/SHA256/SHA224/384/512/CRC32/CRC64/SSDeep/TLSH） | 4 种（MD5/SHA1/SHA256/CRC32） | 缺少 SSDeep/TLSH/SHA224/384/512 |

#### B. 未实现的功能模块

上游 FormatsWidget 有 45 个功能按钮，die-gui 仅实现约 12 个 tab，且部分为简化版：

| 上游功能 | 上游模块 | die-gui 状态 |
| --- | --- | --- |
| 完整文件信息树 | XFileInfo + XFileInfoModel | **缺失**（仅有简化 FileInfoPanel） |
| PE 专用视图 | DialogPE | **缺失** |
| PE Export 目录 | PEExport button | **缺失** |
| PE Import 目录 | PEImport button | **缺失**（FileInfoPanel 有基础 imports） |
| PE Resource 目录 | PEResources button | **缺失** |
| PE .NET metadata | PENET button | **缺失** |
| PE Manifest | PEManifest button | **缺失** |
| PE Version Info | PEVersion button | **缺失** |
| PE TLS | PETLS button | **缺失** |
| PE Overlay | PEOverlay button | **缺失** |
| ELF 专用视图 | DialogELF | **缺失** |
| ELF Program Headers | ELFPrograms button | **缺失** |
| Mach-O 专用视图 | DialogMACH | **缺失** |
| Mach-O Load Commands | MACHCommands button | **缺失** |
| Mach-O Libraries | MACHLibraries button | **缺失** |
| DEX 专用视图 | DialogDEX | **缺失** |
| 区段视图 | XRegionsWidget | **缺失** |
| 可视化视图 | XVisualizationWidget | **缺失** |
| 提取器 | XExtractorWidget | **缺失** |
| MIME 类型 | XMIMEWidget | **缺失** |
| 字符串搜索 | DialogSearchStrings | **缺失** |
| 签名搜索 | DialogSearchSignatures | **缺失** |
| NFD 视图 | nfd_widget | **缺失** |
| InfoDB | XInfoDB | **缺失** |
| 静态脱壳 | XStaticUnpacker | **缺失** |
| VirusTotal | DialogXVirusTotal | **缺失**（OnlineTools 仅有链接） |
| 快捷键配置 | DialogShortcuts | **缺失** |
| 样式选择 | DialogSelectStyle | **缺失** |
| About 对话框 | DialogAbout | **简化** |

### 4. 差距根因分析

1. **FileInfoPanel 架构限制**：当前 FileInfoPanel 是一个简化的平铺信息面板，
   上游 XFileInfo 是一个递归树形模型（XFileInfoModel），每个头部字段都是树节点，
   包含字段名、值、注释、标志位解析。需要完全重构为树形结构。

2. **格式解析库限制**：die-gui 使用 goblin 做通用解析，但 goblin 不提供
   XPE/XELF/XMACH 那样的完整字段级解析。需要使用 pelite（PE）和更深入的
   goblin/elf 扩展来获取完整字段。

3. **FormatWidgets 未集成**：上游 die 的核心是 FormatsWidget，它根据文件类型
   动态显示不同的格式专用视图（DialogPE/DialogELF/DialogMACH 等）。
   die-gui 没有这个架构，所有文件类型共用同一套 tab。

4. **归档库限制**：仅使用 zip crate，上游 XArchive 支持 20+ 格式。
   需要引入 tar/rar/7z 等库或使用七零归档库。

### 5. 优先级评估

按用户影响排序：

**P0（用户一打开就能发现的差距）**：
- FileInfo 缺少完整 PE/ELF/Mach-O 头部字段 → 最明显的差距
- 文件格式检测仅 6 种 vs 上游 50+ → 打开非 PE/ELF/Mach-O 文件时 FileInfo 显示 Unknown

**P1（用户使用常见功能时发现）**：
- PE Import/Export/Resource 目录无独立视图
- 归档仅支持 ZIP
- 字符串搜索/签名搜索缺失
- 提取器缺失

**P2（高级用户发现的差距）**：
- 可视化视图/区段视图/MIME 视图缺失
- .NET/Manifest/Version Info/TLS/Rich Header 缺失
- 快捷键配置/样式选择缺失
- VirusTotal 集成缺失

**P3（可延后）**：
- NFD/InfoDB/静态脱壳/DEX 专用视图
- SSDeep/TLSH 哈希
- 多语言扩展到 22 种

## 结论

Phase 9 修复了信息展示格式和基础功能缺陷，但**架构层面的差距**未解决：
1. FileInfoPanel 需要从平铺面板重构为树形头部解析器
2. 需要引入格式专用视图（PE/ELF/Mach-O 各自的详细视图）
3. 需要扩展格式检测和归档支持的范围
4. 需要补充缺失的工具模块（字符串搜索、提取器、可视化等）

建议创建 Phase 11，分 6-8 个任务批次逐步实现，每个批次聚焦一个主题领域。
