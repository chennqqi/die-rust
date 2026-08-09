# GUI 对齐差距分析 v3 — 基于上游源码实际审查

> 生成日期：2026-08-08
> 基线：上游 DIE-engine master + die_widget + FormatWidgets + XOnlineTools + XVisualizationWidget + XExtractorWidget
> 方法：直接 clone 上游仓库源码，逐文件审查

## 一、上游 GUI 架构总览

### 1.1 主窗口（GuiMainWindow）

上游主窗口极简，核心组件：
- **lineEditFileName**：文件路径输入框（支持回车打开、拖放）
- **checkBoxAdvanced**：高级模式开关
- **widgetFormats**：FormatsWidget（核心，所有功能都在这里）
- **工具栏按钮**：OpenFile / Options / Shortcuts / Demangle / About / Exit / RecentFiles

**关键行为**：
- 高级模式（Advanced）控制 `groupBoxTools`、`stackedWidgetMain`、`groupBoxBaseAddress`、`groupBoxEntryPoint` 的显示
- Demangle 按钮仅在高级模式下显示
- 拖放文件直接打开
- 命令行参数 `argv[1]` 直接作为文件名打开

### 1.2 FormatsWidget 布局

FormatsWidget 是上游 GUI 的核心，分为以下区域：

#### 顶部信息栏（始终显示）
| 字段 | 说明 |
|------|------|
| comboBoxFileType | 文件类型下拉框（可选择不同类型重新解析） |
| lineEditFileSize | 文件大小 |
| lineEditType | 类型字符串 |
| lineEditArch | 架构 |
| lineEditMode | 模式（8/16/32/64位） |
| lineEditEndianness | 字节序 |
| lineEditBaseAddress | 基地址 |
| lineEditEntryPoint | 入口点 |
| comboBoxScanEngine | 扫描引擎选择（DIE/NFD/YARA/PEiD） |

#### 格式专用信息区（stackedWidgetMain，根据文件类型切换）
- **TABINFO_BINARY**：通用二进制
- **TABINFO_ARCHIVE**：归档（含 MANIFEST.MF / AndroidManifest 按钮）
- **TABINFO_COM**：COM 文件
- **TABINFO_DEX**：DEX 文件
- **TABINFO_NE**：NE 文件
- **TABINFO_LE**：LE/LX 文件
- **TABINFO_MSDOS**：MSDOS 文件（含 Overlay 按钮）
- **TABINFO_PE**：PE 文件（含 Sections/Export/Import/Resources/NET/TLS/Manifest/Version/Overlay/TimeDateStamp/SizeOfImage）
- **TABINFO_ELF**：ELF 文件（含 Programs/Sections 计数）
- **TABINFO_MACH**：Mach-O 文件（含 Commands/Sections/Segments/Libraries 计数）

#### 工具栏（groupBoxTools，仅高级模式显示）
| 按钮 | 功能 | 对应 Dialog |
|------|------|------------|
| EntryPoint | 跳转到入口点（Hex 或 Disasm） | 格式专用 Dialog |
| MemoryMap | 内存映射视图 | DialogMemoryMap |
| Search | 搜索（签名/字符串/值） | DialogSearchSignatures |
| FileInfo | 文件信息树 | DialogXFileInfo |
| VirusTotal | VirusTotal 查杀 | DialogXVirusTotal 或浏览器跳转 |
| Strings | 字符串搜索 | DialogSearchStrings |
| Hash | 哈希计算 | DialogHash |
| Disasm | 反汇编 | DialogMultiDisasm |
| Entropy | 熵视图 | DialogEntropy |
| Extractor | 提取器 | DialogXExtractor |
| Signatures | DIE 签名浏览器 | DialogDIESignatures |
| MIME | MIME 类型 | DialogMIME |
| YARA | YARA 扫描 | YARA_Widget |
| Hex | Hex 查看器 | DialogHexView |
| Visualization | 可视化视图 | DialogVisualization |
| Files | 归档文件列表 | DialogArchive |
| Unpack | 静态脱壳 | DialogUnpackFile |

#### 扫描结果区（stackedWidgetScan）
- **pageScanDIE**：DIE_Widget（DIE 引擎扫描结果）
- **pageScanNFD**：NFD_Widget（NFD 引擎扫描结果）
- **pageScanYARA**：YARA_Widget（YARA 引擎扫描结果）
- **pageScanPEID**：PEID_Widget（PEiD 引擎扫描结果）

### 1.3 格式专用 Dialog 结构

每个格式专用 Dialog（如 DialogPE）内部是一个带导航树的窗口：
- 左侧：treeWidgetNavi（导航树，列出所有子视图）
- 右侧：对应的 tableWidget / tableView / textEdit

**PE Dialog 子视图（SPE::TYPE，共 44 项）**：
1. INFO — 文件总览
2. VISUALIZATION — 可视化
3. VIRUSTOTAL — VirusTotal
4. HEX — Hex 查看
5. DISASM — 反汇编
6. HASH — 哈希
7. STRINGS — 字符串
8. SIGNATURES — 签名
9. MEMORYMAP — 内存映射
10. ENTROPY — 熵
11. NFDSCAN — NFD 扫描
12. EXTRACTOR — 提取器
13. SEARCH — 搜索
14. DIESCAN — DIE 扫描
15. YARASCAN — YARA 扫描
16. TOOLS — PE 工具（DosStub 添加/移除/Dump，Overlay 添加/移除/Dump）
17. IMAGE_DOS_HEADER — DOS 头（31 个字段）
18. DOS_STUB — DOS Stub
19. IMAGE_NT_HEADERS — NT 头
20. IMAGE_FILE_HEADER — 文件头（7 个字段）
21. IMAGE_OPTIONAL_HEADER — 可选头（31 个字段，32/64 位不同）
22. IMAGE_DIRECTORY_ENTRIES — 数据目录条目（16 个目录）
23. RICH — Rich Header
24. SECTIONS — 节区表
25. SECTIONS_INFO — 节区信息（熵/大小等统计）
26. EXPORT — 导出表
27. IMPORT — 导入表
28. IMPORT_INFO — 导入信息
29. RESOURCES — 资源树
30. RESOURCES_STRINGTABLE — 资源字符串表
31. RESOURCES_VERSION — 版本信息
32. RESOURCES_MANIFEST — Manifest
33. EXCEPTION — 异常表
34. RELOCS — 重定位表
35. DEBUG — 调试信息
36. TLS — TLS 目录
37. TLSCALLBACKS — TLS 回调
38. LOADCONFIG — 加载配置（50+ 字段）
39. BOUNDIMPORT — 绑定导入
40. DELAYIMPORT — 延迟导入
41. NETHEADER — .NET 头
42. NET_METADATA — .NET 元数据
43. NET_METADATA_STREAM — .NET 元数据流
44. NET_METADATA_TABLE — .NET 元数据表
45. CERTIFICATE — 证书
46. OVERLAY — Overlay

**ELF Dialog 子视图（SELF::TYPE，共 25 项）**：
1-15. 同 PE 的通用视图（INFO/VISUALIZATION/VIRUSTOTAL/HEX/DISASM/HASH/STRINGS/SIGNATURES/MEMORYMAP/ENTROPY/NFDSCAN/EXTRACTOR/SEARCH/DIESCAN/YARASCAN）
16. Elf_Ehdr — ELF 头
17. Elf_Shdr — 节区头
18. Elf_Phdr — 程序头
19. Elf_DynamicArrayTags — 动态标签
20. LIBRARIES — 库
21. INTERPRETER — 解释器
22. NOTES — 注释
23. RUNPATH — 运行路径
24. STRINGTABLE — 字符串表
25. SYMBOLTABLE — 符号表
26. Elf_Rela — 重定位（Rela）
27. Elf_Rel — 重定位（Rel）

**Mach-O Dialog 子视图（SMACH::TYPE，共 45+ 项）**：
1-15. 同 PE 的通用视图
16. mach_header — Mach-O 头
17. mach_commands — Load Commands
18. mach_segments — 段
19. mach_sections — 节
20. mach_libraries — 库
21. mach_weak_libraries — 弱库
22. mach_id_library — ID 库
23. mach_LOADFVMLIB — FVMLIB
24. mach_IDFVMLIB — IDFVMLIB
25. mach_dyld_info_only — Dyld Info
26. mach_uuid — UUID
27. mach_symtab — 符号表
28. mach_dysymtab — 动态符号表
29. mach_version_min — 版本最小值
30. mach_build_version — 构建版本
31. mach_dylinker — Dylinker
32. mach_rpath — RPath
33. mach_source_version — 源版本
34. mach_encryption_info — 加密信息
35. mach_function_starts — 函数起始
36. mach_data_in_code — 代码中的数据
37. mach_code_signature — 代码签名
38. mach_SuperBlob — SuperBlob
39. mach_main — Main
40. mach_unix_thread — Unix Thread（多种架构）
41. mach_dyld_chained_fixups — Dyld 链式修复
42. mach_dyld_exports_trie — Dyld 导出 Trie
43. STRINGTABLE — 字符串表

## 二、VirusTotal 实现详解（基于源码）

### 2.1 入口逻辑（formatswidget.cpp:1133-1152）

```cpp
void FormatsWidget::on_toolButtonVirusTotal_clicked()
{
    if (getGlobalOptions()->getVirusTotalApiKey() != "") {
        // 有 API key → 打开完整 VT Dialog（显示扫描结果表格）
        showType(SBINARY::TYPE_VIRUSTOTAL);
    } else {
        // 无 API key → 用 MD5 打开浏览器跳转
        QString sMD5 = XBinary::getHash(XBinary::HASH_MD5, &file);
        XVirusTotalWidget::showInBrowser(sMD5);
    }
}
```

### 2.2 浏览器跳转（xvirustotalwidget.cpp:245-248）

```cpp
bool XVirusTotalWidget::showInBrowser(const QString &sHash)
{
    return QDesktopServices::openUrl(QUrl(XVirusTotal::getFileLink(sHash)));
}
```

### 2.3 URL 模板（xvirustotal.cpp:146-149）

```cpp
QString XVirusTotal::getFileLink(const QString &sHash)
{
    return QString("https://www.virustotal.com/gui/file/" + sHash);
}
```

### 2.4 API 查询模式（xvirustotalwidget.cpp:51-132）

有 API key 时：
1. 计算文件 MD5（`XBinary::getHash(XBinary::HASH_MD5, pDevice)`）
2. 调用 `GET /api/v3/files/{md5}` 获取文件信息
3. 如果文件不存在（404），提示 "Upload the file for analyze?"
4. 如果用户确认上传，调用 `POST /api/v3/files` 上传文件
5. 轮询 `GET /api/v3/analyses/{id}` 直到 status == "completed"
6. 显示扫描结果表格（Scan/Version/Date/Result 四列）
7. 显示首次扫描时间和最后扫描时间
8. 支持 "Show detects" 复选框（仅显示检测到的）
9. 支持 "Rescan" 按钮（重新扫描）
10. 支持 "Save" 按钮（保存结果到文件）
11. 支持 "Website" 按钮（打开浏览器）

### 2.5 当前 die-gui 实现的问题

| 问题 | 上游行为 | 当前实现 |
|------|---------|---------|
| **Hash 类型** | MD5 | SHA256 ❌ |
| **无 API key 行为** | 浏览器跳转用 MD5 | 浏览器跳转用 SHA256 ❌ |
| **有 API key 模式** | 完整 VT Dialog（API 查询+结果表格） | 未实现 ❌ |
| **API key 配置** | XOptions::ID_ONLINETOOLS_VIRUSTOTAL_APIKEY | 未实现 ❌ |
| **上传提示** | "Upload the file for analyze?" | 未实现 ❌ |

## 三、字符串搜索实现详解（基于源码）

### 3.1 SearchStringsWidget 选项（searchstringswidget.h:48-62）

```cpp
struct OPTIONS {
    qint64 nBaseAddress;
    bool bAnsi;        // ANSI 字符串
    bool bUnicode;     // Unicode（UTF-16LE）字符串
    bool bNullTerminated;  // 仅空终止符字符串
    qint32 nMinLenght;     // 最小长度（默认 5，最小 2）
    bool bLinks;           // 仅链接（URL/文件路径）
    QString sMask;         // 过滤掩码
    bool bMenu_Hex;        // 右键菜单：跳转到 Hex
    bool bMenu_Disasm;     // 右键菜单：跳转到 Disasm
    bool bMenu_Demangle;   // 右键菜单：Demangle
    QString sTitle;
};
```

### 3.2 UI 控件

| 控件 | 说明 |
|------|------|
| checkBoxAnsi | ANSI 字符串开关 |
| checkBoxUnicode | Unicode 字符串开关 |
| checkBoxNullTerminated | 空终止符字符串开关 |
| checkBoxLinks | 仅链接开关 |
| checkBoxRegExp | 正则表达式开关 |
| spinBoxMinLength | 最小长度（2-∞，默认 5） |
| lineEditMask | 过滤掩码 |
| comboBoxType | 文件类型选择 |
| comboBoxMapMode | 映射模式选择 |
| tableViewResult | 结果表格（Number/Offset/Size/Type/Value 五列） |
| toolButtonSearch | 搜索按钮 |
| toolButtonSave | 保存结果 |

### 3.3 搜索逻辑（searchstringswidget.cpp:311-378）

1. 读取 UI 选项
2. 根据 comboBoxType 和 comboBoxMapMode 获取内存映射
3. 调用 `MultiSearch::setSearchData` 执行搜索（在后台线程）
4. 使用 `XModel_MSRecord` 显示结果
5. 结果列：Number / Offset / Size / Type / Value
6. 右键菜单：Copy Row / Follow in Hex / Follow in Disasm / Demangle / Edit String

### 3.4 当前 die-gui 实现的差距

| 功能 | 上游 | 当前 |
|------|------|------|
| ANSI | ✅ | ✅ |
| Unicode (UTF-16LE) | ✅ | ✅ |
| Null-terminated | ✅ | ❌ |
| Links 过滤 | ✅ | ❌ |
| 正则表达式 | ✅ | ❌ |
| MapMode 选择 | ✅ | ❌ |
| 文件类型选择 | ✅ | ❌ |
| 跳转到 Hex | ✅ | ❌ |
| 跳转到 Disasm | ✅ | ❌ |
| Demangle | ✅ | ❌ |
| 编辑字符串 | ✅ | ❌ |
| 保存结果 | ✅ | ❌ |
| 最小长度默认值 | 5 | 4 ❌ |

## 四、可视化视图实现详解（基于源码）

### 4.1 XVisualizationWidget 功能

将文件内容可视化为二维色块图：
- 文件按 block 分块（可配置 block size）
- 每个 block 计算多个指标值（熵/梯度/零字节/文本等）
- 用颜色深浅表示指标值
- 支持区域着色（sections/segments 等用不同颜色标记）
- 支持高亮区域

### 4.2 数据方法（DATAMETHOD）

| 方法 | 说明 |
|------|------|
| NONE | 无 |
| ENTROPY | 熵值 |
| GRADIENT | 梯度（字节变化率） |
| ZEROS | 零字节比例 |
| ZEROS_GRADIENT | 零字节梯度 |
| TEXT | 文本比例 |
| TEXT_GRADIENT | 文本梯度 |

### 4.3 UI 控件

| 控件 | 说明 |
|------|------|
| comboBoxType | 文件类型 |
| comboBoxMapMode | 映射模式 |
| comboBoxMethod | 数据方法（熵/梯度/零字节/文本等） |
| spinBoxBlockSize | 块大小 |
| horizontalSliderZoom | 缩放 |
| listWidgetRegions | 区域列表（可勾选显示/隐藏） |
| listWidgetHighlights | 高亮列表 |
| toolButtonVisualizationSave | 保存图片 |
| toolButtonVisualizationReload | 重新加载 |

### 4.4 当前 die-gui 实现的差距

当前 `SectionVisualizer.tsx` 仅显示节区熵值条形图，与上游的可视化视图完全不同：
- ❌ 缺少二维色块图
- ❌ 缺少多种数据方法（熵/梯度/零字节/文本）
- ❌ 缺少区域着色
- ❌ 缺少高亮功能
- ❌ 缺少缩放
- ❌ 缺少保存图片

## 五、提取器实现详解（基于源码）

### 5.1 XExtractorWidget 功能

从文件中提取嵌入的对象：
- **RAW 模式**：扫描文件中的已知文件头 magic
- **FORMAT 模式**：根据文件格式解析提取（overlay/resource/section）
- **HEURISTIC 模式**：启发式扫描

### 5.2 提取选项

```cpp
struct OPTIONS {
    XBinary::FT fileType;
    QList<XBinary::FT> listFileTypes;
    bool bAllTypes;     // 使用所有文件类型
    qint32 nLimit;       // 结果限制
    bool bDeepScan;      // 深度扫描
    EMODE emode;         // RAW/FORMAT/HEURISTIC
    bool bAnalyze;       // 分析
    bool bExtract;       // 提取
    bool bMenu_Hex;      // 右键菜单 Hex
    QString sOutputDirectory;
    bool bShowList;
    qint64 nBufferSize;
};
```

### 5.3 当前 die-gui 实现的差距

当前完全未实现提取器功能。

## 六、当前 die-gui 与上游的完整差距清单

### 6.1 主窗口级别

| 功能 | 上游 | 当前 | 优先级 |
|------|------|------|--------|
| 文件路径输入框 | ✅ | ✅ | - |
| 拖放打开文件 | ✅ | ❌ | P2 |
| Advanced 模式开关 | ✅ | ❌ | P2 |
| Demangle 工具按钮 | ✅ | ✅（tab） | - |
| Recent files 菜单 | ✅ | ✅ | - |
| 命令行参数打开 | ✅ | ❌ | P3 |

### 6.2 FormatsWidget 级别

| 功能 | 上游 | 当前 | 优先级 |
|------|------|------|--------|
| 文件类型下拉框 | ✅ | ❌ | P2 |
| 扫描引擎切换 | ✅ (DIE/NFD/YARA/PEiD) | 部分（tab 切换） | P2 |
| 文件大小显示 | ✅ | ✅ | - |
| 类型/架构/模式/字节序 | ✅ | ✅ | - |
| 基地址显示 | ✅ | ❌ | P2 |
| 入口点显示 | ✅ | ❌ | P2 |
| PE 节区数/导出/导入/资源等计数 | ✅ | ❌ | P2 |
| ELF 程序头/节区数 | ✅ | ❌ | P2 |
| Mach-O 命令/节/段/库数 | ✅ | ❌ | P2 |

### 6.3 格式专用视图

| 格式 | 上游子视图数 | 当前实现 | 缺失 |
|------|------------|---------|------|
| **PE** | 46 | 8（导入/导出/资源/.NET/manifest/version/TLS/Rich） | DOS Stub/Directory Entries/Relocs/Debug/Exceptions/LoadConfig/BoundImport/DelayImport/Certificate/Sections Info/Import Info/NET Metadata 等 |
| **ELF** | 25 | 0（仅头部树） | Ehdr/Shdr/Phdr/Dynamic/Libraries/Interpreter/Notes/Runpath/StringTable/SymbolTable/Rela/Rel |
| **Mach-O** | 45+ | 0（仅头部树） | header/commands/segments/sections/libraries/weak_libraries/dyld_info/uuid/symtab/dysymtab/version_min/build_version/dylinker/rpath/source_version/encryption_info/function_starts/data_in_code/code_signature 等 |
| **DEX** | 有 | 0 | 全部 |
| **MSDOS** | 有 | 0 | 全部 |
| **NE/LE** | 有 | 0 | 全部 |

### 6.4 通用工具视图

| 工具 | 上游 | 当前 | 优先级 |
|------|------|------|--------|
| Hex 查看器 | ✅ | ✅ | - |
| 反汇编 | ✅ | ✅ | - |
| 字符串搜索 | ✅（完整） | 部分（缺 Null-terminated/Links/RegExp/MapMode） | P2 |
| 哈希计算 | ✅ | ✅（在 FileInfo 中） | - |
| 熵视图 | ✅（独立 Dialog） | ✅（在 FileInfo 中） | - |
| 内存映射 | ✅ | ✅ | - |
| 文件信息树 | ✅ | ✅ | - |
| MIME 类型 | ✅ | ✅（在 FileInfo 中） | - |
| 可视化视图 | ✅（二维色块图） | 部分（仅节区条形图） | P2 |
| 提取器 | ✅ | ❌ | P2 |
| 签名搜索 | ✅ | ❌ | P3 |
| 值搜索 | ✅ | ❌ | P3 |
| VirusTotal | ✅（MD5+API key 模式） | ❌（SHA256+仅跳转） | P1 |
| YARA 扫描 | ✅ | ✅ | - |
| PEiD 扫描 | ✅ | ✅ | - |
| DIE 签名浏览器 | ✅ | ✅ | - |
| 静态脱壳 | ✅ | ❌ | P3 |
| 归档文件列表 | ✅ | ✅ | - |
| Demangle | ✅ | ✅ | - |

### 6.5 PE 专用视图详细差距

当前 `PeViewPanel.tsx` 实现的子视图：
- ✅ 导入表（Import）
- ✅ 导出表（Export）
- ✅ 资源树（Resources）
- ✅ .NET 信息（NET Header）
- ✅ Manifest
- ✅ 版本信息（Version Info）
- ✅ TLS 回调
- ✅ Rich Header
- ✅ Overlay（偏移和大小）

缺失的 PE 子视图：
- ❌ IMAGE_DOS_HEADER（31 字段详细表）
- ❌ DOS_STUB
- ❌ IMAGE_NT_HEADERS
- ❌ IMAGE_FILE_HEADER（7 字段详细表）
- ❌ IMAGE_OPTIONAL_HEADER（31 字段详细表，32/64 位不同）
- ❌ IMAGE_DIRECTORY_ENTRIES（16 个数据目录）
- ❌ SECTIONS（节区表详细视图，含 Characteristics 标志解析）
- ❌ SECTIONS_INFO（节区统计信息）
- ❌ IMPORT_INFO（导入信息汇总）
- ❌ RESOURCES_STRINGTABLE（资源字符串表）
- ❌ EXCEPTION（异常表）
- ❌ RELOCS（重定位表）
- ❌ DEBUG（调试信息）
- ❌ LOADCONFIG（加载配置，50+ 字段）
- ❌ BOUNDIMPORT（绑定导入）
- ❌ DELAYIMPORT（延迟导入）
- ❌ NET_METADATA（.NET 元数据）
- ❌ NET_METADATA_STREAM
- ❌ NET_METADATA_TABLE
- ❌ CERTIFICATE（证书）
- ❌ TOOLS（PE 工具：DosStub/Overlay 添加/移除/Dump）

### 6.6 扫描结果展示差距

| 功能 | 上游 | 当前 |
|------|------|------|
| 检测结果树 | ✅（ScanItemModel，3列：String/Signature/Info） | ✅（检测树） |
| 复制结果 | ✅ | ✅ |
| 跳转到 Hex | ✅ | ✅ |
| 跳转到 Disasm | ✅ | ✅ |
| 查看签名源码 | ✅ | ✅ |
| 扫描目录 | ✅（DialogDIEScanDirectory） | ✅ |
| 签名 profiling | ✅（DialogDIESignaturesElapsed） | ❌ |
| 额外信息 | ✅（pushButtonDieExtraInformation） | ❌ |
| 扫描日志 | ✅（pushButtonDieLog） | ❌ |

## 七、修复计划

### P0 — 立即修复（用户已发现的问题）

1. **VirusTotal 修复**：
   - 将 hash 类型从 SHA256 改为 MD5
   - 添加 API key 配置项到 Settings
   - 有 API key 时：打开 VT Dialog（API 查询+结果表格）
   - 无 API key 时：浏览器跳转用 MD5

### P1 — 核心功能补全

2. **ELF 专用视图**：实现 Ehdr/Shdr/Phdr/Dynamic/Libraries/Symbols/Relocations
3. **Mach-O 专用视图**：实现 header/commands/segments/sections/libraries
4. **PE 头部详细视图**：实现 DOS/File/Optional Header 字段表

### P2 — 重要功能补全

5. **可视化视图**：实现二维色块图（熵/梯度/零字节/文本方法）
6. **提取器**：实现 RAW/FORMAT 模式提取
7. **字符串搜索增强**：Null-terminated/Links/RegExp/MapMode
8. **FormatsWidget 信息栏**：基地址/入口点/节区数等计数显示
9. **拖放打开文件**

### P3 — 扩展功能

10. **签名搜索**（DialogSearchSignatures）
11. **值搜索**（DialogSearchValues）
12. **静态脱壳**（DialogUnpackFile）
13. **DEX/MSDOS/NE/LE 专用视图**
14. **扫描日志和额外信息**
15. **签名 profiling**

## 八、上游源码位置参考

| 组件 | 仓库 | 关键文件 |
|------|------|---------|
| 主窗口 | DIE-engine/gui_source | guimainwindow.cpp/h/ui |
| FormatsWidget | FormatWidgets | formatswidget.cpp/h/ui |
| PE Widget | FormatWidgets/PE | pewidget.cpp/h/ui, pe_defs.h |
| ELF Widget | FormatWidgets/ELF | elfwidget.cpp/h/ui, elf_defs.h |
| Mach-O Widget | FormatWidgets/MACH | machwidget.cpp/h/ui, mach_defs.h |
| 字符串搜索 | FormatWidgets/SearchStrings | searchstringswidget.cpp/h/ui |
| VirusTotal | XOnlineTools | xvirustotal.cpp/h, xvirustotalwidget.cpp/h/ui |
| 可视化 | XVisualizationWidget | xvisualization.cpp/h, xvisualizationwidget.cpp/h/ui |
| 提取器 | XExtractorWidget | xextractorwidget.cpp/h/ui |
| DIE Widget | die_widget | die_widget.cpp/h/ui |

## v3 剩余 35 项实施完成状态 (2026-08-09)

全部 35 项已实施完成，597 个测试通过。
