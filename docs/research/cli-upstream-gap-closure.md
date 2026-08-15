# diec CLI 上游对齐差距分析

Status: Draft

Upstream: `horsicq/DIE-engine@74eaf505c250ab47e709024e9dc41657cd8f2254`

Last updated: 2026-08-15

## 1. 目的

本文档汇总 diec CLI 与上游 DIE-engine release `diec` 的全部可观察行为差距，
为 ROADMAP Phase 13 提供证据基础。每项差距附上游源码位置、固定版本文档和
diec-rust 现有基础设施评估。

差距分为两类：
- **diec 自身实现缺口**（G1-G4）：diec 引擎或 CLI 未实现上游已有能力。
- **测试覆盖缺口**（G5-G6）：diec 功能已对齐但测试基础设施不完整。

## 2. 已对齐能力（无缺口）

以下维度经差分测试和源码审计确认与上游完全对齐，不列入 Phase 13 范围：

| 维度 | 证据来源 | 结论 |
| --- | --- | --- |
| 规则加载 | `COMPATIBILITY.md` § Rule Loading | 1186/1186 = 100% |
| 差分测试 | `COMPATIBILITY.md` § Corpus Differential | 31 基线 + 20 边缘，0 引擎不匹配 |
| CLI 扫描控制选项 | `COMPATIBILITY.md` § CLI Compatibility | 14+ 选项全部 ✅ |
| 输出格式 | `COMPATIBILITY.md` § CLI Compatibility | text/json/xml/csv/tsv/plaintext |
| Host API | `COMPATIBILITY.md` § Host API Compatibility | PE/ELF/Mach-O 全部原生解析 |
| C ABI + 语言绑定 | `COMPATIBILITY.md` § C ABI Compatibility | Go/cgo + Python ctypes + C smoke |
| 性能 | `COMPATIBILITY.md` § Performance Baseline | database_load ~510ms |
| 能力矩阵 | `capability-matrix.md` | 68 个 CAP-* 在 Linux Qt5/Qt6 + Windows 全部 Observed |

4 个差分不匹配全部是规则版本差异（submodule 规则比上游 3.21 bundled 更新），
非引擎 bug，不列入 Phase 13 范围。

## 3. diec 自身实现缺口

### G1: `--struct <value>` 模式未实现（CAP-CLI-MODE-003）

**上游行为**（`cli-special-modes.md` § Struct 选择语义）：

上游 `diec -S <value>` / `--struct <value>` 调用 `XFileInfo::processFile()`
输出特定结构信息。模式优先级为 `--entropy > --struct > --info > normal scan`。

通用方法（4 个，`--showstructs` 输出清单）：

| 方法 | 子方法 | 说明 |
| --- | --- | --- |
| `Hash` | MD4, MD5, SHA1, SHA224, SHA256, SHA384, SHA512 | 返回所有哈希值 |
| `Info` | — | 文件信息（文件名、大小、类型、MIME 等） |
| `Entropy` | — | 分区/区域 Shannon 熵 |
| `Check format` | — | 格式检查 |

格式专用方法（依文件类型动态选择）：

| 格式 | 方法 |
| --- | --- |
| PE32 | `Entry point`, `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`, `IMAGE_SECTION_HEADER`, `IMAGE_RESOURCE_DIRECTORY`, `IMAGE_EXPORT_DIRECTORY` |
| ELF64 | `Entry point`, `Elf_Ehdr` |
| Mach-O 64 | `Entry point`, `Header` |
| DEX | `Header` |

过滤语义：
- `#` 分隔层级过滤，大小写不敏感（`hAsH#mD5` 与 `Hash#MD5` 相同）
- candidate 已没有更多 section 时，额外 section 被当作 wildcard
  （`Hash#MD5#Ignored` 仍返回 MD5）
- `Hash##MD5` 保留空 `Hash` parent；`NoSuch#MD5` 返回空 `data`
- `--struct ""` 退回普通 scan
- 未知方法不报错，JSON 为 `{"data": ""}`，退出码 0
- 空文件 `Hash#MD5` 返回空字符串（非标准空输入 MD5）

输出格式优先级（专用模式）：`JSON > XML > CSV > TSV > formatted/plain text`。
JSON 顶层对象 `data`，叶子值全部序列化为 string。多目标 framing 按输入顺序
先打印 `<filename>:\n`，随后串接独立 JSON object。

**diec 现状**：

`crates/diec-cli/src/main.rs` 第 200-202 行只有 `--showstructs`/`--showmethods`
处理（列出方法名），无 `--struct <value>` 分支。`--showstructs` 输出格式特定
方法列表（如 `ELF.isSignaturePresent`），与上游 4 个通用方法清单不一致。

`crates/diec-core/src/request.rs` 已定义 `ScanMode::Struct(StructSelector)` 和
`StructSelector { raw: String }`，但未实现解析逻辑。

**可复用基础设施**：

| 组件 | 位置 | 状态 |
| --- | --- | --- |
| Hash 计算（MD5/SHA1/SHA256/CRC32） | `crates/die-gui/src/file_info.rs` | 已实现，可复用 |
| Entropy 计算 | `crates/diec-cli/src/main.rs:93-110` | 已实现，可复用 |
| PE 原生解析 | `crates/diec-rules/src/pe_native.rs` | pelite，可复用 |
| ELF 原生解析 | `crates/diec-rules/src/elf_native.rs` | goblin，可复用 |
| Mach-O 原生解析 | `crates/diec-rules/src/macho_native.rs` | goblin，可复用 |
| 格式探测 | `crates/diec-formats/src/probe.rs` | 20+ 格式，可复用 |
| 输出格式化 | `crates/diec-output/src/` | JSON/XML/CSV/TSV/text，需适配 struct schema |

**缺失组件**：
- MD4、SHA224、SHA384、SHA512 哈希算法
- DEX 头解析
- StructSelector `#` 分隔解析逻辑
- struct 模式专用输出格式化（`data` 顶层对象、叶子值 string 序列化）

**复杂度**：中等。约 15-20 个工作日。

**差分测试基线**：`cli-special-modes.md` 记录 95 种输入/模式组合 × 190 次
oracle 执行，5 个基线样本的 JSON stdout SHA-256 已固定。

### G2: `--showstructs` 输出与上游不一致

**上游行为**：

`--showstructs` / `-w` 调用 `XFileInfo::getMethodNames()`，file type 硬编码为
`FT_UNKNOWN`，输出固定 4 行：

```text
Structures:
    Info
    Hash
    Entropy
    Check format
```

即使同时给出 target，输出也不变且不会扫描 target。

**diec 现状**：

`crates/diec-cli/src/main.rs` 第 262-284 行输出格式特定方法列表（如
`ELF.isSignaturePresent`、`PE.isSignaturePresent` 等），与上游 4 个通用方法
完全不同。

**修复方案**：将 `--showstructs` 输出改为上游的 4 个通用方法。

**复杂度**：低。随 G1 一并修复。

### G3: resource/overlay 内部递归扫描未实现（`-r` 语义错位）

**上游行为**（`nested-scan-behavior.md` § 上游递归流程）：

上游 release `diec` 的 `-r` / `--recursivescan` **不控制目录枚举**，而是启用
单文件内部的 PE resource 和 overlay 递归扫描：

- resource 扫描条件：`bIsResourcesScan || bIsRecursiveScan`
- overlay 扫描条件：`bIsOverlayScan || bIsRecursiveScan`
- 发布 CLI 只设置 `bIsRecursiveScan`，不设置独立的 `bIsResourcesScan` 或
  `bIsOverlayScan`
- overlay 始终扫描，不受 aggressive 影响
- resource nLimit：默认 20（实际扫描 21 个，inclusive 判断），aggressive 2000
  （实际扫描 2001 个）
- 非 aggressive 模式只扫描 `isScanable()` 的 resource；aggressive 扫描所有
- 递归调用复制完整 `SCAN_OPTIONS`，resource/overlay 内可继续寻找新的
  resource/overlay
- archive 成员解包需要独立的 `bIsArchivesScan`，`-r` 不启用 archive 解包

8 个确定性嵌套语料的实验结果（`nested-scan-behavior.md` § 嵌套语料实验）：

| Sample | default | recursive | recursive+aggressive |
| --- | --- | --- | --- |
| nested-zip.zip | 顶层 ZIP Unknown | 完全相同；不提取 inner ZIP | 同 recursive |
| pe-pdf-overlay.exe | PE32 Unknown | 增加 PDF Overlay，offset 512、size 331 | 同 recursive |
| pe-pdf-resource.exe | PE32 Unknown | 增加 PDF Resource，offset 608、size 331 | 同 recursive |
| pe-many-pdf-resources.exe | PE32 Unknown | 增加 21 个 PDF Resource | 增加 22 个 |
| pe-manifest-resource.exe | PE32 Unknown | 跳过（不可识别） | 增加 Binary Resource + Manifest |
| pe-zip-overlay.exe | PE32 | 增加 ZIP Overlay，offset 512、size 453 | 同 recursive |

**diec 现状**：

`crates/diec-cli/src/main.rs` 第 33, 142-144 行的 `-r` / `--recursive` 只做
**目录级递归**（`expand_target` 函数遍历目录），语义与上游完全不同。

`crates/diec-engine/src/host.rs` 第 22-45 行 `ScanFlags` 无 `resources`、
`overlays`、`recursive` 字段。第 415-417 行 `is_recursive()` 硬编码返回
`false`。

`crates/diec-core/src/request.rs` 第 64-71 行已定义 `NestingOptions { resources,
overlays, archives }`，但 engine 层未使用。

`crates/diec-engine/src/scanner.rs` 的 `ScanDetection` 结构（第 279-313 行）
已有 `id`、`parent_id`、`file_part`、`offset`、`size` 字段，但始终为 None。

`crates/diec-rules/src/pe_native.rs` 有 `is_resources_present()`、
`get_number_of_resources()` 等方法，但**没有 `getFileParts()` 等价函数**来枚举
每个 resource 的 offset/size/ID。overlay 检测完全缺失。

**语义冲突与兼容性影响**：

diec 的 `-r` 是目录递归，上游的 `-r` 是文件内部递归。对齐上游语义是**破坏性
变更**：现有使用 `diec -r directory` 的用户需改为 `diec --recursive-dir
directory`。需 ADR 0028 记录决策。

**复杂度**：高。需新建 PE resource 枚举、overlay 检测、递归扫描逻辑、ScanFlags
扩展、CLI 选项变更、FFI/server/GUI 全链路适配。

**差分测试基线**：8 个嵌套语料 × 4 种模式（default/aggressive/recursive/
recursive+aggressive），stdout SHA-256 已固定（`nested-scan-behavior.md`
§ 嵌套语料实验）。

### G4: archive 成员解包递归扫描未实现

**上游行为**（`nested-scan-behavior.md` § 上游递归流程 +
`archive-format-behavior.md`）：

上游 engine 的 `bIsArchivesScan` 分支只允许 `ZIP / 7Z / RAR / CAB / ISO9660`
五类格式。解包流程：

1. `initUnpack()` 初始化
2. 从 entry 声明的 uncompressed size 创建 buffer
3. `unpackCurrent()` 解包当前成员
4. aggressive 时无条件扫描，否则先探测成员类型只扫描 `isScanable()` 的成员
5. 成员标记为 `FILEPART_STREAM`，递归调用 `scanProcess()`

边界限制：
- 默认 nLimit = 20，aggressive nLimit = 100000
- 循环硬上限 `i < 100000`
- **无总解压字节数、单成员大小或压缩比限制**（压缩炸弹风险）

已验证的格式行为（`archive-format-behavior.md`）：
- ZIP deflate：支持
- 7Z Copy/LZMA/LZMA2/PPMd7/BZip2/Deflate/Deflate64 + x86/ARM64 BCJ filter：支持
- 7Z AES 加密：需要密码
- RAR4 store：支持
- CAB Store/MSZIP：支持
- CAB LZX/Quantum：不支持（aggressive 模式扫描 Unknown Stream）
- ISO9660：支持

**上游 release CLI 未暴露 `--archivescan` 选项**。`src/console/main_console.cpp`
只设置 `bIsRecursiveScan`，没有注册 `bIsArchivesScan`。archive 解包是 engine
层能力，通过 `XScanEngineConsole` 辅助类或 archive harness 可达。

**diec 现状**：

`crates/diec-engine/src/scanner.rs` 中 archive 仅运行 Binary 规则检测格式
（第 101-103 行），无解包逻辑。`crates/diec-formats/src/archive.rs` 仅通过
magic number 识别格式，无解包能力。

`crates/diec-core/src/limits.rs` 已定义 `max_archive_entries: u64`（默认
4096）、`max_total_decompressed_bytes: u64`（默认 512 MiB）、`max_depth:
u32`（默认 32）、`max_single_allocation_bytes: u64`（默认 128 MiB）。

`crates/die-gui/Cargo.toml` 有 `zip = "8.6"`、`tar = "0.4"`、`flate2 = "1.1"`
依赖，`commands.rs` 的 `list_archive()` 支持 ZIP/TAR/GZIP+TAR 列表功能，但
不支持成员提取。

**RAR 许可证问题**：

上游 XArchive 的 RAR decoder（`xrardecoder.cpp`/`.h`）是 UnRAR 7.13 源码的
近逐字翻译（94.21% token 覆盖率，跨 17 个 UnRAR 源文件），但标注 horsicq MIT
时未保留 UnRAR license 要求的 notice 和 `acknow.txt` 中的 PPM/AES/SHA 归属。
详见 `rar-decoder-provenance.md`。

diec-rust 已明确决定不复制、翻译或改写 XArchive 的 RAR decoder。

**纯 Rust RAR 库调研**（2026-08-15）：

| 库 | 许可证 | 纯 Rust | 兼容性 | 备注 |
| --- | --- | --- | --- | --- |
| `rars` (bitplane) | WTFPL + "don't blame me" | 是 | 宽松，兼容 MIT | 407 commits，69 stars，覆盖 RAR 1.5-7 |
| `weaver-unrar` (scryer-media) | GPL-3.0-or-later | 是 | copyleft，冲突 | 文档含 UnRAR license 段落 |
| `unrar` crate | UnRAR license (C++ 包装) | 否 | 需 native 依赖 | 与"优先纯 Rust"原则冲突 |

**决策**：使用 `rars` (WTFPL)，需 ADR 0029 记录。WTFPL 是宽松许可证（允许
商用/修改/分发），虽非标准 SPDX 但兼容 MIT。`rars` 是独立纯 Rust 实现，不涉及
UnRAR 源码。

**安全边界**：

上游没有总解压字节数、单成员大小或压缩比限制，存在压缩炸弹风险。diec-rust
需增加安全防护，需 ADR 0030 记录。diec-core `limits.rs` 已有框架
（`max_total_decompressed_bytes`、`max_single_allocation_bytes`）。

**复杂度**：高。需新建 5 种格式解包器、递归扫描编排、密码处理、安全边界。

**差分测试基线**：`archive-format-behavior.md` 记录 17 个 coder/container
样本的 archive 解包行为，`archive-gap-closure.md` 记录五类 family 闭集。

## 4. 测试覆盖缺口

### G5: macOS 68 项 platform-missing

**现状**（`capability-coverage-report.md` § 当前结果）：

macOS x86_64 Qt5 平台有 68 个 `platform_missing` 能力项。Linux Qt5/Qt6 和
Windows 的 68 项已全部提升为 `runtime_observed`。

已采集 17 个 candidate report 并提交至 `docs/research/data/macos-qt5/`：

```
oracle-candidate.json          cache-state-candidate.json
cli-baseline-candidate.json    cli-matrix-candidate.json
cli-remaining-candidate.json   cli-database-candidate.json
cli-path-nested-candidate.json cli-database-archive-candidate.json
special-path-fixture-candidate.json
cli-special-path-candidate.json
cli-filesystem-candidate.json  cli-privilege-path-candidate.json
cli-large-directory-candidate.json
long-path-fixture-candidate.json
cli-long-path-candidate.json   cli-toctou-candidate.json
database-cache-harness-build-candidate.json
database-cache-engine-candidate.json
```

macOS Qt5 oracle candidate build 和 5 case warm baseline benchmark 已完成，
但 coverage 矩阵尚未重新生成以接纳为 `runtime_observed`。

**闭合条件**：
1. 在 macOS 环境运行 17 个已存在的采集脚本（`tools/upstream/collect_macos_*.py`）
2. 验证所有 candidate reports（`tools/upstream/validate_macos_*.py`）
3. 生成完整的 68-row macOS closure plan
4. 重新运行 `build_capability_coverage.py` 生成 coverage 报告
5. 将 macOS 68 行从 `platform_missing` 提升为 `runtime_observed`
6. 闭合 `CAP-GAP-008` macOS 部分

**前提条件**：需要 macOS 环境（macOS-14 runner 或本地 macOS 主机）。

**复杂度**：中等。基础设施已存在（17 个脚本 + 17 个 candidate reports），只需
执行和验证。

### G6: 大型语料覆盖不足

**现状**：

基线语料 `baseline-corpus.json` 包含 26 个样本。上游有 68 个 CAP-* 能力项。
差分测试覆盖 31 个基线样本 + 20 个边缘样本 = 51 个，但未覆盖全部 68 个
CAP-* 能力项的所有维度。

**需要补充的样本类型**（基于 CAP-* 能力矩阵）：

| 类别 | 缺失维度 |
| --- | --- |
| 边缘情况 | 截断头部、畸形结构、超大字段、空容器 |
| 特殊路径 | NFC/NFD、中文、emoji、空格、hidden、前导短横线、非 UTF-8 |
| 文件系统 | symlink、alias、mode-000、depth-64、self-cycle |
| 大型目录 | flat/nested 4096 项完整顺序 |
| TOCTOU | stable old/new、enumeration vs open race |
| 归档格式 | 多记录、迭代边界、截断、结构变体、对抗性 |
| 数据库 | ZIP database、load-error、cache |
| 规则编排 | format-specific vs Binary、优先级、去重 |
| 结果模型 | scalar metadata、error/debug/handler lists |

**语料生成工具**：`tools/corpus/generate_*.py` 已有 60+ 个生成脚本，大部分
所需样本类型已有生成器。

**复杂度**：高。需生成约 42 个新样本并添加到差分测试。

## 5. 非 diec 缺口（不列入 Phase 13）

| 缺口 | 来源 | 处理方式 |
| --- | --- | --- |
| 规则版本差异（4 个不匹配） | submodule 规则比上游 3.21 bundled 更新 | 保持当前状态，文档说明（选项 A） |
| `--test` / `--createtest` 未实现 | 上游也标记为 TODO/no-op | 不实现（上游也没做） |

## 6. ADR 需求

| ADR | 标题 | 决策 |
| --- | --- | --- |
| 0028 | `-r` 语义对齐上游 | 破坏性变更：`-r` 改为文件内部递归，目录递归迁移到 `--recursive-dir`/`-R` |
| 0029 | `rars` (WTFPL) RAR 解包库选型 | 纯 Rust，WTFPL 兼容 MIT，覆盖 RAR 1.5-7 |
| 0030 | archive 成员解包递归扫描安全边界 | 压缩炸弹防护：单成员大小限制、总解压字节数限制、压缩比限制 |

## 7. 差距与子任务映射

| 缺口 | Phase 13 子任务 | 优先级 |
| --- | --- | --- |
| G1 | 13.1 `--struct` 通用方法 + 13.2 格式专用方法 + 13.3 输出格式化 | P0 |
| G2 | 13.1（`--showstructs` 修正随 G1 一并修复） | P0 |
| G3 | 13.4 resource/overlay 递归扫描 | P0 |
| G4 | 13.5 archive 成员解包递归扫描 | P1 |
| G5 | 13.6 macOS 平台基线闭合 | P1 |
| G6 | 13.7 大型语料补充 | P2 |
| — | 13.8 兼容性报告更新与文档 | P2 |

## 8. 引用文档

- `COMPATIBILITY.md` — 兼容性报告（规则加载、差分测试、CLI/Host API 兼容性）
- `capability-matrix.md` — 68 个 CAP-* 能力定义和证据索引
- `capability-coverage-report.md` — 68 能力 × 4 平台闭集报告
- `cli-special-modes.md` — `--entropy`/`--info`/`--struct`/`--showstructs` 上游行为
- `nested-scan-behavior.md` — resource/overlay/archive 嵌套扫描上游行为
- `archive-format-behavior.md` — archive 五类格式解包行为
- `archive-gap-closure.md` — archive 五类 family 闭集审计
- `rar-decoder-provenance.md` — 上游 XArchive RAR decoder 来源审计
