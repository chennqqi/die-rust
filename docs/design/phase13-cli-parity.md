# Phase 13：diec CLI 100% 上游对齐 — 设计文档

Status: Accepted
Last updated: 2026-08-15

## 1. 范围

本设计文档覆盖 ROADMAP Phase 13 的 8 个子任务（13.1-13.8），实现 diec CLI
与上游 DIE-engine release `diec` 的 100% 可观察行为对齐。

差距分析：`docs/research/cli-upstream-gap-closure.md`
相关 ADR：0028（`-r` 语义对齐）、0029（`rars` RAR 库选型）、0030（archive
安全边界）

## 2. 架构原则

- CLI 和 FFI 是核心库的薄适配层，核心层不得依赖它们或 GUI 框架。
- 新增解包能力放在独立 crate（`diec-unpack`）或 `diec-formats` 扩展，不
  污染 `diec-engine` 的扫描编排逻辑。
- `--struct` 模式的结构方法实现放在 `diec-engine`，复用 `diec-rules` 的
  原生格式解析和 `diec-formats` 的格式探测。
- 递归扫描（resource/overlay/archive）在 `diec-engine/scanner.rs` 中编排，
  通过 `ScanFlags` 控制开关，通过 `ScanDetection` 的 `parent_id`/`file_part`/
  `offset`/`size` 构建嵌套树。
- 安全边界（ADR 0030）在 `diec-core/limits.rs` 定义，在 `diec-unpack` 和
  `diec-engine/scanner.rs` 中强制执行。

## 3. 子任务设计

### 13.1 `--struct <value>` 通用方法

**模块结构**：

```
crates/diec-engine/src/
├── struct_mode.rs    # StructSelector 解析 + 方法分发
└── hash_methods.rs   # 7 种哈希算法 (MD4/MD5/SHA1/SHA224/SHA256/SHA384/SHA512)
```

**StructSelector 解析**：

```rust
/// Parsed `--struct <value>` selector with `#`-delimited hierarchy.
pub struct StructSelector {
    /// Raw input string (e.g., "Hash#MD5").
    pub raw: String,
    /// Lowercased sections (e.g., ["hash", "md5"]).
    pub sections: Vec<String>,
}
```

解析规则（匹配上游 `XFileInfo` 过滤语义）：
- `#` 分割为 sections，全部转小写
- 空字符串 `""` → 退回普通 scan（不进入 struct 模式）
- `Hash#MD5#Ignored` → sections = ["hash", "md5", "ignored"]，candidate
  "hash" 有子方法 "md5"，"md5" 无子方法，"ignored" 被当作 wildcard 忽略
- `Hash##MD5` → sections = ["hash", "", "md5"]，空 section 保留空 parent
- `NoSuch#MD5` → sections = ["nosuch", "md5"]，"nosuch" 不是有效方法，
  返回空 `data`

**通用方法枚举**：

```rust
pub enum GeneralMethod {
    Info,
    Hash,       // 子方法: MD4, MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    Entropy,
    CheckFormat,
}
```

**Hash 方法实现**：
- 复用 `die-gui/src/file_info.rs` 的 MD5/SHA1/SHA256
- 新增依赖：`md-4` crate（MD4）、`sha2` crate（SHA224/SHA384/SHA512，已有）
- 空文件 `Hash#MD5` 返回空字符串（上游边界行为，非标准空输入 MD5）

**Info 方法**：扩展现有 `--info` 模式为 struct 可查询的 Info 方法。字段集合
依格式变化（PE32 增加 architecture/mode/OS/type/endianness）。

**Entropy 方法**：复用 `compute_entropy` 函数。区域来自格式探测的
memory-map（非固定大小分块）。

**`--showstructs` 修正**：输出固定 4 行（Info、Hash、Entropy、Check format），
不依赖 target。

### 13.2 `--struct <value>` 格式专用方法

**模块结构**：

```
crates/diec-engine/src/
├── pe_struct.rs      # PE 专用方法 (6 个)
├── elf_struct.rs     # ELF 专用方法 (2 个)
├── macho_struct.rs   # Mach-O 专用方法 (2 个)
└── dex_struct.rs     # DEX 专用方法 (1 个)
```

**方法分发**：`struct_mode.rs` 根据格式探测结果选择格式专用方法。格式探测
复用 `diec-formats::ProbeTable`。

**PE32 方法**（复用 `pe_native.rs` pelite 解析）：
- `Entry point` — PE 入口点地址
- `IMAGE_DOS_HEADER` — DOS 头字段（e_magic, e_lfanew 等）
- `IMAGE_NT_HEADERS` — NT 头字段（signature, machine, entry, image_base 等）
- `IMAGE_SECTION_HEADER` — 节区头列表
- `IMAGE_RESOURCE_DIRECTORY` — 资源目录
- `IMAGE_EXPORT_DIRECTORY` — 导出表

**ELF64 方法**（复用 `elf_native.rs` goblin 解析）：
- `Entry point` — ELF 入口点地址
- `Elf_Ehdr` — ELF 头字段

**Mach-O 64 方法**（复用 `macho_native.rs` goblin 解析）：
- `Entry point` — Mach-O 入口点地址
- `Header` — Mach-O 头字段

**DEX 方法**（新增 DEX 头解析）：
- `Header` — DEX 头字段（magic, checksum, file_size, header_size 等）

### 13.3 `--struct` 输出格式化与模式优先级

**模块结构**：

```
crates/diec-output/src/
└── struct_formatter.rs   # struct 模式 5 种输出格式
```

**模式优先级**（`main.rs` 分派顺序）：
1. `--entropy` → entropy 模式
2. `--struct <value>` (非空) → struct 模式
3. `--info` → info 模式
4. 否则 → normal scan

**输出格式优先级**（专用模式）：`JSON > XML > CSV > TSV > formatted/plain text`

**JSON 格式**：顶层对象 `data`，叶子值全部序列化为 string。
```json
{"data": {"Hash": {"MD5": "d41d8cd98f00b204e9800998ecf8427e", ...}}}
```

**XML 格式**：递归 `record` 元素，叶子值在 `value` attribute。
```xml
<data><record name="Hash"><record name="MD5" value="d41d8cd..."/></record></data>
```

**CSV/TSV 格式**：无 header，父节点输出为只有 name 和空 value 的一行。

**多目标 framing**：按输入顺序先打印 `<filename>:\n`，随后串接独立 JSON
object（不是单个合法 JSON 文档）。

**未知方法**：JSON 为 `{"data": ""}`，退出码 0。

### 13.4 resource/overlay 内部递归扫描

**ADR 0028**：`-r` 语义对齐上游（破坏性变更）。

**ScanFlags 扩展**（`diec-engine/src/host.rs`）：

```rust
pub struct ScanFlags {
    // ... existing fields ...
    /// Enable intra-file resource/overlay recursive scanning (upstream -r).
    pub recursive: bool,
    /// Enable resource scanning independently (upstream bIsResourcesScan).
    pub resources: bool,
    /// Enable overlay scanning independently (upstream bIsOverlayScan).
    pub overlays: bool,
}
```

`is_recursive()` 返回 `flags.recursive || flags.resources || flags.overlays`。

**PE resource 枚举**（`diec-rules/src/pe_native.rs` 新增）：

```rust
/// A file part for recursive scanning (resource or overlay).
pub struct FilePart {
    pub kind: FilePartKind,    // Resource or Overlay
    pub offset: u64,
    pub size: u64,
    pub resource_id: Option<u32>,
}

/// Enumerate PE resources and overlay as file parts.
pub fn get_file_parts(data: &[u8]) -> Vec<FilePart> { ... }
```

使用 pelite `resources()` API 递归遍历 resource tree（type/name/language
目录），收集 data entries 的 offset/size/resource_id。上限 10000 个
resource。Overlay 从 header/section 最大末端到文件末尾。

**递归扫描逻辑**（`diec-engine/src/scanner.rs`）：

1. 主扫描完成后，检查 `flags.recursive || flags.resources || flags.overlays`
2. 如果是 PE 且启用 resource/overlay，调用 `get_file_parts()`
3. 对每个 file part：
   - 提取字节切片 `[offset..offset+size]`
   - 非 aggressive 模式先探测子设备类型，只扫描 `isScanable()` 的
   - aggressive 模式无条件扫描
   - resource nLimit：默认 20，aggressive 2000
   - 递归调用 `scan_bytes()`（复制完整 ScanFlags）
   - 设置子 detection 的 `parent_id`、`file_part`、`offset`、`size`
4. 将子 detection 嵌套在父 detection 的结果树中

**CLI 适配**（`diec-cli/src/main.rs`）：

| 选项 | 映射 | 说明 |
| --- | --- | --- |
| `-r` / `--recursivescan` | `flags.recursive = true` | 文件内部递归（上游语义） |
| `-R` / `--recursive-dir` | 目录递归 | 新选项，替代旧 `-r` 目录行为 |
| `-a` / `--aggressivescan` | `flags.aggressive = true` | nLimit 2000，扫描不可识别 resource |

**FFI/server/GUI 传播**：
- FFI: `DIEC_SCAN_FLAG_RECURSIVE = 0x80`（bit 8），`DIEC_SCAN_FLAG_RECURSIVE_DIR = 0x100`（bit 9）
- Server: `ScanFlagsRequest` 新增 `recursive`、`recursive_dir` 字段
- GUI: `ScanFlagsDto` 新增对应字段

### 13.5 archive 成员解包递归扫描

**ADR 0029**：`rars` (WTFPL) RAR 库选型。
**ADR 0030**：archive 安全边界。

**模块结构**：

```
crates/diec-unpack/
├── Cargo.toml          # 依赖: zip, sevenz-rust, rars, cab, iso9660
├── src/
│   ├── lib.rs          # Unpack trait 和公共接口
│   ├── zip.rs          # ZIP 解包器
│   ├── sevenz.rs       # 7Z 解包器
│   ├── rar.rs          # RAR 解包器 (rars)
│   ├── cab.rs          # CAB 解包器
│   ├── iso9660.rs      # ISO9660 解包器
│   └── limits.rs       # 安全边界强制 (ADR 0030)
└── tests/
    ├── zip_test.rs
    ├── sevenz_test.rs
    └── rar_test.rs
```

**Unpack trait**：

```rust
/// Archive member extraction interface.
pub trait ArchiveExtractor {
    /// List archive members with metadata.
    fn list_members(&self, data: &[u8]) -> Result<Vec<ArchiveMember>, UnpackError>;

    /// Extract a single member's decompressed bytes.
    fn extract_member(&self, data: &[u8], member_idx: usize, limits: &UnpackLimits) -> Result<Vec<u8>, UnpackError>;
}
```

**安全边界**（ADR 0030）：
- 单成员解压大小 ≤ 128 MiB
- 总解压字节数 ≤ 512 MiB
- 压缩比 ≤ 100:1
- 成员数 ≤ 20（默认）/ 100000（aggressive）
- 递归深度 ≤ 32
- 超限时跳过成员并发出 diagnostic

**递归扫描编排**（`diec-engine/src/archive_scan.rs` 新建）：

1. 主扫描完成后，检查 `flags.archives`
2. 如果是 archive 格式（ZIP/7Z/RAR/CAB/ISO9660），调用对应 `ArchiveExtractor`
3. 对每个成员：
   - 检查安全边界（ADR 0030）
   - aggressive 模式无条件扫描，否则先探测成员类型
   - 成员标记为 `FILEPART_STREAM`，保留 offset/size/original_name
   - 递归调用 `scan_bytes()`
4. 设置子 detection 的 `parent_id`、`file_part = "Archive"`、`offset`、`size`

**ScanFlags 扩展**：
```rust
pub struct ScanFlags {
    // ... existing fields ...
    /// Enable archive member extraction and recursive scanning.
    pub archives: bool,
}
```

**CLI 适配**：
- `--archivescan` → `flags.archives = true`（上游 release CLI 未暴露，为
  engine 能力扩展）
- `--password <value>` → archive 密码（7Z AES / RAR 加密）

**密码处理**：
- 密码错误时不产生 child（匹配上游行为）
- Copy/PPMd7 的错误密码可能留下非认证输出（上游已知行为）

### 13.6 macOS 平台基线闭合

**执行步骤**：
1. 在 macOS 环境运行 17 个 `tools/upstream/collect_macos_*.py` 脚本
2. 运行对应 `validate_macos_*.py` 验证脚本
3. 生成 68-row macOS closure plan
4. 运行 `build_capability_coverage.py` 更新 coverage 报告
5. 将 macOS 68 行从 `platform_missing` 提升为 `runtime_observed`
6. 闭合 `CAP-GAP-008` macOS 部分

**CI 增强**：
- 添加 macOS 专用 CI job 运行差分测试
- 当前 macOS CI 仅运行基本测试，未运行差分测试

**前提条件**：macOS 环境（macOS-14 runner 或本地 macOS 主机）

### 13.7 大型语料补充

**语料生成**：复用 `tools/corpus/generate_*.py` 60+ 个生成脚本，生成约 42
个新样本覆盖 68 个 CAP-* 能力项。

**差分测试扩展**：
- 新增样本添加到 `crates/diec-engine/tests/corpus_differential.rs`
- 更新 `docs/research/data/baseline-corpus.json`
- 添加样本生成指南文档

**自动化**：语料生成集成到 CI pre-test 阶段，自动验证样本完整性。

### 13.8 兼容性报告更新与文档

**更新文档**：
- `COMPATIBILITY.md`：CLI 兼容性表新增 `--struct`、`--archivescan`、
  `--recursive-dir`；Host API 新增 resource/overlay 递归；Known Differences
  更新 `-r` 语义变更和 archive 安全边界差异
- `README.md` / `README.zh-CN.md`：CLI 选项说明更新
- `RELEASE.md` / `RELEASE_NOTES.md`：新版本发布信息
- `AGENTS.md`：当前阶段描述更新
- `capability-matrix.md`：CAP-CLI-MODE-003 状态更新
- `capability-coverage-report.md`：macOS 状态更新
- `NOTICES.md`：新增 `rars` (WTFPL) 归属
- `AUDIT.md`：新增 WTFPL 许可证记录

## 4. 依赖变更

| 依赖 | 版本 | 用途 | 许可证 | 新增/已有 |
| --- | --- | --- | --- | --- |
| `md-4` | latest stable | MD4 哈希 | MIT/Apache-2.0 | 新增 |
| `sha2` | 已有 | SHA224/SHA384/SHA512 | MIT/Apache-2.0 | 已有 |
| `zip` | 8.6 | ZIP 解包 | MIT | 已有 (die-gui) |
| `sevenz-rust` | latest stable | 7Z 解包 | MIT/Apache-2.0 | 新增 |
| `rars` | latest stable | RAR 解包 | WTFPL | 新增 (ADR 0029) |
| `cab` | latest stable | CAB 解包 | TBD | 新增 |
| `iso9660` | latest stable | ISO9660 解包 | TBD | 新增 |

## 5. 测试策略

| 子任务 | 测试类型 | 基线 |
| --- | --- | --- |
| 13.1-13.2 | 差分测试 | 5 基线样本 × 11 方法 × 6 输出格式 = 330 case |
| 13.3 | 差分测试 | 95 种输入/模式组合 × 190 次 oracle |
| 13.4 | 差分测试 | 8 嵌套语料 × 4 模式 |
| 13.5 | 差分测试 | 17 archive 语料 × archive/aggressive 组合 |
| 13.6 | 平台基线 | 68 能力 × macOS |
| 13.7 | 语料覆盖 | 68 CAP-* 能力项 |
| 全部 | 单元测试 | 每个新模块 |
| 全部 | fuzz | archive 解包 harness |

## 6. 退出条件

- `--struct <value>` 全部通用 + 格式专用方法实现，差分测试 0 不匹配
- `--showstructs` 输出与上游逐字节相同
- resource/overlay 递归扫描实现，8 个嵌套语料差分测试 0 不匹配
- archive 成员解包递归扫描实现（5 种格式），17 个 archive 语料差分测试 0 不匹配
- macOS 68 项 platform-missing 全部闭合为 runtime_observed
- 大型语料覆盖 68 个 CAP-* 能力项
- `cargo fmt --check`、`cargo clippy --workspace --all-targets --all-features -- -D warnings`、
  `cargo test --workspace --all-features` 全部通过
- 3 个 ADR（0028/0029/0030）Accepted
- COMPATIBILITY.md、README.md、能力矩阵、NOTICES.md、AUDIT.md 全部更新
