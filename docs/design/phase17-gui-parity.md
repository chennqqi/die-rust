# Phase 17：GUI 差距 v4 补齐 — demangle / 归档 / 哈希 / DEX

Status: Implemented（17.A–17.E 已落地；17.F ADR 已产出）
Last updated: 2026-10-02

> 实施状态注记：
> - 17.A 已实现：Auto 探测忠实移植上游 `detectMode`；MSVC 全系经
>   `msvc-demangler` 0.11；Borland/Watcom/D/Java 为自实现精简解码；
>   GNU v2/GNAT/Swift/Go/Haskell/OCaml/Tru64/SunPro 枚举存在但返回原串
>   （deferred，见 COMPATIBILITY.md 模式矩阵）。
> - 17.B 已实现：引擎 `archive_unpack` 新增 `list_archive_members` +
>   `extract_member`（ZIP/7Z/RAR），GUI `list_archive` 改走引擎，
>   新增 `extract_archive_member` 命令与前端提取按钮。CAB/ISO9660 未做。
> - 17.C 已实现：`compute_hash`/`list_hash_algorithms` 命令 +
>   FileInfo 勾选面板；算法集 MD4/SHA224/384/512/SHA3 系/BLAKE2/3/
>   Adler32/CRC64。
> - 17.D 已实现：`parse_dex_deep_view` 七表 + MiscViewPanel 子标签。
> - 17.E 已实现：`format_counts` 信息栏（含 Mach-O 匹配修复）、
>   `follow.ts` Follow-in-Hex 总线（PE/ELF/Mach-O 节表）、Extra
>   Information 模态框、`edit_bytes_at_offset` Hex 编辑入口。
> - 17.F 已产出：ADR 0035–0038（见 `docs/design/decisions/`）。

## 目标

`gui-gap-analysis-v4` 实测确认 Phase 11/12 后 GUI 功能面对齐度约 85%。
本 Phase 补齐剩余差距中**用户可感知、无需架构级决策**的部分；NFD、
静态脱壳、InfoDB、自动更新等架构级缺口产出 ADR 后另行立项。

## 依据

- 差距分析：[`docs/research/gui-gap-analysis-v4.md`](../research/gui-gap-analysis-v4.md)
- 上游基线：`DIE-engine@23fec32`（`upstream/components.lock.toml`）
- XDemangle 固定 commit：`161659880361e23cc4e983776becc323ff68da26`（20 模式）
- 已有 RAR 决策：[`decisions/0029-rars-rar-library.md`](decisions/0029-rars-rar-library.md)
- 引擎已有归档提取：`crates/diec-engine/src/archive_unpack.rs`（ZIP/7Z/RAR）

## 任务批次

### 17.A Demangle 扩展（P1 — 最大用户可感知差距，V4-10）

**现状**：`demangle.rs` 仅 31 行，rustc-demangle + cpp_demangle（Itanium）。
上游 XDemangle 20 种模式，其中 MSVC 是 PE 分析最常见场景。

**实现**：

1. `die-gui/src/demangle.rs` 重构为模式分发器：

   ```rust
   /// Demangle mode, mirrors upstream `XDemangle::MODE` subset.
   pub enum DemangleMode {
       Auto, Msvc, Msvc32, Msvc64, MsvcArm32, MsvcArm64,
       GnuV3, Borland, Watcom, Rust, Dlang, Java,
   }
   ```

   `Auto` 按上游 `XDemangle::detectMode` 的特征前缀探测顺序
   （`?`=MSVC、`__Z`=Borland、`W?`=Watcom、`_D`=D、`_Z`=Itanium、
   `_R`/legacy `ZN`=Rust 等）分发。

2. 依赖选型（优先级：纯 Rust、许可宽松、近 7 天以上发布版本）：
   - MSVC：`msvc-demangler`（MIT/Apache-2.0）— 覆盖 MSVC32/64/ARM 四模式
   - Borland/Watcom：无成熟 crate，移植 XDemangle 精简子集
     （`__Z`/`W?` 前缀语法，覆盖 name+args+qualifiers 即可，
     不追求 100% 语义等价）
   - D：`_D` 前缀，自实现 D ABI 基础解码或评估 `d-demangle`
   - Java：`.method` descriptor + `java/lang` 内部名解码（自实现，量小）
   - GNU_V2/GNAT/Swift/Go/Haskell/OCaml/Tru64/Sun：本期不做，
     `MODE_UNKNOWN` 回退原串并在 COMPATIBILITY 标注

3. 前端 `DemangleTool.tsx` 增加模式下拉框（对齐 `XDemangleWidget`
   的 comboBoxMode），Auto 为默认。

4. 测试：每模式至少 3 个样本（上游 `xdemangle` 测试用例可参照，
   注意只取测试向量不抄实现）；Auto 探测正交用例。

**验收**：`demangle` 命令对 `?foo@@YAHXZ`、`__Z3foav`、`_ZN…`、
`_D…` 均返回正确解码；模式覆盖率矩阵写入 COMPATIBILITY.md。

### 17.B 归档列表扩展（P1，V4-11）

**现状**：`list_archive` 手写 ZIP/TAR/GZ；而 `diec-engine` 已有
`extract_zip`/`extract_7z`/`extract_rar` 与 `diec-formats` 的
ZipProbe/RarProbe/SevenZProbe/CabProbe/Iso9660Probe —— **差距主要
是接线而非缺实现**。

**实现**：

1. `diec-engine` 新增 `list_archive_members(data) -> Vec<ArchiveMemberInfo>`
   （name/uncompressed_size/compressed_size/is_dir/mtime），
   ZIP 走目录直读（已有 `zip_member_names`/`decompress` 语义），
   7Z/RAR 复用现有解码头只取元数据不取数据。
2. `die-gui` `list_archive` 改为调用引擎接口，探测顺序统一走
   `diec-formats` probe table（不再手写 magic）。
3. CAB/ISO9660 列表：probe 已有；解码头评估 `cab`（纯 Rust）与
   自实现 ISO9660 目录遍历（量小），本期可选做，未做则
   COMPATIBILITY 标注。
4. BZ2/XZ/LZMA 裸压缩流：上游 XArchive 支持；`bzip2`/`xz2` 为
   native 依赖 —— **不做**，记入 deferred（纯 Rust 替代品
   `bzip2-rs`/`lzma-rs` 成熟度不足以默认引入）。

**验收**：ZIP/7Z/RAR 样本 `list_archive` 返回成员清单；
`extract_item`/`extract_range` 支持按成员名提取；含畸形归档的
负向测试不 panic。

### 17.C 哈希算法扩展（P2，V4-12）

**现状**：FileInfo 固定 MD5/SHA1/SHA256/CRC32；struct 模式 7 种。

**实现**：

1. `compute_hashes` 扩展为可选项驱动的算法集，全部纯 Rust：
   - 已有：MD4/MD5/SHA1/SHA224/256/384/512（struct_mode 复用同一套）
   - 新增：`sha3`（SHA3-224/256/384/512）、`blake2`（BLAKE2b/s）、
     `blake3`、`adler2`（Adler32）、CRC64（`crc` crate 已传递引入则直接用）
2. 新命令 `compute_hash(path, algorithms: Vec<String>)` —
   前端 FileInfo Hash 区改为算法勾选（对齐 XHashWidget 的
   checkable 列表），默认勾选上游默认集（MD5/SHA1/SHA256）。
3. SSDeep/TLSH：native 依赖，**不做**，deferred。

**验收**：同一文件各算法输出与上游 `diec --struct "Hash#*"`
行为一致（差分用例进 tests/）；空文件/大文件边界测试。

### 17.D DEX 深视图（P2，V4-13）

**现状**：`misc_viewer.rs::DexView` 仅 header 字段 + ids 计数。

**实现**：

1. `misc_viewer.rs` 扩展解析：string_ids（偏移表 + uleb128 长度
   前缀字符串）、type_ids（descriptor_idx→string）、proto_ids、
   field_ids、method_ids（class/proto/name 三元组解码）、
   class_def_item、map_list。leb128 解码注意边界（不可信输入）。
   `diec-formats/src/dex_class_pyc.rs` 已有 DEX 探测逻辑可参照，
   但不直接复用（该模块面向 detection 非展示）。
2. `MiscViewPanel.tsx` DEX 分支增加子标签：Strings/Types/Protos/
   Fields/Methods/Classes/Map。

**验收**：样本 dex 各表行数与上游 DEX widget 一致；截断/畸形
dex 不产生 panic（属不可信输入约束）。

### 17.E 交互细节补全（P2，V4-03/20/21/22）

1. **信息栏**（V4-22）：FileInfoPanel 顶部固定显示 base address /
   entry point / 格式计数（PE: sections+imports+exports；
   ELF: phdr+shdr；Mach-O: cmd/sect/seg/lib），数据均已存在。
2. **Follow 链**（V4-21）：PE/ELF/Mach-O 子视图表格中带偏移的列
   加 Follow in Hex 跳转（复用现有 `onFollowInHex` 机制）。
3. **Extra Information**（V4-03）：扫描结果区加 "Formatted text"
   按钮，输出 `ScanItemModel::toFormattedString` 等价的纯文本
   （检测结果扁平化），支持复制。
4. **Hex 字节编辑**（V4-20）：上游 DIE 的 Hex 查看器本就以展示为主；
   本期仅补 `edit_string_at_offset`/`write_binary_file` 的前端
   入口（Hex 右键 → Edit at offset），完整 hex 编辑 deferred。

### 17.F ADR 决策项（不在本 Phase 实现，仅产出 ADR）

| 项 | ADR | 决策内容 |
|----|-----|---------|
| NFD 引擎 | ADR 0035 | 是否 port SpecAbstract（~与 DIE 引擎平级工作量）或永久 deferred |
| 静态脱壳 | ADR 0036 | XStaticUnpacker 逐脱壳器移植评估或 deferred |
| InfoDB | ADR 0037 | 注释/书签持久化基础设施必要性 |
| 多语言 17→22 | ADR 0038 | 上游 .ts XML → i18next JSON 脚本化转换可行性 |
| 自动更新 | ADR 0019 已有 | 维持 deferred |

## 依赖新增清单

| crate | 用途 | 类型 | 许可 |
|-------|------|------|------|
| `msvc-demangler` | MSVC 反混淆 | 纯 Rust | MIT/Apache-2.0 |
| `sha3` | SHA3 系 | 纯 Rust | MIT/Apache-2.0 |
| `blake2`/`blake3` | BLAKE2/3 | 纯 Rust | Apache-2.0/MIT |
| `adler2` | Adler32 | 纯 Rust | 0BSD |
| `cab`（可选） | CAB 列表 | 纯 Rust | MIT/Apache-2.0 |

引入前逐项核对：版本发布距今 ≥7 天、许可证与 `AUDIT.md`/`NOTICES.md`
兼容、无 native 依赖。

## 非目标

- NFD/静态脱壳/InfoDB/自动更新实现（见 17.F ADR）
- SSDeep/TLSH（native 依赖）
- RAR/7z 之外的 XArchive 解码器全家桶（BZ2/XZ/LZMA/ARJ/SFX）
- XStyles 46 主题移植、XTranslation 在线翻译下载
- MIPS/PPC/RISCV 等新反汇编架构（iced-x86/yaxpeax-arm 已覆盖主流；
  如需扩展评估 capstone-rs native 依赖，另行 ADR）

## 验收标准

- 每批次独立提交、独立可验证；每批含单元测试 + 对应上游差分断言
- `cargo fmt --check` / `cargo clippy --workspace --all-targets
  --all-features -- -D warnings` / `cargo test --workspace --all-features` 全绿
- 前端 `npm run build` 通过；GUI-CLI 差分测试通过
- COMPATIBILITY.md 更新 demangle 模式矩阵、归档格式矩阵、哈希算法矩阵
- 新发现的上游 bug/偏离记入 `doc/upstream-bugs.md`（按 Phase 16 教训 12）
- ADR 0035–0038 产出（Accepted 或 Deferred 均可）
