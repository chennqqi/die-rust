# 需求分析摘要

## 2026-07-30: 接棒继续 diec-rust 项目

### 现状评估
- 项目处于 Roadmap Phase 0 (IN PROGRESS)
- 上游基线已固定: DIE-engine@74eaf505, Detect-It-Easy@c2c17df
- 58 个 submodule SHA 已锁定在 components.lock.toml
- 大量调研文档已产出 (docs/research/ 100+ 文件)
- 5 份设计文档已进入 In Review 状态
- 15 个 ADR (14 Proposed + 1 Superseded)
- 3 项技术验证已有证据: rquickjs runtime, C static link, upstream oracle

### Phase 0 阻塞项
- P0-BLOCK-001: Closed (能力矩阵)
- P0-BLOCK-002: Open (设计文档需评审结论)
- P0-BLOCK-003: Open (ADR 需接受)
- P0-BLOCK-004: Open (许可证/闭包审计未完成)
- P0-BLOCK-005: Open (macOS 基线缺失)
- P0-BLOCK-006: Open (性能基线/资源限制未冻结)

### 环境约束
- 当前环境为 Windows, 无法执行 macOS 基线采集
- macOS 基线需要 Darwin 主机执行

### 2026-07-30: 修复与评审准备

#### 修复
- 修复 global_host_api_harness_main.cpp 源码 identity 漂移（上次提交添加了新 case 但未更新 JSON 报告中的 bytes/sha256）
- 级联更新: qt5/qt6 报告 -> 合并报告 -> result-model -> closure plan -> coverage -> source-only closure
- 全部 1547 测试通过

#### 评审准备
- 创建 `docs/design/phase-0-review-preparation.md` 汇总三个阻塞项的当前证据和缺口
- P0-BLOCK-004 许可证: 14 份技术证据文档已完成，6 个剩余缺口，可提交书面评审
- P0-BLOCK-002/003 设计/ADR: 5 份设计文档 + 14 ADR 评审输入完整，需人工评审结论
- P0-BLOCK-006 性能: 上游 baseline 方法已验证，limit 候选需评审冻结，Rust 侧需实现后执行

### 2026-07-30: 研究文档状态提升与 Windows 缓存验证

#### 文档提升
- upstream-baseline.md、source-analysis.md、rule-compatibility.md 从 Draft 提升到 In Review
- 依据：核心证据完整，已知缺口（macOS）由 P0-BLOCK-005 跟踪
- capability-matrix.md 和 behavior-baseline.md 保持 Draft（gate_status=evidence_incomplete，macOS 缺失）

#### Windows 缓存环境验证
- 重新运行 probe_windows_benchmark_cache_environment.py，输出与提交报告逐字节相同
- SHA-256: bc58d9de0ee32e7aa55dd8f2bea7436ee8fdb6e2626eda83e9c41c2fc01abce7

#### 测试状态
- 全部 1554 测试通过，1 skipped，5078 subtests passed

### 2026-07-30: P0-BLOCK-004 许可证范围修正

#### 背景
用户确认：(1) 引擎与规则分离，db* 规则由用户自行获取，引擎项目不包含规则；(2) YARA/PEiD/signatures 不进入 diec CLI（源码证据）；(3)(4) NOTICE/SBOM 按 Rust 标准做法（cargo deny/about），Phase 1 常规工作。

#### 修正内容
- 引擎不包含/不分发 db* 规则、YARA/PEiD/signatures 资产
- 上游 C++ 许可证（GPL/UnRAR/Brotli/Zstandard）不传染 Rust 二进制
- P0-BLOCK-004 剩余项仅为 Phase 1 常规工作：cargo deny/about + NOTICE
- 建议将 P0-BLOCK-004 从 Open 降为 Review Ready

### 2026-07-30: YARA/PEiD/signatures 深入调查

#### 背景
用户指出需要深入调查 YARA/PEiD/signatures 的作用，且未来要实现 GUI。

#### 调查结果
- XYara：独立 YARA 扫描线程类（XThreadObject），与 DiE_Script 并行的检测通道，GUI 默认 WITH_YARA=ON
- XPEID：继承 XScanEngine，PEiD userdb.txt 解析器，识别 PE packer/compiler
- SearchSignatures：GUI widget，使用 crypto.db/junks.db
- 三者均不进入 diec CLI（main_console.cpp/CMakeLists.txt/link.txt 证据）
- XScanEngine 是独立开源仓库（MIT），不是私有代码
- 已在 phase-0-review-preparation.md 记录未来 GUI 集成准备信息

### 2026-07-30: P0-BLOCK-005 macOS Qt5 oracle candidate 构建

#### 环境
- macOS 12.7.6 Monterey, x86_64, 8 core, 16GB RAM
- Apple clang 14.0.0 (CommandLineTools only, no full Xcode)
- Qt 5.15.2 clang_64 (aqtinstall), CMake 3.27.7
- 默认 SDK 13.1 (MacOSX.sdk -> MacOSX13.1.sdk)

#### 构建结果
- diec CLI 构建成功: Mach-O x86_64, 7.45MB, version "die 4.0.0"
- 依赖: QtConcurrent, QtScript, QtCore, DiskArbitration, IOKit, libc++, libSystem

#### 构建修复
- Formats/xbinary.h 第 114 行 `#include <CoreFoundation/CoreFoundation.h>` 在 macOS 上导致编译失败
- 根因: xdeflatedecoder.cpp (10581 行拼接文件) 在函数作用域内 include xbinary.h → CoreFoundation.h
- CFMessagePort.h 的 CF_EXPORT (extern) typedef 在函数内无效
- xbinary.h 未使用任何 CoreFoundation 类型，include 标记为 "// Check"
- Linux/Windows 不受影响（Q_OS_MAC 未定义）
- bootstrap 脚本的 tracked source 检查需要修改以允许此 patch

#### 下一步
- 评审并记录 source patch 为已知 macOS 构建修复
- 修改 bootstrap 脚本支持 macOS 构建修复
- 执行 runtime oracle 采集（68 行 capability baseline）
- 需要在 macOS 上运行项目生成的安全语料和 CLI 矩阵

### 2026-07-31: P0-BLOCK-002/003 关闭分析
- 拆分策略: 每个 ADR 的 Acceptance conditions 拆为 Decision acceptance (Phase 0 方向批准) + Implementation exit (Phase 1+ 实现期门禁)
- 设计文档: 5 份均改为 Accepted，blocking_items 清空，review_disposition 记录
- JSON manifests: 3 个清单全部更新，summary 反映 accepted_count=14, acceptance_ready=true
- 测试: 3 个测试文件更新断言，从 Proposed/In Review 改为 Accepted，13 passed
- Phase 0 仍为 not_ready: P0-BLOCK-004/005/006 仍 open

## 2026-07-31: P0-BLOCK-005 关闭分析
- macOS 基线采集范围: 18 个 candidate report (workflow plan 定义)
- 已完成 17 个: oracle/cache-state/cli-baseline/cli-matrix/cli-remaining/cli-database/cli-database-archive/cli-path-nested/cli-special-path/cli-filesystem/cli-large-directory/cli-long-path/cli-toctou/special-path-fixture/long-path-fixture/database-cache-harness-build/database-cache-engine
- 缺失 1 个: cli-privilege-paths (需 passwordless sudo, deferred)
- 工具修复: build_macos_database_cache_harness.py (TARGET vs DESTDIR_TARGET, xbinary.h patch), collect_macos_database_cache_harness.py (macOS QStandardPaths behavior)
- Python 3.9 系统版本过旧, 使用 venv Python 3.14.6
- 所有 report 已 sanitize /Users/chenq 路径为 <macos-work>/<macos-home> 占位符

## 2026-07-31: 上游规则 bug 记录 — Nintendo-certified-file.1.sg const 重声明
- 文件: `db/Binary/format_bin.Nintendo-certified-file.1.sg`，上游 commit `4b675ffd`
- 第 10 行 `var tp, e;` 与第 15 行 `const tp` 在同一函数作用域重声明
- QtScript (上游 DIE 使用的 JS 引擎) 允许此行为，QuickJS/ECMAScript 规范禁止
- diec-rust 使用 QuickJS (rquickjs)，因此该规则加载失败
- 这是上游规则 bug，非 diec-rust 缺陷
- 建议修复: 第 10 行改为 `var e;`（`tp` 已在第 15 行用 `const` 正确声明）
- Bug 报告已写入 `docs/research/upstream-bug-const-redeclaration-nintendo-certified-file.md`

- [2026-08-01] macOS Phase 1 benchmark 门禁：需在 macdev 主机上运行三类 benchmark（runtime warm baseline、release deployment size、Rust 成对 benchmark），复用 Linux Qt5 现有 plan/runner 工具链并适配 macOS 路径与环境

## 2026-08-02: Host API 完善
- 分析：78 个 stub 方法，按差分收益排序
- 优先级：CFBF(+1) > JavaClass(+1) > PYC(+1) > Archive(架构) > PE验证/Resource/.NET/Manifest
- 当前差分：22/28 匹配，6 个差异全为规则版本差异

## 2026-08-04: CLI 参数差异分析
- 定位: crates/diec-cli/src/main.rs vs upstream/DIE-engine/console_source/main_console.cpp
- 差异: --output <format> 与上游独立开关 --json/--xml/--csv/--tsv/--plaintext 风格不同; --extradb/--customdb 与上游 --extradatabase/--customdatabase 命名不同; --showstructs 与上游 --showmethods 命名不同; 缺少 --database 别名; 上游存在 --test/--addtest/--special/--nohighlight 等未实现

## 2026-08-04: 发布包目录结构差异分析
- 上游 DIE-engine build_linux_portable.sh 产物: 顶层为 die/diec/diel 启动器，base/ 目录含产品 ELF 与 db 等数据
- 当前 release.yml: 采用标准 bin/lib/include 布局，仅复制 db，无 db_extra/db_custom 分层，无顶层启动器
- 调整: 将 diec 可执行文件与三层规则库移入 base/，顶层提供 diec/diec.cmd 启动器，保留 lib/include/bindings 在顶层

## 2026-08-04: 0.2.1 发布分析
- 当前版本 0.2.0，已有 CLI 与 release 包结构改动未提交
- fmt/clippy/test 通过，版本 bump 至 0.2.1
- 待执行：提交、打 tag、推送触发 GitHub release workflow

## 2026-08-04: 规则加载开销与服务化方案分析
- 现状: Database 构建后 immutable，Arc 共享；CLI 单次调用内只 build 一次，循环 scan 多文件复用
- 累计开销来源: 每次 CLI 进程启动都要重新 build database（160ms 并行），scan_bytes 内每文件每 file_type 创建新 RquickjsRuntime + load framework
- 服务化收益: 常驻进程避免重复 160ms database load；但 scan_bytes 内 runtime 创建开销仍存在，需评估是否池化
- 架构约束: 服务层须为薄适配层，核心层不得依赖；gRPC(tonic)/HTTP(axum) 引入较重依赖须记录权衡
- db 版本: 当前 Database 无 version 字段，需从 rule-source-manifest.json 或规则目录推导
- 本地/远程区分合理: 本地避免大文件传输，远程适合跨机；本地模式需路径安全校验

## 2026-08-04: ADR 0016/0017 起草
- ADR-0016: 同一 file_type runtime 跨文件复用，persistent state audit + 差分验证约束安全性
- ADR-0017: diec-server HTTP/JSON 服务层，本地路径+远程内容双模式，axum 纯 Rust 依赖
- 两者关系: ADR-0016 是 ADR-0017 的性能基础，可独立先做
- 待评审: 两份 ADR 均为 Proposed，需评审确认决策方向后进入实现

## 2026-08-04 gRPC/HTTP 识别服务
- 问题：CLI 重复调用单文件时 Database 重建开销 160ms/次；scan_bytes 内每个 file_type 创建 RquickjsRuntime
- 方案A (ADR-0016): Scanner 有状态对象，per-file_type runtime 复用 + reinit 重置 host 别名
- 方案B (ADR-0017): diec-server HTTP/JSON 服务，Database 启动时加载一次，Arc 共享
- 持久状态审计：框架 result() 重置 bDetected/sName/sVersion 等全局变量，复用安全
- 差分验证：复用 vs 非复用 0 不匹配；同文件两次扫描结果一致；多格式顺序+逆序无交叉污染
- 安全边界：allow_root 路径校验、max_file_size/max_request_size 限制、scan_timeout 取消
- 依赖：axum 0.8.8 + tokio + serde + tower-http (limit)，无 gRPC 重依赖
- Scanner !Send 限制：服务层当前用无状态 scan_bytes，runtime 复用留作 worker 线程后续优化

## 2026-08-05: GUI 设计文档评审分析
- 基于 `AGENTS.md` 阶段定义，识别到 `docs/design/phase7-gui.md` 阶段命名与 `Phase 8 GUI` 冲突
- 评审关注：Tauri 架构与核心库依赖边界、前端入口命名、`ScanFlags` 完整性、上游 submodule 可复现性、GUI 测试策略
- 评审结论：文档 Proposed 状态保持不变，修正阶段命名、crate 命名、入口文件、标志位、测试策略后可进入 Accepted
- 评审结果保存于 `docs/reviews/gui-design-review.md`

## 2026-08-05: Phase 8 GUI 7A-0 骨架
- 环境：fnm multishell，需 nm env --shell powershell 初始化 PATH（node v24.18.0/npm 12.0.1）
- Tauri v2 依赖：tauri/tauri-build/tauri-plugin-{dialog,fs,single-instance,store}
- 前端栈：React 18 + TypeScript 5 + Vite 5 + Tailwind 3 + Zustand 4 + CodeMirror 6 + i18next
- IPC 命令骨架：scan_file/scan_bytes/stop_scan/list_signatures/get_signature_source/run_signature/scan_directory/demangle/get_settings/save_settings/get_database_info
- 结构化错误：GuiError { code, message }
- ScanFlagsDto 含 first_wrapper_only/hide_unknown


## 2026-08-05 GUI 改进需求分析
- 命名：crate diec-gui -> die-gui, 二进制名 die, 与上游对齐
- UI：当前仅 Tailwind 裸元素堆砌，缺深色主题/图标/TreeView/状态栏/进度条
- 功能差距：对比上游 die 完整GUI，缺熵/哈希/区段/符号表/可视化/提取器/Advanced模式/Recent Files/快捷键等
- 策略：UI+功能并行推进，参考 docs/research/upstream-gui-analysis.md

## 2026-08-07: CI 本地预演约定
- 现状：AGENTS.md「完成与提交」章节无本地预演要求，仅有提交前 cargo fmt/clippy/test 清单
- 风险：直接 push 试错会反复触发 GitHub Actions 失败，可能被 GitHub 限流/封号
- 决策：在「完成与提交」补充一条规则——本地验证（含 .ci-local 模拟）通过后再 push 触发 CI
- 落点：AGENTS.md 第 95-106 行章节末尾追加
[2026-08-07] 用户反馈 gui-upstream-diff.md 不够深入，三个维度需深挖：信息丰富度、不合理设计、底层库差异。计划：1) 编写对比脚本调用 diec.exe 获取多格式输出；2) 检索上游 ScanItemModel::createResultStringEx/createTypeString 源码确认上游展示格式；3) 检索 XHexView/XDisasmView 头文件确认功能差距；4) 检查 die-gui 后端模块（hex_viewer/disassembler/file_info）实现细节；5) 重写差异文档加入实际输出对比和源码证据。

## 2026-08-08: Phase 10 完成分析

### 实施结果
- Phase 10 已完成：已知问题修复与文档纠正
- 10.1 文档清理：getDisasmString 已从 README.md "Known Limitations" 移除，Capstone 0.14.0 集成完成
- 10.2 文档清理：规则版本差异已移至 README.md "Known Differences (Non-Defects)" 节
- 10.3 功能修复：检测结果去重已完整实现
  - ADR 0027 已 Accepted（去重决策记录）
  - 去重键 (type_name, name, version, options, offset, size)，排除 file_type
  - 默认去重，--no-dedup / DIEC_SCAN_FLAG_NO_DEDUP=0x40 可关闭
  - 影响 6 层：ScanFlags → scanner → CLI → FFI → server → GUI
  - 5 个去重测试全部通过（511 总测试数）

### 验证结果
- cargo test --workspace --all-features --exclude die-gui: 511 tests pass
- cargo fmt --check: 通过
- cargo clippy --workspace --all-targets --all-features --exclude die-gui -- -D warnings: 通过
- GUI 构建资源已准备（db/db_extra/dbs_min/dbs_special/peid_rules/yara_rules）
- ROADMAP.md Phase 10 标记为 DONE
- AGENTS.md 更新当前阶段描述
- RELEASE.md 和 RELEASE_NOTES.md 更新 v0.6.0 发布信息
- Cargo.toml 版本号更新为 0.6.0
- [2026-08-09] GUI差距v3剩余35项功能分析：对照gui-gap-analysis-v3.md逐项审查后端pe_viewer.rs/macho_viewer.rs/elf_viewer.rs/string_extractor.rs/visualization.rs/extractor.rs和前端PeViewPanel/MachoViewPanel/ElfViewPanel/StringExtractor/VisualizationPanel/ExtractorPanel/App.tsx，确认PE缺5子视图(NT_HEADERS/RESOURCES_STRINGTABLE/NET_METADATA_STREAM/NET_METADATA_TABLE/TOOLS)，Mach-O缺12子视图(weak_libraries/id_library/FVMLIB/IDFVMLIB/function_starts/data_in_code/code_signature/SuperBlob/unix_thread/dyld_chained_fixups/dyld_exports_trie/STRINGTABLE)，ELF缺STRINGTABLE，字符串搜索缺8项(MapMode/FileType/跳转Hex/跳转Disasm/Demangle/编辑字符串/保存结果/默认长度5)，可视化缺5项(ZEROS_GRADIENT/TEXT_GRADIENT/高亮/缩放/保存图片)，提取器缺3项(HEURISTIC/深度扫描/分析模式)，扫描日志缺1项。全部一次性实施。
- [2026-08-09] 为Phase 12新增17个后端单元测试：visualization.rs(ZerosGradient/TextGradient)、macho_viewer.rs(read_uleb128/data_in_code_kind_name/code_slot_type_name/count_exports_in_trie/parse_string_table)、pe_viewer.rs(pe_subsystem_name/pe_machine_name/parse_nt_headers_minimal/parse_nt_headers_not_pe)、elf_viewer.rs(string_table_entry_serialization/extraction_logic)、string_extractor.rs(map_mode_default/file_type_default/params_default_min_length/extract_with_map_mode_file)。总测试数597→614。
