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

## 2026-08-15: diec CLI 与上游差距评估

### 分析过程
- 查阅 COMPATIBILITY.md：规则加载 1186/1186=100%，差分测试 31+20 样本 0 引擎不匹配，CLI 14+ 选项全部 ✅，Host API 全部 ✅
- 查阅 capability-matrix.md：68 个 CAP-* 能力在 Linux Qt5/Qt6 和 Windows 全部 Observed
- 查阅 cli-special-modes.md：--entropy/--info/--struct/--showstructs 上游行为已完整记录
- 查阅 ROADMAP.md Phase 4：CLI 标记 DONE，仅 --test/--createtest 未实现（上游也 TODO）
- 查阅 diec-cli/src/main.rs：确认 --struct <value> 模式未实现（仅有 --showstructs 列表）
- 查阅 nested-scan-behavior.md：上游 -r 启用 resource/overlay 内部递归，diec -r 仅做目录递归
- 查阅 diec-engine/src/scanner.rs：确认无 archive 成员解包、无 resource/overlay 递归扫描实现

### 结论
diec CLI 缺口远小于 GUI。缺口分两类：
1. diec 自身实现缺口（来自 diec）：
   - --struct <value> 模式未实现（CAP-CLI-MODE-003）
   - resource/overlay 内部递归扫描未实现（-r 语义与上游不同）
   - archive 成员解包递归扫描未实现（上游 release CLI 也未暴露，但 engine 有能力）
2. 非 diec 缺口（来自规则版本/测试范围/平台）：
   - 规则版本差异（submodule 规则比上游 3.21 bundled 更新，非引擎 bug）
   - macOS 平台 68 项 platform-missing（测试基础设施缺口）
   - 大型语料覆盖不足（31 基线样本 vs 上游 68 CAP-* 项）
   - --test/--createtest 未实现（上游也标记为 TODO/no-op）

## 2026-08-15: Phase 13 规划分析

### 分析过程
- 并行启动 4 个调研子代理：--struct 模式、resource/overlay 递归、archive 解包、测试覆盖
- 调研结果汇总：
  1. --struct：中等复杂度，约 15-20 工作日，通用方法 4 个 + 格式专用方法 11 个
  2. resource/overlay：高复杂度，-r 语义冲突需破坏性变更，PE resource 枚举需新建
  3. archive 解包：高复杂度，5 种格式，RAR 有许可证问题
  4. 测试覆盖：macOS 中等（17 个脚本已存在），语料高（42 个新样本）

### RAR 许可证调研
- 上游 XArchive 直接翻译 UnRAR 源码（94.21% token 覆盖）标注 MIT，未保留 UnRAR notice
- diec-rust 已明确不复制/翻译/改写 XArchive RAR decoder
- 纯 Rust RAR 库调研：
  - rars (bitplane)：WTFPL + "don't blame me"，纯 Rust，覆盖 RAR 1.5-7
  - weaver-unrar (scryer-media)：GPL-3.0-or-later，copyleft，与项目要求冲突
  - unrar crate：UnRAR C 库包装器，需 native 依赖
- 用户决策：使用 rars (WTFPL)，需 ADR 0029 记录

### 决策记录
- -r 语义：对齐上游（破坏性变更），目录递归迁移到 --recursive-dir
- archive 解包：全部 5 种格式纳入，RAR 用 rars (WTFPL)
- macOS + 语料：纳入本 Phase

### Phase 13 结构
- 8 个子任务：13.1-13.8
- 3 个 ADR：0028/0029/0030
- 退出条件：差分测试 0 不匹配，macOS 68 项闭合，语料覆盖 68 CAP-* 项

## 2026-08-23: 兼容性阻断 6 问题根因分析（Phase 14 输入）

### 问题 1：PE 规则 TypeError: not a function（阻断）
- 根因：crates/diec-rules/src/host_api_bridge.rs PE bridge 不完整
  - PE.isResourceGroupNamePresent / PE.isResourceGroupIdPresent 未实现
  - PE.section 数组在 host_api_bridge.rs:2253 硬编码为空 []，未填充区段数据
    （上游 db/PE/_init:147-163 应填充 Number/Name/VirtualSize/VirtualAddress/FileSize/FileOffset/Characteristics）
  - PE.resource 数组在 host_api_bridge.rs:2361 硬编码为空 []
  - PE.nLastSection 在 host_api_bridge.rs:2252 硬编码 -1，应为 getNumberOfSections()-1
  - bridge JS 代码块在 _init 脚本之后执行，覆盖了 _init 填充的数据
- 影响规则：compiler_RealBasic.4.sg、cryptor_404crypter.1.sg、installer_DockerDesktopInstaller.1.sg、
  protector_Adept_Protector.2.sg 等（部分在 db_extra）
- 差分测试盲区：差分测试未含 db_extra 规则；样本不含触发资源组特征的 PE

### 问题 2：ELF 规则 ReferenceError: _B is not defined（阻断）
- 根因：host_api_bridge.rs:3046-3509 ELF 方法定义闭包缺少 `var _B = Binary;`
  - PE 闭包（行 2079）正确定义 _B，ELF 闭包（行 3048）遗漏
  - ELF 辅助函数 _sectionName/_sectionNumber/_libraryNames 使用 _B.__elfSectionNames() / _B.__elfImportLibraries()
  - _B 在 ELF 上下文未定义 → ReferenceError
- 影响规则：所有 ELF compiler/library 规则（compiler_Borland_Kylix/DMD/Free_Pascal/Go/Rust/gcc、library_GLIBC/Curl/FFmpeg）
- 差分测试盲区：corpus_differential.rs 样本不含 ELF 文件（仅 test.7z/jpg/rar/random.bin）

### 问题 3：--alltypes 格式误报（阻断）
- 根因：scanner.rs:427-437 --alltypes 模式直接返回 all_rule_types()（18 种全部），
  完全忽略 ProbeTable 探测结果
  - 上游 bIsAllTypesScan 语义：先 getFileTypes 探测，仅为兼容/容器类型额外执行父类型规则
    （PE→MSDOS、APK→JAR/ZIP），不执行不相关格式规则
  - diec-rust 对 ELF 跑 DEX/JPEG/PDF/PNG/JavaClass/PYC 规则 → 字节模式偶然匹配 → 误报
- 差分测试盲区：--alltypes 测试只验去重和检测数量，未验"不相关格式不应产生检测"；
  样本为构造的最小 PE，未用真实 ELF 如 /usr/bin/ls

### 问题 4：JSON 输出格式不兼容（非阻断）
- 根因：crates/diec-output/src/json.rs:29-150 设计为自有结构
  - 顶层 detections vs 上游 detects；扁平 vs values[] 嵌套
  - type_name 小写（archive/packer）vs 上游首字母大写（Packer/Protector）
  - 缺 string 字段（上游 "Packer: UPX" 含前缀）
  - 无上游兼容模式或 --output json-die 选项

### 问题 5：glibc 2.34+ 要求（非阻断）
- 根因：Rust 1.88+（2025-06）预编译 std 链接 glibc 2.34+ 符号
  - rustup stable 产物即使 ol7 编译仍要求 2.34/2.35
  - nightly + build-std=std 可产出 glibc 2.16 产物
- 文档缺陷：README 未说明 glibc 最低版本

### 问题 6：Go 绑定 Scanner.ScanBytes（非阻断）
- 根因：bindings/go/diec/diec.go:214-233 Scanner.ScanBytes 调用 cgo_scan_bytes（one-shot）
  - 缺 cgo_scanner_scan_bytes / cgo_scanner_scan_path_utf8 helper
  - FFI 侧 diec_v1_scanner_scan_bytes 已实现，仅 Go 绑定层缺失

### 共性根因：差分测试覆盖盲区
- 未含 db_extra 规则（PE 阻断规则多在 db_extra）
- 未用真实系统二进制（/usr/bin/ls、/usr/bin/bash）做 ELF 差分
- --alltypes 测试无"负向断言"（不相关格式不应检测）
- COMPATIBILITY.md 声称与实际不符（PE host API "完整实现"实则 section/resource 数组空）

### Phase 14 规划方向
- P0 阻断修复：ELF _B 注入（1 行级修复）、PE section/resource/nLastSection 填充 + 缺失方法、--alltypes 探测前置过滤
- P0 差分测试加固：纳入 db_extra、真实系统二进制、--alltypes 负向断言
- P1 兼容性增强：上游兼容 JSON 输出（--output json-die）、Go 绑定 reusable scanner
- P1 文档：glibc 要求 + build-std 指南、COMPATIBILITY.md 纠正
- ADR 需求：--alltypes 语义对齐上游（可能破坏性）、json-die 兼容输出

## 2026-08-23: v0.9.0 真实数据差分验证 — host API 语义错误分析

### 问题确认（代码位置已核实）

1. **`getSectionNameCollision(s1, s2)`** — `host_api_bridge.rs:3654`
   - 当前实现：遍历节名，检查字面值 `s1.toLowerCase()` / `s2.toLowerCase()` 是否等于完整节名，两者都找到则返回 `s1`
   - 上游规则用法（VMProtect.2.sg:29）：`var sCollision = PE.getSectionNameCollision("0", "1"); if (PE.isSectionNamePresent(sCollision + "1"))`
   - 正确语义：找到两个节名，一个以 `s1`（"0"）结尾、一个以 `s2`（"1"）结尾，且有共同前缀，返回该**共同前缀**。例：`oiNRhy0` + `oiNRhy1` → 返回 `oiNRhy`
   - 影响规则：VMProtect（2 样本漏检）、BattlEye、ENIGMA、GenericHeuristicAnalysis

2. **`getImportFunctionName(n)`** — `host_api_bridge.rs:3570`
   - 当前实现：只接受 1 个参数，返回 `_peParseImports().functions[n].name`（全局扁平列表第 n 个函数）
   - 上游规则用法（packer_UPX.2.sg:15）：`PE.getImportFunctionName(0, 0) == "LoadLibraryA"` — 2 个参数（库索引, 函数索引）
   - 正确语义：返回第 `libraryIndex` 个库的第 `functionIndex` 个导入函数名
   - 影响规则：UPX（isPatchedUPX 失败）、NsPack、AlushPacker、cryptor_Huan、cryptor_EXECryptor、compiler_RADBasic、protector_StarForce、protector_Private_EXE_Protector、protector_NTkrnl_Protector、protector_ENIGMA

3. **`getNumberOfImportThunks()`** — `host_api_bridge.rs:3575`
   - 当前实现：不接受参数，返回 `_peParseImports().functions.length`（全部库函数总数）
   - 上游规则用法（packer_UPX.2.sg:9）：`PE.getNumberOfImportThunks(0)` — 1 个参数（库索引）
   - 正确语义：返回第 `libraryIndex` 个库的导入函数数量
   - 影响规则：与问题 2 相同的规则集

### 数据结构根因

`PeBatchInfo`（`pe_native.rs:710`）将导入存储为两个独立扁平数组：
- `libraries: Vec<String>` — 去重后的库名列表
- `functions: Vec<String>` — 所有库的所有函数扁平列表

该结构**丢失了函数与库的归属关系**，无法支持按库索引查询函数。修复需扩展为按库分组结构（如 `imports: Vec<(String, Vec<String>)>` 或 `library_functions: Vec<Vec<String>>`）。

### 方法论根因

Phase 15 host API 覆盖率审计（`tools/audit_host_api.py`）仅验证"方法名存在"，未验证"参数签名与语义与上游一致"。覆盖率 100% 不等于语义正确率 100%。需将"参数签名对照"纳入审计标准。

### D2 差分指标

| 指标 | 结果 | 门槛 | 状态 |
|------|------|------|------|
| packer 类检测一致率 | 21/24 (87.5%) | 100% | ❌ |
| protector 类检测一致率 | 20/24 (83.3%) | 100% | ❌ |
| packer 类检测不一致率 | 1/24 (4.2%) | < 5% | ✅ |
| protector 类检测不一致率 | 2/24 (8.3%) | < 5% | ❌ |

> 指标含义：对 24 个已知 packer/protector 样本，比较 diec-rust 与上游 DIE
> 对 packer/protector 类检测的二元决策（检测到 vs 未检测到）一致性。

### Phase 16 规划方向

- P0 语义修正：3 个 host API 方法（getSectionNameCollision / getImportFunctionName / getNumberOfImportThunks）
- P0 数据结构扩展：PeBatchInfo 按库分组导入函数
- P1 差分测试加固：真实 packer/protector 语料（VMProtect/UPX/NsPack/ENIGMA 等）
- P1 审计标准升级：host API 审计纳入参数签名对照
- ADR 需求：PeBatchInfo 数据结构变更（内部结构，非公共 API，可能无需 ADR）

## 2026-08-23: 真实语料大规模差分扫描分析

### 扫描方法
- 工具：`tools/diff_scan_corpus.py`，对比 diec-rust v0.9.0 与上游 diec 4.0.0
- 语料：`/data/virus/{pe,elf}_{benign,malicious}`（~40 万文件）
- 归一化：filetype PE32/PE64 → PE，type 取小写，version 原样保留
- 上游 diec 加载 db + db_extra（-D + -C 选项）

### packer/protector 漏检分析（10 例，全部 diec-rust 漏检）

| 名称 | 样本数 | 根因 |
|------|--------|------|
| VMProtect | 5 | 问题 7：getSectionNameCollision 语义错误 |
| UPX | 1 | 问题 8/9：getImportFunctionName/getNumberOfImportThunks 参数错误 |
| Enigma | 1 | 问题 7：ENIGMA 规则也用 getSectionNameCollision |
| Bat To Exe Converter | 1 | 待调查：检查 packer_BatToExeConverter 规则 |
| PyInstaller | 1 | 待调查：检查 packer_PyInstaller 规则 |
| ASProtect | 2 | 待调查：检查 protector_ASProtect 规则 |

### 非 packer 差异分析

**diec-rust 漏检（上游多检测）**：
- .NET Framework 版本（4 例）：diec-rust 只输出 CLR 版本，缺少 .NET Framework 版本号（如 "4.7.2"）
- ELF Rust compiler（24 例）：ELF Rust 编译器检测完全缺失
- MSVC "by EP" 版本（19 例）：入口点版本推断逻辑差异
- OpenGL library（3 例）：OpenGL 库引用检测缺失
- AutoIt format（1 例）：AutoIt 格式检测缺失

**diec-rust 过度检测（diec-rust 多检测）**：
- Records debug data（5 例）：diec-rust 多检测 debug data 记录
- Windows Authenticode（4 例）：diec-rust 多检测签名工具
- TASM32 compiler（3 例）：diec-rust 多检测 TASM32 编译器
- XerinFuscator protector（1 例）：diec-rust 误检 protector

**表面差异（不影响检测能力）**：
- Unknown 占位（32-52 例）：上游输出 "Unknown" 占位检测，diec-rust 不输出
- 版本格式差异（Borland Delphi/Go/MPRESS 等）：版本范围推断算法不同

### ELF 差异分析
- packer/protector 一致率 100%（ELF 无 packer/protector 漏检）
- 检测一致率低（24-48%）主要由 Unknown 占位和 Rust compiler 漏检导致
- 修复 Rust compiler 漏检 + Unknown 占位后，ELF 一致率应大幅提升

### 修复优先级
- P0：问题 7-9（VMProtect/UPX/Enigma 漏检）— 已有明确修复方案
- P1：.NET Framework 版本、ELF Rust compiler、ASProtect — 影响检测能力
- P2：过度检测项、版本格式差异、Unknown 占位 — 不影响核心检测能力

## Phase 16 host API 语义修复分析（2026-08-23）

### 根因分析

v0.9.0 发布后大规模差分测试发现 8 个 host API 语义问题，根因可分为 3 类：

1. **返回值类型/语义错误**（4 个）：
   - `getResourceSection()` 返回文件偏移而非节索引
   - `read_uint32`/`U32`/`readDword` 返回 u32 被 rquickjs 截断为 i32
   - `isImportPositionHashPresent` 使用 FNV-1a 而非上游的 CRC32C
   - 资源条目返回 RVA 而非文件偏移

2. **数据解析不完整**（2 个）：
   - 导入函数只读 OFT，OFT=0 时全部丢失（加壳 PE 常见）
   - 资源目录只解析 2 层，缺少第 3 层（language 级）

3. **参数签名不匹配**（3 个）：
   - `getSectionNameCollision` 检查字面值而非共同前缀
   - `getImportFunctionName` 只接受 1 参数而非 2
   - `getNumberOfImportThunks` 不接受参数

### 修复效果

packer/protector 检测一致率从 98.4% 提升至 **100%**（500 个 PE 恶意样本），
所有 10 个 P0 漏检样本（VMProtect/UPX/Enigma/PyInstaller/Bat To Exe Converter）
全部修复。

### Phase 16.7 非 packer 检测差异修复（2026-08-23 续）

#### 修复的问题

1. **Unknown 占位检测**（39 次差异）：
   - 上游引擎在无检测时自动添加 "Unknown" 占位
   - 在 `scan_bytes` 和 `Scanner::scan_bytes` 末尾添加 Unknown 占位逻辑

2. **`$` 相对偏移跳转**（21+ 次差异）：
   - `$` 在签名中不是通配符，而是相对偏移跳转标记
   - `$$$$$$$$` (8 个 `$`) = 读取 4 字节有符号整数，计算跳转目标
   - 在 `compareEP` 中实现 PE-aware 的签名匹配（`_peCompareSigWithJumps`）
   - 使用 `OffsetToRVA` + `_peRvaToFileOffset` 进行 RVA↔offset 转换

3. **`getResourceNameOffset` 返回值**（3 次过度检测）：
   - 找不到资源名时返回 0 而非 -1
   - 规则用 `!== -1` 判断，0 被误认为找到
   - 修正为返回 -1

#### 修复效果

| 指标 | 修复前 | 修复后 |
|------|--------|--------|
| pe_malicious 检测一致率 | 81.8% | **93.6%** |
| pe_malicious packer 一致率 | 100% | **100%** |
| pe_benign 检测一致率 | 67.0% | **73.0%** |
| pe_benign packer 一致率 | 100% | **100%** |

#### 第四轮修复（cleanString + getAddressOfEntryPoint）

1. **`File.cleanString` no-op 修复**：
   - 上游 `XBinary::cleanString` 只保留字母、数字和标点
   - diec-rust 的 `cleanString` 是 no-op，导致控制字符残留
   - .NET Framework 版本 "4.7.2\x01" 被 `append("CLR 4.0.30319")` 后
     变成 "CLR 4.0.30319" 而非 "4.7.2, CLR 4.0.30319"
   - 修复：实现 `cleanString` 过滤非字母数字/标点字符

2. **`PE.getAddressOfEntryPoint` 语义修复**：
   - 上游返回 `ImageBase + AddressOfEntryPoint`（虚拟地址）
   - diec-rust 返回 `AddressOfEntryPoint`（RVA）
   - 当 EP RVA=0 时，上游返回 ImageBase（非0），我们返回 0
   - 导致 `archive_Resources.6.sg` 的 `EP == 0` 条件误触发
   - 修复：返回 `_peImageBase() + _peEntryPoint()`

#### 修复效果

| 指标 | 修复前 | 修复后 |
|------|--------|--------|
| pe_malicious 检测一致率 | 81.8% | **93.8%** |
| pe_benign 检测一致率 | 67.0% | **93.0%** |
| packer 一致率 | 100% | **100%** |

### 对齐方法论深刻反思（2026-08-23）

用户要求分析为什么反复对齐仍有大量差异。分析发现 7 个根因：

1. 覆盖率审计验证"存在性"不验证"语义正确性"
2. 签名语法理解错误且被测试"确认"
3. 上游隐式行为未文档化只能源码考古
4. 合成样本不触发边界条件
5. 过度检测与漏检需要不同发现策略
6. 上游规则本身有 bug
7. 对齐是 O(n) 问题但验证是 O(n×m×k) 问题

详见 `doc/alignment-retrospective.md`。

### 上游 Bug 记录（2026-08-23）

用户要求将上游 DIE-engine 的已知 bug 记录下来。已创建
`doc/upstream-bugs.md`，记录 5 个上游 bug：

1. `PE.isNET()` 未定义（5 个规则抛异常，上游静默忽略）
2. `archive_Resources.6.sg` 循环条件逻辑错误（被返回值语义掩盖）
3. `format_bin.Nintendo-certified-file.1.sg` `const` 重声明
4. 上游引擎静默忽略规则异常
5. 空签名 "Invalid signature" 错误

AGENTS.md 第 12 条已更新，要求所有上游 bug 记录到
`doc/upstream-bugs.md`，发现新 bug 时追加。

## 2026-08-24: Free Pascal 版本检测 + Zip 归档检测回归修复

### 根因分析

Free Pascal 版本缺失和 Zip 归档检测丢失的根因是**缺少规则优先级排序**。

上游 DIE-engine 使用 `sort_signature_prio` 按优先级（文件名倒数第二段数字）
排序规则。diec-rust 的 `database.rs` 有 TODO 但未实现，规则按目录遍历顺序
（等价于字母序）执行。

#### 执行顺序差异示例

优先级排序后（正确）：
1. compiler_Delphi.4.sg → includeScript("Borland") → nOffset=1531904, bBorlandC=0
2. library_LCL.5.sg → includeScript("FPC") → nOffset=1646556, bFPC=true
3. _linkers.6.sg → includeScript("FPC")(跳过,bFPC已设), includeScript("Borland")(跳过,bBorlandC已设)
4. compiler_Free_Pascal.6.sg → includeScript("FPC")(跳过) → nOffset=1646556 ✓

字母序（错误）：
1. compiler_Borland_C++.6.sg → Borland → nOffset=1531904
2. compiler_Free_Pascal.6.sg → FPC → nOffset=1646556
3. _linkers.6.sg → FPC(跳过), Borland(跳过,bBorlandC已设) → nOffset=1646556
4. library_LCL.5.sg → FPC(跳过,bFPC已设) → nOffset=1646556
   但某些情况下顺序不同导致 nOffset 被 Borland 覆盖

#### var 作用域误区

之前错误地认为 Qt Script 的 `var` 在 includeScript 中有局部作用域，实现了
save/restore 机制。通过 DIE-engine 调试追踪确认：Qt Script 中 `var x = val`
在全局作用域**确实修改全局变量**，与 QuickJS 的间接 eval 行为一致。"保护"来自
`if (typeof x === "undefined")` 守卫模式，而非 `var` 作用域。

### 修复内容

1. **database.rs**: 实现优先级排序（`extract_priority` + `sort_by`），在读取
   文件内容之前排序以避免索引错位
2. **backend_rquickjs.rs**: 移除错误的 save/restore 机制，简化 includeScript
3. **backend_rquickjs.rs**: 移除 load_database 中的规则源码预评估，改为
   evaluate_rule_source 中的 IIFE 按需评估
4. **backend_rquickjs.rs**: evaluate_rule 委托给 evaluate_rule_source
5. **conformance.rs**: 更新测试以匹配新行为（无 detect 函数返回空结果而非错误）

### 验证结果

- PE malicious 50 样本：98% 匹配（1个 Costura.Fody/DNGuard 差异）
- PE malicious 200 样本：99.5% 匹配（1个 Records debug data 差异）
- PE benign 200 样本：99.5% 匹配（1个 NTkrnl Protector 差异）
- ELF benign 100 样本：96% 匹配（4个版本字符串细微差异）
- 所有 workspace 测试通过，clippy 无警告
- 2026-10-08：定位并修复最后 3 类差异（getLanguage C/C++ 映射、ZIP
  EOCD verified 后缀边界、COFF 字符串表节名→DWARF），差分收敛至 0。

## 2026-10-03 Phase 26 分析
- 三个壳同构（自定义位流解码 + PE rebuild），aPLib 原位解压需共享缓冲区 API 规避借用冲突；MEW 合成流终止字节 0x18（非 0x10）；Petite 为 op-table 驱动 + _doubledl 哨兵位流。所有样本用可重复生成器构造并先经上游 oracle 验证才入库。意外收获：oracle 差分暴露 nEntryPointSection 应为 VA 空间反向查找而非文件偏移，修正后 86 文件 0 差异。

## 2026-10-03 Phase 27 NsPack 分析
- XNSPACK 为 LZMA 变体二进制 range coder：自适应 u16 概率表(init 0x400)、
  literal/match/rep 三类路径、damian 位置状态、oldback×3 历史距离。
- 编码侧逆运算用 LZMA SDK 式 cache/carry shiftLow，literal-only 流可完整构造。
- 上游 _detect 分 2.x(E9 redirector+差值定位) 与 1.4/3.x(_findStartOfStuff
  needle=dsize==sec0.vsize) 两路；OEP 经 loader 尾部 61 9D E9 扫描。
- _deFilterCallJmp 双路径：control 无效→naive 全量逆滤波；有效→marker-gated。
- _reconstructImports 描述符流(marker=记录长自校验)+DLL 名池 KERNEL32.DLL 锚定，
  合成 .idata + IAT 回填；stub 头双布局(1.4 dword/3.x qword 字段距)。
- 偏差：dsize 256MiB 硬上限（上游 -1 无限），对齐 XASPACK 同款守卫语义。

## 2026-10-03 Phase 28 分析
容器提取器属 XStaticUnpacker 记录枚举语义（非 PE 重建），集成点为
archive_unpack 的显式 list/extract 路径；上游 FT_FLAG_STATICUNPACKERS
opt-in 且嵌套扫描不递归容器，故 is_archive/extract_archive 保持闭集。
节名大写化是潜伏偏差：此前语料无小写敏感表条目故差分未暴露，新增
enigmavb/boxedapp fixture 后浮现；修复后 109 文件 0 差异验证无回归。

## 2026-10-03 Phase 29 分析
上游 XBinary 引擎侧仅 7 算法；XHashWidget 扩展集（含 TLSH）在
未检出 submodule，TLSH 采用 tlsh2 纯 Rust 移植并以官方向量验证，
不再走"自实现"预案。RIPEMD-128 "abc" 记忆向量有误，经空串官方
向量 + openssl 交叉验证确认 crate 正确（教训：向量必须实测核对）。

## 2026-10-03 Phase 31 分析
`run_nfd_pass` 抽出 `nfd_scan_opts`/`nfd_scan` 复用层，merged scan
与独立 NFD 面板共享同一映射；hex_edit 会话复用
`edit_bytes_at_offset` 的原位写语义（.bak/越界/上限），撤销栈仅
内存态、capped，undo 直写避免自压栈。测试暴露 temp_file 同尺寸
命名冲突与共享目录 remove_dir_all 竞态，改为原子序号独立子目录。
上游 XHexView 编辑即时落盘可逆，会话层在命令侧补齐同等语义。
109 文件 NFD 差分 0 差异确认重构无回归。

## 2026-10-03 Phase 32 分析
- 逐一考古上游 xarj/xlha/xace/xcpio 的 _readEntry/_collectBlocks/
  infoCurrent，移植枚举语义而非仅签名探测（ACE 需完整块链校验：
  16 位头 CRC、recovery 唯一且末尾、flag 一致性）。
- 上游 unpackCurrent 对记录做 RESULTCRC 校验：ARJ=CRC32(标准)、
  LHA=CRC16/ARC 数据校验、ACE=CRC32 无 final xor、CPIO 无校验。
  合成样本必须填真 CRC 否则上游也解不出（假 CRC 曾致
  unpacked:false 误判）。
- LHA 记录无 mtime、ARJ dir 记录不设 ISFOLDER——均按上游
  infoCurrent 实际属性集对齐，非按格式规范想象。
- UDF/WIM 按 gate 跳过：上游 isValid 要求 AVDP 链/查找表+XML，
  无系统工具可生成合法样本。

## 2026-10-03 剩余项规划分析
- 修正 Phase 32 误判：上游 Algos 含 xarjdecoder/xacedecoder/
  xlzhdecoder/xlha_legacy 完整解码器，oracle 失败是假压缩流，
  压缩方法实为可立项项（编码器镜像法生成合法语料）。
- InstallSimple 永久不可行：XEmulator 非 submodule 也未检入
  pin 树，无源码无 oracle。
- SSDeep 上游在 XHashWidget（pin 291e3ef6 未检出）——可按
  SHA 提取 oracle，否则参考实现+ADR 修订。
- 粒度按 ≤3-4k 上游行/phase 拆 8 个 phase（33-40）。

- 2026-10-03 Phase 33 续：ACE 解码器（uac_dcpr.c）核心为 DWORD LE MSB-first 位读取器 + 非稳定 quicksort 驱动的 makeCode 直接查找表 + meta-Huffman delta 宽度编码 + LZ77 环缓冲（old_dist[4]）；码表派生对同宽符号排序敏感，生成器必须逐字镜像 sortRange/makeCode 才能产出确定性合法流。TECH.PARM 低半字节 + 10 = 字典位宽，经 SecondaryRecord.window_size 透传。ARJ method-4 为 decodeLen/decodePtr 的 unary(前导1计数)+定宽后缀格式，无 blockSize 头；生成器按 token→(n 个1,0?,n 位后缀) 反编码。

## 2026-10-04 Phase 35（LHA legacy + LZHUF）

需求：补齐 LHA 全部剩余压缩方法。移植上游 `xlha_legacy_*`（lhasa/dearkmodule 移植链，ISC 许可）与 `xlzhufdecoder`（Okumura LZHUF 自适应 Huffman）。
要点：(1) `_methodToHandle` 分派——`-lzs-`/`-lz5-`/`-lhx-`/`-lk7-`/`-pm1-`/`-pm2-`→legacy 驱动、`-lh1-`→LZHUF、`-lh0-`/`-lz4-`/`-pm0-`/`-lhd-`→stored；(2) `-lk7-` 仅由 level-1 + OS 0x20 + `-lh7-` 头经 LHARK 重映射产生，裸 `-lk7-` 标签上游不识别；(3) LZHUF 解码 `c += bit; c = son[c]` 选的是位置槽——编码端从 `prnt[leaf]` 起链，叶子边不占位（此前生成器多发一位导致上游拒绝）；(4) PM1 强收尾 copy 块、PM2 自适应树重建阈值、各环缓冲预填值均属可观察语义须逐字保留。

## 2026-10-04 Phase 38（SSDeep）

分析：先核查上游——`upstream/DIE-engine/dep/Formats/xbinary.h` 的 HASH 枚举仅 MD4/MD5/SHA1/SHA2 家族；临时检出 XHashWidget@291e3ef6 仅含 dialoghash/hashprocess 薄封装，无 fuzzy 代码。结论：ADR 0039 v1"上游实现有偏差"的前提不成立，改为 pin 之上扩展。GPL 阻断由 clean-room 实现规避（按 CTPH 算法描述编写，ppdeep 独立验证）；native `ssdeep` crate 维持拒绝（native+GPL 双重问题）。实现要点：7 字节滚动窗触发、双通道摘要（64/32 字符上限）、短摘要减半重试语义、rh==0 尾部 last_char 兜底——均从 ppdeep 语义镜像，9 组向量含块边界/高熵/halving 路径全 parity。

## 2026-10-05 Phase 39（非 x86 反汇编）

分析：ADR 0041 两项阻断均被解除——(1) native 依赖争议由"上游自身即 capstone"正当化（dep/XCapstone/3rdparty/Capstone 含 capstone 5.0 源码+预建静态库，diec-rules 已用 capstone 0.14 做 getDisasmString）；(2) 用户显式要求落地即"维护者决定"复审触发条件。capstone crate bundled 构建避免逐 ISA 的碎片化纯 Rust 移植（yaxpeax-mips 休眠、无 PPC 实现）。DM_RISKVC 是唯一非常规映射：上游只传 CS_MODE_RISCVC 不带 32/64 位，经 Capstone::new_raw+ExtraMode 逐位复刻。oracle 直接链接上游 vendor .a，模式位/端序任何接线漂移都会在 77 指令快照上显形。

## 2026-10-05 Phase 40（收尾）

分析：i18n 用 node eval 真实解析 resources 对象比对——ru/de/fr 各缺 239 键（此前扫描器漏报 zh-CN 引号键名），补齐后 5×269 键全等；ADR 0038 的"增量覆盖、不批量转换 .ts"结论维持。归档视图发现真实缺口：UDF/WIM 在 Phase 36/37 只接了 list_secondary/extract_secondary，`list_secondary_members` 的 kind 映射漏掉两个新变体导致 GUI 归档页静默跳过——补映射并加 corpus 回归。XStyles 为 Qt 专属体系，作为永久平台差异记录；InstallSimple（XEmulator 不在 pin）与 tauri updater（ADR 0019 产品决策）维持不立项。

## 2026-10-05 Phase 41-44 立项分析

四项剩余差距的可行性核查：(1) WIM 压缩流——上游有完整 xlzxdecoder(954)+xxpressdecoder(388)，LZX BLOCK_UNCOMPRESSED=3 块可简易编码做 oracle fixture，XPRESS 编码器可手写，立项中型；(2) MSDOS stubs——compareEP/compareOverlay 等继承 Binary_Script 基类，只需实现 XMSDOS::getEntryPointOffset/getOverlayOffset 语义 + capstone x86-16 getDisasmNextAddress，立项中型；(3) 剩余 DM 模式——capstone 后端已具备，~30 模式纯接线+快照，立项小；(4) demangler——上游 XCppfilt(GNU cp-demangle/d-demangle/rust-demangle)，当前 msvc-demangler 标注精简实现，先跑 oracle 差异评估再定移植粒度。不立项维持：i18n 其余 17 语言（ADR 0038 增量）、RNC old 变体（语料缺口非代码）、InstallSimple/XStyles/更新器。
