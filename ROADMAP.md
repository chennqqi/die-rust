# Roadmap

本路线图按“先建立事实，再冻结设计，最后实现”的顺序推进。阶段状态使用：

- `TODO`：尚未开始。
- `IN PROGRESS`：正在进行。
- `DONE`：退出条件已满足并完成评审。

## Phase 0：上游调研与设计门禁 — DONE

设计门禁已于 2026-07-31 评审通过并关闭。五份调研正文、五份设计正文和十四个有效
ADR 全部 Accepted；六项 blocker 中五项 closed，`P0-BLOCK-005`（macOS 运行时基线
采集）deferred 至 Phase 1 与 Rust 实现并行完成。评审输入见
[`docs/design/phase-0-gate-review.md`](docs/design/phase-0-gate-review.md)。

在本阶段完成前，不开始正式功能开发。允许编写调研工具、上游构建脚本、基线采集工具、测试语料基础设施和验证性原型；验证性原型不得直接视为正式架构或稳定 API。

### 调研交付物

- `docs/research/upstream-baseline.md`
  - 固定的 DIE-engine commit SHA。
  - 构建方式、工具链、依赖和全部 submodule。
  - Linux、Windows、macOS 可重复运行环境。
  - 主仓库、子模块、规则和样本的许可证清单。
- `docs/research/capability-matrix.md`
  - CLI/engine 能力和参数。
  - 支持的文件格式、扫描模式和递归/嵌套行为。
  - 输出字段、检测类别、规则类别和优先级。
  - 每项能力对应的源码位置或可重复实验。
- `docs/research/source-analysis.md`
  - 上游模块关系和 Qt 耦合点。
  - 扫描、格式识别、规则加载和执行调用链。
  - 数据模型、缓存、并发及资源管理方式。
- `docs/research/rule-compatibility.md`
  - 规则目录、完整语法和内建函数。
  - 宿主数据访问模型、执行语义及异常行为。
  - 解释执行、编译或转换方案的可行性比较。
  - 原始规则同步、哈希和溯源方案。
- `docs/research/behavior-baseline.md`
  - 代表性测试语料。
  - 固定上游版本的原始输出。
  - 规范化规则、确定性和平台差异。

### 设计交付物

- [`docs/design/architecture.md`](docs/design/architecture.md) — Accepted
  - Cargo workspace、模块职责、依赖方向和数据流。
  - 可扩展点、资源限制与明确非目标。
- [`docs/design/api.md`](docs/design/api.md) — Accepted
  - 纯 Rust API、CLI 契约、结果及错误模型。
  - 取消、超时、并发和资源限制。
- [`docs/design/c-abi.md`](docs/design/c-abi.md) — Accepted
  - ABI 版本、导出函数和结构布局。
  - 不透明句柄状态机、内存所有权和线程安全。
  - panic 隔离、allocator 和静态链接策略。
- [`docs/design/testing.md`](docs/design/testing.md) — Accepted
  - 测试语料、上游 oracle 和差分算法。
  - 已知差异 allowlist 规则。
  - fuzz、benchmark 和 CI 平台矩阵。
- `docs/design/decisions/`
  - 记录影响长期兼容性、依赖或公共接口的 ADR。
- [`docs/design/risks.md`](docs/design/risks.md) — Accepted
  - 每项风险包含处理策略、触发条件和验证方式。

### 必须回答的问题

- “能力相同”具体比较哪些字段、层级、顺序、置信度和错误行为？
- DIE-engine、Detect-It-Easy 及其 submodule 中哪些内容属于兼容范围？
- 上游规则依赖哪些语法、内建函数和宿主 API？
- 容器嵌套、递归扫描、启发式检测、熵、哈希、字符串及反汇编的行为和资源上限是什么？
- 上游 CLI 在 Linux、Windows、macOS 上是否具有一致的输入输出和退出码？
- Rust 静态链接涉及哪些 runtime、panic、allocator、TLS、系统库和 native 依赖？
- C、Go 和 Python 调用方需要一次性扫描 API、低层句柄 API，还是两者都需要？
- 测试样本如何合法、安全、可重复地获得和保存？
- 性能基线、基准硬件、冷/热缓存条件和峰值内存目标是什么？

### 技术验证

- 规则运行时 spike：执行覆盖复杂语法的代表性上游规则。
- C 静态链接 spike：Windows/Linux x64 的 `.lib`/`.a`、C 调用、结果读取、
  正确释放、panic containment 和 CRT 依赖已完成首轮验证，见
  [`docs/research/c-static-link-spike.md`](docs/research/c-static-link-spike.md)；
  正式 ABI 及其他平台仍待设计和验证。
- 上游 oracle：自动运行固定版本上游并保存原始及结构化基线。

### 退出条件

- 能力矩阵的每一项都有源码证据或可重复实验。
- 基线语料覆盖主要格式和代表性规则语法。
- 三项技术验证完成，或明确记录不可行点及替代设计。
- 架构、规则引擎、ABI 和测试方案均完成书面权衡与评审。
- 风险清单完整。
- 后续每个开发阶段都有可测量的完成条件。

## Phase 1：工程骨架与兼容测试基础设施 — DONE

- 创建 Cargo workspace 和单向依赖边界。
- 建立格式化、lint、测试和跨平台 CI。
- 建立上游规则同步、来源清单和完整性校验。
- 建立测试语料生成/获取、基线保存和差分报告工具。
- 冻结首版内部结果模型，公共 ABI 仍保持实验状态。
- 完成 `P0-BLOCK-005` deferred 项：macOS 运行时基线采集。✅ 已关闭：17 个
  candidate report 已在 Darwin x86_64 主机采集、校验、sanitize 并提交至
  `docs/research/data/macos-qt5/`；`cli-privilege-paths` 因需 passwordless
  sudo 而 deferred（diec 不负责系统权限管理）。

退出条件：三大桌面平台 CI 通过；规则和上游基线可重复获取；差分框架能对最小样本给出可审计报告。

Phase 1 已于 2026-07-31 关闭。Cargo workspace 8 crate 骨架 + 依赖 DAG 校验、
跨平台 CI（default 1.97.1 + MSRV 1.88）、Rust 执行收集器 + 端到端差分审计、
规则同步/来源 manifest/完整性校验均已交付。`P0-BLOCK-005` macOS 运行时基线
已关闭，17 个 candidate report 采集至 `docs/research/data/macos-qt5/`。
macOS runtime benchmark（5 case warm baseline）、macOS deployment size、
Rust 成对 benchmark（2 case）和 Rust deployment size 已完成并提交至
`docs/research/data/`。

## Phase 2：核心数据模型与格式识别 — DONE

- 实现受控字节读取和通用扫描上下文。
- 按能力矩阵逐步实现格式探测与解析。
- 为畸形、截断和整数边界输入建立测试及 fuzz targets。
- 与上游逐格式进行差分验证。

退出条件：本阶段范围内的能力矩阵全部通过差分测试，没有未解释的崩溃、无界分配或非确定性。

Phase 2 已于 2026-07-31 关闭。受控字节读取层（ADR 0013 fail-closed）覆盖
MemorySource/OwnedSource/FileSource/ChunkedSource/EmptySource + read_exact_at +
typed integer reads + checked arithmetic。格式探测框架（FormatProbe trait +
ProbeError + ProbeTable versioned ordered probe table）注册 20 个 probe，覆盖
CAP-DISPATCH-001 至 007 全部组：PE/MSDOS、ELF32/64、Mach-O 32/64/FAT/FAT64、
DEX/Java Class/PYC、PDF/CFBF、ZIP/RAR/7Z/GZIP/TAR/ISO9660/CAB、JPEG/PNG/BMP/WAV。
PE/ELF/Mach-O 提取 header 字段（machine/class/data/osabi/e_type/cputype/
filetype）作为下游规则匹配元数据。测试覆盖：每个格式有 positive/truncated/
malformed/boundary/empty/fuzz/differential cases（见
[`docs/design/phase2-format-test-matrix.md`](docs/design/phase2-format-test-matrix.md)）。
3 个 cargo-fuzz targets + 11 个 property tests + 5 个 corpus differential tests。
总计 211 个测试全部通过，cargo fmt/clippy/check-deps 零警告。

## Phase 3：规则兼容运行时 — DONE

- 原样加载固定版本上游规则。
- 实现或集成经 Phase 0 验证的规则执行方案。
- 完整覆盖规则语法、内建函数和宿主数据访问接口。
- 对未知或不支持语法产生明确诊断，不静默忽略。

退出条件：目标规则集全部可加载；代表性语料的规则结果达到已定义的兼容标准；剩余差异均有精确记录和回归用例。

**完成状态**：1186/1186 规则加载成功（100%）；6 个端到端检测测试通过；
此前 2 个失败均已修复：
1. `Binary/format_bin.Nintendo-certified-file.1.sg`（上游规则 bug：`const` 重声明）—
   通过 `const` → `var` 预处理修复，匹配 Qt Script 行为。
2. PE 规则需 PE 专属 API — 通过原生 `pelite` 解析实现完整 PE host API 修复。
rquickjs 后端 + Binary host API bridge + 签名解析器 + 完整 PE/ELF/Mach-O 原生解析完成。

- 原样加载固定版本上游规则。
- 实现或集成经 Phase 0 验证的规则执行方案。
- 完整覆盖规则语法、内建函数和宿主数据访问接口。
- 对未知或不支持语法产生明确诊断，不静默忽略。

退出条件：目标规则集全部可加载；代表性语料的规则结果达到已定义的兼容标准；剩余差异均有精确记录和回归用例。

## Phase 4：CLI — DONE (2026-08-01)

- 实现薄 CLI 层，不复制核心扫描逻辑。
- 支持稳定的结构化输出和人类可读输出。
- 定义参数、退出码、递归扫描及资源限制行为。
- 与上游 CLI 进行跨平台差分验证。

**进展**：
- diec-engine 扫描编排层完成（Database + Scanner + BufferHost）
- diec-output JSON/text/XML/CSV/TSV 渲染完成（无 serde 依赖）
- diec-cli 参数解析 + 退出码 + 多目标批量扫描 + 递归扫描完成
- CLI 扫描控制标志：--deepscan, --heuristicscan, --verbose, --aggressivescan, --alltypes, --hideunknown
  - 标志通过 ScanFlags → BufferHost → HostApi 传递到规则运行时
  - --alltypes 运行所有文件类型规则（匹配上游 bIsAllTypesScan）
  - --hideunknown 过滤空名和 "Unknown" 检测
- CLI 输出控制：--format（格式化空格）、--profiling（计时）、--messages（诊断输出）
- CLI 专用模式：--entropy（Shannon 熵）、--info（文件信息）
- CLI 数据库功能：--extradb、--customdb（多数据库合并）、--showdatabase（规则统计）、--showstructs（结构方法列表）
- 5 种输出格式：text（默认）、json、xml、csv、tsv
- 文件类型检测 + 误报过滤：使用 ProbeTable 分发规则，匹配上游 scanProcess 行为
  - 可执行格式（PE/ELF/MACH/MACHOFAT）仅运行格式特定规则
  - 非可执行格式运行格式特定 + Binary 规则
  - Java Class 优先于 Mach-O FAT 检查（解决 CAFEBABE 歧义）
- ELF host API 完整实现（30+ 方法，真实 ELF 解析替代 stub）
- Mach-O host API 完整实现（25+ 方法，真实 Mach-O 解析替代 stub）
- PE host API 完整实现（30+ 方法，真实 PE 解析 + 40+ stub 方法）
- 所有格式全局对象独立化（__proto__ = Binary，避免方法覆盖）
- const→var 预处理（匹配 Qt Script 行为，修复 SyntaxError）
- 端序方法补全（read_uint16/32/64_le/be）
- 27 个语料库文件诊断数降为 0
- 差分测试：corpus_differential.rs 27 文件全部通过
- 扫描性能优化：按文件类型共享 runtime（8x 加速，~1s/文件）
- 24 个 CLI 集成测试覆盖输出格式、扫描标志、专用模式、退出码、递归扫描、数据库查询
- 374 个测试全部通过，cargo fmt/clippy/check-deps 零警告

**尚未实现**（低优先级，不影响核心功能）：
- --test、--createtest 测试入口（上游也标记为 TODO）

退出条件：能力矩阵中当前范围的 CLI 功能完成；自动化输出契约和错误行为有集成测试。

## Phase 5：C ABI 与语言集成 — 完成

- 提供带版本的稳定 C ABI 和公共头文件。
- 提供一次性扫描和/或句柄 API。
- 构建 Unix-like `.a` 与 Windows `.lib`/`.dll`。
- 提供 C、Go/cgo 和 Python ctypes/cffi 集成测试或最小示例。

**完成项**：
- 公共头文件 `include/diec.h` 完成（ABI 版本协商、状态码、opaque handle、scan options）
- `diec-ffi` crate 实现完整 C ABI：
  - ABI 版本协商：`diec_abi_version`、`diec_abi_is_compatible`
  - 状态码查询：`diec_v1_status_name`
  - Scan options：`diec_v1_scan_options_init`（repr(C) 结构体，additive extension）
  - Database builder：`diec_v1_database_builder_new/add_path_utf8/build/free`
  - Database：`diec_v1_database_metadata_json/free`
  - Cancel token：`diec_v1_cancel_new/request/free`
  - One-shot scan：`diec_v1_scan_bytes/scan_path_utf8`（thread-neutral）
  - Reusable scanner：`diec_v1_scanner_new/scan_bytes/scan_path_utf8/free`
  - Result accessors：`diec_v1_result_json/path_utf8/detection_count/free`
  - Error accessors：`diec_v1_error_status/message/free`
  - Panic containment：所有 FFI 函数通过 `catch_unwind` 捕获 panic
  - Pointer-to-pointer free：配对释放，double-free 安全
- 构建产物：`diec_ffi.lib`（staticlib）+ `diec_ffi.dll`（cdylib）
- 语言绑定：
  - Go/cgo 绑定 (`bindings/go/diec/`)：Database、Scanner、Result、ScanBytes、ScanPath，5 个测试通过
  - Python ctypes 绑定 (`bindings/python/diec.py`)：Database、Result、scan_bytes、scan_path，9 个测试通过
  - C smoke test (`tests/c/smoke.c`) 验证完整扫描流程
- 35 个 FFI 测试（7 单元 + 12 集成 + 16 sanitizer）覆盖：
  - 完整生命周期（build → scan → verify → cleanup）
  - Double-free 安全（所有 handle 类型）
  - Null 指针验证（所有 accessor）
  - 错误句柄查询和释放
  - Scan options 边界（null、小 size）
- 411 个测试全部通过，cargo fmt/clippy 零警告

退出条件：内存所有权、并发、错误码和 panic 隔离均通过测试；目标平台完成静态链接 smoke test。✅

## Phase 6：兼容性、性能与发布准备 — 已关闭 (2026-08-05)

- 扩大差分测试语料和跨平台矩阵。
- 建立持续 fuzz 和历史回归语料。
- 依据固定基准优化运行时间和峰值内存。
- 完成许可证、归属、供应链和发布物审计。
- 发布首个具备兼容性报告的版本。

**进展**：
- Benchmark 基础设施：
  - `crates/diec-engine/benches/scan.rs`：scan_corpus（9 种格式）、scan_flags（default/heuristic/all_types/deep）、database_load
  - `crates/diec-formats/benches/probe.rs`：probe_corpus（13 种格式）、probe_table 构造
  - 使用 criterion 0.5，harness=false
- 边缘语料差分测试：
  - `tools/corpus/generate_edge_corpus.py`：20 个边缘样本（truncated/malformed/oversized/empty）
  - `crates/diec-engine/tests/edge_corpus.rs`：3 个测试（no-crash、no-spurious、no-hang）
  - 验证截断/畸形输入不崩溃、不误检、不挂起
- FFI 跨平台 CI：
  - `.github/workflows/ci.yml` 新增 ffi-smoke job（Linux/macOS/Windows C smoke test）
  - 新增 python-binding job（Linux/macOS/Windows Python ctypes test）
  - Windows FFI smoke test 使用 DLL import library 链接，无需手动指定系统库
- 许可证和供应链审计：
  - `LICENSE`：MIT 许可证文件
  - `NOTICES.md`：第三方归属（上游 DIE-engine、QuickJS、Capstone、pelite、goblin、所有 Rust 依赖）
  - `AUDIT.md`：供应链安全审计（依赖策略、CI 安全、已知风险）
  - `cargo license --all-features` 验证：无 copyleft 许可证
- 459 个测试全部通过，cargo fmt/clippy 零警告，0 TODO/FIXME
- 原生 PE/ELF/Mach-O 解析重构：使用 pelite（PE）和 goblin（ELF/Mach-O）替换手写 JavaScript 解析
  - 新增 pe_native.rs、elf_native.rs、macho_native.rs 三个模块
  - PE：imports/exports/resources/manifest/version info/.NET/Authenticode/overlay
  - ELF：DT_NEEDED/sections/entry point/image base/overlay
  - Mach-O：LC_LOAD_DYLIB/sections/segments/entry point/image base/overlay
  - PE batch 解析：一次 pelite pass 返回所有 PE 信息，JS 端 JSON.parse 缓存
  - 消除逐字节 JS→Rust FFI 往返，提升性能和正确性
- 扩展差分测试语料：31 个基线样本（含 PE resources/.NET、ELF deps、Mach-O dylib）
- Fuzz 种子语料：165 个种子文件覆盖 6 个 fuzz targets
- 性能优化：database_load 从 ~1.2s 优化到 ~510ms（并行文件 I/O via std::thread::scope）
- Capstone 集成：PE.getDisasmString/getDisasmNextAddress 使用 Capstone 反汇编
  - thread-local 缓存 Capstone 实例，避免重复初始化
- 格式特定规则分发优化：已识别格式不再运行 Binary 规则，避免重复检测
- PDF/JPEG/DEX/CFBF/JavaClass/PYC 版本解析：从文件头解析格式版本号
- PDF HeaderComment 检测：解析 PDF 注释行
- JavaClass 不再运行 Binary 规则（host API 已完整实现）
- Fuzz targets 扩展（6 个）：
  - `fuzz_byte_source`、`fuzz_byte_view_subview`（diec-core 层）
  - `fuzz_format_probe`（diec-formats 层）
  - `fuzz_scan_engine`（diec-engine 层，default/heuristic/all_types 三种 flag）
  - `fuzz_output_render`（diec-output 层，JSON/text/XML/CSV/TSV 渲染）
  - `fuzz_scan_ffi`（diec-ffi 层，C ABI 边界 + double-free 安全）
- 兼容性报告 `COMPATIBILITY.md`：
  - 规则加载兼容性（1186/1186 = 100%）
  - 语料差分测试矩阵（31 基线 + 20 边缘样本，0 不匹配）
  - CLI 功能兼容性清单
  - C ABI 兼容性清单
  - Host API 兼容性清单（含 Capstone 反汇编）
  - 性能基线数据（PE32 ~89ms、ELF64 ~15ms、Mach-O ~14ms）
  - 测试统计（459 个测试）
- **ADR 0016：同一 file_type 的规则运行时跨文件复用**（Accepted）：
  - `Scanner` 有状态对象，per-file_type runtime 缓存 + `reinit` 重置 host 别名
  - 持久状态审计：框架 `result()` 重置全局变量，复用安全
  - 差分验证：复用 vs 非复用 0 不匹配
- **ADR 0017：died (die daemon) HTTP/JSON 扫描服务层**（Accepted）：
  - `GET /health`、`POST /scan/path`、`POST /scan/bytes` 三个端点
  - `Database::version()` 从 manifest 加载 commit/synced_at
  - 安全边界：allow_root、max_file_size、max_request_size、scan_timeout
  - Windows 服务安装/卸载（sc.exe 集成）
  - 打包：DEB（cargo-deb）、RPM（spec）、MSI（cargo-wix）
  - API 文档含 curl/PowerShell/Python/Go 客户端示例
- 测试统计更新：477 个测试（+14 个 Scanner/Database version/Server 集成测试）

**退出条件达成情况**：
- ✅ 既定兼容指标：规则加载 100%，差分测试 0 不匹配
- ✅ 性能目标：database_load < 600ms（实际 ~510ms），scan_corpus < 250ms
- ✅ 发布检查：cargo fmt/clippy/test 全部通过，构建产物完整
- ✅ 已知差异均公开、精确且可复现：4 个规则版本差异已记录在 COMPATIBILITY.md

退出条件：既定兼容指标、性能目标和发布检查全部满足；已知差异均公开、精确且可复现。✅ (2026-08-05)

**关闭记录**：
- v0.3.0 已 tag 并发布（annotated tag，commit `ca656ea79`，4 平台发布物已上传并验证）
- 退出条件全部达成：规则加载 100%，差分 0 引擎不匹配，database_load ~510ms < 600ms
- Fuzz 收尾：种子语料回放（165 seeds × 6 harnesses）在 stable Rust 上 7 测试 0 失败；
  覆盖引导 libFuzzer 5 min/target 委托给 CI fuzz workflow（`.github/workflows/fuzz.yml`）
- 文档收尾：COMPATIBILITY.md / AUDIT.md / RELEASE.md 已按实际状态修正并签字

**发布准备**：
- 双语 README：`README.md`（英文默认）+ `README.zh-CN.md`（中文）
- 多平台构建发布 workflow：`.github/workflows/release.yml`
  - 4 个构建目标：Linux x86_64、Windows x86_64、macOS arm64、macOS x86_64
  - tag 触发自动构建并发布到 GitHub Releases
  - 发布物包含 CLI、FFI 库、C 头文件、规则数据库、语言绑定
- 规则分发策略 ADR 0012：打包固定快照 + `--customdb`/`DIEC_DB_PATH` 覆盖
- CLI 数据库搜索路径增强：`DIEC_DB_PATH` 环境变量 + 可执行文件相邻 `db/` 目录
- 发布说明模板 `RELEASE_NOTES.md`

## Phase 7：维护与上游同步 — 进行中

Phase 6 关闭后进入维护阶段，目标是在不破坏兼容基线的前提下持续跟进上游
DIE-engine 规则与 host API 变化，并保持发布物健康度。

- **上游规则同步**：定期将 `upstream/Detect-It-Easy` subtree 更新到新的上游
  commit，记录来源 commit、哈希和时间；同步后重跑差分测试矩阵，确认 0 引擎
  不匹配或新增差异均用 ADR 记录。
- **CI fuzz 持续化**：`.github/workflows/fuzz.yml` 在每次 push 到 main 和 PR
  上运行 6 个 target 的覆盖引导 fuzz（5 min/target）；发现崩溃立即隔离、修复
  并补充回归种子。
- **发布节奏**：按需发布 patch/minor 版本；每次发布前过一遍 `RELEASE.md`
  检查清单并更新 `COMPATIBILITY.md` 性能基线与测试统计。
- **依赖与供应链**：定期审查 `cargo license`、`cargo audit`，更新 `NOTICES.md`
  和 `AUDIT.md`；新依赖遵守最低发布 7 天和许可证策略。
- ~~**GUI 前置调研**~~：已完成。上游 Qt GUI 源码分析见
  [`docs/research/upstream-gui-analysis.md`](docs/research/upstream-gui-analysis.md)，
  框架选型 ADR 0018（Tauri v2）和 Phase 8 设计文档已交付。

### 当前进展快照

- **上游规则同步**：`upstream/Detect-It-Easy` 为 vendored subtree（非 submodule），
  固定到 commit `8925358d2`（2026-10-01 同步；DIE-engine 基线 `23fec32ca`）。
- **种子语料回放**：165 seeds × 6 harnesses，`cd fuzz && cargo test --no-default-features --features replay`。
- **发布物**：v0.3.0（4 平台：Linux/Windows/macOS arm64/macOS x86_64），含 CLI、died、FFI 库、C 头文件、规则数据库、语言绑定。
- **Benchmark 基础设施**（criterion 0.5）：scan_corpus、scan_flags、database_load、probe_corpus。
- **边缘语料差分测试**：20 个边缘样本 + 3 个测试（no-crash/no-spurious/no-hang）。
- **FFI 跨平台 CI**：ffi-smoke job + python-binding job（Linux/macOS/Windows）。
- **许可证和供应链审计**：LICENSE、NOTICES.md、AUDIT.md。
- **6 个 fuzz targets**（core/formats/engine/output/ffi 层）+ 165 个种子语料。
- **兼容性报告** COMPATIBILITY.md、发布检查清单 RELEASE.md（v0.3.0 已签字）。
- **database_load 优化**：1.2s → 510ms（并行文件 I/O）。
- **原生 PE/ELF/Mach-O 解析重构**：使用 pelite（PE）和 goblin（ELF/Mach-O）替换手写 JavaScript 解析。
  - 新增 `pe_native.rs`、`elf_native.rs`、`macho_native.rs` 三个模块。
  - PE batch 解析：一次 pelite pass 返回所有 PE 信息，JS 端 JSON.parse 缓存。
  - PE32 扫描性能：73ms → 89ms（含原生 resource/manifest/version info 解析）。
  - ELF64 扫描性能：19ms → 15ms。
  - Mach-O 64 扫描性能：18ms → 14ms。
- **规则加载** 1186/1186 = 100%（此前 1184/1186 = 99.83%）。
- **差分测试** 31 基线 + 20 边缘样本，0 不匹配。
- **477 个测试全部通过**，cargo fmt/clippy 零警告，0 TODO/FIXME。
- **ADR 0016**：Scanner per-file_type runtime 跨文件复用（Accepted）。
- **ADR 0017**：died (die daemon) HTTP/JSON 扫描服务层（Accepted）。
  - 三个端点：/health、/scan/path、/scan/bytes。
  - Windows 服务安装/卸载 + DEB/RPM/MSI 打包配置。
  - API 文档含 curl/PowerShell/Python/Go 客户端示例。

退出条件：无固定退出条件；维护阶段持续直到项目所有者决定启动 GUI 阶段或
停止维护。

## Phase 8：GUI（Tauri v2）— DONE (2026-08-06)

用 Tauri v2 实现功能对齐上游 `die` 完整 GUI 的图形界面程序 `die-gui`，
覆盖扫描、签名浏览、目录扫描、Hex 查看器、Demangle、设置、多语言和主题
等全部功能。

### 实现进展

- **7A-0**（DONE）：`die-gui` crate 骨架（Tauri v2 + React 18 + TypeScript）
- **7A-1**（DONE）：前端依赖安装 + `cargo tauri build --no-bundle` 端到端构建通过
- **7A-2**（DONE）：GUI 应用启动验证（修复窗口 label + 数据库路径解析）
- **7A-3**（DONE）：功能验证 — 文件选择 → 扫描 → 检测结果显示
- **7A-4**（DONE）：拖放支持 + 停止扫描 + 设置持久化 + 目录扫描
- **7B**（DONE）：高级功能 — Hex 查看器 + 反汇编器（iced-x86）+ Demangle（cpp_demangle + rustc-demangle）+ 签名浏览器
- **7C**（DONE）：扩展功能 — YARA 扫描（yara-x）+ PEID 扫描 + 在线威胁情报查询
- **7C-extended**（DONE）：内存映射视图 + 归档视图 + 数据转换器
- **7B-enhanced**（DONE）：签名浏览器增强（搜索/编辑/Run/Debug/Profiling）
- **i18n**（DONE）：react-i18next 全量接入，en/zh-CN 完整翻译，ru/de/fr 部分翻译
- **BUG fixes**（DONE）：i18n 接入 + db 路径解析（exe-relative）+ 控制台黑框 + favicon
- **CI**（DONE）：die-gui 构建加入 release workflow（三平台：Windows/Linux/macOS）
- **差分测试**（DONE）：gui_cli_differential 测试 2/2 通过（GUI vs CLI 0 不匹配）
- **ADR 0019**（Accepted）：tauri-plugin-updater 自动更新 deferred 到 Phase 8 之后

### 调研与设计交付物

- [`docs/research/upstream-gui-analysis.md`](docs/research/upstream-gui-analysis.md)：
  上游 `die`/`diel`/`diec` 三变体的程序结构、功能清单、组件依赖和交互流程
  分析，固定到 `DIE-engine@ab0ea3e`。
- [`docs/design/decisions/0018-tauri-gui-framework.md`](docs/design/decisions/0018-tauri-gui-framework.md)：
  Tauri v2 框架选型 ADR（Accepted）。选择 Tauri v2 而非 egui/Slint/Iced/GTK-rs，
  理由：Web 前端 UI 表达力强、Rust 后端直接调用核心库、二进制体积小、
  跨平台 CI 对齐。
- [`docs/design/phase8-gui.md`](docs/design/phase8-gui.md)：Phase 8 GUI 设计文档
  （Proposed），含 IPC 架构、功能规格（7A 核心 + 7B 高级 + 7C 扩展）、
  测试策略和实现顺序（Accepted）。

### 功能范围

**7A 核心扫描 GUI**（对标 diel + die 基础）：

- 主窗口：文件输入、拖放、Recent files、Advanced 切换、全屏、单实例
- 扫描 widget：结果树（String/Signature/Info 3 列）、Flags/Databases 下拉、
  Scan/Stop、异步扫描 + Channel 进度、耗时显示、复制结果、上下文菜单
- 设置持久化：View/File/Scan/Database/Engine 分类，JSON 持久化

**7B 高级功能**（对标 die 完整 GUI）：

- 签名浏览器：签名树、源码查看/编辑、运行/调试单个签名、文本搜索
- 目录扫描：选择目录、批量扫描、子目录递归、结果累积、清除/保存
- 签名 Profiling：每签名耗时、排序
- Hex 查看器：Hex dump、偏移/ASCII/Hex 列、搜索、跳转
- Demangle：C++ 符号 demangle（Itanium/MSVC ABI）
- Options 对话框：扫描引擎/签名搜索/Hex/反汇编/在线工具/InfoDB 选项
- 多语言：react-i18next，对齐上游 XTranslation 支持的语言
- **7B-8 主题样式（与上游 1:1 对齐）**：CSS 变量，light/dark/system + 自定义；对齐上游 QSS 主题 `orange_fix` / `Fusion`
- **7B-8-1 主题自动跟随系统（默认）**：默认使用 `system` 主题，根据操作系统外观在亮色/暗色间自动切换，与上游 `View` → `STYLE` 默认行为对齐
- 快捷键：Open/Exit/Fullscreen 全局 + Hex/Disasm/Table 分组
- 自动更新：tauri-plugin-updater，GitHub Releases 签名更新

**7C 扩展功能**（需独立 ADR）：

- 反汇编视图（Capstone，ADR 0019）、YARA 规则（ADR 0020）、PEID 签名
  （ADR 0021）、NFD 视图（ADR 0022）、在线工具（ADR 0023）
- 熵视图、哈希视图、内存映射视图、区段视图、符号表视图、归档视图、
  数据转换器、提取器

### 退出条件

- 功能对齐上游 `die` 完整 GUI（7A + 7B）— ✅ 达成（自动更新按 ADR 0019 deferred）
- 三平台（Linux/Windows/macOS）构建通过 — ✅ CI 已配置三平台 die-gui 构建
- GUI 扫描结果与 CLI 差分 0 不匹配 — ✅ `gui_cli_differential` 测试 2/2 通过
- `cargo fmt --check` + `cargo clippy --workspace --all-targets --all-features -- -D warnings` 通过 — ✅
- `cargo test --workspace --all-features` 通过 — ✅ 480 个测试全部通过
- 7C 扩展功能可 deferred 到后续 Phase — ✅ 大部分已实现，NFD 视图/提取器 deferred

**退出条件全部达成 (2026-08-06)。**

## Phase 9：GUI 上游对齐增强 — DONE

Phase 8 GUI 发布后，对照 `docs/research/gui-upstream-diff.md` 中识别的差异，
分三个优先级批次完成与上游 DIE-engine GUI 的深度对齐。

### Phase 9.1 P1 核心修复（7 项）— DONE

- ~~**ScanDetection 扩展可选字段**~~：已完成。新增 id/parentId/file_part/offset/
  size/is_heuristic/is_a_heuristic/original_name 字段，贯穿 scanner.rs、runtime.rs、
  backend_rquickjs.rs、json.rs、xml.rs、handlers.rs、commands.rs 及前端
- ~~**数据库选择接线**~~：已完成。scan_file 接收 database_paths 参数，
  新增 list_database_paths IPC 命令，前端 Databases 下拉框生效
- ~~**文件类型覆盖接线**~~：已完成。scan_file 接收 file_type override，
  前端 Type 下拉框生效
- ~~**options 直接显示**~~：已完成。检测树中直接显示 options 字符串，
  不再仅显示计数
- ~~**启发式标记**~~：已完成。检测名称中显示 `(Heur)` / `(A-Heur)` 标记
- ~~**嵌套结果树**~~：已完成。基于 id/parentId 构建嵌套树，
  显示 file_part/offset/size
- ~~**Hex viewer 重写**~~：已完成。虚拟滚动、hex/ASCII 模式搜索、
  jump-to-offset、复制功能。新增 search_bytes/read_hex_range 函数 + 9 个测试
- ~~**Disassembler 修复**~~：已完成。移除 break-on-Ret，多架构支持
  （x86/x64 via iced-x86 instr_info、ARM/ARM64 via yaxpeax），arch 参数，
  默认 max_bytes 提升至 4096，label/comment/jump_target 字段 + 8 个测试

### Phase 9.2 P2 完整度增强（7 项）— DONE

- ~~**9.2.1 Hex 数据检查器 + Follow in Disasm**~~：已完成。点击 hex 行加载 32 字节
  到数据检查器面板（uint8/16/32/64、int8/16/32/64、float32/64、ASCII），
  "Follow in Disasm" 按钮跳转到反汇编标签页
- ~~**9.2.2 Disasm 交叉引用视图 + Analyze All**~~：已完成。跳转/调用注释可点击跟进，
  交叉引用摘要显示标签地址的 xref 计数，"Analyze All" 按钮反汇编 64KB 范围
- ~~**9.2.3 PE 解析增强**~~：已完成。parse_pe_sections 新增 imports 提取
  （goblin pe.imports），导入符号以 "DLL.function" 格式显示
- ~~**9.2.4 Mach-O FAT 支持**~~：已完成。detect_format 识别 0xCAFEBABE /
  0xBEBAFECA magic，返回 "Mach-O FAT" + 7 个格式检测单元测试
- ~~**9.2.5 诊断信息结构化**~~：已完成。新增 Diagnostic 结构（file/line/message/kind），
  JSON/XML 输出包含结构化诊断，前端以表格展示（file/kind/line/message 列）
- ~~**9.2.6 Profiling 数据**~~：已完成。新增 SignatureProfile 结构（file/elapsed_ms），
  Scanner 用 Instant::now() 跟踪每规则耗时，JSON/XML/前端均展示
- ~~**9.2.7 符号表虚拟滚动**~~：已完成。移除 .slice(0, 500) 限制，
  可滚动容器 + 粘性表头（maxHeight 400px），显示完整符号总数

### Phase 9.3 P3 对齐扩展（6 项）— DONE

- ~~**9.3.1 扫描进度事件**~~：已完成。scan_file/scan_bytes_cmd 接收
  tauri::AppHandle，emit "scan_progress" 事件（loading_database/scanning/complete），
  前端监听并显示阶段化进度文案
- ~~**9.3.2 多语言**~~：Phase 8 已覆盖 en/zh-CN/ru/de/fr，无需扩展
- ~~**9.3.3 Hex 数据类型切换**~~：已完成。HexViewer 新增 element mode 下拉
  （Byte/Word/DWord/QWord），formatHexByMode 按小端序重分组字节
- ~~**9.3.4 Disasm Follow in Hex**~~：已完成。Disassembler 新增 "Follow in Hex"
  按钮，HexViewer 接收 initialOffset 并滚动到对应行，实现 Hex ↔ Disasm 双向联动
- ~~**9.3.5 CRC32 哈希**~~：已完成。新增 crc32fast 依赖，FileHashes 增加 crc32 字段
  （8 位大写 hex）
- ~~**9.3.6 熵块大小可配置**~~：已完成。EntropyView 新增块大小下拉
  （64B/128B/256B/512B/1KB/4KB），切换时重新获取熵图数据

### 退出条件

- `cargo fmt --check` + `cargo clippy --workspace --all-targets --all-features -- -D warnings` 通过 — ✅
- `cargo test --workspace --all-features` 通过 — ✅ 506 个测试全部通过
- 前端 `tsc --noEmit` + `vite build` 通过 — ✅
- GUI-CLI 差分测试 2/2 通过 — ✅

**退出条件全部达成。**

## Phase 10：已知问题修复与文档纠正 — DONE

Phase 9 完成后，README.md "Known Limitations" 节列出三个已知问题。
经调查，其中两个为文档过时（代码已修复，README 已加删除线标注但未清理），
一个为真实功能缺陷。本 Phase 旨在清理文档并修复真实缺陷。

调研依据：
- `crates/diec-rules/src/host_api_bridge.rs` 第 4447-4636 行（Capstone 集成）
- `crates/diec-rules/Cargo.toml` 第 12 行（capstone 0.14.0 依赖）
- `COMPATIBILITY.md` 第 53-67 行（4 个规则版本差异详情）
- `crates/diec-engine/src/scanner.rs` 第 39-168 行（detect_rule_types 去重策略）
- `crates/diec-engine/src/scanner.rs` 第 385-516 行（scan_bytes 自由函数）
- `crates/diec-engine/src/scanner.rs` 第 603-747 行（Scanner::scan_bytes 缓存版）
- `crates/diec-engine/src/scanner.rs` 第 224-246 行（all_rule_types 全类型列表）
- `crates/diec-engine/src/host.rs` 第 22-39 行（ScanFlags 结构体）
- `crates/diec-ffi/src/scan.rs` 第 70-99 行（DiecScanOptions C ABI 结构体）
- `crates/diec-ffi/src/scan.rs` 第 136-159 行（options_to_flags 位映射）
- `include/diec.h` 第 51-58 行（DIEC_SCAN_FLAG_* 宏定义，已用 6 位 0x01-0x20）
- `crates/diec-cli/src/main.rs` 第 35-39 行（CLI flags 帮助文本）
- `crates/diec-cli/src/main.rs` 第 153-158 行（CLI flags 解析）
- `crates/diec-server/src/handlers.rs` 第 14-49 行（ScanFlagsRequest DTO）
- `crates/die-gui/src/commands.rs` 第 53-102 行（ScanFlagsDto GUI DTO）
- `crates/diec-engine/src/scanner.rs` 第 248-284 行（ScanDetection 结构体，14 字段）

### 10.1 文档清理：getDisasmString 已集成 Capstone — DONE

**问题**：README.md 第 33-35 行已有删除线标注 "Fixed in Phase 6"，但
条目仍残留在 "Known Limitations" 节中，应清理为正面描述或移除。

**现状**：
- `crates/diec-rules/src/host_api_bridge.rs` 第 4447-4636 行：完整实现
  `disasm_at_va` 函数，使用 Capstone 0.14.0 反汇编 x86/x64 指令
- Thread-local 缓存 Capstone 实例（32/64 位分别缓存）
- 支持 Intel 语法输出
- 完整的 VA → 文件偏移转换逻辑（PE section 映射）
- 4 个单元测试覆盖（INT3/PUSH/next address/invalid VA）
- `COMPATIBILITY.md` 第 129-130 行已正确标记 ✅
- `NOTICES.md` 已记录 Capstone 许可证归属
- README.md 已加 `~~删除线~~` 标注，但未清理条目

**修复**：
- 从 README.md "Known Limitations" 节移除 getDisasmString 条目（已非 limitation）
- 更新 `doc/requirements.md` 第 814 行，将"需引入 capstone-rs 才能修复"
  改为"已在 Phase 6 集成 Capstone 0.14.0 解决"
- 添加集成测试验证 PELock/Arxan/VMProtect/GenericHeuristic 规则
  在含保护器特征的 PE 样本上能正常检测

### 10.2 文档清理：规则版本差异已记录且非引擎 bug — DONE

**问题**：README.md 第 36-39 行已有删除线标注 "Documented, not an engine
bug"，但条目仍残留在 "Known Limitations" 节中，应清理或移至正面描述。

**现状**：
- vendored subtree 固定到 commit `8925358d2`（2026-10-01 同步，前基线 `c2c17dfa5`）
- 上游 DIE 3.21 发布于 2026-04-22（`upstream/Detect-It-Easy/changelog.txt`）
- 4 个差异均为"新规则检测到更多"而非"引擎行为不同"：
  - `minimal.apk` / `minimal.jar` / `payload.zip`：新规则检测 archive:Zip:2.0
  - `minimal.pyc`：新规则检测 Python bytecode
- `COMPATIBILITY.md` 第 53-67 行已完整记录，标记为 "NOT engine bugs"
- `COMPATIBILITY.md` 第 159 行：D001 差异项已归档
- README.md 已加 `~~删除线~~` 标注，但未清理条目

**修复**：
- 从 README.md "Known Limitations" 节移除此条目（已非 limitation）
- 可选：在 README.md 新增 "Known Differences (Non-Defects)" 小节，
  简述规则版本差异并指向 `COMPATIBILITY.md` § Mismatch Details
- 可选：同步上游最新规则到 3.21 release tag 以消除差异（但会丢失新规则
  的检测能力，需 ADR 记录决策）

### 10.3 功能修复：检测结果去重 — DONE

**问题**：scanner.rs 无结果层去重逻辑，`--alltypes` 模式下多个 file_type
组的检测结果直接 push 到同一 Vec，可能产生重复条目。例如 PE 文件同时
匹配 PE 和 MSDOS 规则，两组均输出 "MS-DOS" format 检测。

**现状**：
- `detect_rule_types`（第 39-168 行）通过选择性运行规则避免大部分重复：
  - PE/ELF/MACH 只运行格式特定规则，不运行 Binary 规则
  - Java Class 只运行 JavaClass 规则
  - 非可执行格式只运行格式特定规则
  - 存档格式（ZIP/APK/JAR/RAR）例外，同时运行格式特定和 Binary 规则
- `--alltypes` 模式（第 404-405 行 / 第 620-621 行）运行所有 18 种
  file_type 规则（`all_rule_types()` 第 224-246 行），无去重
- 上游 DIE-engine 同样无结果层去重（通过 `bIsAllTypes` 标志控制）
- `ScanDetection` 结构体有 14 个字段（第 248-284 行），其中 `file_type`
  记录来源规则组而非检测本身
- 无专门的重复检测测试

**设计决策（ADR 0027）**：

去重键：`(type_name, name, version, options, offset, size)` — **排除
`file_type`**。原因：`--alltypes` 下跨 file_type 重复是核心问题（如 PE
和 MSDOS 均输出 "MS-DOS"），包含 `file_type` 在键中会使跨组重复无法被
捕获。`signature_path` 同理排除（不同规则文件可产生相同检测）。

保留策略：保留首次出现的检测，丢弃后续重复项。规则按 file_type 字典序
执行（BTreeMap 迭代顺序），首次出现来自更精确的格式特定规则组。

默认行为：**默认去重**，`--no-dedup` / `DIEC_SCAN_FLAG_NO_DEDUP` 可关闭
以匹配上游原始行为。此为对上游的主动改进（上游 `--alltypes` 输出含重复
条目），需 ADR 0027 记录偏离理由。

**影响链（6 层，自底向上）**：

1. **ScanFlags 结构体**（`crates/diec-engine/src/host.rs` 第 22-39 行）：
   新增 `no_dedup: bool` 字段，默认 `false`（即默认去重）
2. **scanner.rs 去重逻辑**（`scan_bytes` 第 509 行前 / `Scanner::scan_bytes`
   第 740 行前）：在 `hide_unknown` 过滤后、构造 `ScanResult` 前插入去重步骤
3. **CLI**（`crates/diec-cli/src/main.rs`）：新增 `--no-dedup` 参数解析
   + 帮助文本
4. **FFI C ABI**（`crates/diec-ffi/src/scan.rs` + `include/diec.h`）：
   新增 `DIEC_SCAN_FLAG_NO_DEDUP = 0x40`（第 7 位，当前已用 0x01-0x20），
   `options_to_flags` 函数新增 `0x40` 分支
5. **Server DTO**（`crates/diec-server/src/handlers.rs` 第 16-35 行）：
   `ScanFlagsRequest` 新增 `no_dedup: bool` 字段 + `From` impl 映射
6. **GUI DTO**（`crates/die-gui/src/commands.rs` 第 62-88 行）：
   `ScanFlagsDto` 新增 `no_dedup: bool` 字段 + `From` impl 映射

**实现任务（按依赖顺序）**：

1. 创建 ADR 0027：记录去重偏离上游的决策、去重键设计、默认行为
2. `ScanFlags` 新增 `no_dedup` 字段（`crates/diec-engine/src/host.rs`）
3. 实现去重函数 `dedup_detections(&mut Vec<ScanDetection>)`（`scanner.rs`）
   - 去重键：`(type_name, name, version, options, offset, size)`
   - 使用 `HashSet` 跟踪已见键，`retain` 保留首次出现
   - 在 `scan_bytes` 和 `Scanner::scan_bytes` 的 `hide_unknown` 过滤后调用
   - `no_dedup == false` 时执行去重，`true` 时跳过
4. CLI 新增 `--no-dedup` 参数（`crates/diec-cli/src/main.rs`）
5. FFI 新增 `DIEC_SCAN_FLAG_NO_DEDUP = 0x40`（`include/diec.h` + `scan.rs`）
6. Server `ScanFlagsRequest` 新增 `no_dedup` 字段（`handlers.rs`）
7. GUI `ScanFlagsDto` 新增 `no_dedup` 字段（`commands.rs`）
8. README.md "Known Limitations" 节移除 `--alltypes` 重复条目
9. 文档清理（10.1 + 10.2 的 README/requirements 更新）

**风险分析**：

- **风险 R1：去重隐藏合法检测**。两个不同规则在不同 file_type 组中
  检测到相同 `(type_name, name, version, options, offset, size)` 但
  代表不同语义的检测。**缓解**：`--no-dedup` 提供逃生通道；去重键包含
  `offset` 和 `size`，不同位置的检测不会被合并。
- **风险 R2：与上游差分测试不匹配**。默认去重使 `--alltypes` 输出
  与上游不同（上游有重复，我们没有）。**缓解**：差分测试使用
  `--no-dedup` 标志匹配上游行为；默认去重行为有独立测试覆盖。
- **风险 R3：FFI ABI 兼容性**。新增 `DIEC_SCAN_FLAG_NO_DEDUP = 0x40`
  不改变 `DiecScanOptions` 结构体布局（仅用未使用的 flag bit），
  `struct_size` 不变，向后兼容。**缓解**：现有 FFI 测试验证。

**测试计划**：

- **单元测试**（`scanner.rs` tests module 或 `tests/dedup.rs`）：
  - 构造 `Vec<ScanDetection>` 含跨 file_type 重复（如 PE + MSDOS 均输出
    "MS-DOS"），验证 `dedup_detections` 后无重复
  - 验证保留首次出现（file_type 字典序更早的组）
  - 验证 `no_dedup == true` 时不去重
  - 验证不同 offset/size 的同名检测不被合并
  - 验证空 Vec 和无重复 Vec 的边界情况
- **集成测试**（`crates/diec-engine/tests/`）：
  - 构造最小 PE 文件（MZ header），`--alltypes` 扫描，验证结果无重复
  - 对比 `--alltypes` vs `--alltypes --no-dedup` 的检测数量
- **CLI 测试**（`crates/diec-cli/tests/cli_integration.rs`）：
  - `cli_alltypes_flag` 测试扩展：验证 `--alltypes` 默认去重无重复
  - 新增 `cli_no_dedup_flag` 测试：`--no-dedup` 产生 >= 默认去重的检测数
- **差分测试**：
  - `--alltypes --no-dedup` 模式下与上游输出对比（匹配上游原始行为）
  - 规则版本差异除外（COMPATIBILITY.md 已记录的 4 个差异）
- **FFI 测试**（`crates/diec-ffi/tests/`）：
  - 验证 `DIEC_SCAN_FLAG_NO_DEDUP` 位正确映射到 `ScanFlags.no_dedup`
- **回归测试**：
  - 现有 506 个测试全部通过
  - GUI-CLI 差分测试 2/2 通过

### 退出条件

- ADR 0027 Accepted — ✅
- README.md "Known Limitations" 节仅保留真实 limitation（10.1/10.2 条目已清理）— ✅
- `--alltypes` 默认去重，`--no-dedup` 可关闭 — ✅
- 去重覆盖 6 层影响链：ScanFlags → scanner → CLI → FFI → server → GUI — ✅
- `cargo fmt --check` + `cargo clippy --workspace --all-targets --all-features -- -D warnings` 通过 — ✅
- `cargo test --workspace --all-features` 通过（含新增去重测试）— ✅
- 差分测试在 `--alltypes --no-dedup` 模式下 0 引擎不匹配（规则版本差异除外）— ✅
- GUI-CLI 差分测试通过 — ✅

**Phase 10 已于 2026-08-08 关闭。** 所有退出条件已满足：
- ADR 0027 已 Accepted（结果去重决策）
- README.md 文档清理完成（移除过时条目，新增 Known Differences 节）
- 去重功能完整实现并测试（5 个去重测试全部通过）
- CLI、FFI、Server、GUI 四层 API 全部支持 `--no-dedup` 标志
- 506 个测试全部通过，cargo fmt/clippy 零警告
- GUI 构建资源已准备（db/db_extra/dbs_min/dbs_special/peid_rules/yara_rules）

## Phase 11：GUI 深度对齐 — 完整头部解析与缺失模块 — DONE

Phase 9 修复了信息展示格式和基础功能缺陷（20 项 P1/P2/P3），但人工实际
使用发现对齐度仍仅约 30%。根本原因是**架构层面**的差距：FileInfoPanel
缺少完整头部解析、格式专用视图缺失、多个工具模块未实现。

差距分析：`docs/research/gui-gap-analysis-v2.md`
设计文档：`docs/design/phase11-gui-parity.md`

**Phase 11 已于 2026-08-08 关闭。** 所有 8 个任务批次已完成：

- 11.1 FileInfo 完整头部解析（P0）— ✅
  - 后端 HeaderField 树形结构 + PE/ELF/Mach-O 完整头部解析（pelite + goblin）
  - 前端 FileHeaderTree 递归树形组件 + FileInfoPanel 子标签
- 11.2 文件格式检测扩展（P0）— ✅
  - 集成 diec-formats probe table（20+ 格式检测）
  - 手写 magic bytes 作为回退（PE32/PE32+ 子类型区分）
- 11.3 PE 专用视图（P1）— ✅
  - pe_viewer.rs：imports/exports/resources/overlay/.NET/manifest/version info/TLS/Rich Header
  - PeViewPanel.tsx：9 个子标签
- 11.4 字符串搜索与提取器（P1）— ✅
  - string_extractor.rs：ASCII/UTF-16LE 提取 + 过滤搜索
  - StringExtractor.tsx：实时搜索 + 编码过滤
- 11.5 归档格式扩展（P1）— ✅
  - list_archive 扩展支持 ZIP/TAR/GZIP+TAR（tar + flate2 依赖）
- 11.6 可视化视图与区段视图（P2）— ✅
  - SectionVisualizer.tsx：颜色编码区段布局图 + 熵值着色 + overlay 标记
- 11.7 Settings 模态对话框与快捷键配置（P2）— ✅
  - SettingsModal.tsx：5 标签模态对话框（View/Scan/Database/Engine/Shortcuts）
  - ShortcutSettings：8 个可配置快捷键
- 11.8 VirusTotal 集成与 MIME 类型（P2）— ✅
  - FileInfo 新增 mime_type 字段 + detect_mime_type 函数
  - OnlineTools 重构：接收 filePath，自动获取 SHA256，点击跳转 VirusTotal（与上游 Qt 行为一致）

**验证结果**：
- 66 个 Rust 测试全部通过
- cargo fmt/clippy 零警告
- 前端编译通过
### Deferred 项

- NFD/InfoDB/静态脱壳/DEX 专用视图 — 需独立 ADR
- SSDeep/TLSH 哈希 — 需 native 依赖
- RAR 归档 — 需 native 依赖（unrar），需 ADR
- 多语言扩展到 22 种 — 低优先级
- 自动更新 — ADR 0019 deferred

## 后续改进项

### Phase 13：diec CLI 100% 上游对齐 — IN PROGRESS

Phase 12 完成了 GUI 的 35 项剩余功能对齐，但 diec CLI 自身仍有 3 项实现缺口
与上游 DIE-engine 不一致。本 Phase 一次性补齐全部缺口，使 diec CLI 达到与
上游 release `diec` 的 100% 可观察行为对齐，同时闭合 macOS 平台基线和语料
覆盖缺口。

差距分析：`docs/research/cli-upstream-gap-closure.md`
设计文档：`docs/design/phase13-cli-parity.md`

**缺口清单**（3 项 diec 自身实现缺口 + 2 项测试覆盖缺口）：

| ID | 缺口 | 来源 | 影响 |
|----|------|------|------|
| G1 | `--struct <value>` 模式未实现（CAP-CLI-MODE-003） | diec | 通用 Hash/Info/Entropy + PE/ELF/Mach-O/DEX 专用结构无法查询 |
| G2 | `--showstructs` 输出与上游不一致 | diec | 输出格式特定方法列表而非上游 4 个通用方法 |
| G3 | resource/overlay 内部递归扫描未实现（`-r` 语义错位） | diec | `-r` 做目录递归而非上游的文件内部递归 |
| G4 | archive 成员解包递归扫描未实现 | diec | engine 层缺 ZIP/7Z/RAR/CAB/ISO9660 成员解包能力 |
| G5 | macOS 68 项 platform-missing | 测试基础设施 | macOS 平台能力基线未闭合 |
| G6 | 大型语料覆盖不足（26 样本 vs 68 CAP-* 项） | 测试基础设施 | 差分测试语料覆盖范围不足 |

**ADR 需求**：
- ADR 0028：`-r` 语义对齐上游（破坏性变更，目录递归迁移到新选项）
- ADR 0029：`rars` (WTFPL) RAR 解包库选型
- ADR 0030：archive 成员解包递归扫描安全边界（压缩炸弹防护）

#### 13.1 `--struct <value>` 通用方法实现 — P0

实现 `--struct <value>` 模式的 4 个通用结构方法，匹配上游
`XFileInfo::processFile()` 行为。

- **StructSelector 解析**：`#` 分隔层级过滤、大小写不敏感、wildcard 语义
  - `Hash#MD5` 只返回 MD5 子记录
  - `hAsH#mD5` 与 `Hash#MD5` 完全相同
  - `Hash#MD5#Ignored` 额外 section 被当作 wildcard
  - `Hash##MD5` 保留空 `Hash` parent
  - `NoSuch#MD5` 返回空 `data`
  - `--struct ""` 退回普通 scan
- **Hash 方法**：MD4、MD5、SHA1、SHA224、SHA256、SHA384、SHA512
  - 复用 die-gui/file_info.rs 已有 MD5/SHA1/SHA256
  - 新增 MD4（`md-4` crate）、SHA224/SHA384/SHA512（`sha2` crate 已有）
  - 空文件 `Hash#MD5` 返回空字符串（非标准空输入 MD5，上游边界行为）
- **Info 方法**：文件名、大小、类型、MIME、扩展名、架构、端序等
  - 扩展当前 `--info` 模式为 struct 可查询的 Info 方法
  - 字段集合依格式变化（PE32 增加架构/模式/OS/类型/端序）
- **Entropy 方法**：分区/区域 Shannon 熵
  - 复用现有 `compute_entropy` 函数
  - 区域来自格式探测的 memory-map（非固定大小分块）
- **Check format 方法**：格式检查信息
- **`--showstructs` 修正**：输出上游的 4 个通用方法（Info、Hash、Entropy、
  Check format），而非当前格式特定方法列表

新建模块：
- `crates/diec-engine/src/struct_mode.rs` — StructSelector 解析 + 方法分发
- `crates/diec-engine/src/hash_methods.rs` — 7 种哈希算法

差分测试：5 个基线样本 × Hash/Hash#MD5/Info/Entropy/Check format × 6 种输出格式

#### 13.2 `--struct <value>` 格式专用方法实现 — P0

实现 PE/ELF/Mach-O/DEX 格式专用结构方法，匹配上游
`XFileInfo::getMethodNames()` 的格式特定分支。

- **PE32 专用方法**（6 个）：
  - `Entry point` — PE 入口点地址
  - `IMAGE_DOS_HEADER` — DOS 头字段
  - `IMAGE_NT_HEADERS` — NT 头字段
  - `IMAGE_SECTION_HEADER` — 节区头列表
  - `IMAGE_RESOURCE_DIRECTORY` — 资源目录
  - `IMAGE_EXPORT_DIRECTORY` — 导出表
  - 复用 `pe_native.rs` 的 pelite 解析能力
- **ELF64 专用方法**（2 个）：
  - `Entry point` — ELF 入口点地址
  - `Elf_Ehdr` — ELF 头字段
  - 复用 `elf_native.rs` 的 goblin 解析能力
- **Mach-O 64 专用方法**（2 个）：
  - `Entry point` — Mach-O 入口点地址
  - `Header` — Mach-O 头字段
  - 复用 `macho_native.rs` 的 goblin 解析能力
- **DEX 专用方法**（1 个）：
  - `Header` — DEX 头字段
  - 新增 DEX 头解析（magic、checksum、file_size、header_size等）

新建模块：
- `crates/diec-engine/src/pe_struct.rs` — PE 专用结构方法
- `crates/diec-engine/src/elf_struct.rs` — ELF 专用结构方法
- `crates/diec-engine/src/macho_struct.rs` — Mach-O 专用结构方法
- `crates/diec-engine/src/dex_struct.rs` — DEX 专用结构方法

差分测试：minimal.exe × 6 PE 方法、minimal.elf × 2 ELF 方法、
minimal.macho × 2 Mach-O 方法、minimal.dex × 1 DEX 方法

#### 13.3 `--struct` 输出格式化与模式优先级 — P0

实现 struct 模式的所有输出格式和模式优先级，匹配上游
`ScanFiles()` 分派顺序。

- **模式优先级**：`--entropy > --struct > --info > normal scan`
- **输出格式优先级**（专用模式）：`JSON > XML > CSV > TSV > formatted/plain text`
- **JSON 格式**：顶层对象 `data`，叶子值全部序列化为 string
- **XML 格式**：递归 `record` 元素，叶子值在 `value` attribute
- **CSV/TSV 格式**：无 header，父节点输出为只有 name 和空 value 的一行
- **text 格式**：`key: value` 层级缩进
- **多目标 framing**：按输入顺序先打印 `<filename>:\n`，随后串接独立 JSON
- **未知方法**：不报错，JSON 为 `{"data": ""}`，退出码 0
- **`--plaintext`**：与不传输出格式开关逐字节相同（无专用分支）

新建模块：
- `crates/diec-output/src/struct_formatter.rs` — struct 模式 5 种输出格式

差分测试：95 种输入/模式组合 × 190 次 oracle 执行（匹配 cli-special-modes.md 基线）

#### 13.4 resource/overlay 内部递归扫描 — P0

实现 PE resource 和 overlay 的内部递归扫描，对齐上游 `-r`/`--recursivescan`
语义。**此为破坏性变更**（ADR 0028）。

- **ADR 0028：`-r` 语义对齐上游**
  - `-r`/`--recursivescan` 改为启用文件内部 resource/overlay 递归扫描
  - 目录递归迁移到新选项 `--recursive-dir`（或 `-R`）
  - 在 `--help` 和 README 中明确说明语义变更
  - 现有使用 `diec -r directory` 的用户需改为 `diec --recursive-dir directory`
- **PE resource 枚举**：
  - 在 `pe_native.rs` 新增 `get_file_parts()` 函数
  - 递归遍历 pelite resource tree（type/name/language 目录）
  - 收集 data entries 的 offset/size/resource_id
  - 上限 10000 个 resource（匹配上游 `XPE::getFileParts()`）
- **PE overlay 检测**：
  - 计算从 header/section 最大末端到文件末尾的 offset/size
  - overlay 始终扫描（不受 isScanable 过滤）
- **递归扫描逻辑**：
  - 主扫描完成后，检查 `flags.recursive`
  - 对每个 file part 提取字节切片，递归调用 `scan_bytes()`
  - 递归调用复制完整 ScanFlags（resource 内可继续找 resource/overlay）
  - 设置子 detection 的 parent_id、file_part、offset、size
- **边界控制**：
  - resource nLimit：默认 20，aggressive 2000
  - 非 aggressive 模式先探测子设备类型，只扫描 `isScanable()` 的 resource
  - aggressive 模式扫描所有 resource（包括不可识别的）
- **ScanFlags 扩展**：
  - 添加 `recursive: bool`（文件内部递归，对应上游 bIsRecursiveScan）
  - 添加 `resources: bool`（独立 resource 扫描，对应上游 bIsResourcesScan）
  - 添加 `overlays: bool`（独立 overlay 扫描，对应上游 bIsOverlayScan）
  - `is_recursive()` 返回 `flags.recursive || flags.resources || flags.overlays`
- **Host API**：实现 `is_recursive()` 返回正确值（当前硬编码 false）
- **CLI 适配**：
  - `-r`/`--recursivescan` → `flags.recursive = true`
  - 新增 `--recursive-dir`/`-R` → 目录递归
  - `--aggressivescan` + `-r` → nLimit 2000，扫描不可识别 resource

修改模块：
- `crates/diec-rules/src/pe_native.rs` — 新增 `get_file_parts()`
- `crates/diec-engine/src/host.rs` — ScanFlags 扩展 + `is_recursive()`
- `crates/diec-engine/src/scanner.rs` — 递归扫描逻辑
- `crates/diec-cli/src/main.rs` — `-r` 语义变更 + `--recursive-dir`
- `crates/diec-ffi/src/scan.rs` — FFI ScanFlags 映射
- `crates/diec-server/` — server ScanFlags 映射

差分测试：8 个嵌套语料样本 × 4 种模式（default/aggressive/recursive/recursive+aggressive）

#### 13.5 archive 成员解包递归扫描 — P1

实现 ZIP/7Z/RAR/CAB/ISO9660 五种格式的成员解包和递归扫描。上游 release CLI
未暴露 `--archivescan` 选项，但 engine 层有此能力。本子任务实现 engine 层
能力并添加 CLI 选项。

- **ADR 0029：`rars` (WTFPL) RAR 解包库选型**
  - 纯 Rust 实现，无 native 依赖
  - WTFPL 许可证宽松（允许商用/修改/分发），兼容 MIT
  - 覆盖 RAR 1.5-7 全系列
  - 非 standard SPDX，需 ADR 记录决策
- **ADR 0030：archive 解包安全边界**
  - 压缩炸弹防护：单成员大小限制、总解压字节数限制、压缩比限制
  - 递归深度限制（复用 diec-core limits.rs 已有框架）
  - 成员数量限制（默认 20，aggressive 100000，匹配上游）
- **解包器实现**（新建 `diec-unpack` crate 或扩展 `diec-formats`）：
  - ZIP：使用 `zip` crate（die-gui 已依赖）
  - 7Z：使用 `sevenz-rust` crate
  - RAR：使用 `rars` crate（ADR 0029）
  - CAB：使用 `cab` crate 或自行实现 Store/MSZIP
  - ISO9660：使用 `iso9660` crate 或自行实现
- **递归扫描编排**：
  - `ScanFlags` 添加 `archives: bool`（对应上游 bIsArchivesScan）
  - 主扫描完成后，检查 `flags.archives`
  - 对每个 archive 成员解包，递归调用 `scan_bytes()`
  - aggressive 模式无条件扫描，否则先探测成员类型
  - 成员标记为 `FILEPART_STREAM`，保留 offset/size/original_name
- **CLI 适配**：
  - 新增 `--archivescan` 选项（上游 release CLI 未暴露，为 engine 能力扩展）
  - `--aggressivescan` + `--archivescan` → nLimit 100000
- **密码处理**：
  - 新增 `--password` CLI 选项
  - 7Z AES / RAR 加密支持
  - 密码错误时不产生 child（匹配上游行为）

新建模块：
- `crates/diec-unpack/src/` — 5 种格式解包器
- `crates/diec-engine/src/archive_scan.rs` — archive 递归扫描逻辑

差分测试：17 个 archive 语料样本 × archive/aggressive 组合（匹配
archive-format-behavior.md 基线）

#### 13.6 macOS 平台基线闭合 — P1

闭合 macOS x86_64 Qt5 平台的 68 项 `platform-missing` 能力基线。

- **运行 17 个已存在的 macOS 采集脚本**：
  - `tools/upstream/collect_macos_*.py`（13 个采集脚本）
  - 对应的 `validate_macos_*.py` 验证脚本
- **验证 17 个 candidate reports**：
  - `docs/research/data/macos-qt5/*.json`（已采集但未验证）
- **生成 macOS closure plan**：
  - 68 行逐项审计为 `evidence_complete`
  - 绑定 17 份 macOS runtime 证据
- **重新生成 coverage 报告**：
  - 运行 `build_capability_coverage.py`
  - 将 macOS 68 行从 `platform_missing` 提升为 `runtime_observed`
  - 闭合 `CAP-GAP-008` macOS 部分
- **CI 增强**：
  - 添加 macOS 专用 CI job 运行差分测试
  - 当前 macOS CI 仅运行基本测试，未运行差分测试

前提条件：需要在 macOS 环境执行（macOS-14 runner 或本地 macOS 主机）

#### 13.7 大型语料补充 — P2

补充差分测试语料，从 26 个基线样本扩展到覆盖 68 个 CAP-* 能力项。

- **语料生成**（复用 `tools/corpus/generate_*.py` 60+ 个生成脚本）：
  - 边缘情况样本（截断头部、畸形结构、超大字段、空容器）
  - 特殊路径样本（NFC/NFD、中文、emoji、空格、hidden、前导短横线）
  - 文件系统样本（symlink、alias、mode-000、depth-64、self-cycle）
  - 大型目录样本（flat/nested 4096 项）
  - TOCTOU 样本（stable old/new、enumeration vs open race）
  - 归档格式样本（多记录、迭代边界、截断、结构变体、对抗性）
  - 数据库样本（ZIP database、load-error、cache）
  - 规则编排样本（format-specific vs Binary、优先级、去重）
  - 结果模型样本（scalar metadata、error/debug/handler lists）
- **差分测试扩展**：
  - 新增样本添加到 `corpus_differential.rs`
  - 更新 `baseline-corpus.json`
  - 添加样本生成指南文档
- **自动化增强**：
  - 语料生成集成到 CI pre-test 阶段
  - 自动验证样本完整性

#### 13.8 兼容性报告更新与文档 — P2

更新兼容性文档，反映 Phase 13 的全部变更。

- **COMPATIBILITY.md 更新**：
  - CLI 兼容性表新增 `--struct <value>`、`--archivescan`、`--recursive-dir`
  - Host API 兼容性表新增 resource/overlay 递归扫描
  - Known Differences 更新 `-r` 语义变更（ADR 0028）
  - 规则版本差异处理：保持当前状态（选项 A），明确文档说明
- **README.md 更新**：
  - CLI 选项说明更新（`-r` 语义变更、新选项）
  - Known Limitations 移除已闭合项
- **RELEASE.md / RELEASE_NOTES.md**：
  - 新版本发布信息
- **AGENTS.md 更新**：
  - 当前阶段描述更新
- **能力矩阵更新**：
  - `capability-matrix.md` 中 CAP-CLI-MODE-003 状态更新
  - `capability-coverage-report.md` macOS 状态更新

**退出条件**：
- `--struct <value>` 全部通用 + 格式专用方法实现，差分测试 0 不匹配
- `--showstructs` 输出与上游逐字节相同
- resource/overlay 递归扫描实现，8 个嵌套语料差分测试 0 不匹配
- archive 成员解包递归扫描实现（5 种格式），17 个 archive 语料差分测试 0 不匹配
- macOS 68 项 platform-missing 全部闭合为 runtime_observed
- 大型语料覆盖 68 个 CAP-* 能力项
- `cargo fmt --check`、`cargo clippy --workspace --all-targets --all-features -- -D warnings`、
  `cargo test --workspace --all-features` 全部通过
- 3 个 ADR（0028/0029/0030）Accepted
- COMPATIBILITY.md、README.md、能力矩阵全部更新

### Phase 12：GUI 差距 v3 — 35 项剩余功能完整对齐 — DONE

Phase 11 完成了 8 个批次的基础对齐，但 `gui-gap-analysis-v3.md` 仍识别出
35 项缺失功能。本阶段一次性实施全部 35 项，使 GUI 达到与上游 DIE-engine
的完整功能对齐。

差距分析：`docs/research/gui-gap-analysis-v3.md`

**Phase 12 已于 2026-08-09 关闭。** 全部 35 项已完成：

- **Batch A: PE 缺失子视图（5 项）** — ✅
  - A1 IMAGE_NT_HEADERS：NT 头总览（signature/machine/entry/image_base/subsystem）
  - A2 RESOURCES_STRINGTABLE：RT_STRING 资源字符串表
  - A3 NET_METADATA_STREAM：.NET 元数据流详情（#~/#Strings/#US/#GUID/#Blob）
  - A4 NET_METADATA_TABLE：.NET 元数据表（45 种表行计数）
  - A5 TOOLS：6 个 PE 工具命令（DosStub/Overlay dump/remove/add，含 .bak 备份）
- **Batch B: Mach-O 缺失子视图（12 项）** — ✅
  - weak_libraries、id_library、FVMLIB、IDFVMLIB
  - function_starts（ULEB128 解码）、data_in_code、code_signature（SuperBlob）
  - SuperBlob、unix_thread、dyld_chained_fixups、dyld_exports_trie（trie 遍历）
  - STRINGTABLE
- **Batch C: ELF STRINGTABLE（1 项）** — ✅
  - 从 SHT_STRTAB 节区解析字符串表条目
- **Batch D: 字符串搜索增强（8 项）** — ✅
  - MapMode（file/virtual/physical）、FileType（auto/pe/elf/macho/dex/raw）
  - 右键菜单（Follow in Hex/Disasm/Demangle/Edit String）
  - 保存结果（CSV/JSON）、默认长度 4→5
- **Batch E: 可视化增强（5 项）** — ✅
  - ZEROS_GRADIENT、TEXT_GRADIENT 方法
  - 高亮功能（点击 Canvas 添加）、缩放滑块（1-10px）、保存图片（PNG）
- **Batch F: 提取器增强（3 项）** — ✅
  - HEURISTIC 模式（21 种 magic 签名扫描）、深度扫描开关、分析模式（格式识别 + 熵）
- **Batch G: 扫描日志（1 项）** — ✅
  - ScanResultDto 新增 scan_log 字段，前端折叠显示

**验证结果**：
- 614 个测试全部通过（+19 新增测试：visualization 2 + macho 5 + pe 4 + elf 2 + string_extractor 4 + extractor 2）
- cargo fmt/clippy 零警告
- TypeScript 编译零错误

### Host API 完善（差分兼容性）

以下 stub 方法影响差分测试匹配率，按预期收益排序：

- ~~**CFBF 版本解析**~~：已完成。`CFBF.getFileFormatVersion()` 从 CFBF 头解析 major.minor 版本（+1 匹配，`minimal.cfbf`）
- ~~**Java Class 版本解析**~~：已完成。`JavaClass.getFileFormatVersion()` 从 class 文件 major version 映射到 Java SE 版本（+1 匹配，`Minimal.class`）
- ~~**PYC 版本解析**~~：已完成。`PYC.getFileFormatVersion()` 从 pyc 头解析 magic number 映射到 Python 版本（2.7-3.14）
- **Archive host API**：`isVerbose()` 返回 false 与上游 3.21 一致，无需修改
- ~~**PE 验证方法**~~：已完成。8 个 `is*Correct` 方法（isEntryPointCorrect/isSectionAlignmentCorrect/isFileAlignmentCorrect/isHeaderCorrect/isExportTableCorrect/isImportTableCorrect/isRelocsTableCorrect/isResourcesTableCorrect）
- ~~**PE Resource 方法**~~：已完成。`getNumberOfResources`/`isResourceNamePresent`/`getResourceSection` 使用 pelite 原生解析
- ~~**PE .NET 方法**~~：已完成。`isNet` 检查 CLR header，保留 `getNetAssemblyName` 等 stub 通过 legacy 检查
- ~~**PE Manifest 方法**~~：已完成。`getManifest` 使用 pelite 原生解析 resource 目录
- ~~**PE Version Info 方法**~~：已完成。`getFileVersion`/`getProductVersion`/`getVersionStringInfo`/`getPEFileVersion` 使用 pelite 原生解析 VS_FIXEDFILEINFO 和 StringFileInfo
- ~~**PE Authenticode 签名检测**~~：已完成。`isSignedFile`/`isSigned` 使用 pelite 检查 security directory
- ~~**原生 PE/ELF/Mach-O 解析重构**~~：已完成。使用 pelite（PE）和 goblin（ELF/Mach-O）替换手写 JavaScript 解析，消除逐字节 JS→Rust FFI 往返
- ~~**PE Overlay 方法**~~：已完成。`getOverlayOffset`/`isOverlayPresent`/`getOverlaySize`/`compareOverlay`
- ~~**ELF/MACH stub 方法**~~：已完成。ELF: `getImageBase`/`getOverlayOffset`/`getOverlaySize`/`getStringTableOffset`/`getSymbolTableOffset`/`getRelocationTableOffset`。MACH: `getImageBase`/`getOverlayOffset`/`getOverlaySize`

### CI/CD 维护

- ~~**升级 GitHub Actions 到 Node.js 24**~~：已完成。`actions/checkout@v5`、`actions/upload-artifact@v5`、`actions/download-artifact@v5` 已升级，支持 Node.js 24。
- ~~**Windows FFI C smoke test 链接**~~：已完成。改用 DLL import library（`diec_ffi.dll.lib`）替代 staticlib（`diec_ffi.lib`），避免手动指定大量 Windows 系统库。移除 `continue-on-error`，Windows smoke test 现在在 CI 中正常运行。
- ~~**macOS x86_64 构建矩阵**~~：已完成。使用 `macos-14`（arm64 runner）交叉编译 `x86_64-apple-darwin` 目标，避免使用费用较高的 `macos-13` Intel runner。交叉编译构建跳过原生测试（arm64 无法运行 x86_64 二进制），arm64 原生构建仍运行完整测试。

## Phase 14：兼容性阻断修复与差分基线重建 — DONE (2026-08-23)

**启动日期**：2026-08-23
**背景**：实际使用中发现 PE/ELF 规则执行存在脚本异常导致检测能力失效，
`--alltypes` 模式产生大量格式误报，使项目无法达到 1:1 兼容上游的目标。
经核查，项目此前声称"规则加载 100%、差分 0 不匹配"的结论建立在覆盖不足的
差分测试之上，存在重大盲区，导致阻断性缺陷长期未被发现：
- 差分测试未纳入 `db_extra` 规则（PE 阻断规则多在此目录）
- 差分测试未使用真实系统二进制（如 `/usr/bin/ls`、`/usr/bin/bash`）做 ELF 差分
- `--alltypes` 测试只验去重和检测数量，无"不相关格式不应产生检测"的负向断言
- `COMPATIBILITY.md` 声称的 host API 完整性与实际实现不符（PE section/resource
  数组实际为空、ELF `_B` 未注入）

本 Phase 优先级高于 Phase 13 剩余项。Phase 13 的 13.6/13.7 语料补充与本 Phase
14.4 差分加固有协同，可合并执行。

**ADR 需求**：
- ADR 0031：`--alltypes` 语义对齐上游（先探测再分发兼容父类型，可能改变现有输出）
- ADR 0032：上游兼容 JSON 输出模式（`--output json-die`）

**进展**：
- 14.1 ELF `_B` 注入修复 — ✅ 完成（ELF + Mach-O 闭包添加 `var _B = Binary;`）
- 14.2 PE host API 补全 — ✅ 完成（`PE.isNET` 别名、`isResourceGroupNamePresent`/
  `isResourceGroupIdPresent`、`.NET` stub 方法 `compareEP_NET`/`findSignatureInBlob_NET`/
  `isSignatureInBlobPresent_NET`/`isNetTypePresent`/`isNetMethodPresent`/`isNetFieldPresent`，
  移除 `PE.section`/`PE.resource`/`PE.nLastSection` 硬编码，由上游 `_init` 脚本填充）
- 14.3 `--alltypes` 探测前置过滤 — ✅ 完成（`alltypes_rule_types` 基于探测结果 +
  兼容父类型，ELF `--alltypes` 误报从 11 个降到 0）
- 14.4 差分测试加固 — ✅ 完成（6 个新差分测试：`--alltypes` ELF/PE/Mach-O 跨格式
  误报断言、db_extra 规则加载、PE TypeError 断言、真实系统二进制扫描）
- 14.5 上游兼容 JSON 输出 — ✅ 完成（`--json-upstream` 选项 + `render_json_upstream`
  renderer，输出 `[{fileType,name,string,info,version,offset}]` 格式）
- 14.6 Go 绑定 reusable scanner — ✅ 完成（`Scanner.ScanBytes`/`ScanPath` 改用
  `diec_v1_scanner_scan_bytes`/`diec_v1_scanner_scan_path_utf8`，复用 runtime）
- 14.7 文档纠正与 glibc 指南 — ✅ 完成（README 添加 Linux glibc 2.34+ 要求说明）
- 14.8 收尾与回归 — 进行中

### 14.1 ELF `_B` 注入修复 — P0 阻断

**问题**：所有 ELF compiler/library 规则抛出 `ReferenceError: _B is not defined`，
ELF 检测能力完全失效。

**根因**：`crates/diec-rules/src/host_api_bridge.rs:3046-3509` ELF 方法定义闭包
缺少 `var _B = Binary;`（PE 闭包在行 2079 正确定义）。ELF 辅助函数
`_sectionName`/`_sectionNumber`/`_libraryNames` 使用 `_B.__elfSectionNames()` /
`_B.__elfImportLibraries()`，但 `_B` 在 ELF 上下文未定义。

**修复**：
- 在 ELF 方法定义闭包（`host_api_bridge.rs:3048` 之后）添加 `var _B = Binary;`
- 将 ELF 辅助函数中所有 `Binary.*` 引用统一为 `_B.*`（与 PE 实现一致，避免
  `_init` 设置 `File = ELF` 后的潜在递归问题）
- 同步检查 Mach-O、MACHOFAT、MSDOS、DEX、JavaClass、PYC 等其他格式闭包是否
  也遗漏 `_B` 定义，统一修复

**验证**：
- 扫描 `/usr/bin/ls`、`/usr/bin/bash`、`corpus/minimal.elf`、`corpus/elf-with-deps.elf`
  无 `ReferenceError`，能检测到 compiler/library（如 gcc/glibc）
- 单元测试：ELF 规则执行不抛 `_B` 相关异常
- 差分测试：与上游 DIE 3.21 对比 `/usr/bin/ls` 检测结果 0 不匹配

### 14.2 PE host API 补全 — P0 阻断

**问题**：PE protector/cryptor/installer/compiler 规则抛出
`TypeError: not a function`，PE 文件无法检测 protector/packer/compiler/linker。

**根因**：`host_api_bridge.rs` PE bridge 不完整：
1. `PE.isResourceGroupNamePresent(sName)` / `PE.isResourceGroupIdPresent(nID)`
   未实现（`compiler_RealBasic.4.sg:13` 等规则调用）
2. `PE.section` 数组在 `host_api_bridge.rs:2253` 硬编码为空 `[]`，未填充区段数据
   （上游 `db/PE/_init:147-163` 应填充 Number/Name/VirtualSize/VirtualAddress/
   FileSize/FileOffset/Characteristics，支持数字和名称索引）
3. `PE.resource` 数组在 `host_api_bridge.rs:2361` 硬编码为空 `[]`
4. `PE.nLastSection` 在 `host_api_bridge.rs:2252` 硬编码 `-1`，应为
   `getNumberOfSections() - 1`
5. bridge JS 代码块在 `_init` 脚本之后执行，覆盖了 `_init` 填充的数据

**修复**：
- **方案 A（首选）**：移除 bridge 中 `PE.section = []`、`PE.resource = []`、
  `PE.nLastSection = -1` 硬编码，让上游 `db/PE/_init` 脚本负责填充。需验证
  `_init` 脚本依赖的 host API 方法（`getNumberOfSections`、section 遍历等）
  在 bridge 中已实现且返回正确数据。
- **方案 B（兜底）**：若 `_init` 脚本依赖的底层方法不全，在 bridge 中用
  pelite 原生解析填充 `PE.section`/`PE.resource` 数组（参考 `pe_native.rs`
  已有解析能力）。
- 实现 `PE.isResourceGroupNamePresent` / `PE.isResourceGroupIdPresent`：
  使用 pelite 遍历资源目录树，检查指定名称/ID 的资源组是否存在。
- 修正 `PE.nLastSection` 为 `PE.getNumberOfSections() - 1`。
- 审计 `db/PE/_init` 脚本中所有被引用的 PE 属性/方法，逐一核对 bridge 实现，
  补齐缺失项（避免逐个规则报错才发现）。

**验证**：
- 扫描 `corpus/minimal.exe`、`corpus/minimal-pe64.exe`、`corpus/pe-dotnet.exe`、
  `corpus/pe-with-resources.exe`、`corpus/with-tables.exe` 无 `TypeError`
- `pe-dotnet.exe` 检测到 .NET 相关特征
- protector/cryptor/installer/compiler 类规则正常执行（不要求全部命中，但不应异常）
- 差分测试：与上游 DIE 3.21 对比上述 PE 样本检测结果 0 不匹配
- 单元测试：`PE.section`/`PE.resource` 数组填充正确性、`isResourceGroupNamePresent`
  正负用例

### 14.3 `--alltypes` 探测前置过滤 — P0 阻断

**问题**：`diec --alltypes /usr/bin/ls`（ELF）产生 CFBF/DEX/JPEG/PDF/PNG/Java
Class/Python bytecode 等大量格式误报，`--alltypes` 不可用于生产。

**根因**：`crates/diec-engine/src/scanner.rs:427-437` `--alltypes` 模式直接返回
`all_rule_types()`（18 种全部），完全忽略 `ProbeTable` 探测结果。上游
`bIsAllTypesScan` 语义是"先 `getFileTypes` 探测，仅为兼容/容器类型额外执行父类型
规则"（PE→MSDOS、APK→JAR/ZIP），不执行不相关格式规则。

**ADR 0031：`--alltypes` 语义对齐上游**
- `--alltypes` 改为先 `ProbeTable::probe_all` 探测格式，再根据探测结果分发：
  - 主类型规则正常执行
  - 兼容父类型规则额外执行（PE→MSDOS、APK→JAR/ZIP、Mach-O FAT→Mach-O）
  - 不相关格式规则不执行（ELF 不跑 DEX/JPEG/PDF/PNG 等）
- 此为破坏性变更：当前 `--alltypes` 输出含大量误报，修复后输出会显著减少。
  需 ADR 记录，并在 RELEASE_NOTES 明确说明。
- 保留 `--no-dedup` 逃生通道用于匹配上游原始重复行为。
- 若用户确需"对所有格式跑规则"的旧行为（调试/研究），考虑新增
  `--force-all-formats` 选项保留旧行为（ADR 决定）。

**修复**：
- `scanner.rs:427-437` 重构 `--alltypes` 分支：调用 `detect_rule_types` 后，
  追加兼容父类型（基于探测主类型映射），而非返回全部 18 种。
- 抽取兼容父类型映射表：PE→[MSDOS]、APK→[JAR, ZIP]、JAR→[ZIP]、
  Mach-O FAT→[MACH]、IPA→[ZIP] 等（对照上游 `XFormats` 兼容关系）。
- 非可执行格式（PDF/JPEG/PNG 等）的 `--alltypes` 行为：仅运行自身格式规则 +
  Binary 规则（与默认模式一致），不跨格式。

**验证**：
- `diec --alltypes /usr/bin/ls` 不再产生 CFBF/DEX/JPEG/PDF/PNG 等误报
- `diec --alltypes minimal.exe` 仍能检测 PE + MSDOS（兼容父类型）
- 差分测试：真实 ELF/PE/Mach-O 样本 `--alltypes` 与上游 0 不匹配
- 负向断言测试：ELF 样本 `--alltypes` 结果不含 archive:Resources 之外的无关格式

### 14.4 差分测试加固 — P0

**问题**：现有差分测试覆盖盲区导致 3 个阻断项长期未发现。本子任务重建兼容基线
可信度，是 Phase 14 的核心交付物。

**修复**：
- **纳入 `db_extra` 规则**：差分测试和规则加载统计纳入 `db_extra` 目录规则
  （当前 COMPATIBILITY.md 称 1186/1186 仅指 `db/`）。更新规则加载基线数。
- **真实系统二进制语料**：新增 `/usr/bin/ls`、`/usr/bin/bash`、`/usr/bin/echo`
  等 ELF 样本到差分语料（用哈希清单记录，可重复获取）。新增真实 PE 样本
  （含 resources/.NET/protector 特征的合法样本）。
- **`--alltypes` 负向断言**：新增测试断言"不相关格式不应产生检测"
  （ELF 不含 CFBF/JPEG/PDF 等）。
- **host API 完整性审计**：逐一审计 `db/PE/_init`、`db/ELF/_init`、
  `db/MACH/_init` 等脚本引用的全部属性/方法，对照 bridge 实现生成覆盖矩阵，
  标记缺失项。此矩阵成为 COMPATIBILITY.md 的新基线。
- **异常计数断言**：差分测试增加"规则执行异常数 = 0"的断言（当前只验检测结果，
  不验规则是否抛异常）。
- 与 Phase 13 的 13.7（大型语料补充）合并执行，避免重复工作。

**验证**：
- 差分测试语料覆盖 db + db_extra 规则、真实 ELF/PE 二进制
- `--alltypes` 差分测试含负向断言
- 规则执行异常数 = 0 成为差分测试硬性指标
- host API 覆盖矩阵文档化

### 14.5 上游兼容 JSON 输出 — P1

**问题**：diec-rust JSON 输出结构与上游 DIE 不兼容，无法直接替换上游工具。

**ADR 0032：上游兼容 JSON 输出模式**
- 新增 `--output json-die` 选项，输出上游 DIE 兼容结构：
  ```json
  {"detects":[{"filetype":"PE","values":[
    {"name":"Linker","type":"Linker","string":"Linker: Microsoft Linker(14.00)"},
    {"name":"Packer","type":"Packer","string":"Packer: UPX"}]}]}
  ```
- `type` 首字母大写（Packer/Protector/Linker/Compiler/Archive/Installer）
- `string` 字段含类型前缀（`"Packer: UPX"`）
- `values[]` 按 filetype 分组嵌套
- 默认 `--output json` 保持现有结构（向后兼容），`json-die` 为兼容模式
- 差分测试：`json-die` 输出与上游 DIE JSON 逐字节对比（规范化后）

**修复**：
- `crates/diec-output/src/json.rs` 新增 `render_json_die_compat()` 函数
- `crates/diec-cli/src/main.rs` 新增 `json-die` 输出格式选项
- FFI `diec_v1_result_json` 可考虑新增 `json_die` 变体（可选，ADR 决定）

### 14.6 Go 绑定 reusable scanner — P1

**问题**：`bindings/go/diec/diec.go:214-233` `Scanner.ScanBytes` 调用 one-shot
`cgo_scan_bytes`，未复用 scanner runtime 缓存。

**修复**：
- 新增 `cgo_scanner_scan_bytes` / `cgo_scanner_scan_path_utf8` cgo helper
  （包装 `diec_v1_scanner_scan_bytes` / `diec_v1_scanner_scan_path_utf8`）
- `Scanner.ScanBytes` / `Scanner.ScanPath` 改用新 helper
- Go 绑定测试：验证 Scanner 复用 database 加载上下文，性能优于 one-shot

### 14.7 文档纠正与 glibc 指南 — P1

**问题**：COMPATIBILITY.md 声明与实际不符；README 未说明 glibc 最低版本要求。

**修复**：
- **COMPATIBILITY.md 纠正**：
  - PE host API 表：`PE.section`/`PE.resource` 数组填充状态如实标注
  - `isResourceGroupNamePresent`/`isResourceGroupIdPresent` 实现状态
  - ELF host API 表：`_B` 注入状态（修复后标注 ✅）
  - 规则加载统计：区分 `db/` 与 `db + db_extra`，更新基线数
  - `--alltypes` 行为：更新为对齐上游后的语义
- **README.md glibc 说明**：
  - 明确 stable Rust 1.88+ 产物要求 glibc 2.34+（RHEL 9+ / Rocky 9+）
  - 提供 nightly + `build-std=std` 构建指南（产出 glibc 2.16 产物，支持 ol7/ol8）
  - 提供 musl 静态链接替代方案（如适用）
- **RELEASE_NOTES.md**：记录 Phase 14 阻断修复 + 破坏性变更（`--alltypes` 语义）

### 14.8 收尾与回归 — P1

- 全量回归：`cargo fmt --check` + `cargo clippy --workspace --all-targets --all-features -- -D warnings` + `cargo test --workspace --all-features`
- GUI-CLI 差分测试通过（GUI 同步 `--alltypes` 语义变更）
- ADR 0031/0032 Accepted
- COMPATIBILITY.md、README.md、能力矩阵、RELEASE_NOTES 全部更新
- 发布 patch 版本（v0.x.x）并标注阻断修复

### 退出条件

- **P0 阻断修复**：
  - ELF 规则无 `ReferenceError: _B`，`/usr/bin/ls` 能检测 compiler/library
  - PE 规则无 `TypeError`，protector/cryptor/installer/compiler 规则正常执行
  - `--alltypes` 不再产生跨格式误报，对齐上游 bIsAllTypesScan 语义
- **差分测试加固**：
  - 差分语料覆盖 db + db_extra 规则、真实 ELF/PE 系统二进制
  - `--alltypes` 差分含负向断言，规则执行异常数 = 0 为硬性指标
  - host API 覆盖矩阵文档化，COMPATIBILITY.md 声明与实际一致
- **P1 兼容性**：
  - `--output json-die` 输出与上游 DIE JSON 兼容（差分 0 不匹配）
  - Go 绑定 Scanner 真正复用 reusable scanner
  - README 明确 glibc 要求 + build-std 指南
- **质量门禁**：
  - `cargo fmt/clippy/test` 全部通过
  - GUI-CLI 差分测试通过
  - ADR 0031/0032 Accepted
  - 所有文档更新完成

## Phase 15：对齐方法论重建与缺口闭合 — COMPLETED

**背景**：Phase 14 收尾时对"上游对齐方法论"做了系统性回顾（详见
`docs/research/phase14-methodology-retrospective.md`），发现 6 个方法论根因缺陷
导致 Phase 0-13 声称的"规则加载 100%、差分 0 不匹配"掩盖了 3 个阻断性问题。
Phase 15 聚焦"重建对齐方法论 + 闭合已识别缺口"，不再追加新功能。

**完成状态**：全部 7 项（15.1-15.7）已完成，720 个测试通过。

### 15.1 真差分测试框架 — P0 ✅

**目标**：打破"自证非他证"闭环，引入独立上游 oracle 作为参照系。

- [x] 上游 DIE-engine oracle 集成
  - 从源码编译上游 `diec` 4.0.0（Qt6 + 全部 git 子模块）
  - `tools/record_golden_baselines.py` 录制 golden JSON 基线
  - 固定上游 commit SHA `8925358d2`，与兼容基线一致
- [x] `true_differential.rs` 真差分测试
  - 加载 golden 基线，运行 diec-rust `scan_bytes`，对比检测结果
  - 39 个 golden cases，38/38 匹配（1 个 NPM 已知差距跳过）
  - filetype 映射 + 名称别名归一化
- [x] 上游 oracle 不可用时的降级策略
  - golden 基线文件提交到 `tests/golden/upstream-diec-baseline.json`
  - 测试在无 golden 文件时自动 SKIP

### 15.2 规则执行覆盖率与异常断言 — P0 ✅

**目标**：消除"加载成功 ≠ 执行成功"的认知盲区。

- [x] `batch_execute.rs` 批量执行测试
  - 对每个规则执行 `init + evaluate_rule`（用最小合法样本触发）
  - 统计并断言：执行异常数 = 0、`ReferenceError`/`TypeError` 数 = 0
- [x] 所有差分测试添加脚本异常硬断言
  - `corpus_differential.rs`、`edge_corpus.rs`、`true_differential.rs`
    增加 `assert_eq!(script_exception_count, 0)`
- [x] db_extra 纳入所有差分测试
  - `DatabaseBuilder` 默认加载 `db/ + db_extra/`
  - 修复 PE .NET `getNETVersion` 和 MSDOS `compareEP` 等 TypeError

### 15.3 Host API 方法对照审计 — P0 ✅

**目标**：建立"上游 help 文档 → bridge 实现"的自动对照表，消除主观 ✅ 标记。

- [x] 自动化 host API 覆盖率工具 `tools/audit_host_api.py`
  - 解析上游 help 文档提取方法签名清单
  - 解析 `host_api_bridge.rs` 提取已实现方法清单
  - 生成对照矩阵：`docs/research/host-api-coverage-matrix.md`
- [x] 修正 `COMPATIBILITY.md` 的 ✅ 标记
  - 区分"完整实现"与"stub（返回默认值）"
- [x] 闭合 P0 host API 缺口
  - `Binary.calculateMD5`/`calculateCRC32`：md-5 + crc32fast crate
  - PE .NET `getNETVersion`：BSJB 元数据解析修复

### 15.4 `--alltypes` 系统性负向断言 — P1 ✅

**目标**：从"3 个格式有负向断言"扩展到"所有格式 × 所有不相关格式"。

- [x] `alltypes_negative.rs` 交叉验证测试
  - 39 个语料文件 × 允许格式族断言
  - 4 个测试函数：通用交叉验证 + ELF/PE/Image 专项排除
  - 0 跨格式误报

### 15.5 语料覆盖盲区补充 — P1 ✅

**目标**：覆盖小众格式与 db_extra 特殊检测场景。

- [x] 11 个新格式最小样本
  - COM/MSDOS/NE/LE/LX/NPM/PYC/DOS4G/DOS16M/Amiga/AtariST
  - golden 基线更新：29 → 39 cases
  - 真差分测试：38/38 匹配（NPM 已知差距）

### 15.6 P1 host API 缺口闭合 — P1 ✅

**目标**：闭合规则中实际调用的高优先级缺失方法。

- [x] PE 方法：`getSectionNumber`/`getSectionNumberExp`/`getSizeOfCode`/`getSizeOfUninitializedData`
- [x] Binary 方法：`read_UUID`/`read_UUID_bytes`/`findWord`/`findDword`
- [x] ISO9660 方法：`getDataPreparerIdentifier`/`getApplicationIdentifier`（PVD 解析）
- [x] 覆盖率：44.1% → 100.0%（119 → 270 已实现，audit 工具修复 + 批量实现）

### 15.7 文档与基线更新 — P1 ✅

- [x] `COMPATIBILITY.md` host API 覆盖率更新
- [x] `docs/research/host-api-coverage-matrix.md` 自动生成
- [x] ROADMAP.md Phase 15 标记为 COMPLETED

### 退出条件

- **真差分**：`true_differential.rs` 由上游 diec 4.0.0 golden 基线驱动 ✅
- **执行覆盖率**：`batch_execute.rs` 全规则执行，0 异常 ✅
- **Host API 对照**：自动对照矩阵生成，覆盖率 100.0% ✅
- **`--alltypes` 负向断言**：39 文件 × 允许格式族，0 误报 ✅
- **语料覆盖**：11 个新格式样本，39 golden cases ✅
- **P1 host API**：8 个高优先级方法实现 ✅
- **质量门禁**：720 个测试通过，cargo fmt/clippy 零警告 ✅

## Phase 16：真实数据差分验证与 host API 语义修正 — TODO

**启动日期**：2026-08-23
**背景**：v0.9.0（Phase 15：host API 覆盖率 100%、真差分框架）发布后，在真实
packer/protector 样本上执行 D2 差分测试，发现 3 个 host API 实现语义错误，导致
VMProtect（2 样本漏检）和 UPX（1 样本漏检）。Phase 15 的覆盖率审计仅验证"方法名
存在且可调用"，未验证"参数签名与语义与上游一致"，覆盖率 100% 不等于语义正确率
100%。

随后使用 `/data/virus/` 真实语料库（PE/ELF × 良性/恶意，~40 万文件）进行大规模
差分扫描，确认了问题 7-9 的影响范围，并发现多个额外检测差异。

### 真实语料差分基线（2026-08-23 录制）

使用 `tools/diff_scan_corpus.py` 对比 diec-rust v0.9.0 与上游 diec 4.0.0：

| 语料类别 | 样本数 | 检测一致率 | packer/protector 一致率 | packer 漏检 |
|---------|--------|-----------|------------------------|------------|
| pe_malicious | 500 | 80.8% (404/500) | 98.4% (492/500) | 8 |
| pe_benign | 100 | 64.0% (64/100) | 98.0% (98/100) | 2 |
| elf_malicious | 100 | 24.0% (24/100) | 100% (100/100) | 0 |
| elf_benign | 100 | 48.0% (48/100) | 100% (100/100) | 0 |

**packer/protector 漏检清单**（全部为 diec-rust 漏检、上游检测到）：

| 样本 | 检测类型 | 名称 | 版本 | 根因 |
|------|---------|------|------|------|
| 0107b9e0... | protector | VMProtect | 3.2.0-3.5.0 | 问题 7 |
| 0495816d... | protector | VMProtect | 3.2.0-3.5.0 | 问题 7 |
| 04bb40db... | protector | VMProtect | (无版本) | 问题 7 |
| 06e6467b... | protector | VMProtect | 2.0.3-2.13 | 问题 7 |
| 088e0a7e... | protector | VMProtect | 2.0.3-2.13 | 问题 7 |
| 0019fce8... | protector | VMProtect | (无版本) | 问题 7 (pe_benign) |
| 033308e6... | packer | UPX | (无版本) | 问题 8/9 |
| 09154c36... | protector | Enigma | 5.X | 问题 7 (ENIGMA 规则也用 getSectionNameCollision) |
| 06067f26... | packer | Bat To Exe Converter | — | **新发现，待调查** |
| 0037a630... | packer | PyInstaller | — | **新发现，待调查** |
| 00b0fb5e... | protector | XerinFuscator | — | **新发现（diec-rust 误检）** |

**非 packer 检测差异分类**（pe_malicious 500 样本）：

| 差异类型 | 数量 | 方向 | 说明 |
|---------|------|------|------|
| Unknown 占位 | 32 | 上游多 | 上游输出 "Unknown" 占位检测，diec-rust 不输出（表面差异） |
| MSVC compiler 版本 | 19 | 上游多 | 上游检测到更多 "by EP" 版本推断 |
| .NET Framework 版本 | 4 | 版本差异 | 上游输出 "4.7.2, CLR 4.0.30319"，diec-rust 只输出 "CLR 4.0.30319" |
| Records debug data | 5 | diec-rust 多 | diec-rust 过度检测 debug data |
| Windows Authenticode | 4 | diec-rust 多 | diec-rust 过度检测签名工具 |
| TASM32 compiler | 3 | diec-rust 多 | diec-rust 过度检测 TASM32 |
| Borland Delphi 版本 | 5 | 版本差异 | 版本范围推断不同 |
| ASProtect | 2 | 上游多 | **新发现，待调查** |
| OpenGL library | 3 | 上游多 | 上游检测到 OpenGL 库引用 |
| AutoIt format | 1 | 上游多 | 上游检测到 AutoIt 格式 |

**ELF 特有差异**：

| 差异类型 | 数量 | 说明 |
|---------|------|------|
| Unknown 占位 | 48-52 | 同 PE，上游输出 "Unknown" 占位 |
| Rust compiler 漏检 | 24 | **新发现**：diec-rust 未检测到 ELF Rust 编译器 |

### D2 差分指标（原始 24 样本）

| 指标 | 结果 | 门槛 | 状态 |
|------|------|------|------|
| packer 类检测一致率 | 21/24 (87.5%) | 100% | ❌ |
| protector 类检测一致率 | 20/24 (83.3%) | 100% | ❌ |
| packer 类检测不一致率 | 1/24 (4.2%) | < 5% | ✅ |
| protector 类检测不一致率 | 2/24 (8.3%) | < 5% | ❌ |

> 指标含义：对 24 个已知 packer/protector 样本，比较 diec-rust 与上游 DIE
> 对 packer/protector 类检测的二元决策（检测到 vs 未检测到）一致性。

**ADR 需求**：
- ADR 0033：`PeBatchInfo` 导入数据结构扩展（内部结构变更，按库分组函数）
- ADR 0034：host API 审计标准升级（参数签名对照纳入覆盖率审计）

**进展**：
- 16.1 `getSectionNameCollision` 语义修正 — ✅
- 16.2 `getImportFunctionName` 双参数语义修正 — ✅
- 16.3 `getNumberOfImportThunks` 参数语义修正 — ✅
- 16.4 `PeBatchInfo` 数据结构扩展 — ✅
- 16.5 真实语料大规模差分测试 — ✅（packer/protector 一致率 100%）
- 16.5a `getResourceSection()` 返回节索引 — ✅
- 16.5b IAT 后备解析（OFT=0）— ✅
- 16.5c `read_uint32`/`U32`/`readDword` 返回 f64 — ✅
- 16.5d `isImportPositionHashPresent` CRC32C 修正 — ✅
- 16.5e 资源条目 3 层嵌套 + RVA→文件偏移 — ✅
- 16.6 新发现 packer/protector 漏检调查 — ✅（全部修复）
- 16.7 非 packer 检测差异修复 — ✅（commit 5770542，2026-08-23）
- 16.8 host API 参数签名审计 — ✅（回归测试补充，2026-08-26）
- 16.9 收尾与回归 — ✅（10 个回归测试覆盖问题 7-9）

**修复后差分结果**（2026-08-23）：

| 语料类别 | 样本数 | 修复前 packer 一致率 | 修复后 packer 一致率 | 修复前检测一致率 | 修复后检测一致率 |
|---------|--------|---------------------|---------------------|-----------------|-----------------|
| pe_malicious | 500 | 98.4% (8 漏检) | **100.0%** (0 漏检) | 80.8% | **81.8%** |
| pe_benign | 100 | 98.0% (2 漏检) | **100.0%** (0 漏检) | 64.0% | **67.0%** |
| elf_malicious | 100 | 100% | **100.0%** | 24.0% | 24.0% |
| elf_benign | 100 | 100% | **100.0%** | 48.0% | 48.0% |

### 16.1 `getSectionNameCollision(s1, s2)` 语义修正 — P0 阻断

**问题**：`host_api_bridge.rs:3654` 的 `getSectionNameCollision(s1, s2)` 检查
字面值 `s1`/`s2` 是否为完整节名，两者都找到则返回 `s1`。完全不符合规则期望
的语义。

**上游规则用法**（`protector_VMProtect.2.sg:29`）：
```javascript
var sCollision = PE.getSectionNameCollision("0", "1");
if (PE.isSectionNamePresent(sCollision + "1")) { bDetected = true; }
```

**正确语义**：找到两个节名，一个以 `s1` 结尾、一个以 `s2` 结尾，且有共同前缀，
返回该**共同前缀**。例如 `oiNRhy0` 和 `oiNRhy1` → 返回 `oiNRhy`。若无此配对
返回空字符串。

**修复**：
- 重写 `getSectionNameCollision` 算法：
  1. 遍历所有节名，收集以 `s1` 结尾的节名集合 A 和以 `s2` 结尾的节名集合 B
  2. 对 A 中每个节名 `a`（前缀 `pa = a[:-len(s1)]`），检查 B 中是否存在节名
     `b` 使得 `b[:-len(s2)] == pa`
  3. 找到匹配则返回 `pa`（共同前缀），否则返回 `""`
- 大小写处理：节名比较应大小写不敏感（与现有 `isSectionNamePresent` 一致）

**影响规则**：VMProtect（2 样本漏检）、BattlEye、ENIGMA、
`__GenericHeuristicAnalysis_By_DosX.7.sg`

**验证**：
- 构造含 `oiNRhy0`/`oiNRhy1` 节名的 PE 样本，`getSectionNameCollision("0","1")`
  返回 `"oiNRhy"`
- VMProtect 保护样本差分测试：检测结果与上游 0 不匹配
- `getSectionNameCollision("1","2")` / `("2","3")` 变体正确（VMProtect 规则
  使用多种后缀组合）
- ENIGMA 规则 `getSectionNameCollision("1","2") == "enigma"` 正确

### 16.2 `getImportFunctionName(libraryIndex, functionIndex)` 双参数语义修正 — P0 阻断

**问题**：`host_api_bridge.rs:3570` 的 `getImportFunctionName(n)` 只接受 1 个
参数，返回全局扁平函数列表的第 n 个函数。上游规则用 2 个参数调用：
`getImportFunctionName(0, 0)`（库索引, 函数索引）。

**上游规则用法**（`packer_UPX.2.sg:15`）：
```javascript
if (PE.getImportFunctionName(0, 0) == "LoadLibraryA") { funcCounter++; }
if (PE.getImportFunctionName(0, 1) == "GetProcAddress") { funcCounter++; }
```

**正确语义**：返回第 `libraryIndex` 个导入库的第 `functionIndex` 个导入函数名。
越界返回空字符串。

**修复**：
- 修改函数签名为 `getImportFunctionName(libraryIndex, functionIndex)`
- 依赖 16.4 的 `PeBatchInfo` 数据结构扩展（按库分组函数）
- 从按库分组的结构中查询：`imports[libraryIndex].functions[functionIndex]`

**影响规则**（33 处调用）：UPX（isPatchedUPX 失败）、NsPack、AlushPacker、
cryptor_Huan、cryptor_EXECryptor、compiler_RADBasic、protector_StarForce、
protector_Private_EXE_Protector、protector_NTkrnl_Protector、protector_ENIGMA

**验证**：
- 构造含 2 个导入库（KERNEL32.DLL 有 3 函数、USER32.DLL 有 2 函数）的 PE 样本
- `getImportFunctionName(0, 0)` 返回 KERNEL32 第 1 个函数
- `getImportFunctionName(1, 0)` 返回 USER32 第 1 个函数
- `getImportFunctionName(0, 5)` 越界返回 `""`
- UPX 加壳样本差分测试：检测结果与上游 0 不匹配

### 16.3 `getNumberOfImportThunks(libraryIndex)` 参数语义修正 — P0 阻断

**问题**：`host_api_bridge.rs:3575` 的 `getNumberOfImportThunks()` 不接受参数，
返回全部库的函数总数。上游规则用 1 个参数调用：
`getNumberOfImportThunks(0)`（库索引）。

**上游规则用法**（`packer_UPX.2.sg:9`）：
```javascript
var nNumberOfFunctions = PE.getNumberOfImportThunks(0);
if (nNumberOfFunctions > 1 && nNumberOfFunctions < 7) { ... }
```

**正确语义**：返回第 `libraryIndex` 个导入库的函数数量。

**修复**：
- 修改函数签名为 `getNumberOfImportThunks(libraryIndex)`
- 依赖 16.4 的 `PeBatchInfo` 数据结构扩展
- 从按库分组的结构中查询：`imports[libraryIndex].functions.length`

**影响规则**（9 处调用）：与 16.2 相同的规则集

**验证**：
- 构造含 2 个导入库的 PE 样本
- `getNumberOfImportThunks(0)` 返回第 0 个库的函数数
- `getNumberOfImportThunks(1)` 返回第 1 个库的函数数
- UPX 加壳样本 `getNumberOfImportThunks(0)` 返回 2-6 范围内值（匹配
  isPatchedUPX 范围检查）

### 16.4 `PeBatchInfo` 数据结构扩展 — P0

**问题**：`pe_native.rs:710` 的 `PeBatchInfo` 将导入存储为两个独立扁平数组
（`libraries: Vec<String>` + `functions: Vec<String>`），丢失了函数与库的
归属关系，无法支持按库索引查询。

**修复**：
- **ADR 0033**：`PeBatchInfo` 导入数据结构扩展
  - 新增 `imports: Vec<PeImportLibrary>` 字段，其中 `PeImportLibrary` 包含
    `name: String` 和 `functions: Vec<String>`
  - 保留 `libraries` 和 `functions` 扁平数组用于向后兼容（现有调用方不破坏）
  - `parse_batch_pe32` / `parse_batch_pe64` 填充 `imports` 字段：遍历
    `pelite` imports，按 DLL 分组收集函数名
- `_peParseImports()`（`host_api_bridge.rs:3550`）同步扩展：
  - 从 `batch.imports` 构建 `_peImportData.imports`（按库分组结构）
  - 保留 `libraries` / `functions` 扁平数组供现有调用方使用
- `pe_native.rs` 的 `get_import_libraries` / `get_import_functions` 公共函数
  保留不变（向后兼容）

**数据结构设计**：
```rust
pub struct PeImportLibrary {
    pub name: String,
    pub functions: Vec<String>,
}

pub struct PeBatchInfo {
    // ... existing fields ...
    pub imports: Vec<PeImportLibrary>,  // 新增：按库分组
    // libraries / functions 保留（向后兼容）
}
```

**验证**：
- `PeBatchInfo.imports` 正确填充：库名 + 每库函数列表
- 现有使用 `libraries` / `functions` 的方法不受影响（回归测试）
- JS 端 `_peParseImports().imports` 可正确访问按库分组数据

### 16.5 真实语料大规模差分测试 — P1

**问题**：D2 差分测试仅覆盖 24 个 packer/protector 样本。需使用真实语料库
（`/data/virus/`，~40 万文件）进行大规模差分扫描，建立统计显著的基线。

**已完成**：
- `tools/diff_scan_corpus.py` 差分扫描脚本（对比 diec-rust vs 上游 diec 4.0.0）
- 基线已录制（见上方"真实语料差分基线"表）：
  - pe_malicious 500 样本：检测一致率 80.8%，packer 一致率 98.4%
  - pe_benign 100 样本：检测一致率 64.0%，packer 一致率 98.0%
  - elf_malicious 100 样本：检测一致率 24.0%，packer 一致率 100%
  - elf_benign 100 样本：检测一致率 48.0%，packer 一致率 100%

**待完成**：
- 扩大扫描规模到 2000+ 样本/类别，获得更稳定的统计基线
- 将差分扫描脚本集成到 CI 本地模拟（`.ci-local/`）
- 建立差分结果回归跟踪（修复前后对比）
- golden 基线更新：录制新语料的上游 golden JSON 基线

**验证**：
- 修复 16.1-16.3 后重新扫描，packer/protector 漏检数降为 0
- 检测一致率提升至 > 95%（非 packer 差异由 16.7 修复）

### 16.6 新发现 packer/protector 漏检调查 — P1

**问题**：大规模差分扫描发现除问题 7-9 外的额外 packer/protector 漏检。

**新发现漏检清单**：

| 名称 | 类型 | 样本数 | 根因 | 优先级 |
|------|------|--------|------|--------|
| Bat To Exe Converter | packer | 1 | 待调查 | P2 |
| PyInstaller | packer | 1 | 待调查 | P2 |
| ASProtect | protector | 2 | 待调查 | P1 |
| XerinFuscator | protector | 1 | diec-rust 误检（上游未检测） | P2 |

**修复**：
- 逐个调查漏检根因：检查对应规则脚本调用的 host API 方法
- ASProtect：检查 `protector_ASProtect.2.sg` 规则调用的方法是否正确实现
- Bat To Exe Converter / PyInstaller：检查对应 packer 规则的检测逻辑
- XerinFuscator：检查 diec-rust 是否过度检测（误报）

**验证**：
- 每个漏检项修复后在对应样本上差分测试 0 不匹配
- 不引入新的误报

### 16.7 非 packer 检测差异修复 — P2

**问题**：大规模差分扫描发现多种非 packer 检测差异，影响整体检测一致率。

**差异分类与修复优先级**：

| 差异类型 | 方向 | 数量 | 修复方案 | 优先级 |
|---------|------|------|---------|--------|
| Unknown 占位 | 上游多 | 32-52 | diec-rust 添加 "Unknown" 占位输出（匹配上游行为） | P2 |
| .NET Framework 版本 | 版本差异 | 4 | 修正 `getNETVersion` 返回完整版本（如 "4.7.2, CLR 4.0.30319"） | P1 |
| MSVC "by EP" 版本 | 上游多 | 19 | 调查入口点版本推断逻辑 | P2 |
| Records debug data | diec-rust 多 | 5 | 调查过度检测原因 | P2 |
| Windows Authenticode | diec-rust 多 | 4 | 调查过度检测原因 | P2 |
| TASM32 compiler | diec-rust 多 | 3 | 调查过度检测原因 | P2 |
| Borland Delphi 版本 | 版本差异 | 5 | 对齐版本范围推断 | P2 |
| ELF Rust compiler | 上游多 | 24 | 调查 ELF Rust 编译器检测缺失 | P1 |
| OpenGL library | 上游多 | 3 | 调查 OpenGL 库引用检测缺失 | P2 |
| AutoIt format | 上游多 | 1 | 调查 AutoIt 格式检测缺失 | P2 |

**修复**：
- **P1 项**（.NET Framework 版本、ELF Rust compiler）：优先修复
- **P2 项**：批量调查，能快速修复的一并处理，复杂项记录为已知差异
- "Unknown" 占位：确认上游行为后添加匹配输出

**验证**：
- P1 项修复后差分测试 0 不匹配
- P2 项修复或记录为已知差异
- 整体检测一致率提升至 > 95%

### 16.8 host API 参数签名审计 — P1

**问题**：Phase 15 的 `tools/audit_host_api.py` 仅验证方法名存在，未验证参数
签名与上游一致。需升级审计标准。

**修复**：
- **ADR 0034**：host API 审计标准升级
  - 审计矩阵新增"参数签名"列：对照上游 help 文档的方法签名
  - 审计矩阵新增"语义验证"列：标注是否有差分测试覆盖该方法
  - 标记"签名不匹配"和"语义未验证"的方法
- `tools/audit_host_api.py` 增强：
  - 解析上游 help 文档提取方法参数个数和类型
  - 解析 `host_api_bridge.rs` 提取已实现方法的参数个数
  - 生成参数签名对照矩阵
- 全量审计 PE/ELF/Mach-O/Binary host API 方法签名
- 标记并修复发现的签名不匹配项

**验证**：
- `docs/research/host-api-coverage-matrix.md` 新增参数签名列
- 所有已实现方法的参数签名与上游一致（或标注偏离理由）
- `COMPATIBILITY.md` 更新审计标准说明

### 16.9 收尾与回归 — P1

- 全量回归：`cargo fmt --check` + `cargo clippy --workspace --all-targets
  --all-features -- -D warnings` + `cargo test --workspace --all-features`
- GUI-CLI 差分测试通过
- ADR 0033/0034 Accepted
- `COMPATIBILITY.md` 更新：host API 语义修正记录、审计标准升级
- `RELEASE_NOTES.md`：记录 v0.9.1 host API 语义修正
- 版本 bump 0.9.0 → 0.9.1
- 重新运行大规模差分扫描，确认一致率提升

### 退出条件

- **P0 语义修正**：
  - `getSectionNameCollision` 返回共同前缀，VMProtect 样本正确检测
  - `getImportFunctionName(libIdx, funcIdx)` 按库索引查询，UPX 样本正确检测
  - `getNumberOfImportThunks(libIdx)` 返回指定库函数数
  - `PeBatchInfo.imports` 按库分组结构正确填充
- **P1 差分测试**：
  - 真实语料差分扫描 packer/protector 漏检数降为 0
  - packer/protector 类检测一致率 > 99%，不一致率 < 1%
  - 规则执行异常数 = 0
  - 整体检测一致率 > 95%
- **P1 新发现修复**：
  - ASProtect、ELF Rust compiler、.NET Framework 版本修复
  - 其他新发现项修复或记录为已知差异
- **P1 审计升级**：
  - host API 参数签名对照矩阵生成
  - 所有方法参数签名与上游一致（或标注偏离）
- **质量门禁**：
  - `cargo fmt/clippy/test` 全部通过
  - GUI-CLI 差分测试通过
  - ADR 0033/0034 Accepted
  - 所有文档更新完成


## Phase 17：GUI 差距 v4 补齐 — demangle / 归档 / 哈希 / DEX — DONE (2026-10-02)

**背景**：`gui-gap-analysis-v4`（2026-10-02，固定 `DIE-engine@23fec32`）
逐项实测确认 Phase 11/12 后 GUI 功能面对齐度约 85%。剩余差距中用户可
感知且无需架构决策的部分在本 Phase 补齐；NFD/静态脱壳/InfoDB/自动更新
等架构级缺口产出 ADR 后另行立项。

差距分析：`docs/research/gui-gap-analysis-v4.md`
设计文档：`docs/design/phase17-gui-parity.md`

### 任务批次

| 批次 | 内容 | 优先级 | 关键依赖 |
|------|------|--------|---------|
| 17.A | Demangle 扩展为 20 模式子集（MSVC32/64/ARM + Borland/Watcom + D/Java，Auto 探测对齐上游 `detectMode`） | P1 | `msvc-demangler`（纯 Rust）+ Borland/Watcom 精简移植 |
| 17.B | `list_archive` 改调 `diec-engine::archive_unpack`，覆盖 ZIP/7Z/RAR 列表与成员提取；CAB/ISO 可选 | P1 | 引擎已有 ZIP/7Z/RAR 提取（ADR 0029 `rars`） |
| 17.C | 哈希算法扩展（SHA3 系/BLAKE2/BLAKE3/Adler32/CRC64）+ FileInfo 算法勾选 UI | P2 | `sha3`/`blake2`/`blake3`/`adler2` 纯 Rust |
| 17.D | DEX 深视图（string/type/proto/field/method/class_def/map 表） | P2 | `misc_viewer.rs` 扩展解析 |
| 17.E | 交互细节：信息栏固定字段、格式子视图 Follow 链、Extra Information 文本导出、Hex 右键编辑入口 | P2 | — |
| 17.F | ADR 决策产出：NFD(0035)/静态脱壳(0036)/InfoDB(0037)/多语言(0038) | P3 | 仅文档 |

### 非目标

NFD/静态脱壳/InfoDB 实现、自动更新（ADR 0019）、SSDeep/TLSH（native）、
BZ2/XZ/LZMA 裸压缩流、MIPS/PPC/RISCV 反汇编、XStyles 主题生态。

### 退出条件

- 17.A：`?foo@@YAHXZ`/`__Z3foav`/`_ZN…`/`_D…` 解码正确，Auto 探测
  对齐上游顺序；模式矩阵写入 COMPATIBILITY.md ✅（17 个单测通过）
- 17.B：ZIP/7Z/RAR `list_archive` + `extract_archive_member` 工作；
  畸形归档负向测试无 panic ✅（引擎 22 个归档测试通过）
- 17.C：可选算法哈希（MD4/SHA3 系/BLAKE2/3/Adler32/CRC64）+
  勾选 UI；RFC/NIST/官方向量单测通过 ✅
- 17.D：DEX strings/types/protos/fields/methods/class_defs/map 七表
  实现 + 合成 DEX 单测 ✅；真实样本行数差分待语料
- 17.E：信息栏 `format_counts`/Follow 链/Extra Info 模态框/Hex
  字节编辑入口 ✅
- 17.F：ADR 0035–0038 产出 ✅（0035/0036/0037 Deferred，0038 Accepted）
- `cargo fmt/clippy/test` 全绿，前端 `npm run build` 通过 ✅

## Phase 18：上游遗留差距补齐 — DONE (2026-10-05)

Phase 17 显式 deferred 的项目按"阻塞原因 × 可落地性"分层实施，
设计文档：`docs/design/phase18-deferred-parity.md`。

| Phase | 范围 | 状态 | 结果 |
|-------|------|------|------|
| 18.A | Demangle 剩余 8 模式 | DONE | 精简解码器全部落地（Swift/Go/GNAT/GNUv2/Haskell/OCaml/Tru64/SunPro），上游 20 模式全覆盖；前端模式下拉补齐 |
| 18.B | CAB/ISO9660 归档 | DONE | `cab` crate + 自实现 ISO9660 base-spec reader；list/extract/嵌套扫描全通 |
| 18.C | SSDeep/TLSH/BZ2/XZ/LZMA | DONE | ADR 0039（SSDeep rejected/TLSH deferred）+ ADR 0040（BZ2/XZ/LZMA 纯 Rust 解码，已实现） |
| 18.D | 反汇编新架构评估 | DONE | ADR 0041 Deferred——纯 Rust 无 PPC/RISC-V 覆盖，capstone 为唯一完整路径 |
| 19 | InfoDB 注释/书签基础设施 | GATED | ADR 0037 复审 |
| 20 | 静态脱壳（UPX 先行，逐 packer） | GATED | 真实样本 oracle |
| 21 | NFD/SpecAbstract 第二引擎 | GATED | 规则库许可证审计 + 独立预算 |

持续项：多语言增量（ADR 0038）；XStyles 主题不移植。

Phase 18 交付验证：`cargo fmt/clippy/test` 全绿（archive_unpack 31 测试、
demangle 25 测试），前端 `npm run build` 通过。

## Phase 19：InfoDB 注释/书签 — DONE (2026-10-06)

以旁车 JSON 持久化方案实现（ADR 0037 Superseded，不引入 SQLite）。

- 存储：`<file>.diec.json`（version + file_sha256 + entries），
  文件哈希变化标 stale 而非删除；畸形 sidecar 静默忽略。
- 后端 `die-gui::annotations`：`list_annotations` / `upsert_annotation` /
  `delete_annotation` / `clear_annotations` 四个 Tauri 命令。
- 前端 `AnnotationsPanel`：kind（bookmark/comment/label）+ offset +
  文本 + 颜色，HexViewer 与 Disassembler 双挂载；en/zh-CN i18n。

## Phase 20：静态脱壳 — UPX — DONE (2026-10-07)

对齐 DIE `XUPX`/`XStaticUnpacker` 语义（非 `upx -d` 全部行为），
ADR 0036 按"逐 packer"条件实施 UPX。

- `diec-engine::unpack::upx`：`UPX!` pack-header 解析（版本敏感头长、
  filter/CTO/MRU、方法/长度边界校验）；PE filter 还原（0x06/0x26/
  0x36/0x46/0x49，小端）；PE 重建（headers/节表/imports/relocs/
  exports/resources/overlay，目录清理与上游一致）。
- `diec-engine::unpack::nrv`：UCL NRV2B/2D/2E 精确移植，8-bit/LE16/
  LE32 三种位读取器 × 3 算法共 9 变体；重叠回拷、lookbehind/输入/
  输出越界检查；返回实际产出长度（对齐 `*pnDstSize`）。
- LZMA（UPX 双字节属性前缀）+ 裸 DEFLATE 分派。
- CLI：`diec --unpack <file>` 生成 `<file>.unpacked`。
- GUI：`detect_upx` + `unpack_file` 命令；FileInfoPanel UPX 区块
  （方法/级别/filter + 一键脱壳）。
- 语料：UPX 5.2.1 生成 PE32×NRV2B/NRV2E/LZMA/brute、PE64×NRV2B，
  以 `upx -d` 输出为 oracle 节级字节差分（7 测试全过）。

Phase 20 交付验证：`cargo fmt/clippy/test` 全绿（upx_unpack 7 测试、
nrv 单测），前端 `npm run build` 通过。

## Phase 21：NFD/SpecAbstract 第二引擎 — PARTIAL (2026-10-07)

许可证 Gate 通过（MIT），按"读 C++ 写 Rust + 签名表 codegen"路径
落地了有界切片：

- `crates/diec-nfd`：纯 Rust 匹配核心（signature/string/const/
  resources/memory/exp scan，记录级去重与 ft 过滤对齐上游）。
- `tools/nfd_codegen.py`：SpecAbstract C 签名数组 → Rust 静态表
  （35 表 / 1730 条记录 @ 5188e047，生成头含 MIT 归属）。
- 已接通 dispatch：BINARY header/archive、MSDOS、PE32/PE64
  （header、entry-point 链含 NOP/JZ/E9-follow、import hash、
  resources、section names、Rich、deep section scans）。
- 集成：`ScanFlags::nfd`、CLI `--nfd`、GUI engine 勾选；
  NFD 记录在 JSON/GUI 中带 `engine=nfd` 标记。
- 表驱动 dispatch 扩展：COM（header+exp）、NE（linker header+CS:IP
  段表 EP）、LE/LX（linker header）、ELF32/64（PT_LOAD EP scan）、
  DEX（string/type 双 stringScan）、APK（成员名 CRC + fancy-regex
  archiveExpScan）、文本 "Plain text" format 记录（CRLF/LF/CR）。
- ELF 语义层：`elf_info` 解析器（节表/shstrtab/PT_NOTE+SHT_NOTE/
  PT_DYNAMIC/PT_INTERP，端序感知）+ `vi.rs` 44 个 `_get_*_string`
  提取器链（`.comment` 按上游顺序首个命中）+ OS 识别（OSABI→
  解释器→发行版注释→GNU/Android/Minix/NetBSD/OpenBSD ident）+
  GCC/.gcc_except_table + symtab/stab/DWARF 版本 + Qt(.qtversion/
  .qtplugin/libQt5/6)/gold/Android NDK/Go/.NET runpath。
- 语义 handler 首批：`handle_DosExtenders`（WDOSX@0x34 常开；
  CWSDPMI/DOS4G/DOS16M deep-scan 门控）、`handle_VintageCompilers`
  （15 条 vintage 运行时横幅，deep-scan 门控）、APK Signature Block
  ID 扫描（v2/v3 互斥、Walle、GooglePlay）、Kotlin/Java 语言判定
  （成员名探针）、Android OS 记录。
- Mach-O 语义层：`mach.rs` thin Mach-O 解析器（32/64、双端序、
  LC_SEGMENT*/LC_LOAD_DYLIB/LC_VERSION_MIN_*/LC_BUILD_VERSION/
  LC_CODE_SIGNATURE）+ `mach_tables.rs` 版本映射（Foundation 54 /
  iOS 28 / Xcode 133 / toolchain 93，上游 `xmach.cpp` 提取）；
  OS 识别（CPU→LC 覆盖→Foundation 版本修正）、SDK/Xcode/clang/
  Swift/ld 版本链、codesign、Qt/Carbon/Cocoa/VMProtect、`__cstring`
  Zig 标记、Objective-C info。CAFEBABE 消歧：FAT arch 记录逐项校验
  → MACHOFAT，否则 `u32be@4>10` → JAVACLASS（对齐上游判定序）。
- PE 语义 handler 首批（`pe_handlers.rs`）：`handle_OperationSystem`
  （subsystem→OS 家族 + Windows 版本表 + 64 位 ≥5.02 下限 + arch/
  mode/type info）、`handle_import`（ZProtect/PESpin/Alloy 导入序列
  模式）、`handle_DebugData`（.stab/.stabstr/.debug_info→DWARF）、
  `handle_Microsoft` 非 Rich 子集（MFC ^MFC 导入+版本/Unicode 标记
  +CMFCComObject 静态深扫、VB40032/MSVBVM50/60+P-Code、linker
  major.minor 兜底、mapVersions 链、VS build 版本表 158 条+
  linker 版本表 46 条、.NET BSJB 元数据版本）。上游 quirk
  已记录至 doc/upstream-bugs.md（mapVersions (0,1) 死键）。
- PE 语义 handler 第二批：`handle_GCC`（.rdata "GCC:"/`gcc-` 版本
  串、Cygwin DLL `^CYGWIN` 数字版本、`.stabstr` 的
  `/gcc/mingw32/`、`/gcc/i686-pc-cygwin/` 标记、generic linker
  major=2 && minor∈{22..36,56} 启发、linker-minor→MinGW 版本表
  {23:4.7-4.8, 24:4.8.2-4.9.2, 25:5.3.0, 29/30:7.3.0}、GCC→GNU ld
  填充）、`handle_Watcom`（"Open Watcom"/` 2002-`/`WATCOM`/`. 1988-`
  EP 区 vi 串 + linker/compiler 互推）、`handle_Signtools`
  （security dir 首证书 rev 0x200/type 2 → WinAuth 2.0 PKCS#7）、
  `handle_DongleProtection`（单 NOVEX* 导入 → Guardian Stealth）、
  `handle_NeoLite`（EP 段 "NeoLite Executable File Compressor"）、
  `handle_PETools`（VMUNPACKER/XVOLKOLAK/HOODLUM 节名转发）、
  `handle_Joiners`（BladeJoiner/ExeJoiner import+EP+overlay，
  Celesty/NJoiner import+RBIND/NJ/NJOY 资源名）。
- PE 语义 handler 第三批：`handle_Borland`（TurboLinker MZ@0x1E vi、
  `.text` Pascal 元数据数组 TObject/Boolean/string/String、TControl
  VA 反查 VCL 指纹（off,val）15 行表、PACKAGEINFO flags producer
  位覆盖、Borland/CodeGear/Embarcadero 版权串 → C++Builder 版本、
  `__CPPdebugHook` export、Embarcadero Delphi compiler version 串
  → Delphi 发布名表；VCL 记录版本恒空——上游赋值全注释，如实复刻）、
  `handle_Tools`（Rust=TLS+EP+Local\RustBacktraceMutex、Go="go1."
  最大版本、Zig=ZIG_* ansi/utf16、Nim=io.nim/fatal.nim、AutoIt3
  SCRIPT 资源、TinyC msvcrt+6.0+节形、CPADinfo 0x43506164、
  ExcelsiorJET、VisualObjects@0x312、FASM/IExpress/LLD .buildid/
  VALVE/UNILINK/DMD32/GoLink+GoAsm/Lahey@0x200/FlexLM/FlexNet、
  Qt4-6 导入库±Debug、FPC+Lazarus LCL、PYTHONxx/LIBPYTHONx.y/
  PERLxx 导入名版本、VirtualPascal/PowerBASIC/PureBasic/LCC-Win）。
  新增 PeInfo.export_names/tls_present、ResourceEntry data_off/
  data_size（level-3 leaf）、va_to_off、find_utf16le 等原语。
- 仍未移植（显式 deferred）：version-resource FileDescription 链
  （AutoIt 2.XX）、dotAnsiStrings 门控分支、Rich→工具描述链、
  installers/SFX/VB-cryptors/Delphi-cryptors/PrivateEXEProtector/
  UnknownProtection 与完整 handle_Protection/handle_FixDetects；
  JavaClass/PDF/JPEG/CFBF/Amiga/JAR 与 Mach-O FAT 专属 handler，
  走 generic binary 兜底。**剩余项归化与排期见
  `docs/design/phase21-nfd-remaining.md`（21.J–21.N + Phase 22
  非 PE 启发 + Phase 23 差分 oracle）。全部 ⚠ partial 行均有补全
  计划；终态 = 全量移植 + 上游 harness 差分收敛后逐行升 ✅。**
- **21.J 共享原语层已完成**：`pe_version.rs`（VS_VERSIONINFO
  3 层递归 + FixedFileInfo + FileDescription 键查询）、`.NET`
  `#Strings`/`#US` heap 提取 + dotAnsi/dotUnicode 内部扫描 map
  （不下泄输出，供 21.L 消费）、`binary_entropy`/`is_packed(6.5)`/
  `has_section_name`/`entrypoint_section_index` 原语。Rich 表此前
  已生成，`_fixRichSignatures` 归 21.N。

验证：`cargo test -p diec-nfd`（签名语义单测 + UPX/ZIP/畸形输入冒烟）、
workspace 44 套件全绿、clippy `-D warnings` 零警告。
