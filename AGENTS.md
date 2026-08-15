# 项目协作约定

开始工作前先阅读 [README.md](README.md)、[ROADMAP.md](ROADMAP.md) 和 [docs/README.md](docs/README.md)。

## 当前阶段

项目目前处于 Roadmap Phase 7（维护与上游同步）。Phase 0-6 及 Phase 8-10 已全部关闭：
- Phase 0 设计门禁于 2026-07-31 评审通过并关闭。
- Phase 1 工程骨架与兼容测试基础设施于 2026-07-31 关闭。
- Phase 2 核心数据模型与格式识别于 2026-07-31 关闭（20 个格式 probe、211 个测试、3 个 fuzz targets、完整覆盖矩阵）。
- Phase 3 规则兼容运行时于 2026-07-31 关闭（1186/1186 规则加载成功，rquickjs 后端 + Binary host API bridge）。
- Phase 4 CLI 功能对齐于 2026-08-01 关闭（24 个 CLI 集成测试，374 个测试全部通过）。
- Phase 5 C ABI 与语言集成于 2026-08-01 关闭（35 个 FFI 测试、Go/cgo 绑定、Python ctypes 绑定、411 个测试全部通过）。
- Phase 6 兼容性、性能与发布准备于 2026-08-05 关闭（v0.3.0 已发布，477 个测试，规则加载 100%，差分 0 引擎不匹配，database_load ~510ms）。
- Phase 8 GUI（Tauri v2）于 2026-08-06 关闭（480 个测试，三平台 CI，GUI-CLI 差分 0 不匹配，ADR 0019 deferred）。
- Phase 9 GUI 上游对齐增强于 2026-08-07 关闭（506 个测试，9.1 P1 核心修复 7 项 + 9.2 P2 完整度增强 7 项 + 9.3 P3 对齐扩展 6 项，详见 ROADMAP.md Phase 9 节）。
- Phase 10 已知问题修复与文档纠正于 2026-08-08 关闭（ADR 0027 结果去重、README 文档清理、--alltypes 默认去重 + --no-dedup 逃生通道）。
- Phase 11 GUI 深度对齐于 2026-08-08 关闭（8 批次：FileInfo 完整头部解析、格式检测扩展、PE 专用视图 9 子标签、字符串搜索与提取器、归档格式扩展、可视化与区段视图、Settings 模态对话框、VirusTotal 集成与 MIME 类型）。
- Phase 12 GUI 差距 v3 于 2026-08-09 关闭（35 项：PE 5 子视图 + Mach-O 12 子视图 + ELF STRINGTABLE + 字符串搜索 8 项增强 + 可视化 5 项增强 + 提取器 3 项增强 + 扫描日志，614 个测试全部通过）。
- Phase 13 diec CLI 100% 上游对齐于 2026-08-15 启动（--struct 完整实现、resource/overlay 递归扫描 -r 语义对齐、archive 成员解包 5 种格式、macOS 平台基线闭合、大型语料补充，ADR 0028/0029/0030）。

Phase 7 在不破坏兼容基线的前提下持续跟进上游 DIE-engine 规则与 host API 变化，
保持发布物健康度。当前进展：
- 上游规则同步：`upstream/Detect-It-Easy` 为 vendored subtree（非 submodule），固定到 commit `c2c17dfa5`
- CI fuzz 持续化：`.github/workflows/fuzz.yml` 在 push/PR 上运行 6 个 target 的覆盖引导 fuzz（5 min/target）+ 种子语料回放（三平台 stable Rust）
- 种子语料回放：165 seeds × 6 harnesses，`cd fuzz && cargo test --no-default-features --features replay`
- 发布物：v0.3.0（4 平台：Linux/Windows/macOS arm64/macOS x86_64），含 CLI、died、FFI 库、C 头文件、规则数据库、语言绑定
- Benchmark 基础设施（criterion 0.5）：scan_corpus、scan_flags、database_load、probe_corpus
- 边缘语料差分测试：20 个边缘样本 + 3 个测试（no-crash/no-spurious/no-hang）
- FFI 跨平台 CI：ffi-smoke job + python-binding job（Linux/macOS/Windows）
- 许可证和供应链审计：LICENSE、NOTICES.md、AUDIT.md
- 6 个 fuzz targets（core/formats/engine/output/ffi 层）+ 165 个种子语料
- 兼容性报告 COMPATIBILITY.md、发布检查清单 RELEASE.md（v0.3.0 已签字）
- database_load 优化：1.2s → 510ms（并行文件 I/O）
- 原生 PE/ELF/Mach-O 解析重构：使用 pelite（PE）和 goblin（ELF/Mach-O）替换手写 JavaScript 解析
  - 新增 pe_native.rs、elf_native.rs、macho_native.rs 三个模块
  - PE batch 解析：一次 pelite pass 返回所有 PE 信息，JS 端 JSON.parse 缓存
  - PE32 扫描性能：73ms → 89ms（含原生 resource/manifest/version info 解析）
  - ELF64 扫描性能：19ms → 15ms
  - Mach-O 64 扫描性能：18ms → 14ms
- 规则加载 1186/1186 = 100%（此前 1184/1186 = 99.83%）
- 差分测试 31 基线 + 20 边缘样本，0 不匹配
- 477 个测试全部通过，cargo fmt/clippy 零警告，0 TODO/FIXME
- ADR 0016：Scanner per-file_type runtime 跨文件复用（Accepted）
- ADR 0017：died (die daemon) HTTP/JSON 扫描服务层（Accepted）
  - 三个端点：/health、/scan/path、/scan/bytes
  - Windows 服务安装/卸载 + DEB/RPM/MSI 打包配置
  - API 文档含 curl/PowerShell/Python/Go 客户端示例
- Phase 8 GUI 已完成（2026-08-06，v0.4.0 发布）：
  - 上游 GUI 源码分析：`docs/research/upstream-gui-analysis.md`
  - ADR 0018：Tauri v2 GUI 框架选型（Accepted）
  - Phase 8 设计文档：`docs/design/phase8-gui.md`（Accepted）
  - 功能对齐上游 `die` 完整 GUI（7A 核心 + 7B 高级 + 7C 扩展）
  - 7A-0 至 7A-4、7B、7C 扩展、签名浏览器增强、i18n、三平台 CI 均已完成
  - GUI-CLI 差分测试 2/2 通过（0 不匹配），`cargo test --workspace --all-features` 480 个测试通过
  - ADR 0019：tauri-plugin-updater 自动更新 deferred 到 Phase 8 之后
  - v0.4.0 新增：原生安装包（MSI/NSIS/DEB/RPM/DMG）+ 便携版
  - v0.4.0 新增：Windows 右键菜单集成（HKCU 注册表，一键添加/取消）
  - v0.4.0 新增：i18n 全量接入（en/zh-CN/ru/de/fr）
  - v0.4.0 新增：完整数据目录打包（db/db_extra/db_custom/dbs_min/dbs_special/peid_rules/yara_rules）
  - v0.4.0 新增：CLI 自动加载 db_extra/db_custom（与上游 DIE-engine 行为一致，规则数 2037→2175）
  - v0.4.0 新增：PEID/YARA 内置规则加载（前端下拉选择内置 .yar/.userdb 文件）
  - GUI 构建步骤（fnm 环境）：
    1. `cd crates/die-gui/frontend && cnpm install`
    2. `npm run build`（生成 frontend/dist/）
    3. `cargo tauri build --no-bundle`（或 `cargo build -p die-gui --release`）
  - beforeBuildCommand 留空：fnm multishell PATH 不被子进程继承，
    前端构建需手动执行

调研正文写入 `docs/research/`，设计正文写入 `docs/design/`，不要堆积在
本文件或 `README.md` 中。

## 兼容基线

- 上游为 `https://github.com/horsicq/DIE-engine`。
- 所有结论和差分测试固定到确切 commit SHA，不使用“最新版”作为基线。
- 能力结论必须附上游源码位置、固定版本文档或可重复实验。
- 上游规则原样保存，不格式化或手工修改；同步时记录来源路径、commit、哈希和时间。
- Rust 与上游的可观察差异默认视为缺陷。确认需要偏离时，必须用 ADR 记录理由并增加回归测试。
- 导入代码、规则、submodule 或样本前核对许可证并保留归属信息。

## 架构与安全

- CLI 和 FFI 是核心库的薄适配层，核心层不得依赖它们或 GUI 框架。
- 优先纯 Rust、跨平台依赖。引入大型依赖、native 依赖或系统库必须记录权衡。
- 默认不使用 `unsafe`；确有必要时限制在最小模块，记录安全不变量并覆盖边界测试。
- 所有二进制输入均不可信。偏移、长度、整数运算和分配必须受控；畸形输入不得导致 panic、越界、无限循环或无界分配。
- 扫描结果使用统一结构化模型并保持确定性；CLI、JSON 和 FFI 不得各自实现检测逻辑。
- 性能变更以可重复 benchmark 或 profiling 为依据。

## 规则、ABI 与测试

- 规则解析不得静默忽略未知语法；不支持项必须产生明确诊断并计入兼容性失败。
- C ABI 只使用固定布局 C 类型和不透明句柄；不得暴露 Rust 类型。
- FFI 必须明确所有权、释放函数、线程安全和 ABI 版本，且 panic 不得跨越边界。
- 每项能力包含单元/集成测试，并按风险补充差分、FFI、fuzz、性能和跨平台测试。
- 差分测试保留原始及规范化输出；规范化不得隐藏有语义的差异。
- 不直接提交恶意或来源不明样本；使用可重复生成器、哈希清单或隔离语料库。

## 完成与提交

- 新行为有测试，缺陷修复有回归用例。
- Rust workspace 建立后，提交前运行：
  - `cargo fmt --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo test --workspace --all-features`
- 兼容行为运行固定上游版本的对应差分测试；ABI 变更运行 C 链接和生命周期测试。
- 更新相关调研/设计文档、能力矩阵和基线记录。
- 规则同步、实现、FFI 和 CLI 变更尽量分别提交。
- 不提交构建产物、临时扫描输出、私有样本或本机路径。
- 不要直接用 GitHub Actions 做实验或试错：反复失败的 CI 运行易触发
  GitHub 限流甚至封号。须在本地先通过（含 `.ci-local/` 下的本地模拟脚本，
  如 `ci-ubuntu-sim.sh`）再 push 触发 CI。

