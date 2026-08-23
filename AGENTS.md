# 项目协作约定

本文件只承载开发与评审约束（always-on rules）。阶段状态、进展历史和交付物
清单见 [ROADMAP.md](ROADMAP.md)；调研正文见 [docs/research/](docs/research/)，
设计正文见 [docs/design/](docs/design/)，文档索引见 [docs/README.md](docs/README.md)。
开始工作前先阅读 [README.md](README.md) 和 ROADMAP.md 的当前 Phase 节。

## GUI 构建步骤（fnm 环境）

`die-gui` 前端构建需手动执行（`beforeBuildCommand` 留空：fnm multishell PATH
不被子进程继承，前端构建需手动执行）：

1. `cd crates/die-gui/frontend && cnpm install`
2. `npm run build`（生成 `frontend/dist/`）
3. `cargo tauri build --no-bundle`（或 `cargo build -p die-gui --release`）

## 对齐方法论经验教训

以下 6 条必须在此后所有对齐工作中遵守。完整分析与根因缺陷见
[`docs/research/phase14-methodology-retrospective.md`](docs/research/phase14-methodology-retrospective.md)。

1. **差分测试必须用独立 oracle，不能自证**：期望值必须来自上游 DIE-engine
   的实际输出（或其快照），不能由开发者手工编写。手工期望值会把"bug 导致
   的结果"当成"正确期望"（如 ELF 规则全崩 → 无检测 → 期望值设为空）。
2. **加载成功 ≠ 执行成功**：规则覆盖率测试必须执行 `init + evaluate_rule`，
   不能只测 `load_database`。加载只证明语法正确，执行才证明运行时正确。
   所有覆盖率测试必须断言脚本异常数 = 0。
3. **Host API 完整性必须对照上游 help 文档**：不能凭主观判断标 ✅。
   必须维护"上游 help 方法清单 → bridge 实现对照矩阵"，区分"完整实现"与
   "stub（返回默认值）"。stub 方法在 `COMPATIBILITY.md` 中必须标注 `⚠ stub`。
4. **`--alltypes` 必须有系统性负向断言**：不能只测去重。必须对每种格式 ×
   每种不相关格式做交叉验证，断言不产生跨格式误报。
5. **差分测试必须加载 db_extra**：db_extra 含大量 PE protector/cryptor
   规则，不加载会掩盖 host API 缺失。所有差分测试默认加载 `db/ + db_extra/`，
   与 CLI 行为一致。
6. **设计文档必须与实现对齐**：`docs/design/*.md` 中未实现的设计项必须
   标注"未实现"或"已偏离"，不能给"已覆盖"的错觉。

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
