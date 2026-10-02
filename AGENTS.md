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

以下 13 条必须在此后所有对齐工作中遵守。Phase 14 的 6 条经验教训见
[`docs/research/phase14-methodology-retrospective.md`](docs/research/phase14-methodology-retrospective.md)；
Phase 16 的 7 条根因和改进建议见
[`doc/alignment-retrospective.md`](doc/alignment-retrospective.md)
（**开始任何 host API 或签名相关对齐工作前必须先阅读此文件**）。

### Phase 14 经验教训（6 条）

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

### Phase 16 根因教训（7 条）

7. **覆盖率 ≠ 语义正确性**：方法存在且可调用不等于返回值语义正确。
   每个 host API 方法必须验证参数签名、返回值类型、返回值语义和边界行为
   与上游 C++ 源码一致，不能只验证"方法名存在"。典型反例：
   `getAddressOfEntryPoint` 返回 RVA 而非虚拟地址、`cleanString` 是 no-op、
   `getResourceNameOffset` 找不到时返回 0 而非 -1。
8. **签名语法不能从外观推断**：DIE 签名有 7 种特殊标记（`$`/`#`/`%`/`!`/
   `_`/`+`/`*`），每种语义必须从上游 `getSignatureRecords` 源码确认。
   `$` 是相对偏移跳转（不是通配符），`$$$$$$$$` 读取 4 字节有符号整数并
   跳转到目标 RVA 继续匹配。签名解析器应有独立测试套件覆盖每种标记。
9. **上游隐式行为只能通过源码考古发现**：Unknown 占位、`cleanString`
   过滤规则、`getAddressOfEntryPoint` 的 ImageBase+RVA 计算、`_runtime_helpers`
   中的 `String.prototype.append` 等行为不在 help 文档中。实现任何 host API
   方法前必须阅读对应的 C++ 源码实现。
10. **合成样本无法替代真实差分**：合成样本（`minimal.exe` 等）不触发
    边界条件（跨段跳转、控制字符嵌入、多层嵌套资源、ImageBase+EP=0）。
    每轮修复后必须用真实语料库运行差分测试。
11. **过度检测、漏检、版本差异需要三种发现策略**：过度检测需要负向差分
    （上游不检、diec-rust 检），漏检需要正向差分（上游检、diec-rust 不检），
    版本差异需要值差分（比较版本字符串）。差分框架必须同时支持三种模式。
12. **上游规则本身有 bug**：`archive_Resources.6.sg` 的循环条件
    `!bDetected` 在 `bDetected=true` 时立即退出，是规则 bug。上游的
    `getAddressOfEntryPoint` 返回非 0 值掩盖了此 bug。diec-rust 正确实现
    后反而暴露。**所有已发现的上游 bug 必须记录到**
    [`doc/upstream-bugs.md`](doc/upstream-bugs.md)，**避免被误认为
    diec-rust 缺陷**。发现新的上游 bug 时追加到此文件，不得静默修复。
13. **对齐是 O(n) 问题，验证是 O(n×m×k) 问题**：155 个方法 × 1186 个规则 ×
    数百个样本 = 数万次交互。每轮差分只发现当前样本集触发的错误。持续差分
    + 源码考古 + 语义对照矩阵是唯一收敛策略，不追求"100% 一致"。
14. **规则优先级排序是 includeScript 正确性的前提**：上游
    `sort_signature_prio` 按优先级（文件名倒数第二段数字）排序规则。
    `includeScript` 中 `var x = val` 在全局作用域会修改全局变量（Qt Script
    和 QuickJS 行为一致），"保护"来自 `if (typeof x === "undefined")` 守卫
    而非 `var` 作用域。若规则按字母序执行，低优先级规则（如 `_linkers.6.sg`）
    会在高优先级规则（如 `compiler_Free_Pascal.6.sg`）之后运行，其
    `includeScript("Borland")` 会覆盖 FPC 设置的 `nOffset`。**必须在
    `load_database` 读取文件内容之前完成优先级排序**，否则 rule_files 与
    contents 索引错位导致格式检测完全错乱。
15. **规则源码不能在 load_database 阶段预评估**：预评估会污染全局作用域
    （`includeScript` 的 `var` 声明修改全局变量），导致后续规则看到前序规则
    的 include 副作用。规则源码必须在 `evaluate_rule_source` 中通过 IIFE
    按需评估，`detect()` 在 IIFE 内调用。`evaluate_rule` 应委托给
    `evaluate_rule_source`，不应直接调用全局 `detect()`。

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
  - MSRV 工具链（clippy lint 集合随版本变化，1.97 不报不代表 1.88 不报）：
    `cargo +1.88.0 clippy --workspace --exclude die-gui --all-targets --all-features --locked -- -D warnings -A clippy::uninlined_format_args`
  - fuzz crate 不在 workspace 内（独立 `fuzz/Cargo.lock`），提交前必须单独验证：
    `cd fuzz && cargo test --no-default-features --features replay`
- 兼容行为运行固定上游版本的对应差分测试；ABI 变更运行 C 链接和生命周期测试。
- 更新相关调研/设计文档、能力矩阵和基线记录。
- 规则同步、实现、FFI 和 CLI 变更尽量分别提交。
- 不提交构建产物、临时扫描输出、私有样本或本机路径。
- 不要直接用 GitHub Actions 做实验或试错：反复失败的 CI 运行易触发
  GitHub 限流甚至封号。须在本地先通过（含 `.ci-local/` 下的本地模拟脚本，
  如 `ci-ubuntu-sim.sh`）再 push 触发 CI。
