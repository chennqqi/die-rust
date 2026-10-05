# 任务：die-rust 扫描性能优化——消除逐文件规则重复编译

## 背景

目标仓库：`/data/dev/github.com/chennqqi/diec-rust`（上游 `horsicq/DIE-engine` 的
Rust 重实现，QuickJS 后端执行 `.sg` 规则脚本）。

下游产品 oneav 通过 FFI（`libdie_rust.a` → `die_v1_scan_path_utf8` /
`die_v1_scanner_scan_*`）调用 die-rust 对 PE 文件做 packer/protector 识别。
实测每文件扫描耗时远高于上游 C++ DIE，已定位为结构问题而非单点规则慢。

## 实测数据（必须以此复现/验收）

测试集：500 个真实恶意 PE（`pe_malicious` 随机抽样），进程内 DB 复用。

| 数据库 | PE 规则数 | mean | p50 | p95 |
|--------|----------|------|-----|-----|
| 全库 probe_db2 | 883 | 618ms | 314ms | 1.87s |
| 裁剪库（packer/protector/cryptor+辅助） | 332 | 413ms | 169ms | 1.44s |
| 骨架库（仅 `_init`+`_PE.0.sg`） | 2 | 6.5ms | 4.9ms | — |

结论：
- 固定开销（QuickJS runtime 创建 + host API 注册 + `_init`/`read` include 执行 +
  PE 解析）仅 ~6ms
- **~95% 耗时是每次扫描对全部规则源码 `ctx.eval`（JS 重新编译+执行）**
- `die_v1_scanner_*` API 只持有 `Arc<Database>`，内部仍走
  `die_engine::scan_once`，不复用 runtime，无加速效果

## 当前实现（优化切入点）

`crates/die-engine/src/scanner.rs::scan_bytes`（~line 595）：

1. `database.snapshot()` → 按文件类型分组规则
2. 每类型组：`RquickjsRuntime::new()` + `register_host_api` +
   `load_database(framework)` + `init(host)`（执行 `PE/_init`）
3. 对组内**每条规则**调用 `evaluate_rule_in_group` →
   `evaluate_rule_source_impl`（`crates/die-rules/src/backend_rquickjs.rs`）：
   - `rule_source.replace("const ", "var ")` 预处理
   - 拼 IIFE wrapper
   - `ctx.eval_with_options` → **QuickJS 全量解析+执行该规则源码**
   - 每条规则每次扫描重复上述编译

上游 C++（`upstream/DIE-engine/dep/XScanEngine/xscanengine.cpp`）同样是
逐脚本 eval 架构，但 QtScript/QJSEngine 的编译开销远小于当前的每文件全量
重新解析路径。

## 任务目标

在**检测输出逐字节不变**的前提下，把 PE 文件单扫描耗时降至 **≤50ms 档**
（mean/p50 相对当前 332 规则库降低 ≥70%）。

## 要求的工作顺序

### 第 1 步：测量归因（先出报告再动手）

在 `crates/die-engine` 或独立 bench（`cargo bench`/临时 bin）量化单次扫描中：

- runtime 创建 + host API 注册耗时
- `load_database` + `init()`（`_init` 脚本执行）耗时
- 每条规则的 `eval` 中**编译（parse/bytecode 生成）**与**执行（detect() 运行）**的拆分
  - 若 rquickjs 不直接暴露编译计时，用微基准对比：同源码 `eval` vs
    预编译 Function/Module 调用 vs bytecode `JS_ReadObject` 反序列化调用
- 规则循环外的杂项（结果读回、diagnostics、render_json）

输出一份简短 profiling 报告（哪个阶段占大头），据此选择实现方案。

### 第 2 步：实现（按可行性选择，不限于下列方案）

**方案 A（首选预期）：规则编译缓存（bytecode cache）**
- 在 `Database`/snapshot 层为每条规则缓存 QuickJS 编译产物
  （rquickjs 的 `Module`/`Function` bytecode，或 QuickJS 的
  `JS_WriteObject`/`JS_ReadObject`；先调研 rquickjs 当前版本暴露了哪些
  bytecode/compile API，必要时用 feature flag 或 `bindgen` 补）
- 每次扫描新建 runtime（保持全局隔离语义），但规则以"反序列化 bytecode →
  实例化 → 调用"代替"源码 parse → eval"
- 注意：`const`→`var` 预处理与 IIFE 包装应发生在**编译前**，缓存编译后的形态

**方案 B：runtime 池/复用**
- 复用已加载 framework 的 runtime；仅在能可靠重置全局状态时可行
- 风险（见 AGENTS.md 经验教训 14/15）：`includeScript` 会修改全局变量
  （`nOffset`、`bFPC` 等），`if (typeof x === "undefined")` 守卫使脏状态
  跨文件残留会造成结果漂移——若选此方案必须实现全局快照/恢复并给出
  跨文件无泄漏的差分证据

**方案 C：签名预匹配 dispatch**
- 先读上游 `xscanengine.cpp`/`getSignatureRecords` 确认上游是否有
  "签名不匹配则跳过 detect()"的调度；若上游有而 die-rust 无，对齐它即天然提速
  （同时修正兼容度）。若无，不做此方案（擅自跳过会引入与上游的语义差异）

可以 A+C 组合。若某方案经调研不可行，记录原因后换下一个，不要硬上。

### 必须保持的语义（硬约束，AGENTS.md 已有详细教训）

- 规则按优先级（文件名倒数第二段数字）排序执行，`sort_signature_prio` 顺序不变
- 规则源码在独立 IIFE 作用域 eval，`detect()` 在 IIFE 内调用；不得预 eval 污染全局
- `includeScript` 用 indirect eval 在全局作用域执行，其全局副作用须保持
- `_FixDetects`/`_Microsoft` 等后处理规则能看到共享累积结果列表
  （`begin_result_group`/`read_results` 语义不变）
- `_init`/`read` include/`type_init` 的执行时机不变（load vs init 阶段）
- `__die_current_rule` 规则归属戳、cancel token、结构化 diagnostics、
  `SignatureProfile` profiling 数据全部保留
- FFI 边界 panic 不得跨界；C ABI 不变（`die.h` 已有 API 行为不破坏，
  可新增 API 但不得改变现有签名语义）

## 验证要求（全部通过才算完成）

1. **差分零回归**：`diec --json` 对以下语料扫描，与改动前输出逐字节对比
   （保存改动前基线再实现）：
   - `corpus/` 全部样本（含 `.oracle.json`/`*.records` 的跑对应断言）
   - `tools/upstream/` 的 oracle 差分脚本（podman 容器，注意 volume 需 `:z`）
   - 若环境允许，抽 `/data/virus/pe_malicious` 200+ 文件做前后对比
2. **benchmark**：同一批 500 文件、同一命令路径给出改动前后
   mean/p50/p95/max 对比表（可用 `diec` CLI 批量或内嵌 bench）
3. **质量门禁**：
   - `cargo fmt --check`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo +1.88.0 clippy --workspace --exclude die-gui --all-targets
     --all-features --locked -- -D warnings -A clippy::uninlined_format_args`
   - `cargo test --workspace --all-features`
   - `cd fuzz && cargo test --no-default-features --features replay`
4. 畸形/边界输入不得 panic（用 `corpus_pe_edge` 类畸形 PE 跑一遍）

## 环境信息

- Rust 工具链：cargo 1.92（rustup），registry 已配 rsproxy 镜像，可 `--offline`
- 参考数据库：`/data/virus/probe_db2`（883 PE 规则）、`/tmp/die_db_trim3`
  （332 规则裁剪库，oneav 生产候选）
- CLI：`cargo build --release -p die-cli` → `target/release/diec
  --database <db> --json <file>`
- 已知上游 bug 记录于 `doc/upstream-bugs.md`；die-nfd `pe.rs:592` 有已知
  panic 样本（不属本任务）

## 交付

- 实现 + 测试 + profiling/benchmark 对比数据
- 结果写入 `docs/` 或 `doc/` 下新文档（性能结论须附可复现命令）
- 提交遵守仓库约定：规则同步/实现/FFI/CLI 变更分别提交，不提交临时产物
