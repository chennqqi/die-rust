# PE 扫描性能优化报告：QuickJS bytecode 缓存

任务来源：`docs/die-rust-scan-perf-agent-task.md`（下游 oneav FFI 反馈：
PE 扫描远慢于上游 C++ DIE，定位为每文件对全部规则源码重复 `eval` 编译）。

## 成果速览

- **裁剪库（trim3，oneav 生产候选）mean 37.8 → 21.0ms（−44%），
  p50 29.0 → 13.2ms（−54%）**，达到任务"≤50ms 档"目标；
  相对 oneav 上报基线（413ms/169ms）降幅约 −95%。
- **全库（probe_db2，883 PE 规则）mean 101.4 → 76.3ms（−25%），
  p50 82.0 → 53.6ms（−35%）**。
- 检测输出 **0 回归**：corpus 318 文件与 500 文件 PE 抽样逐字节一致；
  21 个畸形输入无 panic。
- 方案：**编译一次、逐扫描执行**——规则与框架脚本在 `DatabaseBuilder`
  预编译为 QuickJS bytecode 存入快照；每次扫描仍新建 runtime
  （保持全局隔离），只做 `JS_ReadObject` + `JS_EvalFunction`。
- 全部 unsafe 隔离在新 crate `die-qjs-bytecode`；`die-rules` 保持
  `#![forbid(unsafe_code)]`。
- 否决路径留痕：runtime 复用有跨文件状态泄漏（500 文件中 2 个漏检）。

### 提交

| commit | 内容 |
|--------|------|
| `38bfd5b69` | `perf(rules)`：die-qjs-bytecode crate + 规则/框架脚本 bytecode 缓存 + bridge shim 进程级缓存 + 测试夹具更新 |
| `fc2885ee1` | `docs(perf)`：`scan_bench` benchmark 工具、`profile_scan_phases` 归因测试、本报告 |

### 交付物索引

- 实现：`crates/die-qjs-bytecode/`、`crates/die-rules/src/backend_rquickjs.rs`
  （`precompile_snapshot`/`wrap_rule_source`/`eval_script_or_bytecode`）、
  `crates/die-rules/src/host_api_bridge.rs`（`eval_shim`/`SHIM_BYTECODE`）、
  `crates/die-rules/src/runtime.rs`（`LoadedRule::bytecode`/`SnapshotBytecode`）、
  `crates/die-engine/src/database.rs`/`scanner.rs`
- 工具：`crates/die-engine/examples/scan_bench.rs`、
  `crates/die-engine/tests/profile_scan_phases.rs`、
  `crates/die-rules` 内 `profile_eval_compile_exec_split`（ignored 测试）
- 文档：本文件、`doc/requirements-analysis-030-2026-10-05.md`

## 结论

| 数据库 | PE 规则数 | 指标 | 优化前 | 优化后 | 降幅 |
|--------|----------|------|--------|--------|------|
| `/tmp/die_db_trim3`（oneav 候选裁剪库） | 333 | mean | 37.8ms | 21.0ms | **−44%** |
| | | p50 | 29.0ms | 13.2ms | **−54%** |
| | | p95 | 50.6ms | 31.8ms | −37% |
| | | max | 1114.4ms | 1102.5ms | — |
| `/data/virus/probe_db2`（全库） | 883 | mean | 101.4ms | 76.3ms | −25% |
| | | p50 | 82.0ms | 53.6ms | −35% |
| | | p95 | 185.1ms | 182.1ms | −2% |

检测输出：corpus（318 文件）与 500 文件 PE 抽样 **逐字节一致**
（detections 1143/1143、1220/1220）。

注意：本机实测基线（mean 37.8ms/p50 29.0ms）远低于任务文档中 oneav 环境
报告的 413ms/169ms——该环境基线无法在本机复现，上表降幅均以本机同一
`scan_bench`、同一样本、同一 release 构建的前后对比为准。相对 oneav 报告
的基线，trim3 库降幅约 −95%（mean）。裁剪库已达到"≤50ms 档"目标；
全库 mean 76ms 仍有差距，剩余瓶颈见下文。

## 瓶颈归因（profiling 先行）

用 `tests/profile_scan_phases.rs`（`#[ignore]`）在真实 PE 文件 + trim3 库上
拆分单次扫描（改动前）：

| 阶段 | 耗时 |
|------|------|
| runtime 创建 | ~0.2ms |
| `register_host_api`（155 个 `Function::new` + 8 个静态 JS shim eval，~231KB） | ~5.3ms |
| `load_database`（`_init`/`read` include 脚本 eval） | ~2.0ms |
| `init`（`PE/_init`） | ~0.5ms |
| 规则循环（333 条，编译+执行） | ~20ms（其中纯编译 ≈0.03ms/条 ≈ 10ms） |

验证：上游 `xscanengine.cpp` 的 `_shouldExecuteSignature` 只按
`DS`/`EP`/`HEUR` 文件名前缀过滤，当前 DB 无此类前缀规则，方案 C（签名
预匹配跳过）在上游语义下不存在收益，未采用。

## 实现

两层缓存，均只缓存编译产物、每次扫描仍新建 runtime（保持全局隔离语义）：

1. **规则 bytecode 缓存**（方案 A）
   - `LoadedRule.bytecode: Option<Arc<[u8]>>`；`DatabaseBuilder` 在加载时
     对每条规则做 `const→var` 预处理 + IIFE 包装后 `compile_global_script`
     （`JS_EVAL_TYPE_GLOBAL | COMPILE_ONLY`，sloppy，与 eval 语义一致），
     `JS_WriteObject(JS_WRITE_OBJ_BYTECODE)` 序列化存入快照。
   - `DatabaseSnapshot.bytecode` 持有 `_init`/各 `type_init`/`read` include
     框架脚本的编译产物。
   - 扫描时 `JS_ReadObject` → `JS_EvalFunction`（`this` = global_obj），
     代替源码 parse+eval；异常路径仍走 `Ctx::catch`，错误文本与文件名
     （`eval_script`）不变。
   - 编译失败或无 bytecode 时回退源码 eval，行为不收敛于缓存。

2. **host bridge 静态 shim 缓存**
   - `host_api_bridge.rs` 中 8 个静态 JS shim（~231KB）按 `&'static str`
     指针地址做进程级缓存；shim 以 **strict** 模式编译（与 `ctx.eval`
     默认 `EvalOptions{strict:true}` 一致）。
   - 每文件的 host 闭包仍每次新建（绑定当前 `BufferHost`），不缓存任何
     文件相关状态。
   - `register_host_api` 热路径 5.3ms → 1.2ms。

## unsafe 隔离

新 crate `die-qjs-bytecode` 是唯一调用 `rquickjs::qjs` 原始 FFI 的位置
（`die-rules` 保持 `#![forbid(unsafe_code)]`）。安全不变量写在 crate 文档：

- 仅接受 `&Ctx<'js>`，类型层面保证 context 已 enter；
- bytecode 只由本 crate 同构建产物生成、内存中流转，不接受外部输入
  （无版本错配/不可信反序列化面）；
- `JS_ReadObject` 不带 `ROM_DATA`（QuickJS 拷贝数据）；
- `JS_EvalFunction` 接管 `JS_ReadObject` 返回的 bfunc 引用，结果值释放。

## 被否决的方案：runtime 复用

`Scanner` 复用同一 runtime 在 500 文件上产生 2 个文件少 1 条 detection
（`includeScript` 全局副作用 + `typeof x === "undefined"` 守卫导致脏状态
跨文件残留），证实状态泄漏。除非实现完整的全局快照/恢复并重新给出
差分证据，否则不作为优化路径。

## 剩余瓶颈（后续方向）

优化后 trim3 库单扫描约 15.5ms 可归属（热路径）：

- 规则 bytecode 反序列化+真实执行 ~11.6ms（执行本身是大头，无法再靠
  编译缓存压缩；需逐规则 profiling 找慢规则，或由调用方按类型裁剪 DB）；
- host API 闭包注册 ~1.2ms（155 个 `Function::new` C API churn）；
- `_init`/include 执行 ~2.1ms、type_init ~0.6ms；
- 其余 ~5ms：文件读取、`detect_rule_types` probe、结果转换、runtime drop/GC。

全库（883 PE 规则）mean 76ms 中规则执行占 ~22ms，`other` 含 probe/结果
转换随规则数放大，建议后续针对慢规则（profiling 显示 `NetReactor` 类
protector 规则单条可达数百 ms）做调用方侧超时/裁剪，而非引擎改动。

## 可复现命令

```bash
cargo build --release -p die-engine --example scan_bench
./target/release/examples/scan_bench \
    --db /tmp/die_db_trim3 --files /tmp/perf_sample500 --count 500
# 阶段分解（忽略测试，需 DIE_PROF_DB 指向数据库）：
DIE_PROF_DB=/tmp/die_db_trim3 cargo test --release -p die-engine \
    --test profile_scan_phases -- --ignored --nocapture
DIE_PROF_DB=/tmp/die_db_trim3 cargo test --release -p die-rules \
    profile_eval_compile_exec_split -- --ignored --nocapture
```

## 验证记录

- `corpus/` 318 文件：`diec --json` 前后逐字节一致；
- `/tmp/perf_sample500` 500 文件（pe_malicious 抽样）：detections
  逐字节一致（1143 条）；
- corpus/edge 21 个畸形输入：无 panic；
- `cargo fmt --check` / `cargo clippy --workspace --all-targets
  --all-features -- -D warnings` / MSRV 1.88 clippy / `cargo test
  --workspace --all-features` / fuzz replay 全部通过。
