# 030 — 2026-10-05 PE 扫描性能优化分析

## 归因
profiling（profile_scan_phases.rs，真实 PE + trim3/333 PE 规则）：runtime
创建 0.2ms、host_api 注册 5.3ms（8 个静态 shim ~231KB JS 编译为主）、
load_database 2.0ms、init 0.5ms、规则循环 20ms（编译 ~10ms）。方案 C
（签名预匹配跳过）上游仅按 DS/EP/HEUR 前缀过滤，当前 DB 无此类规则，
无收益。方案 B（runtime 复用）实测 2 个文件漏检 1 条，确认全局状态泄漏，
否决。

## 方案
方案 A：LoadedRule.bytecode + SnapshotBytecode（_init/type_init/read），
compile_global_script（sloppy，COMPILE_ONLY）→ WriteObject → ReadObject →
EvalFunction，异常仍走 Ctx::catch。bridge shim 用 strict 变体按 &'static str
指针缓存，host 闭包仍每文件新建。unsafe 全在 die-qjs-bytecode。

## 结果
trim3：mean −44%、p50 −54%；probe_db2：mean −25%、p50 −35%。检测逐字节
一致。剩余大头是规则真实执行（NetReactor 类慢规则）与 probe/结果转换，
建议调用方侧裁剪或超时。
