# 分析记录 022 — 规则库漂移重同步（2026-10-12）

## 需求

用户：「规则库漂移重同步 也需要同步」——执行 ADR 0042 #12 的
Conditional 维护项，不满足于文档状态。

## 调查结论

1. **vendor 树已在 pin 上**：`upstream/Detect-It-Easy`（vendored subtree，
   非 submodule）经 `rule-source-manifest.json` 核验——commit `8925358d`、
   4,698 文件、0 缺失、0 哈希差异；与 `dep/Detect-It-Easy` submodule
   检出（同为 `8925358d`）`diff -r` 全树一致（唯一差异为残留空目录
   `db_extra/Binary`，已清理）。
2. **`PE.isNET` 调用方已为零**：vendor 全部规则树（db/db_extra/db_custom/
   dbs_min/dbs_special）grep 无 `PE.isNET(` 调用；`dbs_special`
   CachingEngine `_init` 仅函数字符串表列名且该树不被加载。
   ADR 0042「10 条规则仍调用」的描述已过期——2026-10-01 规则重同步至
   `8925358d` 后上游规则已全部改用 `isNet`。
3. **别名可安全移除**：`PE.isNET = PE.isNet`（host_api_bridge.js）为
   唯一残留。上游 @2550d2d 同样只有 `isNet`——移除即精确 parity。
   `differential_hardened` 的「零 TypeError」断言不受影响（无调用方）。
4. **新增回归**：conformance 测试断言 `typeof PE.isNET === "undefined"`
   且 `PE.isNet` 仍为 function——锁死别名不复归。

## 验证

- `batch_load`/`batch_load_all`/`conformance`/`differential_hardened`
  全绿（含 db_extra PE 规则零 TypeError 断言）。
- manifest 哈希全量核验通过，vendor = pin 基线。

## 文档同步

- ADR 0042 #12：Conditional → DONE（附后续同步程序：xtask sync-rules +
  manifest regen + 调用方核验）。
- ROADMAP：维护任务行改记 ✅。
- COMPATIBILITY D004 此前已声明别名移除，现实与文档现对齐。
