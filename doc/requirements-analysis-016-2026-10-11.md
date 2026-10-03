# Phase 42 分析摘要（2026-10-11）

## 关键结论

- 上游 MSDOS 脚本可见 API 分两层：`Binary_Script`/`MSDOS_Script`
  QObject 槽（native）+ `db/MSDOS/_init` 脚本覆写
  （getBaseOffset/addressToOffset/getNEOffset/getEntryPointOffset/getSize）。
- `getEntryPointOffset`/`compareEP` native 对 FT_MSDOS 恒失败
  （`nEntryPointOffset=-1`：EP 地址 0x100 级，memory map 段记录在
  0x10000000）；脚本可见值来自 `_init` 公式
  `base + ((cs<<4 + ip) & 0xFFFFF)`。
- `getAddressOfEntryPoint` native = `getSegmentAddress(cs,ip)`：
  `cs*16+ip` 若 ≥0x100000 单次减 0x100000（非 &0xFFFFF，二者等价
  因最大 0x10FFEF 只回绕一次）。
- `getDisasmNextAddress`：`CS_GRP_BRANCH_RELATIVE` + imm → 目标地址，
  否则顺序地址；未映射/解码失败返 0（oracle 证实 EB→0x10000006、
  E9→0x1000000E）。
- QJSEngine 不能覆写 QObject 方法（QtScript 可以）——oracle 对
  _init 定义方法报 TypeError，期望值改用 vendored `_init` 公式
  （上游源码）。这不是 Rust 语义偏差。
- 上游 bug：`_init` 的 `AddressToOffset` 别名缺 `return` 恒
  undefined，原样保留。
