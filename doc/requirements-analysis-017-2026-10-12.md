# Phase 43 分析：剩余 capstone DM 模式（2026-10-12）

## 需求
Arch 枚举补全上游 `XCapstone::openHandle` 全部 DM 模式（Phase 39
只接了 MIPS/PPC/RISC-V 11 个）。

## 关键发现
- `capstone` 0.14 的 `Mode` 覆盖几乎全部所需位（含 M680X 十子模式、
  Cbpf、V9、M68k000-040）；`ExtraMode` 仅 MClass/V8/Micro/RiscVC。
  全部模式统一走 `Capstone::new_raw` 显式位掩码，逐位镜像
  `cs_open(arch, cs_mode(...))`。
- 例外 1：`CS_MODE_M68K_060`（1<<6）无 Mode 变体——借同位值
  `Mode::Mips32R6` 承载。
- 例外 2：`capstone::Arch` 无 WASM 变体（sys 层与上游 capstone
  5.0 都支持 CS_ARCH_WASM）——DM_WASM 走 capstone-sys FFI，
  `Insn::from_raw` 复用同一输出胶。crate 级 `forbid(unsafe_code)`
  放宽为 `deny` + 单函数 `allow` 与安全不变量注释（AGENTS.md
  "unsafe 限最小模块"条款允许）。
- `Thumb`/`V9`/`Cbpf` 在 Mode 而非 ExtraMode——首版误配已修。
- MOS65XX/EVM/WASM 上游 mode 为 `cs_mode(0)`，不是
  CS_MODE_MOS65XX_6502——位级等价但按源码记 0。
- `bitness()` 镜像 `getModeFromDisasmMode`：仅 X86_64/AArch64/
  MIPS64 返 64，PPC64/RISCV64 也返 32（上游 quirk）。
- xcore 合成字节难解码，用顺序字节流 fixture（0001/0203/…
  均为合法 XCORE 编码）。

## 验证
- capstone-oracle DM_TABLE 扩至 44 模式；corpus/disasm 新增 33
  fixture + 快照，`test_capstone_arches_oracle_parity` 逐指令
  parity 全过；garbage 输入不 panic。
- 前端下拉 33 项、标签取自上游 `disasmIdToString`。
