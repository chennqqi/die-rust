# 需求分析 011 — Phase 21 NFD 引擎落地（2026-10-07）

## 输入

用户确认启动 Phase 21（此前澄清 Phase 23 不存在，按 19→20→21 顺序）。

## 分析

- SpecAbstract 许可证 MIT，审计通过；不编译/链接 C++，只作语义参照。
- 签名表机械化搬运：`tools/nfd_codegen.py` 解析 C 数组初始化器
  （含 `(quint32)-1` 哨兵、相邻字符串拼接、嵌套 brace），生成
  `gen_tables.rs`/`gen_names.rs`（35 表 / 1730 记录 / 599 FT 常量）。
- 匹配语义从 `XBinary::{compareSignatureStrings,convertSignature,
  getSignature,getStringCustomCRC32}` 考古：前缀比较、`.`/`?` 通配、
  ANSI 字面量、CRC32C 自定义多项式 0x82f63b78。
- 通用 pass 对齐 `NFD_Binary::{signatureScan,stringScan,constScan,
  resourcesScan,signatureExpScan,memoryScan}`：双 ft 过滤 + 按
  record name 去重。exp/memory scan 复用已下沉至 diec-core 的签名 VM
  （`parse_signature`/`match_signature`）。
- PE 路径 `pe_scan` 对齐 `NFD_PE::getInfo` 主体：header、EP 签名 +
  NOP/JZ/E9-follow 表达式链、overlay、import hash32/64 + position
  hash、resource names、section names、Rich 记录、deep section scan。
  `handle_*` heuristic 版本补全显式未移植。
- 集成：`ScanFlags::nfd`、`ScanDetection.engine`、CLI `--nfd`、
  GUI settings.engine.nfd_enabled + scan flags DTO；NFD 记录在 dedup
  之后追加，不参与 DIE 去重。
- 实测：`diec --nfd` on upx-pe32-nrv2b 输出 6 条 nfd 记录
  （Generic Linker/Microsoft linker/Fake signature/Generic/UPX
  0.81-3.81+/UPX 3.91+），JSON `engine` 字段正确。
- 验证：fmt ✅、clippy `-D warnings` 零警告、workspace 44 套件全绿。
