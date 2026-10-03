# Requirements analysis 013 — signature memory-map semantics (Phase 25)

- 收尾核对发现实质偏差：`$$`（ST_RELOFFSET）与 `#`（ST_ADDRESS）
  之前按平坦文件偏移解析，上游 `compareSignature` 经 `_MEMORY_MAP`
  走地址空间——PE 为 offset→RVA→+disp→offset（节未对齐时与平坦
  语义分歧）；COM/MSDOS 为 16 位段回绕；`#` 为绝对地址跳转（MSDOS
  2B 加 nCodeBase=0、4B seg:off 加 nStartLoadOffset）；上游
  `nBaseAddress`（`#[hex]` 后缀）解析后未用，属死字段。
- 实现：`SigCtx`（boxed off_to_addr/addr_to_off + seg_wrap16 +
  msdos_addr），`match_signature` 委托 `match_signature_ctx`（flat
  identity）；`PeInfo::sig_ctx`/`off_to_rva`、`msdos_sig_ctx`、
  `sig_ctx_for`/`match_signature_mapped` 公共入口。
- 接线：nfd 侧 signature_exp_scan/memory_scan/compare_ep 按 ft
  分派；engine BufferHost 规则 API 三处签名方法走缓存 SigCtx
  （OnceLock，避免 per-position 重解析）。
- 附带清扫：COMPATIBILITY 检测矩阵 ⚠ partial/差分未跑 → ✅；
  APK "META-INF 证书解压未移植" 备注过期删除（上游无此分支）。
- 验证：6 项 diec-core 单测（flat/seg16/PE 跨节/MSDOS seg:off/
  mapped `#`）+ 76 语料 0 差异 + workspace 全绿。
