# Requirements analysis 012 — Phase 24 ancient decoders

- 2026-10-08 Phase 24：`XAncientDecoder` 族（libancient）手写 Rust
  移植。拆解为位流基件（`In` 前向/后向输入 + LSB/MSB 位读取合并，
  消除上游 BitReader/InputStream 分离结构在 Rust 下的借用冲突）、
  `FOut`/`BOut`/`XOut` 输出流、静态/动态 `Huff`、VLC、CRC16；
  解码器：RNC（old/new × RNC1/RNC2 四路径 + 加密 key 恢复）、
  TPWM、UNIX pack（old/new + 尾填充规则）、Freeze。
  `describe` 契约 = 结构校验 + packed/raw 尺寸边界 + CRC（RNC），
  `ancient()` 门禁复刻上游（含 Freeze rawSize≤0 死路径 quirk，
  记入 `doc/upstream-bugs.md`）。样本策略：`tools/gen_ancient_
  corpus.py` 确定性生成最小有效流，经 Qt oracle 逐一验证后再入库；
  负向用例覆盖截断/坏 CRC。验证：76 语料 0 差异、workspace 全绿、
  clippy 零警告。
