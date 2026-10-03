# 需求分析 015 — Phase 34：LHA lh4-lh7 解码器（2026-10-03）

## 用户输入
"continue"——继续 Phase 34（LHA 主流压缩方法移植）。

## 分析
- 上游 `xlzhdecoder.cpp` 是 libarchive lzh_decode.c 移植版，
  lh4-lh7 共用状态机（w_bits 12/13/15/16、pos-pt 4/5bit 分派）；
  lh1 走独立 LZHUF 路径，归 Phase 35。
- 强化版上游校验：输入精确消耗（nCountInput==nInputLimit）、
  输出大小精确匹配、残余<8bit、单符号表拒收。
- 语料侧两次修正：token 总数须等于声明 orig 大小（上游
  out==expected 硬校验）；单符号 lt 表非完备码会被
  make_huffman_table 拒收（ptn!=0x10000）。
- meta-pt 表从 {0:1,1:2,2:3,3:3} 扩为 {0:1,1:2,2:3,3:4,4:5,5:5}
  以支持非等宽 lt bitlen（3 符号 lh4 fixture）。

## 结果
lzh_decode.rs ~800 行；4 方法 oracle 字节一致；19/19 测试；
173 文件 0 差异；提交后 Phase 34 关闭。

## Phase 41 实现分析（2026-10-09）

wim_decode.rs 双解码器移植路径确认：XPRESS Huffman 用 256B nibble→512 符号 canonical 完备码校验+16 位字位流+严格终止标记；LZX WIM 变体独立于 CAB 帧（3-bit 块型+16/24-bit 块长+R0-R2+位置槽表+E8 反变换 12000000），不能用 lzxd crate 替代。metadata 资源上游同源走 _readResource 解压——初版遗漏导致压缩 WIM list 直接失败，是主要卡点。上游对 LZMS/solid 同样产空（xwim.cpp:1347/1472），fail-closed 是 parity 而非差距。语料用 Python 编码器生成合法压缩流（XPRESS Huffman 编码 + LZX BLOCK_UNCOMPRESSED=3），经上游 oracle `unpacked:true` + 提取字节 parity 双重验证。
