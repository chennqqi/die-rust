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
