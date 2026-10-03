# 2026-10-12 Phase 45–47 顺序执行 — 分析摘要

## Phase 45（i18n 术语锚定草稿）
- 上游 `die_*.ts` 全为 unfinished skeleton，不可作锚定源；
  `dict_*.po` 24 语言术语表可用 → 短标签锚定率 27–35%。
- 产出：locale JSON catalog 拆分、`tools/i18n/` 生成器+校验器、
  键 parity/`{{var}}`/格式符 cargo 测试门、x-draft 标记、RTL。

## Phase 46（NFD 残余 handler）
- `handle_PolyMorph` 上游仅 Q_UNUSED → parity no-op（注释标注）；
  `handle_AnslymPacker` 上游注释死代码。真实残余 = ZIP 族
  member handler：`app.xml`→OFFICE/WORD/EXCEL、`meta.xml`
  `:opendocument:`→OPENDOCUMENT，移植 promote.rs。
- `tools/gen_p46_corpus.py` 10 fixture，oracle 逐条字节 parity；
  oracle_alignment +3 测试；NFD 差分 332 文件 0 差异。

## Phase 47（RNC old/加密流语料）
- old 变体 = 12B 头 + 后向位流（锚字节 0x80、MSB 序、位字节与
  literal 字节在同一递减排他游标上交错）→ BwdWriter 双游标模拟。
- new1 变体 = 18B 头 + 前向 LSB 位流（16 位 LE 懒 refill，
  `blen==0` 才补字）→ FwdWriter 镜像 refill 时机。
- 加密流：flags bit1 置位；KNOWN_KEYS(0x04d2) 预测命中路径 +
  9-literal-run（run_index 0..8）全 16 位约束唯一密钥 GF(2) 恢复
  （0xBEEF）+ 欠定密钥（0xAB）负向 fail-closed。
- 上游 nfd-oracle 逐条验证（old 两变体 decoded verified、加密两路
  恢复验证、欠定流无记录）；oracle_alignment +5 测试；NFD 差分
  337 文件 0 差异。真实 ProPack 样本 fallback 未启用（生成流已
  被 oracle 接受）。
