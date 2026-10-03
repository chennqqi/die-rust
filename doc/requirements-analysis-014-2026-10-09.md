# 需求分析 014 — 2026-10-09

## 需求

为全部剩余 deferred 项制定 phase 计划，控制单 phase 复杂度。

## 分析

- 盘点真实剩余项（修正此前清单：CAB/ISO9660 已于 18.B 完成，
  InfoDB 已于 Phase 19 完成）。实际剩余：XStaticUnpacker 10 个
  脱壳器（合计 ~9.7k 行上游 C++）、TLSH、小众哈希、反汇编
  架构扩展（ADR 0041 待复审）、GUI NFD 视图。
- 拆分依据"性质 × 规模"：FSG/MEW/Petite/ASPack/NsPack/yoda 为
  PE 解压+重建类（复用 Phase 20 基件，分两批各 ~3.3k 行）；
  AutoIt/EnigmaVB/BoxedApp/InstallSimple 为容器提取类（~3.7k
  行，语义近 archive_unpack）；TLSH+小众哈希为小 phase；
  反汇编为 ADR-gated 评估 phase；GUI 视图单独 phase。
- 关键风险：老壳真实样本获取困难，设为每 phase 的 gate
  （无合法样本则记录跳过，不强行实现）。
- 不立项：自动更新（产品决策）、SSDeep（ADR rejected）、i18n
  （持续增量项）。
- 落地：ROADMAP.md 追加 Phase 26-31 节。
