# 分析记录 007 — 2026-10-01

## 需求
延续上游同步遗留：审计新规则树（Detect-It-Easy 8925358）调用的 host API
与桥接实现差集，重点是 XScanEngine +39 commits 引入的新方法。

## 分析
- 差集方法：规则调用名集合 −（Binary 原生 set + Binary.* JS + 原型链）。
  真差集收敛为归档记录 API、PE.findSignatures、getEPSignature；其余为
  规则内 helper（Archive.add/contents）或字符串字面量误匹配（COM.B）。
- 源码考古（XScanEngine 2550d2d / Formats 65b04be）：
  - XArchive::isArchiveRecordPresent = 成员名精确相等；PresentExp = 正则
    非空匹配（Qt 将 RegExp 参数转 "/src/flags" 字符串 → 字面量永不匹配，
    刻意复现该 quirk）。旧桥接用字节子串搜索，属错误语义，已替换。
  - JAR_Script::getManifestRecord：Qt regExp key+": (.*?)\n" + remove("\r")；
    Qt `.` 匹配 \r 而 JS 不匹配 → 用 [^\n] 等价。
  - APK_Script 继承 JAR_Script；getAndroidManifestRecord 需 AXML 解码 → stub。
  - NPM_Script::getPackageJsonRecord：QJsonValue::toString，非字符串 → ""。
  - Binary_Script::findSignatures：≤128 签名、预算 ≤65536、非法输入返回 []，
    每签名返回偏移或 -1；_fixOffsetAndSize 仅收末端。
  - NE_Script：isNE16=is16()；isDriver/isFont/isDll = XNE::getType
    （ne_flags 0x8000 + 非常驻名表扫描 driver/font，默认 DLL）；
    isImport/Export/ResourcesPresent 需 NE 表解析，0 规则调用 → 暂缺并文档化。
  - is8 = memory map MODE_8（桥接已有近似实现）；PE.isNET 上游已移除
    （仅 isNet），保留别名作为有意超集；getEPSignature 上游引擎不存在 →
    保持未定义以维持上游可观察行为。
