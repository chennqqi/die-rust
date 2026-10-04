# 分析记录 023 — 真实样本长尾验证（2026-10-12）

## 需求

用户：「真实样本长尾值得验证」——为 ASPack 2.11x/Petite/InstallSimple
模拟器分支获取真实世界样本做差分。

## 样本获取

- Petite 2.3 官方发布（un4seen.com/files/petite23.zip）：petite.exe/
  petgui.exe 自打包——免费可再分发。
- unipacker 公开测试语料（GitHub）：lbop20_aspack.exe（NFD 检出
  ASPack 2.12-2.42 + ASProtect SKE 2.72+）、lbop20_PEtite.exe（Petite 2.4）。
- InstallSimple 产品自身 Setup.exe（2024 现网 + 2013 archive.org
  快照）：均为 UPX 2.03 包装。

未获取到：真正触发模拟器成功路径的样本（ASPack 2.11x 打包物、可解包的
Petite 变体、InstallSimple 格式文件）——aspack.com SSL 失败、archive.org
仅有 Gentee 安装器外壳（无 Gentee 提取器）、wine 32 位不可用无法运行
packer 自制样本、tuts4you 需登录。

## 差分结果

6 样本 × installsimple/aspack/petite 三类：上游 oracle 与 Rust 可观察
行为**完全一致**。关键发现：上游对全部真实样本 init_unpack:false——
这些 stub 变体上游同样不支持，parity 落在失败路径（语义上仍是有价值
的对齐证据：claim/init/version 三字段逐类一致，含"不 claim"的一致）。

## 产出

- `corpus/real-unpack/manifest.json`：sha256 + 来源 + oracle 期望
- `tools/corpus/fetch_real_unpack_samples.py`：sha256 校验获取，不入库
- `crates/diec-engine/tests/real_unpack_parity.rs`：逐类 parity 断言，
  样本缺失时跳过
- `.gitignore`：corpus/real-unpack/*.exe
- 文档：ROADMAP/COMPATIBILITY/ADR 0042 记录结论

## 残留

模拟器成功路径真实样本验证仍是缺口（需要 era-specific 打包物或可运行
packer 的 Windows 环境）；已文档化。
