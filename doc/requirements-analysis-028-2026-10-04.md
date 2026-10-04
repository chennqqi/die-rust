# 需求分析 028：die-rust 改名实施（2026-10-04）

## 用户输入

按照 rename-die-rust.md v3 默认策略开始实施项目改名。

## 分析

三步提交按计划执行：

1. `c14a8f4a0` crate/目录 `diec-*`→`die-*`（9 个 crate + xtask
   白名单/DAG + `__diec_*`→`__die_*` QuickJS 内部全局名 +
   lockfile 重生成，203 文件）
2. `59ab812ff` 公开 ABI 面：`die.h`、`die_v1_*`/`DIE_*`/
   `die_abi_*`/`die_status_t`/`Die*`、`libdie_ffi`、py/go 绑定、
   `DIE_*` env、系统路径、sidecar `.die.json`+旧名读回退（61 文件）
3. `40c27e92d` 项目身份：`diec-rust`→`die-rust`（URL、artifact
   `die-*`、schema `$id`/`const`、tool producer 名、现行文档，
   395 文件）

保留（设计规定）：`diec` CLI 二进制名、`died`、`.diec.json` 读侧
兼容、upstream/corpus 字节冻结、doc/+docs/research/ 历史记录、
rename 设计文档自身。

## 验证

- fmt/clippy(-D warnings)/`--all-features` workspace test：52 个
  测试二进制全过、0 失败
- MSRV 1.88 clippy、fuzz replay 7/7、xtask check-deps
- C smoke vs `libdie_ffi`：17/17；python 12/12；go build/vet
- `diec --version` 仍输出 `diec 0.9.1`
- 残余 `diec` 分类：CLI 二进制引用（保留）、`.diec.json` 读回退
  （保留）、上游 oracle 路径（保留）、历史文档（保留）
