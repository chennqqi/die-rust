# 项目改名 diec-rust → die-rust：调查与设计

Status: Draft v3（并入评审发现：sidecar 扩展名决策、xtask 白名单、
字符串面、规模修正，2026-10-04）
Date: 2026-10-04

## 背景与动机

项目定位已从"Rust 版 diec 命令行"扩展为完整实现：CLI（`diec`）、
server（`died`）、GUI（`die`）、FFI/多语言绑定、NFD 引擎。
更名为 `die-rust` 后项目身份 = DIE 的 Rust 实现，diec/died/die
是项目的三个产物。

v2 变更：用户确认——**尚未发布 1.0、无外部用户，对外 API 面也
纳入改名**，彻底一次到位，不留 `diec_`/`DIEC_` 残留让未来用户困惑。

v3 变更：对照实际代码盘点修正规模（`.rs` 中 `diec` 共 1005 处，
其中 `use` 语句 183、`diec_*::` 路径 520），补充评审发现的决策项
与遗漏触点。

## 命名体系（改名后）

| 层 | 新名 | 说明 |
|---|---|---|
| 项目/仓库 | `die-rust` / `chennqqi/die-rust` | DIE 的 Rust 实现 |
| crate | `die-*`（die-cli/engine/rules/nfd/ffi/…） | workspace 包名与目录名 |
| CLI 二进制 | **`diec`（保留）** | 上游 console 二进制就叫 `diec`——
  drop-in 兼容是功能特性，不是残留 |
| server 二进制 | `died`（保留） | "die daemon"，本系列一致 |
| GUI 二进制 | `die`（保留，die-gui crate） | 上游 GUI 就叫 `die` |
| C ABI | `die.h` / `die_v1_*` / `DIE_*` / `DIE_H` | 原 `diec.h`/`diec_v1_*`/`DIEC_*` |
| 动态/静态库 | `libdie_ffi.{so,dll,dylib,a}` | 原 `libdiec_ffi.*` |
| env vars | `DIE_DB_PATH`/`DIE_LIB_PATH`/`DIE_BIN` 等 | 原 `DIEC_*` |
| C 常量 | `DIE_STATUS_*`/`DIE_SCAN_FLAG_*`/`DIE_ABI_*`/`DIE_DATABASE_KIND_*` | |
| Python | `import die`（`bindings/python/die.py`） | 原 `diec.py`/`import diec` |
| Go | package `die`，module `…/die-rust/bindings/go` | 原 package `diec` |
| 系统路径 | `/usr/share/die/db`、`/usr/local/share/die/db`、`/opt/die/db` | died.service/CLI 回退 |
| fuzz | `die-fuzz` | 原 `diec-fuzz` |
| annotation sidecar | `<file>.die.json`（读侧兼容 `.diec.json`） | 用户可见格式，见待决策 1 |
| release artifact | `die-{linux,windows,macos}-*` | 原 `diec-*` |
| oracle 镜像 | `die-rust/upstream-oracle-*` | 本地开发镜像 |
| schema $id | `https://die-rust.invalid/…` | 占位 URI，顺手改 |

唯一保留 `diec` 拼写的是 CLI 二进制名本身——它在 JSON/文档中应
被解读为 "DIE console"，与上游 `diec` 可执行文件同名是刻意的
兼容性设计（README 需一句话说明）。

## 待决策项（v3 新增）

1. **`.diec.json` sidecar 扩展名**：GUI annotations 的用户可见
   格式 `<file>.diec.json`（`die-gui/src/annotations.rs`、
   `commands.rs`、`AnnotationsPanel.tsx` 共 5 处）。选项：
   (a) 改 `.die.json` + 读侧 fallback 兼容 `.diec.json`（推荐，
   保护已存用户数据）；(b) 直接改 `.die.json` 不兼容（pre-1.0
   可接受但需 ADR 注明）；(c) 保留 `.diec.json`（唯一 `diec`
   残留点）。**默认取 (a)**。
2. **`DIEC_MAC_*`（~40 个 env vars）**：仅
   `tools/upstream/build_macos_qt5_oracle.sh` 使用的 oracle
   构建内部前缀。选项：(a) 一并改 `DIE_MAC_*`（推荐，与彻底
   改名一致）；(b) 标注为 oracle 工具内部前缀不动。
3. **spikes/ 范围**：`DIEC_SPIKE_*`/`DIEC_RQUICKJS_SPIKE_*`
   ~35 处分布在多个 spike 子项目（含各自 Cargo.lock 与已编译
   产物）。选项：(a) 全部改；(b) 仅 include guard/公开符号；
   (c) spikes 整体不在改名范围。**默认取 (a)**，与"不留残留"
   目标一致。

## 替换规则（v3 新增，防止机械替换误伤）

| 模式 | 替换为 | 说明 |
|---|---|---|
| `diec-core`/`diec-engine`/… 包名 | `die-*` | Cargo.toml、`-p` 参数 |
| `use diec_*`、`diec_*::` | `use die_*`、`die_*::` | 183+520 处 |
| `diec_v1_*`、`diec_status_t` 等 C 符号 | `die_v1_*`、`die_status_t` | FFI ABI |
| `DIEC_*` 宏/env/常量 | `DIE_*` | 含 `DIEC_MAC_*`、`DIEC_SPIKE_*` |
| `libdiec_ffi` | `libdie_ffi` | 库产物名 |
| `diec-rust`（仓库/字样/URL） | `die-rust` | ~90 处非 .rs 文件 |
| **裸 `diec`**（二进制名/路径） | **不改** | `[[bin]] name="diec"`、`diec.exe`、help 文本中命令名 |
| `.diec.json` sidecar | `.die.json` + fallback | 见待决策 1 |

字符串字面量（help/错误信息/JSON 输出/日志）中的 `diec` 遵循
同一规则：指**命令行二进制名**的保留 `diec`，指项目/crate/库
的改 `die(-rust)`。改名后须跑 golden/diff 测试捕捉连锁变化。

## 改名清单（按目录）

### A. 仓库与元数据

- GitHub Settings → Rename `die-rust`（旧 URL 自动重定向）
- `git remote set-url origin git@github.com:chennqqi/die-rust.git`
- `Cargo.toml`：`repository` 字段、workspace `members`（目录改名后）
- `bindings/go/go.mod` module path
- `crates/die-gui/tauri.conf.json` updater URL
- `died.service`/`died.spec`/`died.wxs` URL、Summary、`/usr/share/die/db`
- README*/COMPATIBILITY.md/AGENTS.md 项目名与链接

### B. crate 名 + 目录名（一次性 `git mv`）

| 目录 | 包名 | 备注 |
|---|---|---|
| `crates/diec-cli` → `crates/die-cli` | `diec-cli`→`die-cli` | `[[bin]] name="diec"` 保留 |
| `crates/diec-server` → `crates/die-server` | →`die-server` | `[[bin]] name="died"` 保留 |
| `crates/diec-ffi` → `crates/die-ffi` | →`die-ffi` | `[lib]` 加 `name="die_ffi"` |
| `crates/diec-core` → `crates/die-core` | →`die-core` | |
| `crates/diec-engine` → `crates/die-engine` | →`die-engine` | |
| `crates/diec-formats` → `crates/die-formats` | →`die-formats` | |
| `crates/diec-rules` → `crates/die-rules` | →`die-rules` | |
| `crates/diec-nfd` → `crates/die-nfd` | →`die-nfd` | |
| `crates/diec-output` → `crates/die-output` | →`die-output` | |
| `fuzz`（diec-fuzz） | →`die-fuzz` | 同步 `fuzz/Cargo.lock`；`fuzz_scan_ffi` 引用 `diec_v1_*` 符号同步改 |

连带修改：workspace `members`/`default-members`、各 crate `package`
名与 dep 名、183 处 `use diec_*`→`use die_*` + 520 处 `diec_*::`
路径（token 级替换，规则见上节）、`cargo build -p diec-server` 等
文档/脚本中的 `-p` 参数、`Cargo.lock`/`fuzz/Cargo.lock` 重新生成。

**`xtask`（v3 补，原文档遗漏）**：`xtask/src/main.rs` 内嵌 crate
白名单与 dep DAG（`diec-*` 名 + 依赖边）必须同步更新，否则
`xtask check-deps` 在改名后直接报错。crate 名注释同步改。

commit 1 内必须立即 `cargo check --workspace` 重新生成 lockfile
并验证编译，不得带失效 lockfile 进入 commit 2。

### C. C ABI（include/ + diec-ffi 内部）

- `include/diec.h` → `include/die.h`：`DIEC_H`→`DIE_H`、
  `DIEC_*` 宏、`diec_v1_*` 函数/类型、`diec_status_t`、注释
- `diec-ffi/src/`：`#[no_mangle] pub extern "C" fn diec_v1_*` →
  `die_v1_*`；`#[export_name]` 若存在同步改；lib 名 `die_ffi`
- `tests/c/smoke.c`：`#include "diec.h"`、函数调用、链接名
- `spikes/`：`diec_spike.h`、`diec_rquickjs_spike.h` 及全部
  `DIEC_SPIKE_*`/`DIEC_RQUICKJS_SPIKE_*` 符号（范围见待决策 3）
- ci.yml FFI smoke 段的 `diec_ffi`/`libdiec_ffi` 引用
- `tests/c/smoke` 编译产物当前已入库——顺手加入 `.gitignore`
  并从索引移除（本就不该入库）

### D. 绑定层

- Python：`bindings/python/diec.py` → `die.py`；`import diec`→`import die`；
  `libdiec_ffi.*` 加载路径、`diec_v1_*` 符号引用、`DIEC_*` 常量；
  `test_diec.py` → `test_die.py`（`DIEC_LIB_PATH`→`DIE_LIB_PATH`）
- Go：`bindings/go/diec/` → `bindings/go/die/`；package/cgo include、
  `diec_v1_*` 符号；module path 改 `die-rust`
- env vars 全仓：`DIEC_DB_PATH`→`DIE_DB_PATH`、`DIEC_LIB_PATH`→
  `DIE_LIB_PATH`、`DIEC_BIN`→`DIE_BIN`（tools、tests、ci.yml、
  docs 共 ~50 处）；`DIEC_MAC_*` 前缀见待决策 2
- `diec-cli/src/main.rs` db 回退路径 `/usr/share/diec/db` 等三处 → `die`
- `[package.metadata.deb]` 等打包元数据中的 maintainer/
  description 字段含 `diec-rust` 字样，一并更新

### E. CI / 脚本 / 打包

- ci.yml：FFI smoke 的 `diec_ffi`/`libdiec_ffi`、`DIEC_DB_PATH`、
  `cargo deb/wix -p diec-server`
- release.yml：artifact 名 `diec-*`→`die-*`、`libdiec_ffi`、
  `bindings/go/diec` 拷贝路径、release notes URL
- fuzz.yml：`diec-fuzz` package 引用（若有）
- `tools/`：`DIEC_RUST`/`DIEC_BIN` python 常量、`diec-rust` 字样
  ~70 处、`target/release/diec` 二进制路径（不变）
- `.ci-local/`、`tools/upstream/`：镜像/容器名前缀
  `diec-rust/`→`die-rust/`、`diec-oracle`→`die-oracle`（本地）
- `died.service` ExecStart 的 `/usr/share/diec/db`

**已知断点（v3 补）**：artifact 名 `diec-*`→`die-*` + `tauri.conf.json`
updater endpoint 硬编码仓库 URL 同步改。改名后旧构建的 updater 将
无法获取新命名 release 的更新——pre-1.0 无外部用户，可接受，
发版说明中注明即可；GitHub 仓库 rename 的重定向不影响新构建。

### F. 文档

- 顶层文档 + `docs/design/` 现行规范中项目名更新
- `docs/design/schemas/` `$id` → `die-rust.invalid`
- `doc/requirements*`/`upstream-bugs.md` 正文中的项目名（仅标题与
  现行描述；历史条目按"历史快照不改"处理）
- `.devin/rules/` 示例
- `docs/research/`、`docs/research/data/` 历史记录、git 历史、
  已发 release artifact——**不改**（历史快照）

### G. 验证

改名后为全量验证（按更新后的 AGENTS.md 提交前检查）：

```
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo +1.88.0 clippy --workspace --exclude die-gui --all-targets --all-features --locked -- -D warnings -A clippy::uninlined_format_args
cd fuzz && cargo test --no-default-features --features replay
DIEC→DIE 后 bindings/python/test_die.py、tests/c smoke 编译
```

另需（v3 补）：

- `cargo xtask check-deps`——xtask 白名单/DAG 改名后必须通过；
- `cargo metadata` 前后 diff 包名集合（确认仅 diec-*→die-*，
  无第三方包名漂移）；
- grep 断言 `diec` 仅剩二进制名与历史文档中的合法出现；
- 反向检查：确认无误伤——`died`、`die.exe`、`diec.exe` 字符串、
  第三方 crate 名（如 `die-gui` 依赖）未被 sed 波及；
- golden/diff 测试捕捉字符串输出面变化（help/JSON/日志）。

## 实施顺序建议

1. commit 1：crate/目录改名 + import/lockfiles（最大机械变更）
2. commit 2：C ABI + 绑定 + env vars + 系统路径
3. commit 3：CI/scripts/打包/文档 URL 与字样
4. GitHub rename 在本地全部改完并验证后执行，随后更新 remote。

每步独立 commit；全部完成后跑 G 节验证再 push。