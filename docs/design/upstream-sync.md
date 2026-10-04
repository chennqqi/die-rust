# 上游同步设计

Status: Accepted  
Last updated: 2026-07-25

## 目标

在本仓库中保留可审计的 DIE-engine 上游快照，并能够在上游更新后：

- 查看主仓库发生了哪些变化。
- 获取新的 submodule gitlink SHA。
- 判断规则、扫描引擎、格式解析器和 CLI 是否需要同步。
- 在升级兼容基线前运行差分测试。

## 决策

将 `horsicq/DIE-engine` 以 squash subtree 导入：

```text
upstream/DIE-engine/
```

配置只读语义的远端名称：

```text
upstream-die -> https://github.com/horsicq/DIE-engine.git
```

新 clone 需要执行：

```sh
git remote add upstream-die https://github.com/horsicq/DIE-engine.git
git remote set-url --push upstream-die DISABLED

git remote add upstream-detect-it-easy https://github.com/horsicq/Detect-It-Easy.git
git remote set-url --push upstream-detect-it-easy DISABLED
```

初始 subtree 固定到：

```text
74eaf505c250ab47e709024e9dc41657cd8f2254
```

subtree 内容仅作为上游参考与变更跟踪来源，不直接成为 die-rust 的编译输入。

当前导入提交记录（2026-10-01 同步）：

| Item | Value |
| --- | --- |
| Local merge commit | `d73a8e83` |
| Squashed subtree commit | `70c74fbe` |
| `git-subtree-split` | `23fec32cac2a562342c1c2db8e22ce231b58f346` |
| Nested gitlinks | 58（全部位于 `dep/` 下） |

历史导入记录：`5f39bfba` / split `74eaf505c250ab47e709024e9dc41657cd8f2254`。

**布局变化**：新基线将上游全部 58 个 submodule 从仓库根目录迁移到
`dep/` 前缀下（如 `dep/XScanEngine`、`dep/Formats`）。`git subtree pull`
无法自动完成 rename/delete 合并，需手动重建 gitlink。lock 清单与
`tools/verify_upstream.py` 已适配嵌套 `dep/` gitlink。

规则/发布数据 sibling subtree（2026-10-01 同步）：

| Item | Value |
| --- | --- |
| Local path | `upstream/Detect-It-Easy/` |
| Local merge commit | `d6e0c45c` |
| Squashed subtree commit | `08b2951b` |
| `git-subtree-split` | `8925358d2298957d758b6bba74c393b622322efc` |
| Nested gitlinks | 0 |

历史导入记录：`e0bcca00` / split `c2c17dfa5ea4e078ba31eab55d87430c96622fb6`。

规则布局变化：大量可疑/低置信度规则移入 `dbs_special/db_dubious/`，
新增 `dbs_special/experimental/`、`help/DOTNET.md`，删除 `update.json`。

## 重要限制

DIE-engine 使用 58 个 git submodule。Git subtree 导入主仓库时：

- 顶层普通文件会进入 `upstream/DIE-engine/`。
- submodule 路径只保存 gitlink SHA。
- `Detect-It-Easy/db`、`XScanEngine`、`Formats`、`die_script` 等 submodule 内容不会随主 subtree 展开。
- subtree 内的 `.gitmodules` 只是上游证据，不能自动管理这些嵌套 gitlink。

因此，不能把“DIE-engine subtree 已更新”解释为“规则和核心组件内容已更新”。

## 组件锁定清单

机器可读 lock manifest 分为两层：

```text
gitlink inventory: upstream path + repository URL + commit SHA
component policy: gitlink path + content role + license + local materialization strategy
```

当前机器可读清单位于 [`../../upstream/components.lock.toml`](../../upstream/components.lock.toml)。其中：

- `[gitlink]` 完整锁定 baseline 的全部 58 个直接 submodule，包括上游路径、repository URL 和 commit SHA。
- `[[component]]` 只为已物化或当前调研直接涉及的组件补充角色、许可证和物化策略，不替代完整 gitlink 清单。
- `subtree-squash` 表示内容已进入本仓库。
- `external-research-checkout` 表示目前只锁定 SHA，内容尚未物化。
- 每个 component commit 必须与 baseline commit 中对应 `gitlink_path` 的 gitlink SHA 一致。

离线一致性校验：

```sh
python3 tools/verify_upstream.py
```

校验器不会 fetch 或修改工作树。它检查 lock 与 baseline 顶层 gitlink 及 `.gitmodules` 是否形成完全相同的 58 项集合，并验证全部 commit 和 repository URL；同时检查 subtree tree、`git-subtree-split` 以及规则目录 tree。失败时返回非零退出码。工具当前要求 Python 3.11+（使用标准库 `tomllib`），未来可在 Rust workspace 建立后迁移为 `xtask`。

## 更新流程

更新前先只获取远端：

```sh
git fetch upstream-die master
```

比较当前基线和候选版本：

```sh
git diff --submodule=log \
  23fec32cac2a562342c1c2db8e22ce231b58f346..upstream-die/master
```

调研并确定新的固定 SHA 后，执行：

```sh
git subtree pull \
  --prefix=upstream/DIE-engine \
  upstream-die <new-fixed-sha> \
  --squash
```

随后必须：

1. 比较 `.gitmodules` 和所有 gitlink。
2. 更新组件 lock manifest。
3. 单独同步受影响的规则或核心组件内容。
4. 更新 `docs/research/upstream-baseline.md`。
5. 运行规则完整性、构建和差分测试。
6. 以独立提交记录上游升级，禁止混入功能修改。

当 DIE-engine 的 `Detect-It-Easy` gitlink 变化时，在完成候选规则差异审计后同步 sibling subtree：

```sh
git fetch upstream-detect-it-easy <new-component-sha>

git subtree pull \
  --prefix=upstream/Detect-It-Easy \
  upstream-detect-it-easy <new-component-sha> \
  --squash
```

同步后必须验证：

```sh
git rev-parse <new-component-sha>:db
git rev-parse HEAD:upstream/Detect-It-Easy/db
```

两个 tree object SHA 必须相同；`db_extra`、`db_custom`、`dbs_min`、`dbs_special`、`yara_rules` 和 `peid_rules` 同样检查。

禁止直接对 `upstream/DIE-engine/` 做项目实现修改。若需要研究性注释，写入 `docs/research/`；若必须维护上游补丁，将补丁保存为独立、可重放的 patch，并记录原因。

## 组件内容的后续方案

以下方案留待 Phase 0 评审：

- `Detect-It-Easy` 使用 `upstream/Detect-It-Easy/` sibling subtree，完整保存规则与发布数据。
- 对 `XScanEngine`、`Formats`、`die_script` 等其他关键仓库分别建立 sibling subtree。
- 仅 vendor 运行所需规则，并用同步工具从固定 component SHA 复制和校验。
- 将完整 recursive checkout 保留在 CI/cache 外部，只在本仓库提交 lock manifest。

选择标准：

- 规则必须保持原始字节与文件名。
- 本仓库大小和 clone 成本可控。
- 上游升级 diff 可审计。
- 不要求使用者理解或初始化嵌套 git submodule。
- 构建和发布不依赖网络。

## 为什么使用 squash

主仓库有大量与 GUI 和 submodule bump 相关的历史。Squash subtree：

- 保留每次同步对应的上游 SHA。
- 让本仓库历史集中在兼容基线升级。
- 避免导入全部上游提交历史。

代价是不能在本仓库直接逐提交遍历上游历史；需要时通过 `upstream-die` remote 查询。
