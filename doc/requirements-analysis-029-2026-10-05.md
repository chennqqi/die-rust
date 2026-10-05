# 需求分析 029 — 2026-10-05

## 需求

用户执行 `gh --help` 报"未找到命令"，要求安装 GitHub 客户端（gh CLI）。

## 环境判断

- Rocky Linux 10.2 x86_64，无免密 sudo（`sudo -n true` 需密码）。
- 官方 dnf 仓库安装需要 root，故选择免 sudo 路径：下载 GitHub
  Releases 官方 tarball，解压到 `~/.local/bin`（已在 PATH 中）。

## 实施

- 查询 `cli/cli` latest release → `v2.102.0`
- 下载 `gh_2.102.0_linux_amd64.tar.gz`，仅提取 `bin/gh` 到 `~/.local/bin`
- `gh --version` 验证通过；清理 /tmp 临时文件

## 遗留

- `gh auth status` 显示未登录；用户需自行执行 `gh auth login`
  （交互式，需浏览器或 token），agent 不代办认证。
- 若以后有 sudo，可改用官方 RPM 仓库以获得自动升级。
