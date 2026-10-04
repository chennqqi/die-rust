# ADR 0017：died 扫描服务层（HTTP/JSON）

Status: Accepted
Last updated: 2026-08-04

## Context

生产环境需要大量文件进行 DIE 识别时，当前唯一的集成方式是 CLI 子进程调用
或 C ABI/FFI 嵌入。两种方式在批量场景下存在开销：

- **CLI 子进程**：每次进程启动都重新 build database（并行加载约 160ms），
  扫描 N 个文件若分 N 次调用则累计 N × 160ms 的规则加载成本。
- **FFI 嵌入**：调用方自行管理 `Database` 生命周期可避免重复加载，但要求
  调用方使用 C/Go/Python 绑定，不适合跨机器或异构客户端场景。

用户提出常驻服务方案：

- **本地请求**：客户端发送文件路径，服务端读取并返回 JSON 识别结果 +
  程序版本 + db 版本。适合同机/同容器批量扫描，避免大文件传输。
- **远程请求**：客户端发送文件内容，服务端返回 JSON 识别结果 + 程序版本
  + db 版本。适合跨机客户端。

当前 `Database` 构建后 immutable，通过 `Arc` 共享
（`crates/die-engine/src/database.rs:300-307`），天然适合常驻进程持有。
`scan_bytes`（`scanner.rs:293-405`）接受 `&Database` + 字节缓冲，与服务端
"收路径读文件"或"收内容直接扫描"两种模式自然对齐。

### 架构约束

AGENTS.md 要求：

- "CLI 和 FFI 是核心库的薄适配层，核心层不得依赖它们或 GUI 框架" — 服务层
  同理，必须是薄适配层，`die-engine` 不得依赖服务框架。
- "优先纯 Rust、跨平台依赖。引入大型依赖、native 依赖或系统库必须记录
  权衡" — HTTP 框架选型需记录权衡。
- "所有二进制输入均不可信" — 服务端接收的路径和文件内容均不可信，需受控。

### db 版本基础设施

当前 `Database` 结构（`database.rs:302`）只有 `snapshot` 和 `db_path`，没有
version 字段。已有 `RuleSourceManifest`（`crates/die-rules/src/manifest.rs`）
记录上游 repository/commit/synced_at 和 per-file sha256，可作为 db 版本来源。
但 `Database` 当前不加载 manifest，需要补充版本推导路径。

## Decision

Proposed：新增 `died (die-server crate)` crate 作为薄服务适配层，提供 HTTP/JSON API，
支持本地（路径）和远程（内容）两种扫描模式。服务层依赖 `die-engine`，
核心层不反向依赖。

### 协议选择：HTTP/JSON（非 gRPC）

选择 HTTP/JSON 而非 gRPC，理由：

- **与现有输出对齐**：`die-output` 已有 JSON 输出格式，服务端可直接复用
  序列化逻辑，不引入 protobuf schema 和 codegen。
- **依赖更轻**：`axum` + `tower` + `hyper` 是纯 Rust，无 protobuf codegen
  构建步骤；gRPC（`tonic` + `prost`）增加 protobuf 编译和 schema 维护面。
- **客户端通用性**：HTTP/JSON 可被 `curl`、任意语言标准库、浏览器直接
  调用，gRPC 需要 protobuf stub 生成。
- **跨平台**：`axum`/`hyper` 纯 Rust，无系统库依赖，符合 AGENTS.md 优先纯
  Rust 跨平台依赖的要求。

代价：HTTP/JSON 无双向流、无内置连接复用多路复用（HTTP/1.1 keep-alive
可缓解）。批量扫描场景以请求-响应为主，不需要流式。

### API 设计

#### `GET /health`
返回服务健康状态和版本信息。
```json
{
  "status": "ok",
  "program_version": "0.2.1",
  "db_version": {
    "commit": "c2c17dfa5ea4e078ba31eab55d87430c96622fb6",
    "rule_count": 1186,
    "synced_at": "2026-07-31T..."
  }
}
```

#### `POST /scan/path` — 本地路径模式
请求：
```json
{
  "path": "C:/samples/example.exe",
  "flags": {
    "all_types": false,
    "deep": false,
    "heuristic": false,
    "aggressive": false,
    "hide_unknown": false
  }
}
```
响应：
```json
{
  "path": "C:/samples/example.exe",
  "detections": [
    {
      "file_type": "PE",
      "type": "compiler",
      "name": "Microsoft Visual C++",
      "version": "14.29",
      "options": null
    }
  ],
  "diagnostics": [],
  "program_version": "0.2.1",
  "db_version": { "commit": "...", "rule_count": 1186 }
}
```

#### `POST /scan/bytes` — 远程内容模式
请求：`multipart/form-data` 或 `application/octet-stream`（文件内容）+
查询参数传递 flags。
响应：同 `/scan/path`，`path` 字段为客户端提供的文件名（可选）。

### 安全边界

#### 本地路径模式（`/scan/path`）

服务端读取客户端指定路径，这是最大的攻击面：

- **路径规范化**：使用 `std::fs::canonicalize` 解析符号链接和 `..`，
  拒绝无法 canonicalize 的路径。
- **根目录约束（可选）**：启动时通过 `--allow-root <dir>` 指定允许扫描的
  根目录，canonicalize 后检查路径是否在允许根下。未指定时拒绝路径模式
  或仅允许绝对路径（由部署者自行承担风险）。
- **文件大小上限**：`--max-file-size <bytes>`（默认 256 MiB），超过则
  返回 413。
- **符号链接策略**：`canonicalize` 已跟随符号链接，canonicalize 后的路径
  用于根目录检查，避免符号链接逃逸。
- **TOCTOU**：canonicalize 和 `std::fs::read` 之间存在 TOCTOU 窗口，
  但服务端以调用方权限运行，且路径已规范化，风险可控。高安全场景应使用
  `--allow-root` 限制。

#### 远程内容模式（`/scan/bytes`）

- **请求大小上限**：`--max-request-size <bytes>`（默认 256 MiB），由
  HTTP 框架的 body limit 强制。
- **超时**：`--scan-timeout <secs>`（默认 30s），超时返回 408/504。
- **内容不可信**：`scan_bytes` 已按 AGENTS.md "所有二进制输入均不可信"
  原则实现受控读取和 panic 隔离，服务层不额外处理。

#### 通用

- **监听地址**：默认 `127.0.0.1:0`（仅本地），生产部署通过 `--bind
  <addr>` 指定。不默认监听 0.0.0.0。
- **并发**：使用 `axum` 的异步处理，`scan_bytes` 是 CPU 密集型同步操作，
  通过 `tokio::task::spawn_blocking` 调度，避免阻塞异步运行时。并发数
  受 `--max-concurrent-scans <n>`（默认 = CPU 核心数）限制。
- **认证**：v1 不内置认证，依赖网络层隔离（本地监听或反向代理）。未来
  可扩展 API key 中间件。

### Runtime 复用

服务层应使用 ADR 0016 的 `Scanner` 有状态对象（若已实现），在常驻进程内
复用 per-file_type runtime。若 ADR 0016 尚未实现，服务层退化为每次请求
调用 `scan_bytes`，仍有"避免重复 database load"的收益，但 per-request
runtime 创建开销仍在。

### db 版本推导

`Database` 新增 `version()` 方法，返回 `DatabaseVersion` 结构：

```rust
pub struct DatabaseVersion {
    pub commit: String,      // 上游 commit SHA
    pub rule_count: usize,   // 规则数量
    pub synced_at: String,   // 同步时间（ISO-8601）
}
```

版本信息来源：
1. 优先从 `rule-source-manifest.json` 加载（若存在于 db 目录旁）。
2. 若 manifest 不存在，`commit` 为 `"unknown"`，`rule_count` 从
   `Database::rule_count()` 获取，`synced_at` 为 `"unknown"`。

此变更属于 `die-engine` 核心层的小幅扩展，不依赖服务层。

### Crate 结构

```
crates/died (die-server crate)/       # 新增
  Cargo.toml              # 依赖: die-engine, die-output, axum, tokio, tower
  src/
    lib.rs                # Server builder, 启动/停止
    routes.rs             # HTTP 路由定义
    handlers.rs           # 请求处理，调用 die-engine scan_bytes/Scanner
    error.rs              # HTTP 错误响应映射
    config.rs             # 服务配置（bind, max-file-size, allow-root 等）
  tests/
    server_integration.rs # 集成测试
```

`died (die-server crate)` 不进入 C ABI，不进入 CLI 默认构建。通过 feature gate 或
独立二进制 `died (die-server crate)` 提供。

### 依赖权衡

| 依赖 | 版本要求 | 用途 | 纯 Rust | 备注 |
|------|---------|------|---------|------|
| axum | >=0.7 | HTTP 框架 | 是 | 基于 hyper/tower |
| tokio | >=1.0 | 异步运行时 | 是 | 已是 rquickjs 间接依赖 |
| tower | >=0.4 | 中间件 | 是 | axum 依赖 |
| hyper | >=1.0 | HTTP 底层 | 是 | axum 依赖 |
| serde_json | >=1.0 | JSON 序列化 | 是 | 已在 workspace |

所有依赖均为纯 Rust，无系统库，无 native codegen。`tokio` 可能已是
workspace 间接依赖（需确认）。版本选择遵循 AGENTS.md "新依赖优先发布
>=7 天的版本"。

## Alternatives considered

### gRPC（tonic + prost）

优点：强类型 schema、双向流、连接多路复用。

代价：protobuf schema 维护、codegen 构建步骤、客户端需要 stub 生成、
与现有 JSON 输出格式不对齐需额外映射层。

结论：拒绝 v1。批量扫描以请求-响应为主，HTTP/JSON 足够。若未来需要流式
批量扫描可重新评估。

### Unix domain socket / named pipe

优点：无网络开销，天然本地安全。

代价：跨平台不一致（Unix socket vs Windows named pipe）、无标准客户端
工具、远程场景不可用。

结论：保留为未来本地优化选项。v1 用 HTTP 监听 127.0.0.1 覆盖本地场景。

### 不做服务层，仅优化 CLI 批量模式

在 CLI `--recursive` 内复用 database（当前已实现）+ runtime（ADR 0016），
避免服务化。

代价：无法服务跨机客户端；CLI 子进程模式对调用方仍有进程启动开销；
无法提供常驻 API 端点供异构客户端调用。

结论：CLI 批量优化（ADR 0016）应先做，但不替代服务层。两者互补：CLI
适合本地一次性批量，服务层适合常驻多客户端场景。

## Implementation

### 已实现（2026-08-04）

- **`Database::version()`**（`crates/die-engine/src/database.rs`）：
  从 `rule-source-manifest.json` 加载 commit/synced_at，fallback 用
  `DatabaseVersion::unknown(rule_count)`。无 serde 依赖（最小 JSON 解析）。
- **`died (die-server crate)` crate**（`crates/died (die-server crate)/`）：
  - `GET /health` — 返回 status + programVersion + dbVersion
  - `POST /scan/path` — 本地文件路径模式，支持 allow_root 路径校验
  - `POST /scan/bytes` — 远程内容模式，query 参数传 scan flags
  - 安全边界：max_file_size、max_request_size、scan_timeout、allow_root
  - 扫描在 `spawn_blocking` 线程执行，避免阻塞 tokio runtime
- **依赖**：axum 0.8.8 + tokio (full) + serde + serde_json + tower +
  tower-http (limit)。无 gRPC/protobuf 重依赖。
- **测试**：5 个集成测试（health、scan_bytes 检测、scan_path 404、
  随机数据无误报、allow_root 拒绝外部路径），全部通过。
- **端到端冒烟测试**：`died (die-server crate).exe --db upstream/Detect-It-Easy/db
  --bind 127.0.0.1:18099` 启动成功，三个端点均返回正确 JSON。
  扫描 `died (die-server crate).exe` 正确检测到 Microsoft Linker 14.44、
  MSVC 19.44、Visual Studio 2022 17.14。

### Scanner !Send 限制

`RquickjsRuntime`（QuickJS context）是 `!Send`，因此 ADR 0016 的 `Scanner`
不能直接放入 axum 的 `Send + Sync` 共享 state。当前服务层使用无状态
`scan_bytes`（每次请求创建新 runtime），但仍享受 `Database` 启动时一次
加载的收益（消除 160ms/进程 的 database 重建开销）。

未来优化：用专用 worker 线程持有 `Scanner`，通过 channel 接收扫描请求，
实现服务层 runtime 复用。这是后续 ADR 的范围。

### 二进制命名：died (die daemon)

二进制名定为 `died`（die daemon），crate 名保留 `die-server`。`died`
作为独立命令不进入 `diec` CLI，通过 `cargo build --package die-server`
单独构建。

### Windows 服务安装

`died install` / `died uninstall` 子命令通过 `sc.exe` 注册/注销 Windows
服务。服务以 `died --db <path> --bind <addr>` 命令行运行在 SCM 管理下。
非 Windows 平台 `install` 打印 systemd unit 模板供手动安装。

### 打包

- **DEB**：`cargo deb --package die-server`，配置在 `[package.metadata.deb]`，
  含 systemd unit 自动启用。输出 `target/debian/died_*.deb`。
- **RPM**：`rpmbuild -ba packaging/died.spec`，spec 文件在
  `crates/die-server/packaging/died.spec`，含 systemd unit + 用户创建。
- **MSI**：`cargo wix --package die-server`，WiX 配置在
  `crates/die-server/packaging/died.wxs`。输出 `target/wix/died-*.msi`。
- 打包说明文档：`crates/die-server/packaging/README.md`。

### FFI 嵌入 + 调用方自管 database

调用方通过 C ABI/Go/Python 绑定嵌入 diec，自行持有 `Database` 句柄。

代价：要求调用方使用特定语言绑定；不支持跨机；调用方需理解 database
生命周期管理。

结论：保留为嵌入场景的推荐方案。服务层面向"不想嵌入或需要跨机"的场景。

## Consequences

正面：

- 生产批量扫描避免重复 database load（160ms/进程 → 一次性）；
- 提供跨机、异构客户端的统一 API 端点；
- 本地/远程双模式覆盖同机和跨机部署；
- HTTP/JSON 客户端零依赖，`curl` 即可调用；
- 为 ADR 0016 runtime 复用提供常驻载体。

代价：

- 新增 `died (die-server crate)` crate 和 axum/tokio/tower/hyper 依赖闭包；
- 服务层安全边界（路径校验、大小限制、超时、并发控制）需持续维护；
- 本地路径模式有 TOCTOU 和路径逃逸风险，需 `--allow-root` 缓解；
- `Database` 需新增 version 基础设施（小幅核心层变更）；
- 服务层测试需覆盖 HTTP 协议、安全边界和并发场景；
- 不在当前 Phase 6 roadmap 范围内，需明确排期。

## Evidence

- `crates/die-engine/src/database.rs:300-307` — Database immutable + Arc
- `crates/die-engine/src/scanner.rs:293-405` — scan_bytes 接受 &Database
- `crates/die-rules/src/manifest.rs:46-63` — RuleSourceManifest 含 commit
- `crates/die-cli/src/main.rs:413-455` — CLI 当前 database build + 循环 scan
- ADR 0016 — runtime 复用方案（本 ADR 的性能基础）
- ADR 0002 — 分层 workspace 约束（服务层为薄适配层）
- 待补充：`docs/research/scan-service-design.md` — 服务层详细调研
- 待补充：`docs/design/scan-service-api.md` — API 契约详细设计

## Decision acceptance

评审确认以下决策方向：

- HTTP/JSON 优于 gRPC 的选型合理（与现有 JSON 输出对齐、依赖更轻、客户端
  通用）；
- 本地路径 + 远程内容双模式覆盖目标场景；
- `died (die-server crate)` 作为薄适配层不污染核心层的架构约束合理；
- 安全边界设计（路径规范化、根目录约束、大小/超时/并发限制、默认本地
  监听）方向正确；
- `Database` 新增 version 基础设施属合理的小幅核心层扩展；
- 依赖均为纯 Rust 跨平台，符合 AGENTS.md 要求。

## Implementation exit

以下条件满足后才能视为完整交付：

- `died (die-server crate)` crate 建立并通过 `xtask check-deps` DAG 校验（依赖方向：
  server → engine/output，核心层不反向依赖）；
- `/health`、`/scan/path`、`/scan/bytes` 三个端点有集成测试覆盖（正常、
  错误路径、超时、大小超限、并发）；
- 本地路径模式有安全测试覆盖：`..` 遍历、符号链接逃逸、`--allow-root`
  约束、文件大小上限；
- 远程内容模式有安全测试覆盖：请求大小上限、超时、畸形输入不崩溃；
- `Database::version()` 实现并有测试（manifest 存在/不存在两种路径）；
- 服务层在 31 基线 + 20 边缘样本上的差分结果与 CLI 一致（0 不匹配）；
- 并发扫描测试：多请求并发不产生状态泄漏或 panic；
- 依赖闭包通过 cargo deny 许可证审计；
- `died (die-server crate)` 二进制有 `--help`、`--version`、`--bind`、`--db`、
  `--allow-root`、`--max-file-size`、`--max-request-size`、
  `--scan-timeout`、`--max-concurrent-scans` 参数；
- cargo fmt/clippy/test --workspace --all-features 全部通过；
- `docs/design/scan-service-api.md` API 契约文档完成。
