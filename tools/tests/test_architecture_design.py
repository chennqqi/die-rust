from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
ARCHITECTURE = ROOT / "docs" / "design" / "architecture.md"
ADR = ROOT / "docs" / "design" / "decisions" / "0002-layered-workspace.md"


class ArchitectureDesignTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.architecture = ARCHITECTURE.read_text(encoding="utf-8")
        cls.adr = ADR.read_text(encoding="utf-8")

    def test_document_is_draft_and_evidence_backed(self) -> None:
        self.assertIn("Status: In Review", self.architecture)
        for evidence in (
            "source-analysis.md",
            "behavior-baseline.md",
            "rule-compatibility.md",
            "nested-scan-behavior.md",
            "rule-runtime-spike.md",
            "rquickjs-rule-runtime-spike.md",
            "c-static-link-spike.md",
            "c-abi.md",
        ):
            self.assertIn(evidence, self.architecture)

    def test_workspace_layers_are_defined(self) -> None:
        for crate in (
            "die-core",
            "die-formats",
            "die-rules",
            "die-engine",
            "die-output",
            "die-cli",
            "die-ffi",
            "xtask",
        ):
            self.assertIn(f"`{crate}`", self.architecture)

        self.assertIn("当前 workspace 不包含 `die-gui`", self.architecture)
        self.assertIn("CLI、FFI 和 output crate 不得复制", self.architecture)

    def test_dependency_direction_and_forbidden_edges_are_explicit(self) -> None:
        required_edges = (
            "`die-formats` | library | 格式探测与安全解析，返回格式事实 | `die-core`",
            "`die-rules` | library | 规则数据库、语法诊断、runtime/host ports 和 backend 隔离 | `die-core`",
            "`die-engine` | library | 扫描编排、候选选择、嵌套队列、结果聚合 | `die-core`, `die-formats`, `die-rules`",
            "`die-output` | library | canonical JSON 和人类可读渲染 | `die-core`",
        )
        for edge in required_edges:
            self.assertIn(edge, self.architecture)

        for forbidden in (
            "`die-core -> die-formats|die-rules|die-engine|die-output|die-cli|die-ffi`",
            "`die-rules -> die-formats|die-engine|die-output|die-cli|die-ffi`",
            "`die-engine -> die-cli|die-ffi|die-output`",
            "`die-output -> die-engine|die-formats|die-rules|die-cli|die-ffi`",
        ):
            self.assertIn(forbidden, self.architecture)

    def test_security_and_determinism_contracts_exist(self) -> None:
        for contract in (
            "checked arithmetic",
            "显式有界 work queue",
            "整个 scan 共享以下 hard budget",
            "不允许按 `HashMap` 的迭代顺序输出",
            "并行结果按输入 ordinal 合并",
            "workspace 默认禁止 `unsafe`",
            "runtime backend 必须提供 interrupt/fuel/heap 机制",
        ):
            self.assertIn(contract, self.architecture)

    def test_runtime_is_a_port_not_a_selected_backend(self) -> None:
        self.assertIn("`RuleRuntime` 与 `HostApi` ports", self.architecture)
        self.assertIn("由 `die-engine` 的 adapter 实现", self.architecture)
        self.assertIn("本文不选择 runtime", self.architecture)
        self.assertNotRegex(
            self.architecture,
            re.compile(r"(采用|选择|决定使用) (Boa|QuickJS)", re.IGNORECASE),
        )

    def test_adr_is_proposed_and_complete(self) -> None:
        self.assertIn("Status: Proposed", self.adr)
        for heading in (
            "## Context",
            "## Decision",
            "## Alternatives considered",
            "## Consequences",
            "## Evidence",
            "## Acceptance conditions",
        ):
            self.assertIn(heading, self.adr)
        self.assertIn("显式、有界 work queue", self.adr)
        self.assertIn("rules 定义 `RuleRuntime`/`HostApi` ports", self.adr)


if __name__ == "__main__":
    unittest.main()
