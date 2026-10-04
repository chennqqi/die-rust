import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[2]
DESIGN = ROOT / "docs" / "design" / "c-abi.md"
ADR = (
    ROOT
    / "docs"
    / "design"
    / "decisions"
    / "0001-c-abi-opaque-ownership.md"
)


class CAbiDesignTests(unittest.TestCase):
    def test_design_links_evidence_and_covers_required_contracts(self):
        text = DESIGN.read_text(encoding="utf-8")
        self.assertIn("Status: In Review", text)
        self.assertIn("../research/c-static-link-spike.md", text)
        self.assertIn("../research/source-analysis.md", text)
        self.assertIn("max_total_allocation_bytes", text)
        for field in (
            "script_heap_bytes",
            "script_stack_bytes",
            "script_fuel_quanta",
            "script_deadline_ms",
        ):
            self.assertIn(field, text)
        for heading in (
            "## 三种独立版本",
            "## 公共 C 类型",
            "## 状态码",
            "## Database API",
            "## Scanner 与两层调用",
            "## Cancellation",
            "## Result handle",
            "## 线程模型",
            "## Panic、异常与 native fault",
            "## Allocator 策略",
            "## 静态链接策略",
            "## C、Go 与 Python 消费",
            "## 验收矩阵",
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, text)

    def test_design_uses_versioned_symbols_not_spike_symbols(self):
        text = DESIGN.read_text(encoding="utf-8")
        for symbol in (
            "die_v1_database_builder_new",
            "die_v1_scanner_new",
            "die_v1_scanner_scan_bytes",
            "die_v1_scan_bytes",
            "die_v1_cancel_request",
            "die_v1_result_json",
            "die_v1_result_free",
            "die_v1_error_free",
        ):
            with self.subTest(symbol=symbol):
                self.assertIn(symbol, text)
        self.assertIn(
            "不得直接复制 spike 的\n`die_spike_*` 名称",
            text,
        )

    def test_adr_has_required_sections_and_remains_proposed(self):
        text = ADR.read_text(encoding="utf-8")
        self.assertIn("Status: Proposed", text)
        for heading in (
            "## Context",
            "## Decision",
            "## Alternatives considered",
            "## Consequences",
            "## Evidence",
            "## Acceptance conditions",
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, text)


if __name__ == "__main__":
    unittest.main()
