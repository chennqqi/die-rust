import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROBE_PATH = (
    ROOT / "tools" / "benchmark" / "probe_upstream_benchmark.py"
)
RUNNER_PATH = (
    ROOT / "tools" / "benchmark" / "run_process_benchmark.py"
)
PLANS_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "upstream-benchmark-plans.json"
)
REPORT_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "upstream-benchmark-linux-qt5.json"
)
AFFINITY_REPORT_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "upstream-benchmark-linux-qt5-affinity.json"
)
DOCKERFILE_PATH = (
    ROOT
    / "tools"
    / "upstream"
    / "Dockerfile.upstream-benchmark-qt5"
)
HARNESS_PATH = (
    ROOT
    / "tools"
    / "upstream"
    / "upstream_benchmark_harness_main.cpp"
)
DOCUMENT_PATH = (
    ROOT / "docs" / "research" / "upstream-performance-baseline.md"
)
AFFINITY_DOCUMENT_PATH = (
    ROOT / "docs" / "research" / "upstream-performance-affinity.md"
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PROBE = load_module("probe_upstream_benchmark", PROBE_PATH)
RUNNER = load_module("runner_for_upstream_benchmark_test", RUNNER_PATH)


class ProbeUpstreamBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = json.loads(
            REPORT_PATH.read_text(encoding="utf-8")
        )
        cls.affinity_report = json.loads(
            AFFINITY_REPORT_PATH.read_text(encoding="utf-8")
        )
        cls.plans = json.loads(
            PLANS_PATH.read_text(encoding="utf-8")
        )

    def test_committed_report_passes_semantic_verifier(self):
        self.assertTrue(self.report["passed"])
        self.assertEqual(self.report["failures"], [])
        self.assertEqual(PROBE.evaluate_report(self.report), [])
        self.assertEqual(
            self.report["baseline_scope"],
            "descriptive_upstream_only",
        )
        self.assertFalse(self.report["targets_frozen"])

    def test_report_binds_exact_plan_suite_and_case_set(self):
        self.assertEqual(self.report["plan_suite"], self.plans)
        self.assertEqual(
            self.report["plan_suite_sha256"],
            hashlib.sha256(PLANS_PATH.read_bytes()).hexdigest(),
        )
        expected_ids = {
            plan["benchmark_id"] for plan in self.plans["plans"]
        }
        self.assertEqual(
            set(self.report["case_reports"]),
            expected_ids,
        )

    def test_embedded_runner_reports_retain_exact_raw_hashes(self):
        for benchmark_id, wrapped in self.report[
            "case_reports"
        ].items():
            with self.subTest(benchmark=benchmark_id):
                raw = RUNNER.serialize_report(wrapped["report"])
                self.assertEqual(
                    hashlib.sha256(raw).hexdigest(),
                    wrapped["report_sha256"],
                )
                self.assertEqual(len(raw), wrapped["report_size"])
                self.assertEqual(
                    len(wrapped["report"]["runs"]),
                    wrapped["report"]["execution"]["measured_runs"],
                )

    def test_cgroup_and_upstream_identity_are_fixed(self):
        environment = self.report["environment"]
        self.assertEqual(
            environment["image_identity"]["revision"],
            PROBE.EXPECTED_REVISION,
        )
        self.assertRegex(
            environment["image_identity"]["id"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(
            environment["cgroup"]["cpu_max"],
            "100000 100000",
        )
        self.assertEqual(
            environment["cgroup"]["memory_max"],
            str(512 * 1024 * 1024),
        )
        self.assertEqual(environment["cgroup"]["pids_max"], "128")

        cli_reports = [
            wrapped["report"]
            for wrapped in self.report["case_reports"].values()
            if wrapped["report"]["executable"]["path"]
            == "/opt/die-build/src/console/diec"
        ]
        self.assertTrue(cli_reports)
        self.assertTrue(
            all(
                item["executable"]["sha256"]
                == PROBE.EXPECTED_CLI_SHA256
                for item in cli_reports
            )
        )

    def test_single_cpu_cpuset_is_strict_and_reaches_docker(self):
        self.assertEqual(PROBE.parse_single_cpu("0"), "0")
        self.assertEqual(PROBE.parse_single_cpu("007"), "7")
        for invalid in ("", "-1", "0-1", "1,2", "１"):
            with self.subTest(value=invalid):
                with self.assertRaises(argparse.ArgumentTypeError):
                    PROBE.parse_single_cpu(invalid)
        with self.assertRaises(argparse.ArgumentTypeError):
            PROBE.parse_single_cpu(str(2**31))

        arguments = PROBE.resource_arguments(
            self.plans["container_limits"],
            "0",
        )
        self.assertEqual(arguments[-2:], ["--cpuset-cpus", "0"])
        self.assertNotIn(
            "--cpuset-cpus",
            PROBE.resource_arguments(
                self.plans["container_limits"],
            ),
        )

    def test_affinity_contract_requires_exact_linux_vcpu_cpuset(self):
        report = json.loads(json.dumps(self.report))
        report["environment"]["cpu_affinity"] = {
            "requested_cpuset_cpu": "0",
            "scope": "linux_vcpu",
        }
        report["environment"]["cgroup"]["cpuset_effective"] = "0"
        self.assertEqual(PROBE.evaluate_report(report), [])

        report["environment"]["cgroup"]["cpuset_effective"] = "0-3"
        self.assertIn(
            "cgroup.cpuset_effective",
            PROBE.evaluate_report(report),
        )

    def test_affinity_allows_only_partial_control_rss(self):
        report = json.loads(json.dumps(self.report))
        report["environment"]["cpu_affinity"] = {
            "requested_cpuset_cpu": "0",
            "scope": "linux_vcpu",
        }
        report["environment"]["cgroup"]["cpuset_effective"] = "0"
        control = report["case_reports"][
            "upstream.qt-process-control.v1"
        ]["report"]
        for run in control["runs"][3:]:
            run["peak_rss_bytes"] = None
        retained = [
            run["peak_rss_bytes"]
            for run in control["runs"][:3]
        ]
        control["summary"]["peak_rss_bytes"] = {
            "max": max(retained),
            "median": sorted(retained)[1],
            "sample_count": 3,
        }
        wrapped = report["case_reports"][
            "upstream.qt-process-control.v1"
        ]
        raw = RUNNER.serialize_report(control)
        wrapped["report_sha256"] = hashlib.sha256(raw).hexdigest()
        wrapped["report_size"] = len(raw)
        self.assertEqual(PROBE.evaluate_report(report), [])

        pe = report["case_reports"][
            "upstream.cli-pe32-json.v1"
        ]["report"]
        pe["runs"][0]["peak_rss_bytes"] = None
        pe["summary"]["peak_rss_bytes"]["sample_count"] -= 1
        pe_wrapped = report["case_reports"][
            "upstream.cli-pe32-json.v1"
        ]
        raw = RUNNER.serialize_report(pe)
        pe_wrapped["report_sha256"] = hashlib.sha256(raw).hexdigest()
        pe_wrapped["report_size"] = len(raw)
        self.assertIn(
            "upstream.cli-pe32-json.v1.peak_rss",
            PROBE.evaluate_report(report),
        )

    def test_noise_is_retained_but_does_not_freeze_targets(self):
        interpretation = self.report["noise_interpretation"]
        self.assertEqual(
            interpretation["guardrails"],
            PROBE.NOISE_GUARDRAILS,
        )
        self.assertFalse(
            interpretation["short_process_regression_eligible"]
        )
        control = self.report["noise"][
            "upstream.qt-process-control.v1"
        ]
        self.assertGreaterEqual(control["mad_over_median"], 0)
        self.assertGreaterEqual(control["p95_over_median"], 1)
        for wrapped in self.report["case_reports"].values():
            duration = wrapped["report"]["summary"]["duration_ns"]
            self.assertGreater(duration["median"], 0)
            self.assertGreaterEqual(duration["mad"], 0)

    def test_committed_affinity_report_is_exact_and_auditable(self):
        report = self.affinity_report
        self.assertTrue(report["passed"])
        self.assertEqual(report["failures"], [])
        self.assertEqual(PROBE.evaluate_report(report), [])
        self.assertFalse(report["targets_frozen"])
        environment = report["environment"]
        self.assertEqual(
            environment["cpu_affinity"],
            {
                "requested_cpuset_cpu": "0",
                "scope": "linux_vcpu",
            },
        )
        self.assertEqual(
            environment["cgroup"]["cpuset_effective"],
            "0",
        )

        for benchmark_id, wrapped in report["case_reports"].items():
            item = wrapped["report"]
            measured = item["execution"]["measured_runs"]
            samples = item["summary"]["peak_rss_bytes"][
                "sample_count"
            ]
            if benchmark_id == "upstream.qt-process-control.v1":
                self.assertGreaterEqual(samples, 3)
                self.assertLess(samples, measured)
            else:
                self.assertEqual(samples, measured)
        interpretation = report["noise_interpretation"]
        self.assertFalse(
            interpretation["control_peak_rss_complete"]
        )
        self.assertFalse(
            interpretation["control_peak_rss_product_evidence"]
        )

    def test_report_contains_no_windows_host_path(self):
        for report in (self.report, self.affinity_report):
            serialized = json.dumps(report, ensure_ascii=False)
            self.assertNotRegex(serialized, r"[A-Za-z]:\\\\")

    def test_dockerfile_relinks_only_main_and_generates_corpora(self):
        dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
        harness = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "ARG BASE_IMAGE=die-rust/upstream-oracle-cmake:74eaf505",
            dockerfile,
        )
        self.assertIn(
            "CMakeFiles/diec.dir/main_console.cpp.o",
            dockerfile,
        )
        self.assertIn("generate_baseline_corpus.py", dockerfile)
        self.assertIn("generate_archive_limit_fixture.py", dockerfile)
        self.assertIn("engine.loadDatabase", harness)
        self.assertIn("engine.scanFile", harness)
        self.assertNotIn("QElapsedTimer", harness)
        self.assertNotIn("getrusage", harness)

    def test_research_document_keeps_scope_and_exact_baseline_values(self):
        document = DOCUMENT_PATH.read_text(encoding="utf-8")
        self.assertIn("descriptive upstream baseline", document)
        self.assertIn("`targets_frozen=false`", document)
        self.assertIn("17 warmup、90 measured", document)
        self.assertIn("115.289 ms", document)
        self.assertIn("1,368.636 ms", document)
        self.assertIn("76.79 MiB", document)
        self.assertIn(
            self.report["environment"]["image_identity"]["id"],
            document,
        )

    def test_affinity_document_keeps_precise_scope_and_values(self):
        document = AFFINITY_DOCUMENT_PATH.read_text(encoding="utf-8")
        report = self.affinity_report
        self.assertIn("Linux vCPU", document)
        self.assertIn("不是物理核心证明", document)
        self.assertIn("`cpuset.cpus.effective=0`", document)
        self.assertIn("9/30", document)
        self.assertIn("167.141 ms", document)
        self.assertIn("1,373.345 ms", document)
        self.assertIn(
            report["environment"]["image_identity"]["id"],
            document,
        )
        self.assertIn(
            hashlib.sha256(AFFINITY_REPORT_PATH.read_bytes()).hexdigest(),
            document,
        )


if __name__ == "__main__":
    unittest.main()
