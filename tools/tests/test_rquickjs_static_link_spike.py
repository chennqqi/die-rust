import hashlib
import json
import pathlib
import re
import tomllib
import unittest


ROOT = pathlib.Path(__file__).parents[2]
SPIKE = ROOT / "spikes" / "rquickjs-static-link"
REFERENCE = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "rquickjs-static-link.json"
)


class RquickjsStaticLinkSpikeTests(unittest.TestCase):
    def setUp(self):
        self.reference = json.loads(
            REFERENCE.read_text(encoding="utf-8")
        )

    def test_reference_matches_all_experiment_inputs(self):
        for relative, expected in self.reference["experiment"][
            "hashes"
        ].items():
            with self.subTest(path=relative):
                actual = hashlib.sha256(
                    (SPIKE / relative).read_bytes()
                ).hexdigest()
                self.assertEqual(actual, expected)

    def test_license_inventory_matches_exact_lock_packages(self):
        lock = tomllib.loads(
            (SPIKE / "Cargo.lock").read_text(encoding="utf-8")
        )
        root_name = "diec-rquickjs-static-link-spike"
        locked = {
            (package["name"], package["version"])
            for package in lock["package"]
            if package["name"] != root_name
        }
        recorded = {
            (package["name"], package["version"])
            for package in self.reference["licenses"][
                "cargo_packages"
            ]
        }

        self.assertEqual(locked, recorded)
        self.assertEqual(
            len(recorded),
            self.reference["licenses"]["package_count"],
        )
        self.assertEqual(
            self.reference["licenses"][
                "enabled_build_package_count"
            ],
            10,
        )
        self.assertLessEqual(
            self.reference["licenses"][
                "enabled_build_package_count"
            ],
            self.reference["licenses"]["package_count"],
        )
        self.assertTrue(
            all(
                package["license"]
                for package in self.reference["licenses"][
                    "cargo_packages"
                ]
            )
        )

    def test_runtime_and_vendored_license_identity_are_fixed(self):
        runtime = self.reference["runtime"]
        self.assertEqual(runtime["rquickjs"], "0.12.1")
        self.assertEqual(runtime["rquickjs_sys"], "0.12.1")
        self.assertEqual(runtime["native_engine"], "QuickJS-NG")
        self.assertTrue(runtime["vendored_c"])

        licenses = self.reference["licenses"]
        self.assertEqual(
            licenses["rquickjs_license"]["expression"],
            "MIT",
        )
        self.assertEqual(
            licenses["quickjs_ng_license"]["expression"],
            "MIT",
        )
        for key in ("rquickjs_license", "quickjs_ng_license"):
            self.assertRegex(
                licenses[key]["sha256"],
                r"^[0-9a-f]{64}$",
            )

    def test_header_constants_and_exports_match_rust(self):
        header = (
            SPIKE / "include" / "die_rquickjs_spike.h"
        ).read_text(encoding="utf-8")
        rust = (SPIKE / "src" / "lib.rs").read_text(
            encoding="utf-8"
        )
        statuses = {
            "DIE_RQUICKJS_SPIKE_STATUS_OK": 0,
            "DIE_RQUICKJS_SPIKE_STATUS_INVALID_ARGUMENT": 1,
            "DIE_RQUICKJS_SPIKE_STATUS_RUNTIME_ERROR": 2,
            "DIE_RQUICKJS_SPIKE_STATUS_PANIC": 3,
        }
        for name, expected in statuses.items():
            match = re.search(
                rf"#define {name} UINT32_C\((\d+)\)",
                header,
            )
            self.assertIsNotNone(match)
            self.assertEqual(int(match.group(1)), expected)

        for symbol in (
            "die_rquickjs_spike_eval",
            "die_rquickjs_spike_force_panic",
        ):
            self.assertIn(symbol, header)
            self.assertIn(f"fn {symbol}", rust)
        self.assertIn("Runtime::new()", rust)
        self.assertIn("Context::full(&runtime)", rust)
        self.assertIn('"40 + 2"', rust)

    def test_three_native_smoke_paths_are_recorded(self):
        windows = self.reference["windows_msvc"]
        linux = self.reference["linux_gnu"]
        self.assertEqual(
            windows["dynamic_crt"]["smoke_exit_code"],
            0,
        )
        self.assertEqual(
            windows["static_crt"]["smoke_exit_code"],
            0,
        )
        self.assertEqual(linux["smoke_exit_code"], 0)
        self.assertGreater(
            windows["dynamic_crt"]["staticlib_bytes"],
            0,
        )
        self.assertGreater(linux["archive_bytes"], 0)
        self.assertTrue(
            self.reference["fixture"]["panic_contained"]
        )
        self.assertEqual(
            self.reference["fixture"]["expected_value"],
            42,
        )

        dependency_names = [
            *windows["dynamic_crt"]["dynamic_dependencies"],
            *windows["static_crt"]["dynamic_dependencies"],
            *linux["dynamic_dependencies"],
        ]
        self.assertFalse(
            any(
                "quickjs" in dependency.lower()
                for dependency in dependency_names
            )
        )


if __name__ == "__main__":
    unittest.main()
