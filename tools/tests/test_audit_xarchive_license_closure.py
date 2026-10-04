import importlib.util
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = (
    ROOT / "tools/upstream/audit_xarchive_license_closure.py"
)
SPEC = importlib.util.spec_from_file_location(
    "audit_xarchive_license_closure", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class AuditXArchiveLicenseClosureUnitTests(unittest.TestCase):
    def test_find_markers_is_case_insensitive_and_sorted(self):
        markers = {
            "z-last": b"second marker",
            "a-first": b"FIRST MARKER",
        }
        self.assertEqual(
            MODULE.find_markers(
                b"first marker and SECOND MARKER", markers
            ),
            ["a-first", "z-last"],
        )

    def test_parse_dependency_file_handles_continuations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "source.o.d"
            path.write_text(
                "source.o: /src/source.cpp \\\n"
                " /src/header.h\n",
                encoding="utf-8",
            )
            dependencies = MODULE.parse_dependency_file(path)
        self.assertEqual(
            dependencies,
            [
                pathlib.Path("/src/source.cpp"),
                pathlib.Path("/src/header.h"),
            ],
        )

    def test_direct_units_map_objects_to_sources_and_depfiles(self):
        link_directory = pathlib.Path("/build/src/console")
        component_root = pathlib.Path("/source/XArchive")
        units = MODULE.direct_compile_units(
            [
                "CMakeFiles/diec.dir/__/__/XArchive/xarchive.cpp.o",
                "CMakeFiles/diec.dir/main_console.cpp.o",
            ],
            link_directory,
            component_root,
        )
        self.assertEqual(
            units,
            [
                (
                    component_root / "xarchive.cpp",
                    link_directory
                    / "CMakeFiles/diec.dir/__/__/XArchive/"
                    "xarchive.cpp.o.d",
                    "die-direct",
                )
            ],
        )


if __name__ == "__main__":
    unittest.main()
