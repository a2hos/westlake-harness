import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/nanhai_plus_env.py"
spec = importlib.util.spec_from_file_location("nanhai_plus_env", SCRIPT)
env_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(env_module)


class EnvironmentEntryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nanhai env ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pool = self.root / "source pool"
        self.pool.mkdir()
        self.alias = self.root / "inputs"
        self.alias.symlink_to(self.pool, target_is_directory=True)
        self.document = self.root / "local_env.md"
        self.config = {
            "schema": 1,
            "paths": {"NANHAI_TEST_ROOT": str(self.pool), "NANHAI_TEST_LINK": str(self.alias)},
            "values": {"NANHAI_TEST_VALUE": "literal $(printf surprise) ' spaced"},
            "links": [{"link": "NANHAI_TEST_LINK", "target": "NANHAI_TEST_ROOT"}],
        }
        self.write()

    def write(self, prose="Environment"):
        self.document.write_text(prose + "\n" + env_module.START + "\n```json\n" +
                                 json.dumps(self.config) + "\n```\n" + env_module.END + "\n")

    def cli(self, *args, environment=None):
        return subprocess.run([sys.executable, str(SCRIPT), "--file", str(self.document), *args],
                              capture_output=True, text=True, env=environment)

    def test_child_uses_document_and_discards_stale_environment(self):
        ambient = os.environ.copy()
        ambient.update(NANHAI_TEST_ROOT="wrong-version", NANHAI_OLD_VERSION="stale")
        result = self.cli("--run", sys.executable, "-c",
                          "import os,json; print(json.dumps({k:v for k,v in os.environ.items() if k.startswith('NANHAI_')}))",
                          environment=ambient)
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = json.loads(result.stdout)
        self.assertEqual(actual["NANHAI_TEST_ROOT"], str(self.pool))
        self.assertEqual(actual["NANHAI_TEST_VALUE"], self.config["values"]["NANHAI_TEST_VALUE"])
        self.assertNotIn("NANHAI_OLD_VERSION", actual)

    def test_shell_exports_preserve_literal_characters_and_spaces(self):
        exports = self.cli("--shell")
        self.assertEqual(exports.returncode, 0, exports.stderr)
        result = subprocess.run(["sh", "-c", exports.stdout + '\nprintf "%s" "$NANHAI_TEST_VALUE"'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, self.config["values"]["NANHAI_TEST_VALUE"])

    def test_missing_source_prevents_child_execution(self):
        self.config["paths"]["NANHAI_TEST_ROOT"] = str(self.root / "missing")
        self.write()
        marker = self.root / "must-not-exist"
        result = self.cli("--run", sys.executable, "-c", "from pathlib import Path; import sys; Path(sys.argv[1]).touch()", str(marker))
        self.assertEqual(result.returncode, 2)
        self.assertIn("NANHAI_TEST_ROOT", result.stderr)
        self.assertFalse(marker.exists())

    def test_wrong_alias_is_rejected(self):
        wrong = self.root / "other-version"
        wrong.mkdir()
        self.alias.unlink()
        self.alias.symlink_to(wrong, target_is_directory=True)
        result = self.cli("--check")
        self.assertEqual(result.returncode, 2)
        self.assertIn("alias mismatch", result.stderr)

    def test_relative_and_duplicate_definitions_are_rejected(self):
        self.config["paths"]["NANHAI_TEST_ROOT"] = "relative/source"
        self.write()
        self.assertEqual(self.cli("--check").returncode, 2)
        self.document.write_text(env_module.START + '\n```json\n{"schema":1,"schema":1}\n```\n' + env_module.END)
        result = self.cli("--check")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Duplicate", result.stderr)

    def test_cache_identity_changes_with_bindings_but_not_prose(self):
        first = env_module.load_environment(self.document)[0]["NANHAI_ENV_CONFIG_SHA256"]
        self.write("Updated explanation")
        self.assertEqual(first, env_module.load_environment(self.document)[0]["NANHAI_ENV_CONFIG_SHA256"])
        self.config["values"]["NANHAI_TEST_VALUE"] = "changed"
        self.write()
        self.assertNotEqual(first, env_module.load_environment(self.document)[0]["NANHAI_ENV_CONFIG_SHA256"])

    def test_forbidden_container_launcher_is_rejected_before_execution(self):
        self.config["values"]["NANHAI_CONTAINER_POLICY"] = "forbidden"
        self.write()
        result = self.cli("--run", "/usr/local/bin/docker", "--version")
        self.assertEqual(result.returncode, 2)
        self.assertIn("forbidden by current project policy: docker", result.stderr)

    def test_historical_container_graph_executor_is_rejected(self):
        self.config["values"]["NANHAI_CONTAINER_POLICY"] = "forbidden"
        self.write()
        result = self.cli("--run", sys.executable, "-B",
                          "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/stock-bionic-target-graph-v21-g277-candidate-v1/executor.py",
                          "run")
        self.assertEqual(result.returncode, 2)
        self.assertIn("container graph executor is revoked", result.stderr)


if __name__ == "__main__":
    unittest.main()
