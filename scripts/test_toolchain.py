"""Keep CI, release builds, Docker and downloaded toolchains on one patch baseline."""

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent


class ToolchainTests(unittest.TestCase):
    def test_toolchain_versions_match_module(self):
        version = re.search(r"^go (\d+\.\d+\.\d+)$", (ROOT / "go.mod").read_text(), re.M).group(1)
        self.assertGreaterEqual(tuple(map(int, version.split("."))), (1, 26, 11))
        stages = re.findall(r"^FROM golang:([^ ]+)", (ROOT / "Dockerfile").read_text(), re.M)
        self.assertEqual(stages, [version + "-alpine", version + "-alpine"])
        lock = json.loads((ROOT / "scripts/dependencies.json").read_text())
        for url, _ in lock["artifacts"]["go"].values():
            self.assertIn("/go" + version + ".", url)

    def test_workflows_use_module_version_and_bypass_stale_cache(self):
        for name in ("ci.yml", "release.yml"):
            workflow = (ROOT / ".github/workflows" / name).read_text()
            steps = re.findall(r"uses: actions/setup-go@[^\n]+\n(.*?)(?=\n\s*- |\Z)", workflow, re.S)
            self.assertTrue(steps, name)
            for step in steps:
                self.assertIn("go-version-file: go.mod", step, name)
                self.assertIn("check-latest: true", step, name)
                self.assertNotRegex(step, r"\bgo-version:")


if __name__ == "__main__":
    unittest.main()
