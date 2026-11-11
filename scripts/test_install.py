"""Exercise the quick installer without network access or privileged writes."""

import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


INSTALLER = Path(__file__).with_name("install.sh").resolve()


@unittest.skipIf(os.name == "nt", "Bash installer tests run on Unix")
class InstallerTests(unittest.TestCase):
    def fixture(self, root, mismatch=False, checksums=True):
        tools, install_dir = root / "tools", root / "installed"
        tools.mkdir()
        archive = root / "release.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            data = b"test executable contents\n"
            info = tarfile.TarInfo("redhands")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        digest = "0" * 64 if mismatch else hashlib.sha256(archive.read_bytes()).hexdigest()
        sums = root / "sums"
        platform = subprocess.check_output(["uname", "-s"], text=True).strip().lower()
        machine = subprocess.check_output(["uname", "-m"], text=True).strip()
        arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[machine]
        sums.write_text(f"{digest}  redhands_1.2.3_{platform}_{arch}.tar.gz\n")
        curl = tools / "curl"
        curl.write_text("""#!/usr/bin/env bash
set -eu
url=""
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) output="$2"; shift 2 ;;
    https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
case "$url" in
  */releases/latest) echo '{"tag_name": "v1.2.3"}' ;;
  */SHA256SUMS) [[ "$TEST_CHECKSUMS" == yes ]]; cp "$TEST_SUMS" "$output" ;;
  *.tar.gz) cp "$TEST_ARCHIVE" "$output" ;;
  *) exit 99 ;;
esac
""")
        curl.chmod(0o755)
        env = os.environ.copy()
        env.pop("REDHANDS_VERSION", None)
        env.update(PATH=str(tools) + os.pathsep + env["PATH"], TEST_ARCHIVE=str(archive), TEST_SUMS=str(sums), TEST_CHECKSUMS="yes" if checksums else "no", TMPDIR=str(root))
        return install_dir, env

    def test_verified_release_and_tool_instructions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination, env = self.fixture(root)
            result = subprocess.run(["bash", str(INSTALLER), f"--dir={destination}", "--with-tools"], env=env, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((destination / "redhands").read_bytes(), b"test executable contents\n")
            self.assertIn("no downloaded root script", result.stdout)
            self.assertFalse(list(root.glob("tmp.*")), "temporary files leaked")

    def test_bad_or_missing_checksum_never_overwrites_binary(self):
        for mismatch, checksums in [(True, True), (False, False)]:
            with self.subTest(mismatch=mismatch, checksums=checksums), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                destination, env = self.fixture(root, mismatch=mismatch, checksums=checksums)
                destination.mkdir()
                binary = destination / "redhands"
                binary.write_bytes(b"existing")
                result = subprocess.run(["bash", str(INSTALLER), f"--dir={destination}"], env=env, text=True, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(binary.read_bytes(), b"existing")


if __name__ == "__main__":
    unittest.main()
