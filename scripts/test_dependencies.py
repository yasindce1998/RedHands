import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

import dependencies


class DependencyTests(unittest.TestCase):
    def test_manifest(self):
        lock = dependencies.load_manifest()
        self.assertIn("linux-arm64", lock["artifacts"]["chisel"])

    def test_checksum_failure_preserves_destination(self):
        class Response(io.BytesIO):
            def geturl(self):
                return "https://trusted.test/asset"

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "binary"
            path.write_bytes(b"existing")
            with mock.patch("urllib.request.urlopen", return_value=Response(b"tampered")):
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    dependencies.download("https://trusted.test/asset", "0" * 64, path)
            self.assertEqual(path.read_bytes(), b"existing")

    def test_verified_download(self):
        class Response(io.BytesIO):
            def geturl(self):
                return "https://trusted.test/asset"

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "binary"
            with mock.patch("urllib.request.urlopen", return_value=Response(b"verified")):
                dependencies.download("https://trusted.test/asset", hashlib.sha256(b"verified").hexdigest(), path)
            self.assertEqual(path.read_bytes(), b"verified")

    def test_archive_paths_not_extracted(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, output = Path(tmp) / "input.zip", Path(tmp) / "output"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("../../outside", b"evil")
                z.writestr("nested/chisel", b"expected")
            dependencies.extract_binary(archive, "https://trusted.test/file.zip", "chisel", output)
            self.assertEqual(output.read_bytes(), b"expected")
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["input.zip", "output"])

    def test_unsupported_platform_fails_without_download(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch("urllib.request.urlopen") as fetch:
            with self.assertRaisesRegex(ValueError, "no verified artifact"):
                dependencies.install(dependencies.load_manifest(), "kubedagger-client", "windows-amd64", tmp)
            fetch.assert_not_called()

    def test_symlink_member_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, output = Path(tmp) / "input.zip", Path(tmp) / "output"
            with zipfile.ZipFile(archive, "w") as z:
                link = zipfile.ZipInfo("chisel")
                link.create_system = 3
                link.external_attr = 0o120777 << 16
                z.writestr(link, "elsewhere")
            with self.assertRaises(ValueError):
                dependencies.extract_binary(archive, "https://trusted.test/file.zip", "chisel", output)

    def test_manifest_cannot_use_mutable_go_versions(self):
        import json
        lock = dependencies.load_manifest()
        lock["go"]["subfinder"] = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "dependencies.json"
            manifest.write_text(json.dumps(lock))
            with mock.patch.object(dependencies, "MANIFEST", manifest), self.assertRaises(ValueError):
                dependencies.load_manifest()


if __name__ == "__main__":
    unittest.main()
