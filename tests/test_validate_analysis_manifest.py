import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def _load_validator():
    path = Path("scripts/validate_analysis_manifest.py")
    spec = importlib.util.spec_from_file_location("validate_analysis_manifest", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AnalysisManifestTests(unittest.TestCase):
    def test_valid_manifest_checks_declared_bytes(self) -> None:
        module = _load_validator()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "summary.json"
            output.write_bytes(b'{"ok": true}\n')
            digest = hashlib.sha256(output.read_bytes()).hexdigest()
            (root / "analysis_manifest.json").write_text(
                json.dumps({"outputs": {"summary.json": digest}, "output_sha256": {"summary.json": digest}})
            )
            result = module.validate_manifest(root / "analysis_manifest.json")
            self.assertEqual(result["checked_outputs"], 1)

    def test_mismatched_legacy_hash_maps_are_rejected(self) -> None:
        module = _load_validator()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "summary.json"
            output.write_bytes(b"ok\n")
            digest = hashlib.sha256(output.read_bytes()).hexdigest()
            (root / "analysis_manifest.json").write_text(
                json.dumps({"outputs": {"summary.json": "0" * 64}, "output_sha256": {"summary.json": digest}})
            )
            with self.assertRaisesRegex(ValueError, "outputs and output_sha256 differ"):
                module.validate_manifest(root / "analysis_manifest.json")

    def test_output_path_cannot_escape_manifest_directory(self) -> None:
        module = _load_validator()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root.parent / "outside.txt"
            outside.write_bytes(b"outside\n")
            digest = hashlib.sha256(outside.read_bytes()).hexdigest()
            (root / "analysis_manifest.json").write_text(
                json.dumps({"outputs": {"../outside.txt": digest}, "output_sha256": {"../outside.txt": digest}})
            )
            with self.assertRaisesRegex(ValueError, "basename"):
                module.validate_manifest(root / "analysis_manifest.json")


if __name__ == "__main__":
    unittest.main()
