import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    archive = Path(sys.argv[1]).resolve()
    fixtures = Path(sys.argv[2]).resolve()
    with tempfile.TemporaryDirectory(prefix="bdscan-release-") as temporary:
        work = Path(temporary)
        unpacked = work / "package"
        shutil.unpack_archive(str(archive), str(unpacked))
        binaries = [path for path in unpacked.rglob("*") if path.name.lower() in ("bd-scan", "bd-scan.exe")]
        assert len(binaries) == 1, "expected exactly one scanner binary"
        scanner = binaries[0]
        for name in ("lua_patterns.txt", "binary_patterns.txt", "data_patterns.txt", "module_patterns.txt", "composite_rules.txt", "known_hashes.txt", "whitelist.txt"):
            assert (scanner.parent / name).is_file(), f"release is missing {name}"
        output = work / "output"
        output.mkdir()
        for name, expected, required in (
            ("clean", 0, set()),
            ("malicious", 1, {"LUA-010", "COMP-003"}),
            ("composite", 1, {"COMP-002"}),
        ):
            result = subprocess.run(
                [str(scanner), "-d", str(fixtures / name), "-o", str(output), "-s", "critical", "-q", "--html"],
                cwd=work, capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == expected, result.stdout + result.stderr
            data = json.loads((output / "scan_log.json").read_text(encoding="utf-8"))
            assert required <= {item["id"] for item in data["detections"]}, data
            assert data["complete"] and data["unscanned"]["total"] == 0, data
            assert "LUA-042" not in {item["id"] for item in data["detections"]}, data
            assert (output / "scan_report.html").is_file()
        print("release smoke: extracted package passed all fixtures")


if __name__ == "__main__":
    main()
