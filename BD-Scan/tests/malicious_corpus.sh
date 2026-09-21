#!/usr/bin/env bash
#
# Scans real Garry's Mod backdoors that were caught in the wild and fails if the
# scanner does worse than malicious_corpus.expected records.
#
# real_corpus.sh asks the opposite question. It scans published, legitimate code
# and fails on a CRITICAL nobody can explain, which measures false positives.
# This one scans code that is known to be malicious and measures what gets
# through. A scanner needs both numbers; either one alone is trivial to game.
#
# The samples are not stored in this repository. They are cloned from public
# sources at pinned commits, and every file is checked against a sha256 recorded
# here before anything is scanned. A source that cannot be reached is skipped
# rather than failed, so the suite still runs without network access.
#
# Usage: malicious_corpus.sh <path to scanner> [checkout dir]
#
set -euo pipefail

SCANNER=${1:?usage: malicious_corpus.sh <scanner> [checkout dir]}
SCANNER="$(cd "$(dirname "$SCANNER")" && pwd)/$(basename "$SCANNER")"
WORK=${2:-/tmp/bd-malicious-corpus}
HERE=$(cd "$(dirname "$0")" && pwd)
RULES=$(dirname "$HERE")
EXPECTED="$HERE/malicious_corpus.expected"

# Argument 2 is a scratch checkout directory, not the rule directory the other
# test scripts take there. Cloning the corpus into the source tree mixes these
# samples into the benign corpus run, so refuse it.
if [ -e "$WORK/lua_patterns.txt" ]; then
  echo "::error::$WORK is the rule directory; argument 2 is a scratch checkout path" >&2
  exit 2
fi

mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
SRC="$WORK/src"
mkdir -p "$SRC"

MISSING=0
while read -r _ id url commit; do
  [ -n "${id:-}" ] || continue
  target="$SRC/$id"
  if [ ! -d "$target/.git" ]; then
    if ! git clone --quiet -c core.autocrlf=false -c core.eol=lf "$url" "$target" 2>/dev/null; then
      echo "malicious corpus: could not reach $url, skipping $id"
      MISSING=1
      continue
    fi
  fi
  git -C "$target" config core.longpaths true
  git -C "$target" config core.autocrlf false
  git -C "$target" config core.eol lf
  if ! git -C "$target" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$target" fetch --quiet origin 2>/dev/null || true
  fi
  if ! git -C "$target" checkout --quiet --force "$commit" 2>/dev/null; then
    echo "malicious corpus: commit $commit unavailable for $id, skipping"
    MISSING=1
  fi
done < <(grep '^source ' "$EXPECTED")

if [ "$MISSING" = "1" ]; then
  echo "malicious corpus: skipped, not every source could be fetched"
  exit 0
fi

OUT="$WORK/out"
rm -rf "$OUT"
mkdir -p "$OUT"

python3 - "$SCANNER" "$RULES" "$SRC" "$OUT" "$EXPECTED" <<'PY'
import hashlib
import json
import os
import shutil
import subprocess
import sys

scanner, rules, src, out, expected_path = sys.argv[1:6]
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}

expected = {}
hashes = {}
floor = 0
for line in open(expected_path, encoding="utf-8"):
    stripped = line.strip()
    if stripped.startswith("# family-recall-floor"):
        floor = int(stripped.split()[-1])
        continue
    if not stripped or stripped.startswith("#"):
        continue
    parts = stripped.split()
    if parts[0] == "sha256" and len(parts) >= 3:
        hashes[" ".join(parts[2:])] = parts[1]
    elif parts[0] == "source":
        continue
    elif len(parts) == 2 and parts[1] in ORDER:
        expected[parts[0]] = parts[1]

problems = []
for name, digest in sorted(hashes.items()):
    path = os.path.join(src, name.replace("/", os.sep))
    if not os.path.isfile(path):
        problems.append("missing sample: " + name)
        continue
    if hashlib.sha256(open(path, "rb").read()).hexdigest() != digest:
        problems.append("content changed upstream: " + name)

if problems:
    print("malicious corpus: the pinned samples do not match this checkout")
    for problem in problems[:10]:
        print("   " + problem)
    sys.exit(1)


def scan(rule_dir, output):
    os.makedirs(output, exist_ok=True)
    done = subprocess.run(
        [scanner, "-d", src, "-o", output, "--rules", rule_dir, "-q", "--color", "never"],
        capture_output=True, text=True)
    if done.returncode not in (1, 3):
        print("malicious corpus: scanner exited " + str(done.returncode))
        print(done.stdout[-2000:])
        print(done.stderr[-2000:])
        sys.exit(1)
    return json.load(open(os.path.join(output, "scan_log.json"), encoding="utf-8"))


blind = os.path.join(out, "rules-without-hashes")
os.makedirs(blind, exist_ok=True)
for name in os.listdir(rules):
    if name.endswith(".txt") and not name.endswith(".test.txt"):
        source = os.path.join(rules, name)
        if os.path.isfile(source):
            shutil.copy(source, os.path.join(blind, name))
open(os.path.join(blind, "known_hashes.txt"), "w").write(
    "# blanked by malicious_corpus.sh so the recall below measures the rules\n")

recognised = sum(1 for item in scan(rules, os.path.join(out, "shipped"))["detections"]
                 if item.get("id") == "HASH-001")

best = {}
seen_ids = set()
for item in scan(blind, os.path.join(out, "rules-only"))["detections"]:
    seen_ids.add(item.get("id", ""))
    name = item["file"].replace("\\", "/")
    if "/src/" in name:
        name = name.split("/src/", 1)[1]
    if ORDER[item["severity"]] < ORDER.get(best.get(name, "none"), 4):
        best[name] = item["severity"]


def family_of(name):
    longest = ""
    for candidate in expected:
        if (name == candidate or name.startswith(candidate + "/")) and len(candidate) > len(longest):
            longest = candidate
    return longest


families = {name: "none" for name in expected}
unclaimed = []
for name in hashes:
    family = family_of(name)
    if not family:
        unclaimed.append(name)
        continue
    found = best.get(name, "none")
    if ORDER[found] < ORDER[families[family]]:
        families[family] = found

failures = ["sample belongs to no declared family: " + name for name in unclaimed[:5]]
for family, want in sorted(expected.items()):
    got = families[family]
    if ORDER[got] > ORDER[want]:
        failures.append("%s dropped from %s to %s" % (family, want, got))

caught = sum(1 for value in families.values() if value == "critical")
silent = sum(1 for name in hashes if name not in best)
sources = len({name.split("/")[0] for name in hashes})

print("malicious corpus: %d samples in %d families from %d sources, %d bytes of known-bad Lua"
      % (len(hashes), len(families), sources,
         sum(os.path.getsize(os.path.join(src, n.replace('/', os.sep))) for n in hashes)))
print("malicious corpus: %d of %d families reach CRITICAL, %d samples produce nothing"
      % (caught, len(families), silent))
print("malicious corpus: %d of %d samples are also recognised by known_hashes.txt"
      % (recognised, len(hashes)))

# Recall is measured against Lua and nothing else: there is no .vmt, no .dll and
# no .gma in here. Say how many rules a sample actually exercises, so the rules
# resting on their own test cases are visible rather than inferred.
shipped = {"LUA": 0, "OBF": 0, "BIN": 0, "DATA": 0, "MOD": 0, "COMP": 0}
covered = {name: 0 for name in shipped}
for rule_file in ("lua_patterns.txt", "binary_patterns.txt", "data_patterns.txt",
                  "module_patterns.txt", "composite_rules.txt"):
    path = os.path.join(rules, rule_file)
    if not os.path.exists(path):
        continue
    for line in open(path, encoding="utf-8"):
        if line.startswith("#") or ";;;" not in line:
            continue
        fields = line.split(";;;")
        if len(fields) < 2:
            continue
        prefix = fields[1].split("]")[-1].strip().split(" ")[0].split("-")[0]
        if prefix in shipped:
            shipped[prefix] += 1
for rule_id in seen_ids:
    prefix = rule_id.split("-")[0]
    if prefix in covered:
        covered[prefix] += 1

print("malicious corpus: rules a sample reaches -- " + ", ".join(
    "%s %d/%d" % (name, covered[name], shipped[name])
    for name in ("LUA", "OBF", "BIN", "DATA", "MOD", "COMP") if shipped[name]))
bare = [name for name in ("BIN", "DATA", "MOD") if shipped[name] and not covered[name]]
if bare:
    print("malicious corpus: no sample reaches %s; those rules stand on their test cases alone"
          % ", ".join(bare))

for family in sorted(families):
    if families[family] != "critical":
        print("   below critical: %-40s %-8s (recorded %s)"
              % (family, families[family], expected[family]))

if caught < floor:
    failures.append("family recall fell from %d to %d" % (floor, caught))
if caught > floor:
    print("malicious corpus: recall improved from %d to %d; raise the floor in %s"
          % (floor, caught, os.path.basename(expected_path)))

if failures:
    print("malicious corpus: FAILED")
    for failure in failures:
        print("   " + failure)
    sys.exit(1)

print("malicious corpus: no regression against the recorded results")
PY
