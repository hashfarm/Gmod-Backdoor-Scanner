#!/usr/bin/env bash
#
# Scans real, published Garry's Mod code and fails on any CRITICAL finding that
# is not already accounted for in real_corpus.expected.
#
# Usage: real_corpus.sh <path to scanner> [checkout dir]
#
set -euo pipefail

SCANNER=${1:?usage: real_corpus.sh <scanner> [checkout dir]}
SCANNER="$(cd "$(dirname "$SCANNER")" && pwd)/$(basename "$SCANNER")"
WORK=${2:-/tmp/bd-real-corpus}
HERE=$(cd "$(dirname "$0")" && pwd)
RULES=$(dirname "$HERE")
EXPECTED="$HERE/real_corpus.expected"

REPOS=(
  "https://github.com/Facepunch/garrysmod 52ad10f3bca95a9230384da29516faae5cd85433"
  "https://github.com/TeamUlysses/ulx     2278df2a41332a6906800dbde197080e61b9d009"
  "https://github.com/TeamUlysses/ulib    147657e31a15bdcc5b5fec89dd9f5650aebeb54a"
  "https://github.com/FPtje/DarkRP        5abcf7abab9e489b2d882a55d95f84c206d9d05c"
  "https://github.com/wiremod/wire        b2db79f104c45836d1722b994c7f4e2fef73e389"
  "https://github.com/thegrb93/StarfallEx a03a967a0ac2c153e037629901d3fd5542567f3f"
  "https://github.com/CapsAdmin/pac3      bdfea7a6a5b0eb034dc661ebffa2fe10698bc07b"
)

# Argument 2 is a scratch checkout directory, not the rule directory the other
# test scripts take there. Cloning into the source tree drags whatever else is
# checked out there into this scan, which then reads as a false positive.
if [ -e "$WORK/lua_patterns.txt" ]; then
  echo "::error::$WORK is the rule directory; argument 2 is a scratch checkout path" >&2
  exit 2
fi

mkdir -p "$WORK/src"
WORK="$(cd "$WORK" && pwd)"
for entry in "${REPOS[@]}"; do
  set -- $entry
  url=$1 sha=$2 name=$(basename "$1")
  if [ ! -d "$WORK/src/$name/.git" ]; then
    git clone --quiet --filter=blob:none --no-checkout "$url" "$WORK/src/$name"
  fi
  # Some paths in Facepunch/garrysmod exceed MAX_PATH on Windows.
  git -C "$WORK/src/$name" config core.longpaths true
  git -C "$WORK/src/$name" fetch --quiet --depth 1 origin "$sha"
  git -C "$WORK/src/$name" checkout --quiet --force "$sha"
done

cd "$WORK"

set +e
"$SCANNER" --rules "$RULES" -d "$WORK/src" -q
status=$?
set -e
if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
  echo "::error::scanner could not complete the scan (exit $status)"
  exit 1
fi

python3 - "$WORK/scan_log.json" "$EXPECTED" <<'PY'
import json, re, sys

log, expected_path = sys.argv[1], sys.argv[2]
data = json.load(open(log, encoding="utf-8"))
if not data.get("complete", False) or data.get("unscanned", {}).get("total", 0):
    sys.exit("::error::real corpus scan was incomplete")

found = set()
hits = {}
files = {}
severity_of = {}
for d in data.get("detections", []):
    rule = d.get("id", "")
    severity = d.get("severity", "").lower()
    path = re.sub(r".*[/\\]src[/\\]", "", d["file"]).replace("\\", "/")
    if rule:
        hits[rule] = hits.get(rule, 0) + 1
        files.setdefault(rule, set()).add(path.lower())
        severity_of[rule] = severity
    if severity == "critical":
        found.add((rule, path.lower()))

expected = set()
profile = {}
for line in open(expected_path, encoding="utf-8"):
    stripped = line.strip()
    if stripped.startswith("profile "):
        parts = stripped.split()
        profile[parts[1]] = (int(parts[2]), int(parts[3]))
        continue
    line = line.split("#", 1)[0].strip()
    if line and not line.startswith("profile "):
        pid, path = line.split(None, 1)
        expected.add((pid, path.strip().lower()))

new = sorted(found - expected)
gone = sorted(expected - found)
highs = sum(1 for d in data.get("detections", []) if d.get("severity") == "high")

print("real corpus: %d files, %d findings, %d critical, %d high"
      % (data["files_processed"], len(data.get("detections", [])), len(found), highs))
print("real corpus: %d of the rules fire on this code" % len(hits))

failed = False

for pid, path in gone:
    print("  stale expectation (no longer fires): %s %s" % (pid, path))

if new:
    failed = True
    print("::error::CRITICAL findings on known-good published code:")
    for pid, path in new:
        print("  %s %s" % (pid, path))
    print("Either the rule is wrong, or the finding is real and belongs in")
    print("BD-Scan/tests/real_corpus.expected with a line saying why.")
else:
    print("real corpus: no unexplained critical findings")

unlisted = sorted(rule for rule in hits if rule not in profile)
grown = []
for rule in sorted(hits):
    if rule not in profile:
        continue
    max_hits, max_files = profile[rule]
    if hits[rule] > max_hits or len(files[rule]) > max_files:
        grown.append((rule, hits[rule], len(files[rule]), max_hits, max_files))

if unlisted:
    failed = True
    print("::error::rules that fire on known-good code without a recorded budget:")
    for rule in unlisted:
        print("  %-9s %-8s %3d findings in %d files"
              % (rule, severity_of.get(rule, "?"), hits[rule], len(files[rule])))
    print("Every rule that touches legitimate code needs a `profile` line in")
    print("real_corpus.expected saying how much is acceptable. Add one, or narrow")
    print("the rule until it stops firing here.")

if grown:
    failed = True
    print("::error::rules that got broader:")
    for rule, got_hits, got_files, max_hits, max_files in grown:
        print("  %-9s %d findings in %d files, budget %d in %d"
              % (rule, got_hits, got_files, max_hits, max_files))
    print("A rule that grows on stock code is describing ordinary Lua. Narrow it,")
    print("or raise its budget and say in the commit why the new findings are")
    print("worth someone's time.")

quiet = sorted(rule for rule in profile if rule not in hits)
for rule in quiet:
    print("  budget no longer used: %s" % rule)

if failed:
    sys.exit(1)

print("real corpus: no rule exceeded its false-positive budget")
PY
