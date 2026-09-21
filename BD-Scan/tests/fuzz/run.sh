#!/usr/bin/env bash
# Build and run the libFuzzer targets under AddressSanitizer + UBSan.
#
#   tests/fuzz/run.sh [seconds-per-target] [output-dir]
#
# Corpora live in <output-dir>/<target>/corpus and are reused when present, so
# pointing successive runs at the same directory (or restoring it from a cache)
# lets coverage accumulate. Seeds are added on every run; libFuzzer deduplicates.
#
#   FUZZ_MINIMIZE=1   after fuzzing, replace each corpus with a minimal subset
#                     that keeps the same coverage (keeps a cached corpus small)
#
# Requires clang with -fsanitize=fuzzer (LLVM 8+, any platform where the fuzzer
# runtime ships; on Windows add <LLVM>/lib/clang/<ver>/lib/windows to PATH so
# the ASan DLL is found). Run from the repository root.
#
# Exits non-zero if any target crashed or left an artifact. A crash writes
# crash-<hash> into <output-dir>/<target>/artifacts; reproduce it with
#   <output-dir>/fuzz_<target> <artifact>
set -euo pipefail

SECONDS_PER_TARGET="${1:-60}"
OUT="${2:-fuzz-out}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$ROOT/BD-Scan"
FUZZ="$SRC/tests/fuzz"
CXX="${CXX:-clang++}"

# libFuzzer re-executes itself for -merge; on Windows that goes through
# CreateProcess, which will not find a binary without the .exe suffix.
EXE=""
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;;
esac

mkdir -p "$OUT"/{lzma,gma,scanner,names,cli,rules}/{corpus,artifacts}

FLAGS=(-std=c++17 -O1 -g -fno-omit-frame-pointer
       -fsanitize=fuzzer,address,undefined
       -fno-sanitize-recover=undefined
       -D_DISABLE_STRING_ANNOTATION -D_DISABLE_VECTOR_ANNOTATION -D_CRT_SECURE_NO_WARNINGS
       -I "$SRC")

echo "== building"
"$CXX" "${FLAGS[@]}" "$FUZZ/fuzz_lzma.cpp"    -o "$OUT/fuzz_lzma$EXE"
"$CXX" "${FLAGS[@]}" "$FUZZ/fuzz_gma.cpp"     -o "$OUT/fuzz_gma$EXE"
"$CXX" "${FLAGS[@]}" "$FUZZ/fuzz_scanner.cpp" -o "$OUT/fuzz_scanner$EXE"
"$CXX" "${FLAGS[@]}" "$FUZZ/fuzz_names.cpp"   -o "$OUT/fuzz_names$EXE"
"$CXX" "${FLAGS[@]}" "$FUZZ/fuzz_cli.cpp" "$SRC/CommandLine.cpp" -o "$OUT/fuzz_cli$EXE"
"$CXX" "${FLAGS[@]}" "$FUZZ/fuzz_rules.cpp"  -o "$OUT/fuzz_rules$EXE"

echo "== seeding"
python3 - "$OUT" "$SRC" <<'PY'
import sys, os, lzma, struct, shutil, glob
out, src = sys.argv[1], sys.argv[2]

def cstr(s): return s.encode() + b"\x00"
def gma(files):
    h = b"GMAD" + struct.pack("<B", 3) + struct.pack("<QQ", 0, 0) + b"\x00"
    h += cstr("seed") + cstr("d") + cstr("a") + struct.pack("<i", 1)
    body = b""
    for i, (n, d) in enumerate(files):
        h += struct.pack("<I", i + 1) + cstr(n) + struct.pack("<q", len(d)) + struct.pack("<I", 0)
        body += d
    return h + struct.pack("<I", 0) + body

archive = gma([("lua/autorun/a.lua", b"RunString(x)\n"), ("materials/m.vmt", b'"UnlitGeneric"\n')])
open(os.path.join(out, "gma", "corpus", "valid.gma"), "wb").write(archive)
open(os.path.join(out, "gma", "corpus", "empty_index.gma"), "wb").write(gma([]))
open(os.path.join(out, "gma", "corpus", "many.gma"), "wb").write(
    gma([("f%d.lua" % i, b"y" * i) for i in range(30)]))

for name, raw in [("gma", archive), ("text", b"The quick brown fox. " * 30), ("tiny", b"A"), ("empty", b"")]:
    open(os.path.join(out, "lzma", "corpus", name + ".lzma"), "wb").write(
        lzma.compress(raw, format=lzma.FORMAT_ALONE, preset=6))

for pattern in ("fixtures/*/*.lua", "fixtures/*/*.vmt"):
    for path in glob.glob(os.path.join(src, "tests", pattern)):
        shutil.copy(path, os.path.join(out, "scanner", "corpus",
                                       os.path.basename(os.path.dirname(path)) + "_" + os.path.basename(path)))
open(os.path.join(out, "scanner", "corpus", "obfuscated.lua"), "w").write(
    'local f = _G["RunStr" .. "ing"]\nlocal g = _G[string.char(82,117,110)]\n'
    '-- RunString(comment)\n--[[ block ]] print("--")\nlocal s = ("gnirtS"):reverse()\n')


for index, name in enumerate([
        b"lua/autorun/server/init.lua",
        b"../../../etc/passwd",
        b"C:/windows/system32/x.lua",
        b"lua/bin/gmsv_thing_win64.dll",
        b"data/payload.txt",
        bytes([0xff, 0xfe]) + b"bad.lua",
        b"lua/" + bytes([0xed, 0xa0, 0x80]) + b".lua"]):
    open(os.path.join(out, "names", "corpus", "n%d" % index), "wb").write(name)

for index, args in enumerate([
        b"-d\x00.\x00-o\x00out",
        b"--accept\x00LUA-001@*/x/*\x00--reason\x00fine",
        b"--memory-limit\x00512\x00--color\x00never",
        b"-s\x00critical\x00--exclude-tags\x00darkrp,economy",
        b"--workshop\x00104604709",
        b"--version"]):
    open(os.path.join(out, "cli", "corpus", "c%d" % index), "wb").write(args)

for name in ("lua_patterns.txt", "binary_patterns.txt", "data_patterns.txt",
             "module_patterns.txt", "composite_rules.txt", "whitelist.txt"):
    path = os.path.join(src, name)
    if not os.path.exists(path):
        continue
    kept = [line for line in open(path, encoding="utf-8").read().splitlines() if line][:25]
    open(os.path.join(out, "rules", "corpus", name), "w", encoding="utf-8").write(
        "\n".join(kept) + "\n")
open(os.path.join(out, "rules", "corpus", "edge.txt"), "w", encoding="utf-8").write(
    "(a+)+;;;[HIGH] LUA-900 Backtracking;;;hint\n"
    "[[:alpha:]]{2,400};;;[LOW] LUA-901 Posix class;;;hint\n"
    ";;;[HIGH] LUA-902 Empty expression;;;hint\n"
    "x;;;[NOPE] LUA-903 Bad severity;;;hint\n"
    "x;;;[HIGH] missing-id;;;hint\n"
    "x;;;[HIGH] LUA-904 Duplicate;;;hint\n"
    "y;;;[HIGH] LUA-904 Duplicate;;;hint\n"
    "atleast(2, LUA-900 and LUA-901);;;[HIGH] COMP-900 Combined;;;hint\n"
    "not LUA-900 or (LUA-901 and LUA-902);;;[HIGH] COMP-901 Mixed;;;hint\n"
    "*/lua/autorun/*;;;LUA-900\n"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
    "*/vendor/*;;;;;;e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")
PY

FAILED=0

run() {
  local target="$1"; shift
  local name="${target#fuzz_}"
  local log="$OUT/$name/run.log"
  local dict="$FUZZ/$name.dict"
  local extra=()
  [ -f "$dict" ] && extra+=("-dict=$dict")

  echo "== $target for ${SECONDS_PER_TARGET}s ($(ls -1 "$OUT/$name/corpus" | wc -l) corpus files)"
  set +e
  "$OUT/$target$EXE" \
    -max_total_time="$SECONDS_PER_TARGET" \
    -artifact_prefix="$OUT/$name/artifacts/" \
    -print_final_stats=1 \
    "${extra[@]}" \
    "$@" \
    "$OUT/$name/corpus" >"$log" 2>&1
  local status=$?
  set -e

  grep -E '^(#[0-9]+.*DONE|.*stat::(number_of_executed_units|new_units_added|peak_rss_mb)|SUMMARY|.*runtime error)' "$log" | tail -6 || true
  if [ "$status" -ne 0 ]; then
    echo "!! $target exited with status $status (see $log)"
    FAILED=1
  fi
}

run fuzz_lzma    -max_len=4096  -timeout=10 -rss_limit_mb=2048
run fuzz_gma     -max_len=8192  -timeout=10 -rss_limit_mb=2048
BD_SCAN_RULES="$SRC" run fuzz_scanner -max_len=2048 -timeout=20 -rss_limit_mb=2048
run fuzz_names   -max_len=512   -timeout=10 -rss_limit_mb=2048
run fuzz_cli     -max_len=512   -timeout=10 -rss_limit_mb=2048
run fuzz_rules   -max_len=4096  -timeout=25 -rss_limit_mb=2048 -close_fd_mask=3

if [ "${FUZZ_MINIMIZE:-0}" = "1" ] && [ "$FAILED" -eq 0 ]; then
  echo "== minimizing corpora"
  for name in lzma gma scanner names cli rules; do
    before=$(ls -1 "$OUT/$name/corpus" | wc -l)
    rm -rf "$OUT/$name/corpus.min"
    mkdir -p "$OUT/$name/corpus.min"
    env BD_SCAN_RULES="$SRC" "$OUT/fuzz_$name$EXE" -merge=1 \
      "$OUT/$name/corpus.min" "$OUT/$name/corpus" >"$OUT/$name/merge.log" 2>&1 || true
    if [ -n "$(ls -A "$OUT/$name/corpus.min")" ]; then
      rm -rf "$OUT/$name/corpus"
      mv "$OUT/$name/corpus.min" "$OUT/$name/corpus"
      echo "   $name: $before -> $(ls -1 "$OUT/$name/corpus" | wc -l) files"
    else
      rm -rf "$OUT/$name/corpus.min"
      echo "   $name: merge produced nothing, corpus kept as is"
    fi
  done
fi

echo "== artifacts"
ARTIFACTS="$(find "$OUT" -path '*/artifacts/*' -type f 2>/dev/null || true)"
if [ -n "$ARTIFACTS" ]; then
  echo "$ARTIFACTS" | sed 's/^/  /'
  FAILED=1
else
  echo "  none"
fi

exit "$FAILED"
