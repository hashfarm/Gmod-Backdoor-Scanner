r"""The same backdoor, written differently, must still be a backdoor.

The pattern tests, the disguises and the integration cases all check inputs that
somebody sat down and thought of. Every file in them is written with line feeds,
loose on disk, without a byte order mark, in a short ASCII path -- because that is
how a person writing a test file writes it. A defect that only shows up in some
other spelling of the same bytes therefore survives all of them.

That is not hypothetical. The comment stripper looked for a line feed, so a file
saved with classic Mac line endings went completely quiet behind its first
comment, and no test noticed, because no test file was saved that way. Put that
defect back and this suite reports 273 losses.

So this asks the question from the other side. It takes the real backdoors from
the malicious corpus, applies changes that Lua cannot tell apart, puts them where
a real addon would be, and requires that the verdict never gets weaker. It knows
nothing about the rules, so a new rule needs no entry here, and a sample that was
never detected in the first place is not the subject: only a drop counts.

Three passes:

  source      84 corpus samples, respelled seven ways, in seven placements
  module      the strings module_patterns.txt looks for, laid out in a .dll the
              several ways a linker would lay them out
  cache       a warm cache replays findings through different code than the scan
              that produced them, so the second run has to agree with the first

Usage: metamorphic.py <scanner> <rules> <corpus dir> [--verbose]

The corpus directory is the checkout malicious_corpus.sh makes, by default
/tmp/bd-malicious-corpus/src.
"""
import json
import lzma
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def gma(files):
    header = (b"GMAD" + struct.pack("<BQQ", 3, 0, 0) +
              b"\0review\0description\0author\0" + struct.pack("<i", 1))
    body = b""
    for index, (name, content) in enumerate(files, 1):
        header += struct.pack("<I", index) + name.encode() + b"\0" + struct.pack("<qI", len(content), 0)
        body += content
    return header + struct.pack("<I", 0) + body


def to_lf(raw):
    return raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def write(path, raw):
    """Windows refuses a path past MAX_PATH unless it is spelled the long way."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt" and len(str(path)) > 240:
        with open("\\\\?\\" + str(path), "wb") as handle:
            handle.write(raw)
    else:
        path.write_bytes(raw)


# Lua ends a line at CR, LF or CRLF alike and normalises all three inside a long
# string, so none of these can change what the file means.
TRANSFORMS = {
    "line feeds": lambda raw: raw,
    "carriage returns": lambda raw: raw.replace(b"\n", b"\r"),
    "both": lambda raw: raw.replace(b"\n", b"\r\n"),
    "byte order mark": lambda raw: b"\xef\xbb\xbf" + raw,
    "comment on top": lambda raw: b"-- version 3, reviewed\n" + raw,
    "no final newline": lambda raw: raw.rstrip(b"\r\n"),
    "comment and returns": lambda raw: b"-- version 3, reviewed\r" + raw.replace(b"\n", b"\r"),
}

# Where the addon sits says nothing about what it does.
PLACEMENTS = {
    "loose": "addons/suspect/lua/autorun",
    "deep": "addons/" + "/".join("level%02d" % i for i in range(1, 13)) + "/lua/autorun",
    "non-ascii path": "addons/アドオン-café/lua/autorun",
    "path past MAX_PATH": "addons/" + "/".join("a" * 40 for _ in range(8)) + "/lua/autorun",
}

CONTAINERS = ("archive", "compressed archive", "archive in an archive")

# A linker is free to lay a string out any of these ways.
LAYOUTS = {
    "ascii": lambda text: text.encode() + b"\0",
    "utf-16": lambda text: text.encode("utf-16-le") + b"\0\0",
    "padded": lambda text: b"\0" * 64 + text.encode() + b"\0" * 64,
    "after noise": lambda text: bytes(range(1, 32)) * 8 + b"\0" + text.encode() + b"\0",
    "among symbols": lambda text: (b"luaL_register\0lua_pushcclosure\0" + text.encode() +
                                   b"\0GCC: (GNU) 13.2.0\0"),
}


def verdicts(scanner, rules, tree, out, extra=()):
    """Highest severity reached per sample, keyed by the sample's own name."""
    subprocess.run([str(scanner), "-d", str(tree), "-o", str(out), "--rules", str(rules),
                    "-q", *extra],
                   capture_output=True, text=True, timeout=900)
    log = json.loads((out / "scan_log.json").read_text(encoding="utf-8"))
    best = {}
    for detection in log.get("detections", []):
        name = detection["file"].replace("\\", "/").split("/")[-1]
        rank = RANK.get(detection.get("severity", "low"), 0)
        if rank > best.get(name, -1):
            best[name] = rank
    return best, log


def build_source(tree, samples, transform, placement=None, container=None):
    changed = [(name, transform(raw)) for name, raw in samples]
    if placement is not None:
        folder = tree / Path(PLACEMENTS[placement])
        for name, raw in changed:
            write(folder / name, raw)
        return True

    archive = gma([("lua/autorun/" + name, raw) for name, raw in changed])
    if container == "archive in an archive":
        archive = gma([("inner.gma", archive)])
    elif container == "compressed archive":
        archive = lzma.compress(archive, format=lzma.FORMAT_ALONE)
    write(tree / "addons" / "suspect.gma", archive)
    return True


def module_samples(rules):
    """The strings the module rules exist to find, from their own test file."""
    path = rules / "module_patterns.test.txt"
    if not path.is_file():
        return []
    found = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("+"):
            continue
        parts = line[1:].split(";;;", 1)
        if len(parts) != 2:
            continue
        rule, text = parts[0].strip(), parts[1].strip()
        if rule and text:
            found.append(("gmsv_%s_%02d_win64.dll" % (rule.replace("-", "").lower(), len(found)),
                          text))
    return found


def build_modules(tree, modules, layout):
    folder = tree / "addons" / "suspect" / "lua" / "bin"
    for name, text in modules:
        write(folder / name, b"MZ\x90\x00" + LAYOUTS[layout](text) + b"\0")


def rules_without_hashes(rules, work):
    """A hash is meant to change when the bytes change, so it would report a drop
    for every variant and say nothing about the rules. Measure without it."""
    copy = work / "rules"
    shutil.copytree(rules, copy, ignore=shutil.ignore_patterns(
        "*.test.txt", "tests", "nlohmann", "*.h", "*.cpp", "*.vcxproj*",
        "x64", "Release", "out", "src", ".git"))
    (copy / "known_hashes.txt").write_text("", encoding="utf-8")
    return copy


def compare(detected, got, axis, label, drops):
    for sample, rank in sorted(detected.items()):
        now = got.get(sample, -1)
        if now < rank:
            drops.append((axis, label, sample, rank, now))


def main():
    scanner, rules = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    corpus = Path(sys.argv[3]).resolve()
    verbose = "--verbose" in sys.argv

    samples = []
    seen = set()
    for path in sorted(corpus.rglob("*.lua")):
        name = path.name
        if name in seen:
            name = "%d_%s" % (len(seen), path.name)
        seen.add(name)
        raw = to_lf(path.read_bytes())
        if raw.strip():
            samples.append((name, raw))
    if not samples:
        print("::error::no .lua samples under %s, run malicious_corpus.sh first" % corpus)
        return 2

    work = Path(tempfile.mkdtemp(prefix="bdscan-metamorphic-"))
    rules = rules_without_hashes(rules, work)
    modules = module_samples(Path(sys.argv[2]).resolve())
    print("metamorphic: %d source samples from %s, %d module strings"
          % (len(samples), corpus, len(modules)))

    drops = []
    checks = 0
    skipped = []

    def note(axis, label, detected, got):
        if verbose:
            kept = sum(1 for s in detected if got.get(s, -1) >= detected[s])
            print("   %-22s %-22s %d of %d still found" % (axis, label, kept, len(detected)))

    build_source(work / "base", samples, TRANSFORMS["line feeds"], placement="loose")
    detected, _ = verdicts(scanner, rules, work / "base", work / "out" / "base")
    print("metamorphic: %d of %d source samples are detected at all, %d of them critical"
          % (len(detected), len(samples), sum(1 for r in detected.values() if r == 3)))

    for placement in PLACEMENTS:
        for label, transform in TRANSFORMS.items():
            if placement == "loose" and label == "line feeds":
                continue
            name = ("src-%s-%s" % (placement, label)).replace(" ", "_")
            try:
                build_source(work / name, samples, transform, placement=placement)
            except OSError as error:
                skipped.append("%s (%s)" % (placement, error.__class__.__name__))
                break
            got, _ = verdicts(scanner, rules, work / name, work / "out" / name)
            checks += 1
            compare(detected, got, placement, label, drops)
            note(placement, label, detected, got)

    for container in CONTAINERS:
        for label, transform in TRANSFORMS.items():
            name = ("box-%s-%s" % (container, label)).replace(" ", "_")
            build_source(work / name, samples, transform, container=container)
            got, _ = verdicts(scanner, rules, work / name, work / "out" / name)
            checks += 1
            compare(detected, got, container, label, drops)
            note(container, label, detected, got)

    if modules:
        build_modules(work / "mod-base", modules, "ascii")
        found, _ = verdicts(scanner, rules, work / "mod-base", work / "out" / "mod-base")
        print("metamorphic: %d of %d module strings are detected at all"
              % (len(found), len(modules)))
        for layout in LAYOUTS:
            if layout == "ascii":
                continue
            name = ("mod-%s" % layout).replace(" ", "_")
            build_modules(work / name, modules, layout)
            got, _ = verdicts(scanner, rules, work / name, work / "out" / name)
            checks += 1
            compare(found, got, "module", layout, drops)
            note("module", layout, found, got)

    cache = work / "cache.json"
    build_source(work / "cached", samples, TRANSFORMS["line feeds"], placement="loose")
    cold, _ = verdicts(scanner, rules, work / "cached", work / "out" / "cold", ["--cache", str(cache)])
    warm, _ = verdicts(scanner, rules, work / "cached", work / "out" / "warm", ["--cache", str(cache)])
    checks += 2
    compare(cold, warm, "warm cache", "unchanged file", drops)
    note("warm cache", "unchanged file", cold, warm)

    print("metamorphic: %d variants scanned" % checks)
    for entry in skipped:
        print("metamorphic: skipped %s, this system will not create it" % entry)
    if not drops:
        print("metamorphic: no spelling of a known backdoor made it quieter")
        return 0

    worst = {}
    for axis, label, sample, was, now in drops:
        worst.setdefault((axis, label), []).append(sample)
    print("::error::%d sample/variant combinations lost severity:" % len(drops))
    for (axis, label), names in sorted(worst.items()):
        print("  %s, %s: %d samples, e.g. %s"
              % (axis, label, len(names), ", ".join(sorted(names)[:3])))
    return 1


sys.exit(main())
