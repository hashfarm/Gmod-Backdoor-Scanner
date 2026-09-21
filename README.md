# Gmod Backdoor Scanner

[![build](https://github.com/RRelicc/Gmod-Backdoor-Scanner/actions/workflows/build.yml/badge.svg)](https://github.com/RRelicc/Gmod-Backdoor-Scanner/actions/workflows/build.yml)

Finds backdoors in Garry's Mod addons. Point it at a directory; it reads every
`.lua` file, every `.vmt`, `.vtf` and `.ttf`, and looks inside `.gma` workshop
archives without unpacking them.

```bash
BD-Scan -d /srv/gmod/garrysmod/addons --html
```

That writes `scan_report.html` next to `scan_log.json` and exits `1` if it found
something. Open the HTML report; it is ordered so the files worth reading first
are at the top.

This will not find everything, and it will flag things that turn out to be fine.
It is a tool for narrowing a thousand files down to ten worth reading, not a
verdict.

## What you get

**130 rules** — 101 for Lua, 14 for the binary asset files an addon can smuggle
code into, 8 for the strings inside a native module, and 7 for what lands in
`data/` and `cache/` at runtime. Each has a stable ID, a severity that means
something specific in Garry's Mod, a hint written for someone who does not read
Lua, and at least one positive and one negative test case that CI runs on every
push.

**28 combination rules** that fire on things no single rule can express: a file
that enumerates hooks *and* removes them, a permission change next to a
hardcoded SteamID. Two of them combine findings across files within the same addon or GMA
archive, so unrelated addons do not create a shared critical finding.

**Deobfuscation before matching.** Comments are stripped. `string.char(82,117,
110)`, `"Run" .. "String"`, `"\x52\x75\x6e"` and `("gnirtSnuR"):reverse()` are
all folded back to the string they build, across line breaks, before any rule
sees the file. Base64 blobs are decoded and shown in the report.

**Exit codes you can use in a script**, including the one most scanners do not
have: `3` means "found nothing, but could not open part of the tree", so a
truncated archive cannot pass as a clean result.

## Usage

```
BD-Scan -d <path>            scan a directory recursively, or a single file
        --workshop <id>      download that Workshop item and scan it
        -o <directory>       where to write the reports (default: current directory)
        -s <severity>        minimum severity: low, medium, high, critical
        --exclude-tags a,b   skip rules carrying these tags, e.g. darkrp
        --rules <directory>  load the rule files from here
        --memory-limit <MiB> shared archive buffer budget (default: 1024, minimum: 64)
        --html               also write scan_report.html
        --sarif              also write scan_results.sarif for CI code scanning
        --cache <file>       reuse results for files unchanged since the last run
        --color <when>       auto (default), always or never
        --accept <rule>@<glob>   record a finding as reviewed
        --reason <text>      why it is fine, stored with the entry
        --diff               report only what is new since the last full scan
        -q, --quiet          summary only
        -h, --help
        --version            version, rule count and rule fingerprint
```

Run it with no arguments for a prompt that accepts a path and options together.

| Exit code | Meaning |
|-----------|---------|
| `0` | Nothing found, and everything was examined |
| `1` | Detections reported |
| `2` | Error: bad arguments, unreadable path, missing rule files |
| `3` | Nothing found, but part of the tree could not be examined |

The full result is `scan_log.json`, documented field by field in
[SCAN_LOG.md](SCAN_LOG.md) for anyone reading it from a script.

Rule files are read from `--rules` if given, otherwise from the directory
holding the executable when `lua_patterns.txt` sits next to it, otherwise from
the working directory. Files are loaded from one directory; an explicit
`--rules` directory never falls back to another location. `lua_patterns.txt`,
`binary_patterns.txt`, `data_patterns.txt` and `module_patterns.txt` are
required; `composite_rules.txt`, `whitelist.txt` and `known_hashes.txt` are
optional. Missing IDs, severities, duplicate IDs,
invalid regexes and invalid composite expressions stop startup with exit code
`2`. Unknown command-line options and missing option values also fail.

## Comparing scans

`--diff` compares the absolute file path, line number, rule ID and a SHA-256
fingerprint of the file content. A replacement on the same line is reported
again. Composite fingerprints cover the contributing files, and their evidence
is included as `related_findings` in JSON and as file paths and lines in HTML.

Only complete scans at the default severity, without `--diff` or excluded tags,
update `last_scan.json`. Reports and baselines are written through a temporary
file and replaced only after writing succeeds. A scan with unreadable files or
failed workers preserves the previous baseline.

Baselines include the scan root, rule version and hash/whitelist configuration.
If those differ, or the baseline comes from an older report schema, the scanner
warns and reports all findings. Run a complete unfiltered scan to establish a
new baseline. Comments and other harmless file edits also change fingerprints;
the comparison deliberately reports changed files for another review.

## Where the numbers come from

Every claim here is checked by CI rather than asserted:

- **Recall** — every sample under `tests/corpus/malicious/` must produce a
  CRITICAL or HIGH finding. The bar is 100%. Against the published backdoors it
  is 23 of 26 families at CRITICAL, and the harness also prints how many rules a
  real sample reaches: 56 of 101 Lua rules, 3 of 8 module rules, and none of the
  14 binary or 7 runtime-folder rules, because no published sample here is a
  `.vmt`, a `.dll` or a file in `data/`.
- **False positives on real code** — `tests/real_corpus.sh` checks out Facepunch's
  own `garrysmod`, ULX, ULib, DarkRP, Wiremod, Starfall and PAC3 at pinned
  commits, scans all 2690 files, and fails on any CRITICAL that is not listed
  with a reason in `tests/real_corpus.expected`. Every other rule that fires
  there carries a budget in the same file, and exceeding it fails the build.
- **Evasion by reformatting** — every positive test case is re-run indented,
  with a trailing comment, with spaced parentheses and with its arguments
  wrapped across lines. A rule that stops matching is a rule an attacker walks
  past; this found and closed one such hole in the literal folder.
- **False positives across rules** — every negative test case is run against all
  130 rules, not just its own. Any CRITICAL it raises fails the build unless the
  test file says out loud that the rule is right to fire.
- **Hostile input** — six libFuzzer targets, covering everything the scanner
  reads from outside: the LZMA decoder, the GMA parser, the scanner itself,
  archive entry names, the command line and the rule files. They run under ASan
  and UBSan on every push and nightly. Both real defects found so far came from
  there rather than from the test suite.
- **Data races** — a ThreadSanitizer run over a tree large enough to keep the
  worker pool busy.

Numbers that are not checked are not claimed. The figures themselves, and
what each rule costs on real code, are in
[docs/measurements.md](docs/measurements.md).

## Contributing

Most useful contributions are rules, and a rule is one line of text. See
[CONTRIBUTING.md](CONTRIBUTING.md) — it covers the rule format, how to pick a
severity that will survive contact with real code, and the test cases a new rule
needs.

If a scan flags something that was fine, that is worth an issue: the pattern ID,
the line, and what the code was doing. That is enough to either fix the rule or
add the snippet to the benign corpus, and the second is what stops the report
coming back.

## Requirements

A C++17 compiler, and nothing else. Visual Studio 2019 or later on Windows, GCC
or Clang elsewhere. [nlohmann/json](https://github.com/nlohmann/json) is vendored
at `BD-Scan/nlohmann/json.hpp`, so there is nothing to fetch and no package
manager to set up.

Python 3 is optional: CTest uses it to run the integration and evasion suites.

## Contributors

- **hashfarm** — original author.
- **Hungryy2K/RRelicc** — everything since.

Version history is in [CHANGELOG.md](CHANGELOG.md).

## Download

Tagged releases publish a Windows x64 `.zip`, a Linux x64 `.tar.gz` and a macOS
`.tar.gz` on the
[releases page](https://github.com/RRelicc/Gmod-Backdoor-Scanner/releases), each
with a `.sha256` next to it. Unpack and run — the rule files must stay beside
the executable:

```bash
./bd-scan -d /home/gmod/garrysmod/addons
```

All three archives are built by CI from the tagged commit and are checked
against the test fixtures before being published. To build from source instead,
see below.

The macOS binary is universal: one file with an arm64 and an x86_64 slice, so it
runs on Apple Silicon and on Intel Macs. It is built against the macOS 11
deployment target rather than whatever the runner happens to be on, for the same
reason the Linux binary is linked statically — a binary built against a newer
system quietly refuses to start on an older one.

The Linux binary is linked statically, so it does not care which distribution it
lands on: Debian, Ubuntu, Rocky, Arch, Gentoo, Alpine, anything x86-64. That is
worth doing here because the alternative fails quietly in the wrong direction — a
binary linked against the build machine's glibc refuses to start on anything
older, and a release built on a current runner wants glibc 2.38, which Debian 12
and Ubuntu 22.04 do not have. Those are what game servers mostly run. The scanner
shells out to `curl` for the two Workshop requests and resolves no names itself,
so linking statically costs nothing.

### Windows Defender flags the executable

Defender reports `Trojan:Win32/Sabsik.FL.A!ml` on `BD-Scan.exe`, and its cloud
engine reports `Trojan:Win32/Phonzy.A!ml` for the same file, so the name you see
depends on the machine. Both end in `!ml`: no signature matched, the verdict
comes from a model, and those buckets collect unsigned binaries nobody has
downloaded yet. Every release starts there. The rule files in the archive are
not flagged.

Rather than take that on trust:

- Check the archive against the `.sha256` published beside it.
- Read the `release` workflow run for the tag. It builds the archive from the
  tagged commit and runs it against the fixtures before publishing anything.
- Or build it yourself, below. It needs no dependencies beyond a compiler.

### macOS refuses to run the binary

The Mac binary is neither signed nor notarized, and macOS quarantines anything a
browser downloads, so Gatekeeper blocks the first run. Fetching the archive with
`curl -LO` sets no quarantine flag. If you already downloaded it in a browser,
clear the flag after unpacking:

```bash
xattr -d com.apple.quarantine bd-scan
```

## Building

### Windows
Open `BD-Scan.sln` in Visual Studio 2019 or later and build Release x64. The
build copies the rule files next to the executable. x64 is the only Windows
configuration: Garry's Mod servers are 64-bit, and a 32-bit build nobody tested
would only rot.

### Linux and macOS
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

This produces `build/bd-scan` with the rule files alongside it, and runs the
self-check as a test. A Linux server can then be scanned in place:

```bash
./build/bd-scan -d /home/gmod/garrysmod/addons -q
```

The entry point is in `BD-Scan.cpp`, option parsing and console input in
`CommandLine.cpp`, scan orchestration in `ScanApplication.cpp`, and HTML output
in `HtmlReport.cpp`. Windows-specific console and atomic file replacement code
is guarded by `_WIN32`. With Python 3 installed, CTest also runs the CLI
integration regressions.

## Compressed workshop archives

Addons downloaded from the Steam Workshop are stored LZMA-compressed under
`garrysmod/cache/workshop/`, and a malicious workshop addon is a well-known
infection route. Previously these were skipped, which meant a large and
plausible part of the attack surface was never examined.

The scanner now decompresses them in memory and scans their contents. Findings
are reported under a path of the form
`.../cache/workshop/3012345678.gma/lua/autorun/server/sv_init.lua`, and
`scan_log.json` reports how many archives were decompressed in
`decompressed_archives`. Uncompressed archives in `addons/` are read directly,
without the decompression step.

`--memory-limit` sets a shared budget for compressed input, decompressed archive
buffers and decoder workspace across workers. It defaults to 1024 MiB; workers
wait for capacity instead of each allocating a full archive independently.
Archives that cannot fit within the budget or the per-archive size limit are
listed as `too_large`. Decompressed data is read directly without copying it
into another stream buffer. This is an archive-buffer budget, not a hard limit
on the process RSS: rules, findings and per-file matching also use memory.

The decoder is in `BD-Scan/Lzma.h` — about 300 lines, no external dependency.
Because it parses attacker-controlled data, it is deliberately conservative:
every dictionary reference is bounds-checked, output is capped (512 MB per
archive by default), and a stream that ends without its end marker is reported
as truncated rather than accepted. The self-check verifies it against LZMA
streams produced by liblzma, and checks that no truncation and no single-bit
corruption ever returns success with wrong output.

## Long paths

On Windows the scanner asks for the extended-length form of the scan root, so a
tree nested past the usual 260-character limit is read rather than reported as
unreadable. That matters beyond convenience: a payload buried deep enough would
otherwise never be opened, and the operator would see a count of skipped files
instead of a finding. Paths in the reports keep their ordinary spelling.

## Unscanned files

A scanner that quietly skips half a server and then reports "0 findings" is
worse than no scanner. Compressed workshop archives are decompressed and
scanned (see *Building*), and anything that still could not be opened is
counted, categorised and listed:

```
!! 40 files were NOT examined. This scan is incomplete.
   40 compressed archive (extract with gmad first):
     .../garrysmod/cache/workshop/1000000.gma
     ... and 35 more (full list in scan_log.json)
```

The same information is in `scan_log.json` under `unscanned` (counts by reason
plus the full file list) and at the top of the HTML report. The reasons are
`compressed_archive`, `too_large`, `unreadable`, `malformed_archive`,
`pattern_limit` and `scan_error`. Unreadable directories are listed by path;
processing exceptions and short reads also make the scan incomplete. Empty
files, including empty archive members, count as successfully examined.

If nothing was found **and** something was skipped, the exit code is `3`, not
`0`. A scan with no findings that never opened part of the tree is not a clean
bill of health, and the exit code says so.

## How it decides

What each rule group covers, how the combination rules work, why the scanner
judges a file by shape as well as by content, and what it does with native
modules and the folders Garry's Mod writes to at runtime: [docs/detection.md](docs/detection.md).

What all of that measures against a labelled corpus, real published addons and
real published backdoors, and what it costs in time: [docs/measurements.md](docs/measurements.md).

## Reading a finding

Each finding carries three things beyond the matched line:

- **A stable ID** (`LUA-010`) for whitelisting and diffing.
- **Three lines of context** either side of the match, so the HTML report can be
  judged without opening the file. In `scan_log.json` this is the `context`
  object (`start_line` plus `lines`).
- **A hint** written for a server owner rather than a Lua developer: what the
  construct does and what separates a legitimate use from a malicious one. Hints
  live in the optional third field of a pattern line and are shown under each
  finding in the HTML report.

The HTML report shows full detail for the 100 highest-scoring files and at most
20 findings per file; the remaining files appear as a compact table sorted by
score. Without that cap a badly infected server produced a 20 MB page that no
browser handled well. `scan_log.json` is never truncated, and the report's
counter says how many findings it is showing out of the total.

The report is deliberately plain: light background, system typeface, colour only
where it carries meaning (critical and high are tinted, medium and low are grey).
Findings are separated by a thin rule rather than boxed in cards, source context
sits in a monospace block with a line-number gutter, and the whole thing prints
without the toolbar. It is meant to read like a tool's output, not a dashboard.

```
regex;;;[SEVERITY] ID Description;;;Optional hint;;;Optional attributes
```

The fourth field holds `key=value` attributes, separated by spaces:

| Attribute | Effect |
|---|---|
| `path=*/lua/autorun/*` | The rule only applies to files whose path matches the glob |
| `tags=darkrp` | Grouping; `--exclude-tags darkrp` turns the rule off |
| `added=2026-09-16` | When the rule entered the set |
| `ref=<url>` | Where the technique is documented |

Path scoping is what lets severity depend on context. `file.Write` in a
configuration addon is routine; the same call from `lua/autorun/`, which runs on
every start, is how a payload re-establishes itself — so `LUA-180` exists only
there.

`--exclude-tags` reaches further than the rules it names. A composite rule has no
tags of its own; it fires on what the rules it refers to have found, so switching
off a tag can leave a composite with a clause that nothing can satisfy any more.
Excluding `darkrp` — the example everyone starts with — takes six composites with
it, three of them critical. The scanner says which ones at startup, and a scan
with `--exclude-tags` never becomes a `--diff` baseline for the same reason.

Every scan reports a `ruleset_version`: the first twelve hex digits of a
SHA-256 over all loaded rule content. It appears in the console banner and in
`scan_log.json`, so a diff across weeks can answer "did the rules change, or did
the server?" without bookkeeping anyone has to remember.

## Suppressing False Positives

On a real server, `RunConsoleCommand`, `game.ConsoleCommand`, `file.Delete`,
`io.open(..., "w")` and `getfenv` all appear in perfectly legitimate addons and
are reported as HIGH or MEDIUM. Without suppression the report fills up with
noise, and a report nobody reads is where a real backdoor survives.

`whitelist.txt` accepts four forms, one per line:

| Form | Effect |
|---|---|
| `<sha256>` | The file is skipped entirely, wherever it sits |
| `<path glob>;;;<pattern ID>` | Suppresses that detection for matching files |
| `<path glob>;;;<sha256>` | Skips the file, but only at that path with that exact content |
| `<path glob>` | Suppresses every detection for matching files |

The second field is matched as a substring of the detection text, so a pattern
ID such as `LUA-045` is the stable way to name a rule. Descriptions get
reworded; IDs do not.

`known_hashes.txt` wins over all of it. The whitelist is for false positives, and
a file whose hash is on the published backdoor list is not one — so a whitelist
entry never silences `HASH-001`, and the scanner names the conflicting entries at
startup. This matters because the two lists move at different speeds: you exempt
a file today, the hash list learns next month what that file is, and without this
rule nothing would ever tell you.

Globs support `*` and `?`, match case-insensitively, treat `/` and `\` as
interchangeable, and are matched against the whole path, so start with `*` to
match a suffix.

A path glob matches **where the file sits on your disk**. For a file inside a
`.gma` that is the archive, not the name the archive gives the file — an archive
author picks those names, so letting them satisfy a glob would mean anyone could
name an entry `addons/trusted/x.lua` and slip past a whitelist written for a real
addon. Use the file's SHA-256 to exempt a single file inside an archive. Reports
still show `<archive path>/<file inside archive>`; only the matching is
restricted.

```
*/addons/ulx/*;;;LUA-045
*/lua/includes/modules/*;;;LUA-020
*/gamemodes/base/entities/entities/lua_run.lua;;;e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
*/addons/my_trusted_addon/*
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Prefer the second or third form. Whitelisting a whole addon hides real backdoors
in it too, and an entry stops being justified the moment the addon updates.

The third form is the one for stock game files that legitimately contain
`RunString`. Pinning the hash alongside the path means the entry expires by
itself: replace the file with a backdoor and the hash no longer matches, so it
gets scanned again. A bare path glob would keep quiet about the replacement.

## Continuous integration

`--sarif` writes `scan_results.sarif` alongside the JSON. GitHub reads that
format directly, so findings appear as annotations on the changed lines of a
pull request instead of scrolling past in a log:

```yaml
- run: BD-Scan -d addons -o . --sarif -q
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scan_results.sarif
```

`continue-on-error` is there because the scanner exits `1` when it finds
something, which is the case where you most want the upload to happen. Severity
maps to `error` for critical and high, `warning` for medium and `note` for low,
and each rule carries a `security-severity` score so the repository's own
alert thresholds apply.

`--cache <file>` skips the pattern scan for files whose content has not changed.
It decides on a SHA-256 of the file, not on its size and timestamp: anyone who
can drop a file into `addons/` can also set its timestamp back, and a cache that
trusted that could be told to skip the one file worth reading. The file is still
read and hashed every run, which is cheap next to running 129 patterns over it.

The cache stores the rule fingerprint and the tag settings alongside the results
and ignores itself when either changes, so editing a rule re-scans everything. It
is worth using on a large `addons/` tree that is scanned often; on a few hundred
files the saving is not worth the file.

The cache file is something you have to trust. It records which files were read
and what was found in them, so anyone who can write to it can list the hash of
their own backdoor with an empty result and the next scan will skip that file
and exit clean. Keep it somewhere the machine being scanned cannot write to, and
not next to `addons/` on the game server itself. There is no signature on it,
and there is no useful one to add: the scanner holds no secret that an attacker
with write access to the cache would not also hold. A damaged or unreadable
cache is a different matter and is safe -- the scanner warns, ignores it, and
scans everything.

## Scanning a Workshop item

```
BD-Scan --workshop 104604709 -o .
```

The id is the number in the Workshop URL. The scanner asks the Steam Web API
what the item is called, prints that, and then looks for the files in three
places in turn:

1. **An already downloaded copy.** If the machine is subscribed to the item, it
   is already sitting in `steamapps/workshop/content/4000/<id>/`. This costs
   nothing and needs no network at all.
2. **A direct download URL**, if Steam publishes one for the item.
3. **steamcmd**, if it is on `PATH`.

The order matters because of a limitation worth stating plainly: the public
Steam Web API returns an empty `file_url` for Garry's Mod items. Every one of
them. So for this game step 2 effectively never fires, and `--workshop` is a
convenience for items you are subscribed to, or a wrapper around steamcmd. When
neither is available the scanner says so and prints the exact steamcmd line:

```
steamcmd +force_install_dir <dir> +login anonymous \
         +workshop_download_item 4000 <id> +quit
```

Nothing that is downloaded is ever executed, and a URL from Steam is only passed
to `curl` if it is plain `https` with no shell metacharacters in it.

## Known limits

- **Rules are regular expressions, not a Lua parser.** A backdoor that builds
  its payload through arithmetic, a table lookup or a custom decoder gets past
  them. Folding covers the common encodings, not arbitrary computation.
- **Binary Lua modules cannot be read.** `gmsv_*.dll` and `gmcl_*.so` are
  reported by hash and path so you know they are there, on disk and inside
  archives alike; what they do is not visible to this tool.
- **A compressed archive inside an archive is not opened.** It is reported as
  unscanned, so the scan exits 3 rather than claiming to be complete. Archives
  nested more than four deep are treated the same way.
- **The published hash list is a floor, not a catalogue.** `known_hashes.txt`
  ships 83 verified samples, and a scan that matches none of them says so rather
  than reporting a reassuring zero. Eighty-three is a fraction of what is out
  there; a file the list does not name is not thereby clean.
- **The real-code corpus is seven repositories.** Facepunch's own game code,
  ULX, ULib, DarkRP, Wiremod, Starfall and PAC3 cover a stock installation, the
  most common admin mod and gamemode, and three addons that build code at
  runtime for a living. A rule that is noisy only on some other large addon will
  still not be caught by CI.
- **Deobfuscation stops where the evidence stops.** Comments, concatenation,
  `string.char` in any base, byte and Unicode escapes, `:reverse()` and
  `table.concat` of literals are all folded back before matching. Strings built
  with `string.format`, `:gsub`, `:upper` or `:rep` are not: no sample in the
  malicious corpus builds a name that way, while the benign corpus makes 702
  `string.format` and 190 `:gsub` calls, so folding them would cost far more in
  noise than it buys. A payload assembled by arithmetic or by a loop is out of
  reach of a pattern scanner altogether.
- **The recall evidence is Lua.** The published backdoors are Lua source; there
  is no malicious `.vmt`, `.dll` or `.gma` among them, and none in the benign
  corpus either. The rules for binary assets, native modules and the runtime
  folders — a fifth of the rule set — are therefore proved only by test cases
  written alongside them, which is the one thing the real-code corpus exists to
  avoid. Treat a clean result on those file types as less well founded than a
  clean result on Lua.
- **x64, and Apple Silicon.** Windows, Linux and macOS each get a release
  archive, and the macOS one carries both Mac architectures. Beyond that there
  is no 32-bit and no ARM build: not Windows on ARM, not aarch64 Linux, not a
  Raspberry Pi. Building from source on those is untried.

Issues and rule contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
