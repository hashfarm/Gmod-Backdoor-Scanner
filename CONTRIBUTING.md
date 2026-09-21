Written for: people adding detection rules, not necessarily C++ developers.

# Contributing

Most useful contributions here are rules, and a rule is a line of text. You do
not need to touch the C++ to add one.

## Adding a pattern

One line in `BD-Scan/lua_patterns.txt` or `BD-Scan/binary_patterns.txt`:

```
regex;;;[SEVERITY] ID Description;;;Hint;;;Attributes
```

- **regex** — ECMAScript syntax, case-sensitive. Bound every open-ended span:
  write `[\s\S]{0,400}?` rather than `[\s\S]*`, and avoid a `\s*` next to a
  negated class that also matches whitespace. An unbounded or ambiguous span is
  how this scanner once got a pattern that could not finish on a 420-byte file.
- **ID** — the next free number in the block you are adding to. It is what
  `--diff` keys on and what whitelists reference, so it never changes once
  published, even if the description is reworded.
- **SEVERITY** — what the construct means *in Garry's Mod*, not how alarming it
  sounds. `os.execute` is HIGH, not CRITICAL, because the sandbox removed it and
  the code cannot run.

  Severity is consequence *and* specificity, not either alone:

  | | |
  |---|---|
  | **CRITICAL** | If this is malicious you have lost the server, and the construct is specific enough that legitimate uses are rare and nameable. `RunString` is CRITICAL even though stock Garry's Mod contains four legitimate uses — those four are listed by name in `tests/real_corpus.expected`. If you cannot list the exceptions, the rule is too broad to be CRITICAL. |
  | **HIGH** | A strong indicator, but with a legitimate use you can describe in one sentence. Mass-banning every player is HIGH, not CRITICAL, because every admin mod has that command. |
  | **MEDIUM** | Worth reading in context. Usually one half of a combination rule. |
  | **LOW** | Normal, listed so the report is complete and so combination rules can refer to it. |

  The test for CRITICAL is not "does this sound bad" but "can I name the
  legitimate uses, and are they few enough to list?" `RunConsoleCommand(` on its
  own fired 257 times on 800 files of stock code — that rule now matches only a
  command name built at runtime, and sits at MEDIUM.
- **Hint** — written for a server owner who does not read Lua: what the
  construct does, and what separates a legitimate use from a malicious one. If
  you cannot name that difference, the severity is probably too high.
- **Attributes** — optional `key=value` pairs: `path=*/lua/autorun/*` to scope
  the rule to a location, `tags=darkrp` for grouping, `added=YYYY-MM-DD`,
  `ref=<url>` pointing at where the technique is documented.

## Every rule needs test cases

In the matching `.test.txt`, at least one case that must match and one that must
not:

```
+ LUA-140 ;;; if os.time() > 1893456000 then RunString(payload) end
- LUA-140 ;;; local now = os.time()\nif now > lastCheck then lastCheck = now end
```

The self-check fails if either is missing. This is not bureaucracy: fifteen
combination patterns in this project were dead for a year because nothing ever
executed them, and the test files exist so that cannot happen again.

Write the negative case as the *closest legitimate code you can think of*. A
negative that is obviously different proves nothing. The best source is real
published code: the negative for `LUA-005` is a line lifted from Facepunch's
sandbox gamemode, and the negative for `LUA-115` is the line in ULX that the
rule used to flag by accident.

Every negative case is also run against **every other rule**, and any CRITICAL
it raises fails the build. That turns each snippet someone writes for one rule
into a false-positive check for all shipped rules. If another rule fires and is
*right* to fire -- a guarded `RunString` is still a `RunString` -- add the same
snippet as a positive case for that rule. Saying so out loud is the exemption.

## Combination rules

When a finding only means something next to another, put it in
`composite_rules.txt` rather than trying to express it in one regex:

```
LUA-042 and (LUA-040 or LUA-041);;;[CRITICAL] COMP-002 ...;;;hint
```

`and`, `or`, `not`, parentheses and `atleast(n, ID, ...)` over pattern IDs. A
`scan:` prefix evaluates the rule across files within the same addon or GMA
archive. Separate addons and archives never share evidence. Integration tests
exercise both related and unrelated files; expression-only tests are not enough.

## Corpus samples

A new rule should bring a sample under `BD-Scan/tests/corpus/malicious/` that it
catches. A false positive you hit should become a sample under
`BD-Scan/tests/corpus/benign/`, with its provenance recorded in the corpus README.
Do not add code comments; keep explanations in documentation and use clear names
in code.

The self-check requires every malicious sample to produce at least one CRITICAL
or HIGH finding and every benign sample to produce no CRITICAL at all. Those two
numbers are what stops the calibration drifting.

Samples must be synthetic or licensed to allow redistribution. Nothing in the
corpus is functional code.

## Real published code

The corpus above is written by the same people who write the rules, which makes
it good at catching regressions and bad at catching wishful thinking. So CI also
scans code nobody here wrote:

```bash
BD-Scan/tests/real_corpus.sh ./build/bd-scan
BD-Scan/tests/malicious_corpus.sh ./build/bd-scan
```

It checks out Facepunch/garrysmod, TeamUlysses/ulx, TeamUlysses/ulib,
FPtje/DarkRP, wiremod/wire, thegrb93/StarfallEx and CapsAdmin/pac3 at pinned
commits, scans all 2690 files, and fails on any CRITICAL that is not already
listed in `real_corpus.expected`. Everything below CRITICAL is capped by a
budget in the same file rather than listed one by one.

This is worth running before proposing a new CRITICAL rule. When it was first
written it reported thirty-four CRITICAL findings on stock Garry's Mod, all of
them wrong, and four of the rules involved had passed every test in this repo.

If a finding is real, add a line to `real_corpus.expected` saying why. If it is
not, the rule needs narrowing and the line belongs in the benign corpus too.

Any rule that fires here below CRITICAL needs a `profile` line giving it a budget:
how many findings it may produce and across how many files. The run fails without
one. That is deliberate friction -- it puts a moment of looking at what the rule
actually matched between writing it and shipping it.

Bumping the pinned commits is a deliberate change: do it in its own commit and
say what moved.

`malicious_corpus.sh` asks the opposite question against 26 backdoor families
caught on real servers and published, from seven sources dated 2015 to 2025. It fails if a family that used to
reach CRITICAL stops doing so, or if overall family recall drops below the floor
recorded in `malicious_corpus.expected`. Neither number is worth much alone: a
rule that flags everything scores perfectly here and fails `real_corpus.sh`, and a
rule that flags nothing does the reverse. Run both.

The samples are not in this repository and never should be. The harness clones
them at a pinned commit and verifies every file against a recorded sha256, so a
change upstream fails the run instead of silently altering what is tested.

Raising the floor after improving a rule is the point. Lowering it is a claim
that the scanner got worse, and belongs in its own commit with a reason.

The fuzzers cover three layers. `fuzz_lzma`, `fuzz_gma` and `fuzz_scanner` feed
file contents; `fuzz_names` and `fuzz_cli` feed the things that arrive from
outside without being file contents -- archive entry names and command-line
values, where every defect found in that area came from; `fuzz_rules` feeds the
input the operator supplies, a rule file, through the pattern, whitelist and
composite parsers in one pass.

`fuzz_rules` was left out for a long time with a reason: under AddressSanitizer
the loader died inside the standard library on valid rule content, and a target
that fails for reasons outside the code under test teaches people to ignore it.
That was the libstdc++ regex recursion, and bounding the patterns and enlarging
the worker stack fixed it. The ASan build now takes every shipped rule file, and
all of them concatenated, without complaint.

## Trying to defeat the scanner

`BD-Scan/tests/evasion.py` holds one backdoor and every disguise anyone has
thought of for it: string continuations that hide code behind a comment, archive
entries named after somebody else's addon, payloads sitting on a scan window
boundary. All of them must still be reported.

This is a different question from the other test layers. The pattern tests ask
whether a rule matches, the mutation pass whether it survives reformatting, the
fuzzers whether the scanner crashes. Only this one asks what an attacker asks:
can I make it stay quiet?

Both of the worst defects found in this project came from asking that by hand --
an archive entry that named itself past a whitelist, and a `\z` escape that hid
the rest of the line. If you find another, add it here before you fix it, and
check that it fails first.

## Running the checks

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
ctest --test-dir build --output-on-failure
```

On Windows, open `BD-Scan.sln` and build, then:

```bat
cl /std:c++17 /EHsc /I BD-Scan BD-Scan\tests\selfcheck.cpp /Fe:selfcheck.exe && selfcheck.exe BD-Scan
```

Pass `--rules <dir>` to the scanner when testing it by hand. Without it the
scanner prefers the rule files sitting next to the executable, which the build
copies there, so an edit to `BD-Scan/lua_patterns.txt` can silently not be the
thing you just measured.

Expected last line: `selfcheck: all checks passed`. Error messages from
deliberately invalid rule fixtures are expected: the checks verify that those
files are rejected rather than partially loaded. With Python 3 available, CTest
also runs `tests/integration.py`, including content changes under `--diff`,
incomplete scans, archive budgets and addon isolation. `tests/release_smoke.py`
checks an actual ZIP or tar.gz after extraction.

Four suites, each answering a different question:

| | |
|---|---|
| `selfcheck` | Do the rules match what they claim, and nothing else? |
| `integration.py` | Does the scanner behave correctly end to end -- exit codes, baselines, archives, memory, malformed rule files? |
| `evasion.py` | Can an attacker make it stay quiet? |
| `metamorphic.py` | Does the same backdoor, written differently, still read as one? |

The first three check inputs somebody thought of, and every file in them is
written with line feeds, loose on disk, without a byte order mark, in a short
ASCII path, because that is how a person writing a test file writes it.
`metamorphic.py` asks from the other side: it takes the real corpus, respells
each sample in ways Lua cannot tell apart, puts it where a real addon would be,
and requires that the verdict never gets weaker. It names no rule, so it needs no
maintenance when the rules change, and it found nothing the other three were
looking for -- it found the carriage-return defect, which all three had passed
over for the same reason.

It makes 54 variants of the corpus per run, across three passes:

| Pass | What varies |
|---|---|
| source | seven spellings (CR, LF, CRLF, byte order mark, a comment on top, no final newline) across four placements (shallow, twelve levels deep, a non-ASCII directory, a path past `MAX_PATH`) and three containers (`.gma`, compressed `.gma`, `.gma` inside a `.gma`) |
| module | the strings `module_patterns.txt` exists to find, laid out in a `.dll` as ASCII, as UTF-16, padded, after binary noise, and among ordinary Lua symbol names |
| cache | a warm cache replays findings through different code than the scan that produced them, so the second run has to agree with the first |

It needs the corpus checkout, so run `malicious_corpus.sh` first and point it at
that directory:

```
python BD-Scan/tests/metamorphic.py ./x64/Release/BD-Scan.exe BD-Scan \
    /tmp/bd-malicious-corpus/src
```

Add `--verbose` to see every variant rather than only the failures.

CI runs all four suites on Windows, Linux and macOS for every pull request, plus
both corpus scans on each. macOS runs twice, on Apple Silicon and on Intel,
against the universal binary the release ships. Linux additionally runs the corpora under
AddressSanitizer and UndefinedBehaviorSanitizer, a ThreadSanitizer pass, and
thirty seconds of fuzzing per target. Nothing is asserted in the workflow file
itself: if a check is worth making, it belongs in one of the suites, where you can
run it locally.

If you add a transformation, it has to be one Lua genuinely cannot tell apart.
A change that alters what the file means would make the suite report losses that
are not defects, and a suite that cries wolf gets switched off. The way to tell
whether a new axis is worth having is to break the thing it covers on purpose and
check that it says so: reinstate the carriage-return defect and the suite reports
273 losses, encode the module strings as UTF-32 and it reports 8.

### Finding out what the suites never run

Picking where to look next by intuition runs out. To see it instead, on Windows:

```
winget install OpenCppCoverage.OpenCppCoverage

OpenCppCoverage --sources BD-Scan --excluded_sources nlohmann --excluded_sources tests ^
    --cover_children --export_type html:cov ^
    -- python BD-Scan\tests\integration.py x64\Release\BD-Scan.exe BD-Scan
```

It needs the `.pdb` next to the binary, which a Release build already writes.
The first run of this said 86.5% of lines, and the gaps were more useful than the
number: every rejection path in the archive reader had never run, and neither had
the prompt the scanner shows when started with no arguments. Both are now covered,
because an archive is the one input an attacker writes from scratch and the prompt
is the entry point a person actually uses.

Measured that way, `integration.py` and `evasion.py` together reach 93.0% of
lines. Three things make up most of the rest, and all three are deliberate: the
Steam Web API call and the steamcmd download behind `--workshop`, which need the
network -- the branch that finds an already subscribed item is tested, by
pointing `STEAM_PATH` at a tree made for it; the terminal detection in
`Console.h`, which is covered where a pty exists and therefore not in this
measurement, which runs on Windows; and the error branches inside the directory
walk in `ScanTasks.h`, which need a filesystem that fails partway through an
enumeration.

## Reporting a false positive

Open an issue with the pattern ID, the line that triggered it, and what the code
was actually doing. That is enough to either fix the rule or add the snippet to
the benign corpus. Both outcomes are useful; the second is what keeps the fix
from being undone later.

## Changing the C++

Keep the build warning-free at `/W4 /WX` and `-Wall -Wextra`. Anything that
parses untrusted input — archives, compressed data, scanned content, rule files
— belongs behind a fuzz target in `BD-Scan/tests/fuzz/`; the two real defects
found so far both came from there rather than from the test suite.

`BDSCAN_THREADS=<n>` pins the worker count. It exists so the suites can prove
that the answer does not depend on how many cores the machine has, and it makes
a crash that only shows up under concurrency reproducible: set it to 1 and the
scan runs in a single thread, in order.
