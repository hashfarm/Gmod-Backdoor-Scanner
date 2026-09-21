# What the numbers are measured against

Recall, false positives on published addons, what each rule costs on real code,
and throughput. Every figure comes out of a script in `BD-Scan/tests/` that CI
runs on every push. For running a scan, see the [README](../README.md).

## Measured against a labelled corpus

`BD-Scan/tests/corpus/` holds files labelled by directory, and the self-check
turns the labels into two numbers:

- Every file under `malicious/` must produce at least one CRITICAL or HIGH
  finding. Currently 11 of 11.
- No file under `benign/` may produce a CRITICAL. Currently 0 of 6.

`benign/` is deliberately the code that trips naive scanners: ULX commands that
kick every player, a DarkRP module overriding `IsSuperAdmin`, a sandbox tool
using `getfenv`/`setfenv`, an auto-updater fetching from GitHub, an owner config
full of hardcoded SteamIDs. HIGH findings are allowed there — they are worth a
look, just not conclusive. A CRITICAL means a rule is wrong.

Both numbers are checked on every push. Without them, "the calibration is fine"
is an opinion that can quietly stop being true.

They are necessary and not sufficient, because everything in that directory was
written by the same people who wrote the rules. The first time the scanner was
pointed at real published code it produced thirty-four CRITICAL false positives
while this corpus reported none, which is why `tests/real_corpus.sh` exists and
runs alongside it.

## What each rule costs on real code

Every rule that fires on the benign corpus carries a budget in
`real_corpus.expected`:

```
profile LUA-113    59  30
profile LUA-045    38  25
profile LUA-120     6   4
```

At most that many findings, across at most that many files, on 2690 files of
published Garry's Mod, ULX, ULib, DarkRP, Wiremod, Starfall and PAC3. The run
budget, and it also fails if a rule fires here without having one at all. Writing
the line is the moment to look at what the rule matched and decide it is right.

This replaced a single ceiling over all HIGH findings. The ceiling could tell you
that something had got broader but never which rule, and it crept upwards every
time an unrelated rule was added. Forty-nine of the 130 rules currently fire on
legitimate code, and now each of them is accountable separately.

## Measured against real backdoors

The corpus above is written by the same people who write the rules, so passing it
proves only that the scanner finds what its authors imagined. This one is not.

`tests/malicious_corpus.sh` scans backdoors that were caught on real servers and
then published: **26 families, 85 Lua files, 1.0 MB**, from seven sources dated
2015 to 2025. None of it was written for this project and none of it is stored
here. The harness clones each source at a pinned commit, forces `core.autocrlf=off`
so the bytes match what upstream stores, and checks every file against a recorded
sha256 before scanning.

```
BD-Scan/tests/malicious_corpus.sh ./build/bd-scan
```

```
malicious corpus: 85 samples in 26 families from 7 sources, 1065881 bytes of known-bad Lua
malicious corpus: 23 of 26 families reach CRITICAL, 7 samples produce nothing
malicious corpus: 85 of 85 samples are also recognised by known_hashes.txt
   below critical: bb2015/BD013_CPT_Base                    none     (recorded none)
   below critical: cmdremove                                high     (recorded high)
   below critical: kickblock                                high     (recorded high)
```

A family is one backdoor, and its score is the best the scanner reaches on any of
its files: would this have been stopped. The three below CRITICAL are recorded
rather than hidden. Two of them are rated correctly — a file whose entire content
is a hook that blocks kicks is worth knowing about, but it is not a takeover, and
HIGH is the honest answer. The third is a genuine miss, and it stays visible.

Recall is measured with `known_hashes.txt` blanked, so it reflects the pattern
rules alone. Otherwise every sample would be a hit by construction and the number
would mean nothing. The hash list is then measured separately, on its own line.

### What the 2015 set found

The first run scored **13 of 19**, not the 100% the hand-written corpus reports.
Four things came out of the six failures:

- **`RunConsoleCommand("ulx", "adduserid", id, "superadmin")`** was not covered.
  Four separate families use that exact line, and it is the most common payload in
  real Garry's Mod backdoors: no obfuscation, no remote code, one line that hands
  out superadmin. The existing rule only matched `"ulx adduser"` written as a
  single string. Now `LUA-121`, and `COMP-024` when the SteamID is hardcoded too.
- **An admin check widened with `or ply:SteamID() == "STEAM_..."`.** The code still
  reads as if it checks for admin. Now `LUA-132`.
- **Invisible characters used as identifiers.** One family names every variable
  with a different-length run of U+202A LEFT-TO-RIGHT EMBEDDING, so the file looks
  blank in an editor. Now `OBF-006`, and `COMP-026` with any second structural
  signal.
- **A bug in this scanner's own heuristics.** `OBF-005` skips files that are mostly
  valid non-ASCII UTF-8, added so a Japanese localisation file would stop being a
  false positive. That exemption covered the invisible-character family exactly,
  because U+202A is valid UTF-8. The fix was to count only characters that are
  plausibly text and ignore format controls, which repairs both cases at once.

### What the 2019-2025 set found

Adding newer samples was worth more than adding older ones, because the techniques
had moved on. Three of them exist only because scanners like this one exist:

- **Console commands registered under a scanner's own name.** One sample claims
  `bs_scan`, `nomalua_scan`, `braxscan`, `gac_checkbackdoors` and two more, each
  bound to a function that prints a blank line. An admin who runs a scan gets that
  handler instead of their tool, and is told nothing is wrong. Now `LUA-137`, and
  it is CRITICAL because there is no second reading of it.
- **The kick and ban events hooked** so the operator cannot be removed. Now
  `LUA-136`.
- **An admin console command deleted** with `concommand.Remove`. Now `LUA-138`.
- **The player's screen captured** and streamed out in Base64 chunks. Now
  `LUA-139`, with `COMP-029` when it meets a network call. The sample aliases the
  function first — `local grab = render_Capture or render.Capture` — so the rule
  deliberately does not require a following bracket.

A 2015 corpus could not have found any of the first three. That is the argument
for keeping this file growing.

### Its limits

Twenty-six families is better than eleven hand-written ones and it is still small.
Seven sources on GitHub are what happens to be public; whatever is currently being
sold in private is not here. A scanner that scores 23 of 26 has proven it catches
these, not that it catches the next one.

One new false positive came out of it, and it is recorded in
`real_corpus.expected` with its reason: ULX's own admin panel really does call
`ulx adduserid`, with values from its UI rather than an ID written into the file.
`COMP-024` correctly stays quiet on it.

The most useful thing anyone running a server can contribute is a sample. If you
find a backdoor on a machine you administer, its hash is already in your
`scan_log.json`, and the file itself is worth more to this project than any number
of new rules.

## How it goes fast

Running all the regexes over every window is the obvious implementation and
the slow one. Before any regex runs, one Aho-Corasick pass over the window
records which literal substrings are present; a pattern is only evaluated if one
of its required literals is there.

The required literals are derived from the regexes themselves at load time, by a
small parser that walks the expression and returns the most selective literal
that *must* appear for a match to be possible. It is deliberately conservative:
anything it cannot reason about — a pure character class such as
`[0-9]{2,3}(?:,[0-9]{2,3}){6,}`, a hex-escape pattern, an alternation where one
branch has no literal — yields no requirement, and that pattern simply always
runs. Being wrong in that direction costs time; being wrong the other way would
lose findings.

On 400 000 lines of Lua this took the scan from 6.8 s to 1.6 s, a little over
four times faster, with byte-identical results.

That last part is not an assumption. The self-check scans every fixture and
every pattern test snippet twice, once with the prefilter and once without, and
fails if a single finding differs. An optimisation that silently drops a
detection is the worst possible bug in this program, so it is checked rather
than trusted.
