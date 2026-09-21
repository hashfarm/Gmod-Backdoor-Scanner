# Changelog

Written for: anyone tracing when a behaviour changed.

Newest first. The scanner's rule IDs are stable across all of this: a whitelist
or baseline written against an old version still refers to the same rules.

## 2.2.0

### What it finds

Rules, severities, and the shapes the scanner learned to recognise.

- Let `known_hashes.txt` win over `whitelist.txt`. The whitelist was consulted
  first at all four decision points, so a file whose hash is on the published
  backdoor list stayed silent if anyone had exempted it: exit 0, nothing
  reported. The two lists move at different speeds -- a file is exempted today
  and the hash list learns what it is next month -- and nothing would ever have
  said so. The whitelist still suppresses everything it suppressed before; it
  just no longer covers a known backdoor, and conflicting entries are named at
  startup. **This changes what a scan reports** for anyone whose whitelist names
  such a hash.
- Say which composite rules `--exclude-tags` switches off. A composite carries no
  tags of its own and fires on what the rules it names have found, so excluding a
  tag can leave a clause nothing can satisfy. Excluding `darkrp`, the example in
  `--help` and in the README, quietly took six composites with it, three of them
  critical; `network` takes nine and `execution` fourteen. The behaviour is
  unchanged -- a scan with `--exclude-tags` was already refused as a `--diff`
  baseline -- but it is no longer silent.
- End a Lua line at a carriage return, not only at a line feed. Lua treats CR,
  LF and CRLF alike, so `-- anything<CR>payload` runs the payload -- but the
  comment stripper searched for the line feed, found none in a file saved with
  classic Mac endings, and blanked everything after the first comment. One
  harmless first line hid the whole file while the server still ran it. The same
  assumption made an ordinary CR file look like a single 8 KB line, so OBF-001
  called it packed, and put every finding on line 1. Line numbers, the comment
  stripper, unterminated short strings and the structural heuristics now agree
  with Lua. Four disguises in `evasion.py` and both directions in
  `integration.py` cover it.
- Parse POSIX bracket expressions in the prefilter's literal extractor. `[[:alpha:]]`
  ended at the `:]` instead of the class, so the closing `]` was taken for a
  literal character and a rule like `posix[[:alpha:]]classword` demanded the text
  `]classword`, which no matching line contains. Any rule written that way never
  fired, and nothing said so. No shipped rule uses the syntax; a hand-written one
  would have gone quiet. `selfcheck` now checks the extractor's actual promise --
  that text matching a rule always holds one of the literals the prefilter
  requires -- over 33 expressions rather than only comparing known answers.
- Fold `string.char` arguments written with leading zeros. Lua reads `0082` as
  `82`, but folding bounded each argument to three digits, so the padded spelling
  was never folded and the reconstructed name never appeared: the same payload
  dropped from CRITICAL to HIGH. Two disguises in `evasion.py` cover it now.
- Decide a file's composite scope from its path below the scan root instead of
  from the whole absolute path. A parent directory named `lua`, `sound`,
  `models`, `materials` or `resource` above the root collapsed every addon into
  one scope, and scan-level rules then combined evidence from addons that have
  nothing to do with each other.
- Run the composite rules over findings from native modules. They were reported
  individually but never combined, so a composite over MOD ids could not fire.
- Read the string table of native modules. `module_patterns.txt` runs eight rules
  (`MOD-010`..`MOD-017`) against the printable runs pulled out of a `.dll`, `.so`
  or `.dylib`, looking for network endpoints and hardcoded identities rather than
  Lua symbol names, which every binding module carries. The one real sample
  available goes from invisible to CRITICAL: its command-and-control URL is in
  plain text. Any native binary is now scanned, not only files named `gmsv_`.
- Cover techniques aimed at scanners themselves, which the older samples predate:
  console commands registered under a security addon's own name (`LUA-137`), the
  kick and ban events hooked to prevent removal (`LUA-136`), admin commands deleted
  with `concommand.Remove` (`LUA-138`) and client screen capture (`LUA-139`), with
  `COMP-028` and `COMP-029`.
- Cover `RunConsoleCommand("ulx", "adduserid", ...)` written as separate
  arguments (`LUA-121`), bans lifted from code (`LUA-122`), admin checks widened
  with a hardcoded SteamID (`LUA-132`) and explosives detonated from code
  (`LUA-135`), with `COMP-024` and `COMP-027` combining them with a hardcoded
  account. Four of the six families the corpus exposed used the first of these.
- Report invisible and bidirectional control characters used inside source
  (`OBF-006`), with `COMP-025` and `COMP-026`. One corpus family names every
  variable with runs of U+202A.
- Stop `OBF-005` exempting files whose non-ASCII content is format controls
  rather than text. The exemption added for non-Latin localisation files covered
  the invisible-character family exactly.
- Fill `known_hashes.txt` with 71 verified samples and their provenance. The
  corpus harness blanks the list for its recall run so the number measures rules.
- Scan the folders Garry's Mod writes to at runtime. `data_patterns.txt` covers
  `.txt`, `.dat` and `.json` under `data/`, `cache/`, `download/` and `lua_temp/`
  with seven path-scoped rules; those extensions are read nowhere else.
- Judge files by shape as well as by content. Five structural signals
  (`OBF-001`..`OBF-005`) measure packed lines, escape runs, whitespace density,
  look-alike identifiers and byte entropy, and need no pattern for the payload.
  `COMP-022` and `COMP-023` turn them into findings.
- Report a global called through a name assembled at runtime. New `LUA-031` and
  `LUA-032`; `COMP-020` and `COMP-021` raise the pair to critical. A call that
  never spells out `RunString` was previously medium at most.
- Extend `LUA-028`, `LUA-029` and `LUA-031` from `_G` to `_R`, `_ENV` and
  `getfenv(...)`. Found by the six new name disguises in `evasion.py`, two of
  which the scanner did not defeat.
- Accept several globs in a rule's `path=` attribute, separated by commas.
- Scope cross-file combinations to addons, gamemodes and individual GMA archives;
  show contributing files and lines in JSON and HTML.
- Match whitelist path globs against a file's location on disk, so a name chosen
  inside a GMA cannot satisfy one. Report a deceptive entry name as GMA-001.
- Keep a string open across a \z escape, so code after one is no longer mistaken
  for a comment.
- Carry the file's SHA-256 on every finding, so known_hashes.txt can be filled
  from a report instead of by hand.
- Warn when the scan target is a whole Garry's Mod install, where stock files
  legitimately trigger CRITICAL rules.
- Stop LUA-153 contradicting itself. It told you to use sql.SQLStr while firing
  on code that does: 30 of its 40 findings on real code were correctly escaped.
  It now needs a value that is neither a literal nor an SQLStr call, which took
  it from 40 findings to 8.
- Apply the same file selection inside a GMA as on disk. A binary Lua module
  packed into an archive is now reported as MOD-001 exactly as one sitting in
  lua/bin, and an archive nested inside another is scanned rather than dropped.
  Previously an archive holding a native module, a nested archive and a data
  blob scanned one of its four entries and exited 0 with "unscanned: 0".
- Read a call that is written without parentheses. Lua lets a function taking one
  string or table argument be called as `RunString"payload"`, `RunString[[payload]]`
  or `RunString[==[payload]==]`, and the rules for `RunString`, `CompileString`,
  `loadstring` and `CompileFile` all required a literal `(`, so every one of those
  spellings scanned clean. Six of them are now in `evasion.py`.
- Report `load` as an execution primitive (`LUA-188`). It sits next to `loadstring`
  in Garry's Mod and had no rule at all, which a backdoor in the corpus exploits on
  purpose: `if load then t,y = load(w,e) else t,y = loadstring(w,e) end`. Another
  fetches a URL and calls `load` on the body. The rule refuses a name preceded by a dot, a colon or a quote, and refuses
  an opening paren followed by two English words, because `load` also ends sentences
  -- "Menu failed to load", "Open old tabs on load" -- and those cost thirty findings
  across seventeen files before the shape was narrowed. What remains is PAC3's own
  local function called `load`, recorded with its reason and a budget.
- Scan the `downloads/` folder. The walker queues it, the seven `DATA-*` rules named
  `download/` and never `downloads/`, so anything the game wrote there was read and
  then matched against nothing.
- Fold three more ways of spelling the same string. `string.char` read decimal
  arguments only, so `string.char(0x52,0x75,0x6e)` -- the same call in another
  base -- dropped the finding from CRITICAL to MEDIUM. A `\u{52}` escape was not
  read at all and a name built that way produced nothing whatever; one corpus
  sample uses it and no file in the 2690 benign ones does. `table.concat` of
  string literals was not read either, and seven corpus samples build a name that
  way. All three fold now, along with `string.char(82.0)`, which Lua accepts.
  What deliberately still does not fold is in the README: `string.format`,
  `:gsub`, `:upper` and `:rep` also build strings, but no sample uses them for
  this and ordinary code uses them constantly -- 702 `string.format` calls in the
  benign corpus -- so folding them would buy noise.
- Rewrite a call written without parentheses into one that has them, before any
  rule sees the file. Lua lets `f"x"`, `f'x'`, `f[[x]]` and `f[==[x]==]` stand for
  `f("x")`, and fifteen rules -- `require`, `ents.Create`, `timer.Remove`,
  `sql.Query`, `AddCSLuaFile`, `concommand.Remove`, `ULib.unban`, `file.Delete`,
  `util.AddNetworkString`, `ConCommand`, `SetUserGroup` and the rest -- matched only
  the parenthesised form. `require"ffi"` is the ordinary way to write it, and the
  rule for loading FFI did not see it. A long string in the argument, parenthesised
  or not, is now read as the quoted string it stands for, so a rule that asks for a
  string argument gets one. The rules are unchanged; the text they read is
  canonical, which is how the comment stripper and the literal folder already work.
- Stop `OBF-006` firing on ordinary right-to-left text. The invisible-character
  set lumped the marks that reorder text -- U+202A..U+202E and the isolates, which
  are the Trojan Source vector and what the corpus family actually uses -- together
  with U+200E, U+200F, U+061C, U+200C and U+200D, which every Arabic, Hebrew and
  Persian translation contains and which Persian and Indic scripts need in order to
  render at all. A five-entry `lang_ar.lua` with no code in it was reported HIGH.
  The reordering marks are still reported; a language file is not.

### What it gets right

Wrong answers, crashes, and the platforms they only showed up on.

- Refuse a rule that repeats a group which already repeats. `(a+)+` has to try
  every way of splitting the input: MSVC gives up and throws, which the scanner
  reports as a partly examined file, but libstdc++ has no limit and simply never
  returns, so the same rule file that is a bad afternoon on Windows is a scan that
  never finishes on a Linux server. Both platforms now refuse the shape at load
  with an error naming the rule. No shipped rule is written that way, and a group
  anchored by a literal -- `(?:,[0-9]{2,3}){6,}`, which is how `BIN-012` finds
  character-code sequences -- cannot backtrack and is left alone.
- Stop crashing on Linux and macOS. libstdc++ recurses once per repetition when
  matching, so an unbounded repeat costs a stack frame per character. An ordinary
  `.vtf` texture was enough: four of the fifty-four Workshop archives in a real
  install segmentation-faulted the scanner, and so did a minified addon on one
  50,000-character line. A rule file with a single very long pattern crashed
  inside the `std::regex` constructor, where no `catch` can help. The folding
  patterns are bounded now, rule expressions are capped at 4000 characters, and
  workers get a 32 MB stack. MSVC does not recurse this way, which is why none of
  it showed on Windows.
- Read the addon metadata of real Workshop archives. Garry's Mod writes the
  addon's description as a JSON blob into the GMA header, and the reader stopped
  at 4096 bytes and called the archive malformed. In a real install that rejected
  4 of 54 archives: 2512 files inside them were never examined, 74 findings never
  reported, and the scan said `malformed archive` rather than admitting it had not
  looked. Entry names keep the old limit, since those are the ones an archive
  author controls per file.
- Say so when a native module holds more readable text than the scanner extracts.
  Only the first 4 MB of a `.dll`'s strings are examined, which is a limit and not
  a verdict, but nothing recorded it: a 5 MB module whose C2 endpoint and hardcoded
  SteamID sat past the mark produced neither finding, and the scan still reported
  `complete: true` with nothing unscanned. The same module with its payload inside
  the limit produces four findings. The cut is now a `string_limit` entry in the
  unscanned list, so the scan stops calling itself complete, and a single run
  longer than the limit is cut to what fits instead of being dropped whole.
- Refuse a line in `known_hashes.txt` that is not a SHA-256, and say which. Any
  non-empty line was accepted and counted, so a hash that lost a character on its
  way through a clipboard became an entry that can never match, while the summary
  still said it had been checked: five lines of which one was a hash reported
  `checked against 5 hashes`. The number an operator reads as assurance now counts
  only entries that can actually match. `whitelist.txt` already validated the
  form; this uses the same check.
- Print the path someone typed in the `Selected file` / `Selected directory`
  banner, which still showed the internal `\\?\` prefix, and stop saying
  "1 hashes".
- Make the skipped-file samples in the console summary and the HTML report the
  same on every run. They were the first entries recorded, and with several
  threads that is whichever file finished first, so two scans of an unchanged
  tree printed different examples. `scan_log.json` was already sorted and did not
  change.
- Print the path someone typed in the two path errors that showed the internal
  `\\?\` extended-length prefix instead.
- Stop reserving the worst case when a compressed `.gma` does not declare its
  decompressed size. liblzma writes that size as unknown, which is what most
  `.gma` files carry, and the scanner answered by reserving the full 512 MiB
  limit: 517 MB of commit charge for a 106-byte archive, and a shared memory
  budget so full that archives decompressed one at a time. Scanning 24 archives
  took 2.95 s where 0.38 s was available. It now guesses 64x the compressed size
  and grows the reservation on a retry if the guess was short, so the guess costs
  throughput at worst and never a finding -- archives expanding 310x, 6457x and
  6979x are still read in full.
- Scan paths longer than the Windows limit. Without the extended-length form the
  files came back as unscanned and nothing looked at them, which is a way to hide
  a payload: nest it deeply and the operator sees a skip count. Reported paths
  keep their ordinary spelling.
- Warn when a whitelist rule names a rule id that does not exist. The field after
  `;;;` is a substring of the finding text by design, so a shortened `LUA-1` also
  silences `LUA-121` without saying so. `--accept` already refused an unknown id;
  a hand-edited `whitelist.txt` could not.
- Make archive entry name sanitisation reach a fixed point. A drive letter that
  only became visible once the path had been resolved survived: `.ll/.././l:`
  came out as `l:`, and `./C:./C:x.lua` kept its prefix. Drive prefixes are now
  stripped per path segment before the segment is classified, so sanitising twice
  gives what sanitising once does. Found by the new name fuzzer.
- Never write invalid UTF-8 into a report. An archive entry name is raw bytes
  chosen by whoever built the archive, and a malformed one aborted the JSON
  writer: the scan found the payload, then exited with no report at all. Entry
  names and paths are now checked, and a malformed name is itself reported.
- Reject a composite expression nested deeper than 64 levels instead of
  overflowing the stack, and stop error messages echoing a whole rule line.
- Reject an `--accept` or `--reason` value containing `;;;`, a line break or a
  control character. Either could write a different whitelist rule from the one
  asked for, or a second one.
- Decide the scan cache on file content instead of size and timestamp. A file
  swapped for a backdoor while keeping both was served from the cache and never
  re-scanned; anyone able to write the file can set its timestamp.
- Record a native binary larger than the scan limit as unscanned. It was counted
  as processed, its strings were never read, and the scan still called itself
  complete.
- Stop findings in a binary carrying line numbers from the extracted string
  buffer. The report showed "line 388" for a file that has no lines; context is
  now rendered without numbers when there are none to give.
- Read a native binary once instead of twice, and guard the entropy text check
  against an empty file.
- Reject invalid pattern and composite files, unknown options and missing option values.
- Record unreadable directories, short reads and worker exceptions as incomplete scans.
- Preserve the baseline after incomplete or filtered scans; compare content fingerprints
  and reject baselines from different roots, rules or suppression settings.
- Write JSON reports and baselines atomically, checking write failures.
- Add a shared archive buffer budget through `--memory-limit` and remove archive
  stream copies. Accept empty archive members as examined.
- Visit each directory once, keyed by canonical path, so NTFS junctions no longer
  produce loops or duplicate findings.
- Check the rule id given to --accept. It used to write anything: a typo, the
  wrong case, or a word that is not an id at all, leaving an entry that suppresses
  nothing while telling the user the finding was dealt with. A wrong id is now
  refused, with the nearest real id suggested.
- Report whitelist rules that matched nothing during a scan. The tool asks for a
  reason so an entry can be reviewed later; it now helps with the review.
- Surface what still cannot be opened: a compressed archive inside an archive,
  and nesting deeper than four levels, are recorded as unscanned instead of
  being ignored.
- Refuse a composite expression with more than 256 terms. `LUA-001 and LUA-001
  and ...` is parsed in a loop, so the 64-level nesting guard never saw it, but
  it builds a tree one level deeper per term, and evaluating or destroying that
  tree recurses: twenty thousand terms overflowed the stack in a release build
  and two thousand in a debug one, where the frames are larger. A rule file is
  operator-supplied rather than hostile input, but the promise is exit `2` with
  an error, not a crash. The shipped composites use at most a handful of terms.
  The hostile rule-file case had been feeding two thousand since it was written
  and accepting whatever came back; running it against a debug build is what
  turned it up.
- Correct what the README says about finding rule files. `module_patterns.txt`
  is required and the README listed it as optional, and the executable's own
  directory is chosen on `lua_patterns.txt` alone, not on "both required pattern
  files". Writing the test for that paragraph is what turned it up.
- Fold literals until they stop changing rather than four times. Each pass joins
  two adjacent pieces, so four passes collapse sixteen; a name split into seventeen
  ran out of passes and the assembled string never appeared. `_G["R".."u".."n"..` and
  so on through seventeen fragments produced no finding at all, and the loop already
  stops early when a pass changes nothing, so the old bound bought nothing.
- Scan a tree that holds a name the system code page cannot spell. Windows
  converts a path to a narrow string through that code page and throws when a
  character has no mapping, and the file walker asked every queued file for its
  extension that way. One file called `readme.<three kanji>` was enough to end the
  whole scan with exit `2` and no report, so a payload sitting beside it was never
  examined -- dropping such a file into an addon switched the scanner off. The scan
  root and the output directory failed the same way. Paths now convert through
  UTF-8, which cannot fail. A Japanese, Cyrillic, Korean or emoji name is ordinary
  input, and `integration.py` now scans all four.
- Stop losing a match that is longer than the overlap between scan windows.
  Text is matched in 64 KiB windows that overlap by 8 KiB, so a match had to fit
  inside one of them; four rules could match a blob of any length and therefore
  lost it whenever it started in the wrong place. The same 9,000-character base64
  literal was reported at offset 16, 20,000, 50,000 and 60,000 but not at 57,000,
  so whether a payload was found depended on how much code sat above it. Those rules now stop at 8,000 characters and accept one more character
  of the blob in place of the closing delimiter, which keeps a half-megabyte blob
  matching while keeping every match inside the overlap. `integration.py` places
  the same literal at four offsets and requires all four.
- Tell the regex engine that a scan window has text in front of it. Each window was
  matched as if it were the whole file, so `\b` and `^` were evaluated against a
  boundary that is not there: a rule anchored at the start of the text could fire at
  any of the window starts, and a word boundary in the middle of an identifier read
  as a real one. Windows after the first now pass `match_prev_avail`.
- Say so when a directory link is not followed. A symbolic link to a directory
  is deliberately not walked -- one pointing at its own parent would loop, and one
  pointing inside the tree would count every file twice -- but it was dropped
  without a word, so a link to a tree full of payloads produced `complete: true`,
  nothing unscanned and exit `0`. A link whose target lies inside the scan is
  still silent, because that content is read by its real path; one pointing
  outside is now recorded as unscanned, which is what makes the scan incomplete.
- Stop merging two directories on Linux that differ only in case. The set of
  directories already visited was keyed on a lowercased path, which is right on
  Windows and wrong everywhere else: `Addons/` and `addons/` side by side are two
  directories on a Linux server, and the second one was skipped as though it had
  already been walked. A scan of the pair read one of the two files and called
  itself complete. The key is only folded where the filesystem folds it.
- Keep collecting context past a blank line. Three lines either side of a finding
  are shown so the report can be judged without opening the file, but collection
  stopped at the first empty line after the match, which in Lua is almost always
  the next one. Most findings therefore shipped with no trailing context at all.
  It now stops at the end of the file, which is what the check was for.
- Make `ToLowerAscii` and `ToUpperAscii` ASCII, as their names say. Both called
  `std::tolower` and `std::toupper`, which follow the C locale, and they decide
  which file extension a rule group covers, whether two rule ids are the same and
  whether a hash matches a listed one. Nothing in the scanner calls `setlocale`,
  so the C locale has always applied and the behaviour has always been right --
  but one library that sets a locale, and in a Turkish one `.LUA` would no longer
  have folded to `.lua`. They now compare bytes.
- Bound the number in `atleast(n, ...)`. It was parsed with `std::atoi`, which is
  undefined on overflow, and the count is whatever run of digits the rule file
  holds. `integration.py` has fed it four hundred nines since the hostile rule
  cases were written, so the undefined behaviour ran on every push; it happened
  not to crash. A count longer than six digits is now refused with the same error
  as a count larger than the number of ids.
- Pin the GitHub-owned actions by commit, the way the third-party ones already
  were. They sat on floating v4 tags, which both leaves the pinning policy half
  applied and holds them on the Node 20 runtime that GitHub has started forcing
  onto Node 24. checkout, upload-artifact, download-artifact and cache now name a
  commit with the version beside it. checkout v7 refuses fork pull request code by
  default, which does not reach these workflows: they run on push, pull_request
  and tags, not on pull_request_target or workflow_run.
  `ilammy/msvc-dev-cmd` stays where it is. Its newest release is from 2024 and
  still declares Node 20, so the warning it raises cannot be fixed from here.
- Measure a whitelist glob after it is expanded, not before. Each `*` becomes
  `.*`, so a 4000-character glob builds an 8000-character expression. The length
  check ran on the glob, and whether the regex engine then accepted the result
  differed between compilers: on one the scan reported the finding, on another
  every file came back as a scan error and the run exited 3. A glob that expands
  past the limit is now refused when the whitelist loads, with the same warning as
  any other bad entry, and that warning no longer prints four thousand characters.
- Refuse a repeated group whose branches can match the same text. The check
  added earlier caught a repeat inside a repeat, `(a+)+`, and missed the other
  half of the same problem: `(?:a|aa)+b` has no nested quantifier at all, yet
  every split of a run of `a` has to be tried. MSVC gives up and reports the file
  as only partly examined; libstdc++ has no limit and a scan of one 400-character
  line never returns, which is how this surfaced -- a new test written against the
  Windows behaviour hung the Linux build. The check now also rejects a repeated
  group whose alternatives can start with the same character, and names the fix in
  the error. None of the 130 shipped rules is affected. It still only catches the
  shapes it can name: two branches that begin with an escape, such as
  `(?:\w|\d)+`, are ambiguous for the same reason and are not refused.
- Stop `--cache` laundering an incomplete scan into a complete one. When a rule
  gives up on a file partway -- the regex engine reaching its complexity limit,
  recorded as `pattern_limit` and "only partly examined" -- the file was still
  stored in the cache as a finished result. The cold run said exit `3`,
  `complete: false`, one file unscanned; the warm run over the same unchanged tree
  said exit `0`, `complete: true`, nothing unscanned. Exit `3` exists so a scan
  that could not read part of the tree cannot pass as a clean one, and the cache
  was the one way around it. A partly examined file is no longer cacheable.
- Keep the path that `--accept <sha256>@<glob>` was given. The hash form parsed
  the glob, validated it, and then wrote a bare hash: an exemption a reviewer had
  deliberately scoped to one directory silenced that file's content everywhere,
  including a copy planted somewhere else. `whitelist.txt` has had the pinned
  `<glob>;;;<sha256>` form all along; `--accept` now writes it.
- Let `--accept` find the rule files the way a scan does. It looked next to the
  executable and nowhere else, so from a working directory holding the rules --
  which is how the release package is meant to be used -- a scan succeeded and
  `--accept` failed with "Could not open rule file". Both now go through the same
  resolution.
- Stop folding `--accept` and `--reason` to ASCII. Every character outside ASCII
  became `?`, which is a wildcard in a path glob, so an exemption written for
  `*/münzen_shop/*` was stored as `*/m?nzen_shop/*` and matched paths nobody had
  reviewed. Both values now reach `whitelist.txt` as they were typed.
- Trim the tags in `--exclude-tags a, b`. Splitting on the comma kept the leading
  space, so the second tag was stored as `" b"` and matched no rule: the scan
  silently excluded less than it was asked to. Rule files written that way were
  affected the same way.
- Count distinct ids in `atleast(n, ...)`. Evaluation incremented once per listed
  argument, so `atleast(3, LUA-050, LUA-050, LUA-050)` -- a copy/paste slip in a
  long list -- was satisfied by a single detection. The count is now over distinct
  ids in both the evaluator and the load-time check, so that expression is refused
  at startup with a reason instead of quietly meaning something else.
- Keep the last character of a UTF-16 string in a native module. The reader
  decided a run was wide text by looking one byte ahead of the next character,
  which fails at the end of the run, so big-endian text was flushed one character
  early. `http://evil-bx.example/d.lua` arrived as `...d.lu`, which is not a Lua
  URL, and a CRITICAL `MOD-010` became a MEDIUM `MOD-016`.
- Put the scanner version in the cache identity. A cache was reused whenever the
  rule fingerprint and policy matched, and neither covers the binary, so upgrading
  to a build that changed what a rule matches replayed the old answer for every
  file that had not been edited -- exactly the files a fix is meant to re-examine.

### What it tells you

The console, the HTML report, the JSON and the SARIF.

- Point a composite finding inside an archive at the archive in the SARIF report.
  It named `addon.gma/lua/autorun/x.lua`, which is not a file anything can open,
  so the alert had nothing to anchor to; pattern findings already got this right.
  The JSON and HTML reports keep the full path, which is what a person wants.
- Close `<div class='stats'>` in the HTML report. It was opened after the header
  and never closed, so every report ever written was unbalanced and everything
  below the summary was nested inside it. The class has no styling, so nothing
  looked wrong; the document was simply invalid. `integration.py` now checks that
  every container in the report closes, on a small report and on one large enough
  to reach the sections that only appear when there are many files.
- Stop promising a "full list in scan_log.json" when the unscanned list hit its
  2000-entry cap. The count was right, the list was capped, and the sentence said
  otherwise.
- Percent-encode the artifact URIs in the SARIF report. They are URI references,
  not paths: an addon directory holding a `#` ended the URI at a fragment, so the
  finding named a file that does not exist, and a `%` made an invalid escape.
  Spaces and non-ASCII names were malformed as well. Sub-delimiters that are legal
  in a path stay readable.
- Say in `--help` that `--cache` decides on the SHA-256, not on size and
  timestamp. The help text still described the behaviour from before that change.
- Write down that the cache file is something you have to trust. A damaged one is
  safe and was already tested, but anyone who can write to it can record their own
  backdoor's hash with an empty result and the scan exits clean. `integration.py`
  now covers six shapes of damaged cache, including the deep nesting that can take
  a recursive JSON parser's stack.
- Add `--sarif`, writing `scan_results.sarif` for GitHub code scanning, with
  `security-severity` scores and per-finding fingerprints.
- Add `--cache <file>`, reusing results for files whose size and timestamp are
  unchanged. The cache carries the rule fingerprint and tag settings and ignores
  itself when either differs.
- Add `--workshop <id>`, resolving an item through the Steam Web API and then
  reading an already subscribed copy, a direct download URL, or steamcmd, in that
  order. Garry's Mod items never publish a direct URL, so the first and third
  paths are the ones that fire. URLs that are not plain `https` are refused and
  nothing downloaded is executed.
- Add `--version`, printing the version, the rule counts and the rule digest.
  The banner now takes its version from the same constant.
- Give the report a heading outline, a label on the filter box and a live region
  on the finding counter, so it can be navigated without seeing it.
- Fix the highlighted source line in the report, which kept a hard-coded light
  background after the dark theme was added: light text on a near-white row, a
  contrast of 1.1 to 1, so the one line a finding points at was the only one you
  could not read. It is now a token in both themes, 10.3 to 1 in dark and 13.9 to
  1 in light, with a coloured edge marking the row instead of relying on fill.
- Take the first person out of the console. A command line tool describes what
  it does, it does not announce what it intends to do.
- Print output paths with one separator instead of mixing them, and stop naming
  the HTML report twice.
- Give the HTML report a dark theme and the same severity colours as the console,
  so the two surfaces stop teaching different palettes for the same four words.
- Add a filter box to the report covering file, rule id and source text, shorten
  paths against the scan root and keep the full path as a tooltip.
- Document scan_log.json in SCAN_LOG.md: every field, what schema_version
  promises, and a worked example. It carried a version number nobody could
  look up.
- Order console findings by severity instead of by file, so the two CRITICAL
  results in a scan no longer sit among forty LOW ones. Print the most serious
  first, summarise the rest, and shorten paths against the scan root.
- Colour the output: severity badges, bars in the summary, dimmed code. Honours
  --color, NO_COLOR, TERM=dumb and switches itself off when piped.
- Say what to do next. The summary now points at the report and explains the
  loop: read, accept, scan again with --diff.
- Add --accept <rule>@<glob> with --reason, which appends a dated, explained
  entry to whitelist.txt so triage no longer means hand-editing a file.
- Replace the bare interactive prompt with an example path and produce the HTML
  report automatically when run without arguments.
- Show every rule that fired on a file in the HTML report. The per-file cap kept
  the first twenty findings after sorting by severity and line, so a file with
  twenty-five `LUA-001` hits and three other rules showed only `LUA-001` -- the
  other three rule types appeared nowhere on the page, under a note claiming the
  hidden findings "repeat rule types already shown above". The cap now takes one
  finding of each rule first and fills the rest of its budget afterwards, and the
  note only makes that claim when it is true.
- Stop the console calling hidden findings "of lower severity" when they are not.
  A file with a hundred CRITICAL findings printed forty of them and said the other
  sixty were less severe, which is exactly the sentence that stops someone reading
  further.
- Count a file once in the summary. Scan-level combination rules were counted
  among the files with findings, so a scan of two files could print "3 findings in
  3 of 2 files".
- Count distinct hashes, not detections, in the known-backdoor line. Two copies of
  one listed file printed "2 of 1 listed hashes matched".

### How it is checked

Suites, corpora, sanitisers, and what the build ships.

- Add Wiremod, StarfallEx and PAC3 to the benign corpus: 1232 files to 2690, and
  31 rules exercised to 48. They are the hard case rather than the easy one, since
  a sandbox, a compiler and a part builder all do openly what a backdoor does in
  secret. Every CRITICAL they produce is correct and is listed with its reason.
  Two weak matches are now budgeted rather than argued away: `OBF-001` on a long
  `local` line and a table of sound paths, `BIN-014` on a stretch of a bundled
  font.
- Say in `malicious_corpus.expected` why one family is recorded as finding
  nothing: 38 lines that print and kill on a catchphrase, with nothing executed,
  fetched, hidden or persisted. Catching it would mean firing on the kind of code
  every gamemode is made of, so the entry is a boundary and not a miss.
- Check `SanitizeUtf8` against 50,000 random byte strings and two dozen malformed
  encodings, requiring valid UTF-8 out of all of them and no change on a second
  pass. Invalid UTF-8 here once aborted a report that had already found the
  payload. `--color always` is checked too, for colour runs left open.
- Test the decompression retry and the backtracking check. Both were written in
  this release and no suite reached either. The retry is what keeps a short size
  guess costing throughput instead of a finding, so an archive that expands far
  past the guess now has to give up the payload inside it.
- Cover what the suites had never run. A coverage pass put line coverage at 86.5%
  and named the gaps: every rejection path in the archive reader, and the prompt
  shown when the scanner starts with no arguments, 41% of `CommandLine.cpp`. Both are tested now, along with the argument errors, `--help`,
  the `--workshop` branch that finds an already-subscribed copy, and the pinned
  `<glob>;;;<sha256>` whitelist form. 86.5% to 93.0% over the two suites.
- Link the Linux release statically. A binary linked against the build runner's
  glibc wants 2.38, which Debian 12 and Ubuntu 22.04 do not have -- and those are
  what most Garry's Mod servers run, so the published binary would not have
  started for many of the people it is for. The scanner shells out to `curl` and
  resolves no names itself, so a static link has none of the usual drawbacks; the
  release job now also fails if the binary comes out dynamically linked.
- Add `tests/metamorphic.py`, which asks whether the same backdoor written
  differently still reads as one. Every corpus sample is respelled seven ways Lua
  cannot tell apart, across four placements and three containers, and the module
  strings are laid out in a `.dll` five ways a linker might: 54 variants per run,
  failing if any sample's severity drops. It names no rule, so new rules need no
  entry. Put the carriage-return defect back and it reports 273 losses where the
  other three suites all passed, because every test file ever written here used
  line feeds.
- Run both corpora under AddressSanitizer and UndefinedBehaviorSanitizer in CI,
  cold cache and warm. The fuzzers cover inputs nobody ever wrote and the
  ThreadSanitizer pass covers a synthetic tree; neither reaches what 2690 real
  published files and 85 real backdoors reach.
- Scan the malicious corpus on macOS too. That job stopped after the benign
  corpus, so the platform with its own filesystem semantics never saw a backdoor.
- Refuse a corpus checkout directory that is the rule directory. `integration.py`
  and `evasion.py` take the rules as argument 2 and the corpus scripts take a
  scratch path there, so passing the rules clones the corpora into the source
  tree, after which the benign run scans the malicious samples and reports them
  as rules firing on known-good code.
- Check prefilter equivalence for every rule group rather than `.lua` alone. A
  prefilter that wrongly skips a rule loses findings silently; measured over both
  corpora it agrees on all 1722 files and is 4.5x faster.
- Pin the third-party GitHub Actions to a commit SHA instead of a moving tag, and
  add a Dependabot entry so the pins get updated deliberately. `release.yml` runs
  with `contents: write` and builds the binary people download to look for
  backdoors; an action whose tag is repointed could replace it. Added a read-only
  permissions block to `build.yml`, which had none.
- Put every rule file into the release packages. `release.yml` named them one by
  one and never learned about `data_patterns.txt` or `module_patterns.txt`, so a
  package would have refused to start. The release smoke test catches it, which
  means releases would have been blocked rather than shipped broken, but no
  release could have been cut. Both platforms now glob the rule files, the way
  the build workflow already did.
- Build the ThreadSanitizer job from every source file rather than a list that
  went stale when `SarifReport.cpp` was added, and run it over native modules,
  runtime data files and a second pass through the cache.
- Fuzz the layer that takes outside data but was never fuzzed: archive entry
  names (`fuzz_names`) and command-line parsing (`fuzz_cli`). The existing
  targets all feed file *contents*; every defect found in this area came from
  names and configuration instead.
- Load rule files, the whitelist and composites from lines as well as from a
  path, so parsers can be exercised without touching the filesystem.
- Budget false positives per rule instead of capping HIGH findings globally.
  `real_corpus.expected` records how many findings each rule may produce on the
  benign corpus and across how many files; a rule that fires there without a
  budget now fails the run. The old ceiling could not say which rule had grown.
- Measure the scanner against real backdoors. `tests/malicious_corpus.sh` scans 84
  samples in 26 families from seven public sources dated 2015 to 2025, each pinned
  by commit and verified by sha256; the samples are not stored in this repository.
  Family recall on the 2015 set started at 13 of 19; the corpus now stands at 23 of
  26 reaching CRITICAL, with the three exceptions recorded rather than hidden.
- Fix the corpus metric dropping families that produced no findings at all, which
  hid the one family the scanner misses entirely.
- Include composite rules in both release packages and test extracted packages.
- Resolve the real-corpus scanner path before changing directories.
- Separate the entry point, command-line parsing, scan orchestration and HTML output.
- Add CLI, failure-handling, concurrency and packaged-release regression checks.
- Add an evasion suite: one backdoor, twenty-five disguises, all of which must
  still be reported.
- Drop the unused LooksCompressed helper left behind by an earlier change.
- Cover directory symlinks in the integration suite, on the platforms where they
  can be created without special rights.
- Drop the 32-bit Windows configuration. Garry's Mod servers are 64-bit and the
  x86 build was neither tested in CI nor published.
- Build and test on macOS in CI, so "Linux and macOS" in the README stops being
  a claim nobody had checked.
- Stop telling people to download nlohmann/json. It has been vendored at
  BD-Scan/nlohmann/json.hpp since the first commit that used it; the README had
  been describing a setup step nobody needed to perform.
- Move the fixture checks out of the workflow file into integration.py, so the
  three that were Windows-only -- context and hint on every finding, a composite
  surviving a filter that hides its parts, and the regression tree being examined
  in full -- now run on Linux too. build.yml drops from 205 lines to 104 and each
  check runs once per platform.

- Parse the HTML report instead of searching it for substrings. No suite had
  ever read the page as markup, which is how an unclosed `<div class='stats'>`
  shipped. Four reports are now checked for balanced tags, including both
  truncation branches and one built from lines an attacker wrote.
- Check the SARIF against the shape the format requires rather than the fields a
  test happened to read: schema and version, the driver's identity, unique rule
  ids with a description and a valid level each, a location and a message on
  every result, and no result naming a rule the file does not declare. From inside
  the suite, a report the code scanner rejects looks like one it accepts.
- Make writing a report fail. Reports go to a temporary file and are renamed over
  the target, which only matters when the write fails, and nothing had ever made
  it fail. A directory standing in for each of the three report files now does:
  the scanner has to stop with exit `2`, name what it could not write, and leave
  no temporary file behind.
- Scan without `--rules`. Every test passed it, so the path an actual user takes
  -- the binary next to its rule files, or the rule files in the working
  directory -- was covered only by the release smoke test, which runs on a tag
  rather than on a push. Both branches now run every time, together with the
  promise that an explicit `--rules` never falls back somewhere else, and with
  each required rule file removed in turn.
- Fuzz the rule loader. Pattern, whitelist and composite files all end up in a
  regular expression compiler, three of the crashes fixed in this release came
  from that code, and it was the only untrusted input without a fuzz target.
  `fuzz_rules` reaches more of the binary than any of the five targets that came
  before it.
- Give the scanner a terminal. Whether output is coloured is decided by asking
  whether stdout is one, every run in the suite captures output through a pipe,
  and `--color always` answers before the question is asked -- so the path every
  user gets by default had never run. A pty covers it now, where the platform
  has one.
- Scan an LZMA stream that unpacks into something that is not an archive. Every
  malformed-archive case until now fails before it is decompressed; this is the
  other order, and only the reader on the far side can tell.
- Keep every fuzz corpus between nightly runs, not the first three. `fuzz_names`
  and `fuzz_cli` had been running nightly without their corpora being cached, so
  each night restarted them from the seeds and threw the night's work away.
- Pin the archive index against `int64` bounds: an entry declaring `INT64_MAX`,
  one declaring `INT64_MIN`, and four whose declared sizes would sum past the
  file if the per-entry check were ever dropped.
- Add `BDSCAN_THREADS`. The worker count came from `hardware_concurrency` alone,
  so nothing could ask whether the answer depends on the number of cores. It
  does not: one thread and sixteen produce the same findings, the same lines and
  the same file count, and the suite now says so on every push. It also makes a
  crash that only appears under concurrency reproducible in a single thread.
- Audit fourteen subsystems with one agent each and three independent reviewers per
  finding, then check every surviving claim by running it. Forty-five findings came
  through review; running them kept the ones above and threw out several that three
  readers in a row had failed to refute: a whitelist bypass through archive entry
  names that the scanner handles correctly, and carriage-return line numbers that
  are already right. It cut the other way once. The code page defect is real and
  the first explanation of it was wrong, and only a run settled that.
- Keep reading a file after recognising it by hash. A match against
  `known_hashes.txt` ended the examination there, so the report said HASH-001 and
  nothing else: not the URL the backdoor fetches from, not the SteamID it grants
  admin to, and not the hook it installs. The combination rules also lost an
  input, so a neighbouring file's evidence could go unreported. On one sample,
  listing the hash removed eight findings including both composites. An operator
  needs to know what the backdoor does to the server, and scanning one file it has
  already recognised costs nothing.
- Count how many rules a real sample actually reaches, and print it. Recall was
  reported as families caught, which says nothing about which rules earned it.
  Measured: 56 of 101 Lua rules, 15 of 28 composites, 3 of 8 module rules, and
  none at all of the 14 binary or 7 runtime-folder rules -- because the published
  backdoors are Lua source and there is no malicious `.vmt`, `.dll` or `.gma`
  among them, nor in the 2690 benign files. A fifth of the rule set is proved only
  by test cases written next to it, which is the one thing the real-code corpus
  exists to avoid. The harness now says so on every run and the README lists it as
  a limit; nothing here fixes it, because fixing it needs samples nobody has
  published.
- Say out loud that the window boundary test cannot fail. It builds its input
  from `kWindowSize - kWindowOverlap`, the two constants it is checking, so the
  payload moves with the window and the test passes however the window is cut.
  It still earns its place -- it proves a match is found across a boundary at all
  -- but what pins the window is the bounded-reach check and the fixed offsets in
  `integration.py`, and the comment now says so rather than leaving the next
  reader to assume the constant is covered.
- Close the four gaps the mutation pass found. Lowering the window overlap to 64
  bytes, cutting the context to one line, putting the folding pass cap back to
  four and switching the call normaliser off all left every suite green. Two of
  those were defects fixed in this release whose fix nobody had pinned. There is
  now a differential check that the same call written `f("x")`, `f"x"` and
  `f[[x]]` produces the same findings for five rules that only ever knew the first
  spelling; a context check that a blank line does not end it; a folding check at
  16, 17 and 40 pieces; and a selfcheck line that reports the widest bounded rule
  against the overlap it has to fit in -- 8002 characters against 8192, which is
  thin enough to be worth printing on every run.
- Break the scanner on purpose and see whether the suites notice. Fourteen
  deliberate regressions were compiled in one at a time -- comments never
  stripped, literals never folded, composites never firing, the prefilter
  dropping every file, archive entries never scanned, line numbers off by one,
  the window overlap cut to 64 bytes, a partly examined file cacheable again --
  and each had to be caught by at least one suite. A test that cannot fail is
  worth nothing, and the only way to know is to make it fail. `selfcheck` caught
  none of the pipeline ones, which is right: it tests rules against snippets, and
  the pipeline is what `evasion.py` and `integration.py` are for. `evasion.py`
  caught five of the first six, which is more than its name suggests it does.
- Mutate the call syntax, not just the whitespace. The reformatting pass took every
  positive test case indented, with a trailing comment, with spaced parentheses and
  with its arguments wrapped; all four keep the shape `f(x)`, which is why a rule
  that only matched that shape looked fine. Five more mutations put a space, a tab
  and a comment before the call, and rewrite it into its parenthesis-free and
  long-string forms: 1149 variants per run instead of 640. The first three found
  nothing -- every rule already handled them -- and the last two found fifteen rules
  an attacker walks past by changing one character.
- Reproduce every audit finding before acting on it. Eight mid-severity claims
  that had survived three reviewers each were run against the binary: six behaved
  as described, one behaved differently than described and one did not happen at
  all. The six are fixed above and each has a regression test; the other two are
  recorded as not reproduced.
- Correct what `SCAN_LOG.md` and the README say about the report. `start_time` and
  `end_time` are Unix seconds and were documented as formatted local time;
  `statistics` counts severities and was documented as counts per rule id; the
  unscanned reason is `malformed_archive` and was documented as `malformed`, with
  `string_limit` missing entirely. A script written against any of those three
  fails on every scan. The README's own limits section still said the hash list
  ships empty -- it ships 83 -- and that the real-code corpus is four repositories
  when it has been seven since Wiremod, Starfall and PAC3 were added.

Two of the defects above are worth more than one line each.

### An archive entry could name itself past a whitelist

A `.gma` stores a path for every file it contains, and that path was used as-is
when the whitelist was consulted. Since the archive author picks those names, an
entry called `addons/trusted/x.lua` inside any archive matched a whitelist glob
written for a real addon at that location. With a whitelist of
`*/addons/trusted/*` -- the form shown in this project's own documentation -- a
scan of five backdoored archives reported:

```
  CRITICAL:  0
  TOTAL:     0
  WHITELIST: 5 suppressed
EXIT=0
```

A clean bill of health for five backdoors. Traversal (`../`), a leading slash
and a drive letter all worked, and so did a plain relative path with no trick in
it at all.

Path globs now match where a file sits on disk. For archive contents that is the
archive; the name inside it cannot satisfy a glob. Whitelisting one file inside
an archive is still possible by its SHA-256, which an author cannot forge the
same way.

Entry names are also normalised before use, and a name that tries to leave its
archive is now reported in its own right as `GMA-001`: Garry's Mod never writes
such an archive, so the name is itself a finding. The file is still scanned,
under its real location inside the archive.

### Directory junctions were followed

`std::filesystem::is_symlink` does not report NTFS junctions, which is the link
type that needs no administrator rights. A junction pointing at its own parent
made the scanner walk the loop until the path outgrew `MAX_PATH`: one file
reported twenty-three times, two bogus "unreadable" entries, and exit code 3 on a
tree that was in fact clean.

Directories are now visited at most once, keyed by canonical path. That covers
junctions, symlinks and any future reparse type, and removes the duplicate
reports that a junction produced even without a loop.

## Earlier Work (July 2025)
The following improvements were implemented by **Hungryy2K/RRelicc** in July 2025:
- **Fixed Linker Errors**: Defined global vectors (`LuaCheckPatterns`, `LuaCheckDefs`, etc.) in `BD-Scan.cpp` to resolve unresolved external symbol errors.
- **Resolved Switch-Case Warnings**: Replaced `switch` with `if-else` in `CheckLine` to eliminate `fallthrough` warnings, ensuring compatibility with stricter compiler settings.
- **Improved JSON Initialization**: Explicitly initialized `logJson` as `json::object()` to suppress static analyzer warnings about uninitialized members.
- **Enhanced Detections Counter**: Refined logic in `ProcessFile` to count only actual pattern matches, improving accuracy of the `detections_found` metric.
- **Added Unicode Support**: Used `std::wstring` for directory input to handle non-ASCII paths.
- **Command-Line Support**: Added support for `-d <directory>` argument to specify the scan directory directly.
- **JSON Logging**: Implemented structured JSON output in `scan_log.json` with details on detected patterns, file paths, and scan statistics.
- **Performance Optimization**: Introduced parallel processing with `std::async` for faster scanning of large directories.
- **Error Handling**: Added robust checks for empty files, invalid paths, and regex compilation errors.
- **Pattern Refinement**: Updated `vmt_patterns.txt` and `ttf_patterns.txt` to improve CharCode detection with the regex `[0-9]{2,3}(,[0-9]{2,3})*`.

## NEW Features (December 2025)
The following features were added by RRelicc in this version:

### New Capabilities
- **GMA Archive Support**: Scan inside `.gma` addon files without extraction
- **Severity Levels**: All detections now classified as CRITICAL, HIGH, MEDIUM, or LOW
- **Base64 Decoding**: Automatic decoding and display of Base64 obfuscated content
- **HTML Reports**: Generate styled HTML reports with `--html` flag
- **96 Patterns**: 82 for Lua, 14 for binary asset files, each with a stable ID, test cases and a plain-language hint
- **13 Composite rules**: boolean combinations of pattern IDs, evaluated per file and across the whole scan

### New Command Line Options
- `-d <path>`: Directory to scan recursively, or a single file
- `-o <directory>`: Where to write `scan_log.json`, `last_scan.json` and `scan_report.html` (default: working directory)
- `-s <severity>`: Filter by minimum severity level (low, medium, high, critical)
- `-q, --quiet`: Quiet mode - suppress console output, show only summary
- `--html`: Generate HTML report (`scan_report.html`)
- `--diff`: Show only NEW detections since last scan
- `-h, --help`: Show help message

### Exit Codes
- `0`: no detections, and everything was examined
- `1`: detections reported
- `2`: error (bad arguments, unreadable directory, missing pattern files)
- `3`: no detections, but some files could not be examined

So `BD-Scan.exe -d /srv/gmod/addons -q` can be used directly in CI without
parsing the JSON to find out whether anything was found. Treat `3` as "look at
the report": it means the scan produced no findings but is not a clean bill of
health, because part of the tree was never opened. See *Unscanned files* below.

### Interactive Mode
When running without arguments, you can enter path and options together:
```
Enter path [options]: C:/gmod/addons --html --diff
```

### Files
- `lua_patterns.txt`: Patterns applied to `.lua` files
- `binary_patterns.txt`: Patterns applied to `.vmt`, `.vtf` and `.ttf` files
- `known_hashes.txt`: Known backdoor file hashes, SHA-256 (optional)
- `whitelist.txt`: False-positive suppression (optional)
- `last_scan.json`: Baseline for `--diff`, written by unfiltered scans only

### Technical Improvements
- **Thread Safety**: Fixed race conditions in concurrent logging
- **Improved Pattern Files**: All patterns now include severity tags
- **Better CharCode Detection**: Enhanced decoding for obfuscated numeric sequences

## Coverage and Usability (September 2026)

Four things, each found by probing the scanner rather than reading it.

### The workshop cache is now readable

A synthetic split backdoor showed the shape: a loader in `lua/autorun/` reading
a Base64 payload out of `materials/logo_hd.vmt`. The loader was caught; the
payload file produced **nothing**, because `binary_patterns.txt` had no Base64
rule. And the equally common shape — a loader reading an asset file and
executing it — had no rule of its own either, only the generic `RunString` hit.
Both are closed: `BIN-014` for encoded blobs in asset files, `LUA-008` for file
contents being executed. Neither fires on the legitimate corpus.

Separately, LZMA-compressed workshop archives are decompressed and scanned
instead of skipped. See *Compressed workshop archives*.

### The HTML report is usable at realistic sizes

978 findings across 338 files was a flat 620 KB wall. The report now has a
severity filter and collapsible per-file sections (the ten highest-scoring open
by default). Verified in a browser: unchecking low, medium and high takes it
from 978 findings in 338 files to 45 in 28, with a live count, and files whose
findings are all filtered out disappear.

### Linux

`main`/`wmain` and two console calls are the only Windows-specific code left;
a `CMakeLists.txt` builds the scanner and the self-check and registers the
latter with `ctest`. The CMake build is verified on Windows. **The Linux build
was not compiled where this was written** — no toolchain was available — but
the CI workflow has a Linux job that builds with CMake, runs `ctest`, replays
the fixture smoke test and fuzzes each target for 30 seconds, so the first push
is the real test and the badge will say how it went.

## Measured Against Real Addon Code (September 2026)

The severity calibration had been argued, never measured. Five files of
realistic legitimate addon code (ULX commands, a DarkRP module, a sandbox tool,
an auto-updater, an owner config) produced **17 findings and zero CRITICAL**,
which is the result that matters. Two things came out of it:

- **A scan could report success while never opening part of the tree.** Pointed
  at a server root with a compressed workshop cache, the scanner printed one
  error line per archive — invisible under `-q` — and then summarised
  "1 file scanned, 0 findings". Unscanned files are now counted, categorised,
  listed in every output, and produce exit code `3`. See *Unscanned files*.
- **`raw.githubusercontent.com` at HIGH was a false-positive driver.** A large
  share of legitimate addons auto-update from GitHub. It is now `LUA-073` at
  MEDIUM, while paste sites and URL shorteners stay HIGH as `LUA-072`; the two
  are different kinds of source. HIGH findings on the legitimate corpus dropped
  from 7 to 6.

Findings now carry three lines of context either side of the match and a
plain-language hint, so the HTML report can be judged without opening the file.

One idea was **dropped because the measurement contradicted it**: escalating
severity when correlated patterns appear together. Checked against a real
backdoor versus a legitimate updater, the existing file score already separates
them (33 vs 5), so correlation rules would have been mechanism without gain.

## Pattern Overhaul (September 2026)

### The combination patterns had never matched anything, and nothing noticed

Roughly fifteen patterns were written as `http\.Fetch\s*\([^)]*function[^)]*RunString`.
`[^)]*` cannot cross a closing parenthesis and a Lua callback signature always
has one, so none of them could ever fire — not on one line, not on several:

```
http.Fetch("u", function(body) RunString(body) end)   -> no match
http.Fetch("u", function() RunString(x) end)          -> no match
```

These are the rules that separate "uses a risky function" from "this is a
backdoor". They were dead for the life of the project because nothing ever
executed them. The fix is in two parts, and the second matters more:

1. The spans are now single bounded lazy spans that cross parentheses and
   newlines (`\([\s\S]{0,400}?`). Nested spans (`{0,400}?…function…{0,400}?`)
   were measured at ~300 ms each per 3 MB of Lua, because each anchor
   occurrence costs up to 400×400 backtracking steps; collapsing them to one
   span cut the pattern set from 1673 ms to 766 ms and made the rules *more*
   permissive, so `net.Receive("x", RunString)` matches too.
2. **Every pattern now has test cases** in `lua_patterns.test.txt` /
   `binary_patterns.test.txt`, run by the self-check and by CI. A pattern
   without both a `+` and a `-` case is a failure. This is the part that keeps
   the above from happening again.

### Patterns are identified, not described

Each pattern carries a stable ID (`LUA-010`). `--diff` keys on it and whitelist
entries reference it, so descriptions can be reworded without invalidating
baselines or whitelists — which had already happened twice.

### Comments are stripped before matching

`-- RunString("example")` and `--[[ ... ]]` blocks produced CRITICAL findings.
A string-aware stripper blanks comments while preserving length and newlines, so
line numbers and reported source lines stay exact, and
`print("-- not a comment") RunString(x)` still fires.

### Techniques that had no pattern at all

Verified as missed before, caught now: `RunStringEx`; an execution function
passed as a *reference* (`http.Fetch(url, RunString)`, `local r = RunString`);
`timer.Create` beacons; the `HTTP({...})` table form; admin-check overrides
(`function PLAYER:IsSuperAdmin()`); hardcoded SteamIDs; direct `ucl.addUser`;
forced client commands (`ply:ConCommand("connect ...")`); reversed string
literals; `string.format("%c%c%c")`; byte-pair and XOR decoding loops;
Base64-decode-then-execute; Discord webhooks, hardcoded-IP URLs and paste-site
sources; and world-entity removal.

### Severity now reflects Garry's Mod, not general Lua

`os.execute`, `io.open`, `ffi.*` and `package.loadlib` were eight CRITICAL
patterns for APIs the GMod sandbox removes — code that cannot run. They are one
HIGH pattern meaning "foreign or probing code". Conversely `RunConsoleCommand`
dropped to LOW with a separate CRITICAL rule for security-relevant convars, and
`debug.getregistry` dropped to MEDIUM because half of all addons use it to reach
a metatable.

Removed: `rcon\s+[a-zA-Z]` (matched any text containing "rcon " and a letter;
addons cannot run rcon anyway) and two registry patterns that were strict
subsets of a third.

### Binary Lua modules are surfaced

`require("x")` loads `lua/bin/gmsv_x_win64.dll`, which runs native code with no
sandbox. No regex can see inside it. Such files are now reported as `MOD-001`
with their SHA-256 so they can be reviewed once and whitelisted by hash.

## Detection Improvements (September 2026)

### The combination patterns never matched anything

Roughly fifteen patterns were written as `http\.Fetch\s*\([^)]*function[^)]*RunString`
and similar. `[^)]*` cannot cross a closing parenthesis, and a Lua callback
signature always has one, so the span could never reach past `function(body)` to
the `RunString` behind it. Verified against every realistic shape:

```
http.Fetch("u", function(body) RunString(body) end)   -> no match
http.Fetch("u", function() RunString(x) end)          -> no match
http.Fetch("u",
  function(b)
    RunString(b)
  end)  -> no match
```

These are exactly the rules that separate "uses a risky function" from "this is
a backdoor", and none of them had ever fired. The unbounded spans are now
bounded lazy spans (`[\s\S]{0,400}?`) that cross parentheses and newlines while
keeping the regex cost capped. The same change removes a quadratic-scan risk
that the two `player.GetAll()[^;]*:Kick` patterns carried, since Lua code rarely
contains a semicolon to stop them.

### Scanning is now whole-file, not line-by-line

Every pattern is matched against the file content in overlapping 64 KB windows
instead of one line at a time, so multi-line constructs match without any
per-pattern opt-in. Line numbers come from the match offset, and the reported
`line_text` is still the single line the match starts on.

### Obfuscated string literals are folded before matching

`_G["RunStr" .. "ing"]` is the standard way to hide a call from a scanner and
previously produced zero detections. Three encodings are now folded back into
plain literals before patterns are applied:

| Written as | Folded to |
|---|---|
| `"RunStr" .. "ing"` | `"RunString"` |
| `string.char(82, 117, 110, 83, 116, 114, 105, 110, 103)` | `"RunString"` |
| `"\x52\x75\x6e\x53\x74\x72\x69\x6e\x67"` or `"\82\117\110..."` | `"RunString"` |

The three combine, so `string.char(82,117,110) .. "Str" .. "\x69\x6e\x67"` also
resolves. Only printable characters are folded; quotes, backslashes and control
characters are left alone so string boundaries and line breaks never move, which
keeps line numbers accurate.

Every file is matched twice: once as written and once folded. The first pass
keeps the obfuscation itself visible (`CharCode Obfuscation`, `Multiple Hex
Escapes`), the second pass matches what the obfuscation was hiding. The report
shows the original line with the folded form next to it. A new pattern catches
dangerous functions reached through a `_G[...]` lookup.

### Files are scored

Five hits of `RunConsoleCommand` in one file and one `http.Fetch` callback that
runs its response are not the same thing. Each file gets a score that adds a
weight per *distinct* detection type (critical 10, high 3, medium 1), so a file
combining several kinds of evidence ranks above one that repeats a single
pattern. `scan_log.json` carries a `files` array sorted by score, the HTML
report is grouped by file in that order, and the console prints the top five.

### Other
- A whitelist (`whitelist.txt`) suppresses known false positives by path glob,
  detection name, or file hash.
- Exit codes: `0` clean, `1` detections, `2` error.
- `-d` accepts a single file, and `-o` chooses where the output files go.
- `sv_allowcslua` and `rcon_password` are keyword hits, not code execution, and
  moved from CRITICAL to HIGH.
- A `.gma` that is LZMA-compressed (as downloaded into `garrysmod/cache/workshop/`)
  is reported as such instead of as a generic header error; extract it with
  `gmad` first. Archives in `addons/` are not compressed and scan directly.
- CI builds the solution, runs the self-check and scans two fixture directories
  on every push and pull request (`.github/workflows/build.yml`).
- `scan_log.json` is sorted by file and line, so two scans of unchanged content
  produce byte-identical output instead of thread-dependent ordering.
- The HTML report is sorted by severity.
- `vmt_patterns.txt`, `vtf_patterns.txt` and `ttf_patterns.txt` were identical
  and are now one `binary_patterns.txt`.
- Severity is parsed once at load time; a pattern without a `[SEVERITY]` tag is
  reported as a warning instead of silently becoming LOW.
- Scanning logic moved out of `BD-Scan.cpp` into `Scanner.h`, `Rules.h` and
  `Report.h`, and is covered by the self-check.

## Fixes (September 2026)

### Correctness
- **`--diff` now works.** The comparison against `last_scan.json` was loaded but
  never applied; every detection was reported regardless. Detections already
  present in the baseline are now suppressed and counted separately.
- **Baseline integrity.** `last_scan.json` is only rewritten by unfiltered scans
  (no `-s`, no `--diff`). A filtered run no longer overwrites the baseline with a
  partial result, which used to make the next diff report everything as new.
- **Console output respects `-s`.** Detections below the severity threshold were
  printed to the console even though they were excluded from the report.
- **Duplicate suppression.** A `file:line:detection` key is now recorded once, so
  the same finding cannot be counted twice.
- **Unix timestamps.** `start_time` / `end_time` are seconds since the epoch
  instead of raw clock ticks.

### Robustness against hostile input
- **GMA parsing is validated.** Every read is checked, string reads are length
  capped, declared file sizes are checked against the real archive size, and the
  file index is bounded. A truncated or crafted `.gma` previously left `fileNum`
  uninitialised, which could spin the read loop or allocate from an attacker
  controlled 64-bit size field.
- **Binary reads.** Files are opened in binary mode. In text mode a `0x1A` byte
  ended the read on Windows, so anything after it was never scanned.
- **Bounded regex input.** Long lines are scanned in overlapping 4 KB windows.
  A minified Lua file or a binary `.vtf` could otherwise hand a multi-megabyte
  "line" to `std::regex`, which recurses.
- **Size cap.** Files above 64 MB are skipped and reported in the summary.
- **Report sanitising.** Raw bytes from binary files are replaced before being
  written to JSON; invalid UTF-8 used to make `json::dump()` throw at the end of
  an otherwise complete scan.
- **HTML escaping.** Detected source lines are escaped in the HTML report. A
  backdoor containing markup could otherwise execute in the report.
- **Directory traversal errors** (permission denied, vanished files) skip the
  entry instead of aborting the scan.

### Behaviour
- **Unicode paths work.** The entry point is `wmain`; paths are no longer
  truncated through a byte-wise `wchar_t` conversion.
- **Bounded parallelism.** One worker per CPU core replaces one `std::async` task
  per file.
- **No prompt in CLI mode.** The "Press Enter" pause only happens when the
  scanner was started without `-d`, so `-q` is usable from scripts.
- **Data files resolve next to the executable**, falling back to the working
  directory.
- **Invalid `-s` values are rejected** instead of silently disabling the filter.
- **`known_hashes.txt` is case-insensitive** and tolerates surrounding whitespace.
- **Known-backdoor and diff counters** are shown in the summary and the reports.
