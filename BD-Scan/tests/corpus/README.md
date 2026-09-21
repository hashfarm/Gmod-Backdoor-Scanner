Written for: anyone adding or reviewing rules.

# Labelled corpus

Every file here is labelled by which directory it sits in, and the self-check
turns those labels into two numbers it refuses to let slip:

- **Recall** — every file under `malicious/` must produce at least one CRITICAL
  or HIGH finding. A file we called malicious that the scanner does not flag is
  a regression, so the bar is 100%.
- **Benign criticals** — no file under `benign/` may produce a CRITICAL finding.
  HIGH and below are allowed there: `getfenv` in a sandbox library or a Discord
  webhook in a logging addon are genuinely worth a look, they are just not
  conclusive. A CRITICAL on benign code means a rule is wrong.

Both are checked on every push. Without them, "the calibration is fine" is an
opinion that can quietly stop being true.

They are not sufficient on their own. Everything in this directory was written
by the same people who wrote the rules, so it can only catch mistakes someone
here thought to make. `tests/real_corpus.sh` covers the rest by scanning eight
hundred files of published Garry's Mod code that nobody here wrote; when it was
first run against this ruleset it found thirty-four CRITICAL false positives
while the six files in `benign/` reported none.

When that script finds something, the fix belongs in both places: narrow the
rule, and add a `benign/` sample with the shape of the code that tripped it, so
the check keeps working offline and on every platform.

## What is in here

`benign/` is ordinary addon code of the kind that trips naive scanners: ULX
commands that kick every player, a DarkRP module that overrides `IsSuperAdmin`,
a sandbox tool using `getfenv`/`setfenv` and `_G[...]`, an auto-updater fetching
from GitHub, an owner config full of hardcoded SteamIDs, and a gamemode pushing
fixed Lua to clients with `SendLua` and `string.format`.

`malicious/` covers the shapes the scanner is meant to catch: staged HTTP
loaders, obfuscated `_G` lookups, self-concealment by overriding `file.Find`,
mass hook removal, time-delayed activation, a non-ULX admin rank change,
identity exfiltration, and a hardcoded SteamID next to a privilege grant.

Nothing here is functional. The files are synthetic samples written to exercise
rules, not working addons.

## Adding to it

A new rule should bring a `malicious/` sample that it catches. A false positive
someone reports should become a `benign/` sample with its provenance recorded in this README — that is how the report stops coming back.

Keep samples small and about one thing. Real code from a real server can go in
only if it is licensed to allow it; when in doubt, write a synthetic sample with
the same shape instead.
