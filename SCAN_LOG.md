Written for: anyone reading `scan_log.json` from a script.

# scan_log.json

Every scan writes this file to the `-o` directory. It is the whole result; the
HTML report is a view of it and the console prints a summary of it.

```json
{ "schema_version": 2, "complete": true, "detections": [ ... ] }
```

## What `schema_version` promises

Within a major version, fields are added but never removed or given a new
meaning. Read the file by name, ignore fields you do not know, and a scanner
update will not break you. A field disappearing or changing meaning bumps the
number, and the change is listed in [CHANGELOG.md](CHANGELOG.md).

Version 2 is current.

## The scan

| Field | |
|---|---|
| `schema_version` | `2` |
| `complete` | `false` when anything could not be examined. **Check this before trusting an empty `detections`.** The exit code says the same thing: `3` means nothing found but the scan was not complete. |
| `scan_root` | The directory that was scanned, forward slashes. Every `file` below starts with it. |
| `start_time`, `end_time` | Unix time in seconds, as an integer. |
| `files_processed` | Files actually opened and examined, archive members included. |
| `detections_found` | Length of `detections`. |
| `composite_hits` | How many of those came from a combination rule. |
| `decompressed_archives` | LZMA-compressed `.gma` files unpacked in memory. |
| `whitelisted` | Files skipped whole because `whitelist.txt` matched. |
| `known_backdoors` | Hash matches against `known_hashes.txt`. |
| `min_severity` | The `-s` floor in effect. Findings below it are not in the file. |
| `diff_mode` | `true` when `--diff` was used, so this file holds only what is new. |
| `ruleset_version` | Hash of the loaded rule files. |
| `policy_version` | Hash of `whitelist.txt` and `known_hashes.txt`. Together with `ruleset_version` this decides whether a baseline is still comparable. |
| `archive_memory_limit_bytes` | The `--memory-limit` budget. |
| `archive_memory_peak_bytes` | The most that was held at once. |
| `statistics` | Findings per severity: `critical`, `high`, `medium`, `low`. |
| `files` | Per-file scores, in the order the report uses: `file`, `score`, `detections`, `distinct_types` and a count per severity. `score` weights each *distinct* kind of finding, so a file combining several kinds ranks above one repeating a single rule. |
| `unscanned` | See below. |
| `detections` | See below. |

## A finding

```json
{
  "id": "LUA-001",
  "severity": "critical",
  "detection": "[CRITICAL] LUA-001 Code Execution (RunString)",
  "file": "C:/srv/garrysmod/addons/evil/lua/init.lua",
  "line_number": 42,
  "line_text": "RunString(net.ReadString())",
  "hint": "Runs Lua source built at runtime. ...",
  "hash": "e0ff51e0...",
  "fingerprint": "e0ff51e0...",
  "context": { "start_line": 39, "lines": ["...", "..."] }
}
```

| Field | |
|---|---|
| `id` | Stable. Safe to key on; descriptions get reworded, ids do not. |
| `severity` | `critical`, `high`, `medium` or `low`, lower case. |
| `detection` | The full rule line, severity and id included. Prefer `id` and `severity`. |
| `file` | Forward slashes. A file inside an archive reads `<archive>.gma/<member>`, and members are normalised, so a `..` never appears. |
| `line_number` | 1-based. `0` for findings about a whole file, such as `MOD-001`, `HASH-001` and most `OBF-*`. |
| `line_text` | The matching line, trimmed and stripped of control characters. |
| `hint` | Plain-language explanation from the rule. This is what to show a person. |
| `hash` | SHA-256 of the file the finding came from. This is the field to collect when filling `known_hashes.txt`. |
| `fingerprint` | What `--diff` compares. Equal to `hash` for ordinary findings; derived from the contributing findings for a combination rule. |
| `context` | Surrounding source, with `start_line` naming the first line. |
| `decoded_content` | Only when the scanner decoded something, for example a Base64 blob. |
| `related_findings` | Only on combination rules: the findings that made it fire, each with `id`, `file` and `line_number`. |

## `unscanned`

```json
"unscanned": {
  "total": 1,
  "by_reason": { "too_large": 1 },
  "files": [ { "reason": "too_large", "file": "...", "detail": "90 MB" } ]
}
```

Reasons are `too_large`, `compressed_archive`, `unreadable`,
`malformed_archive`, `pattern_limit`, `string_limit` and `scan_error`. `files` is
capped at 2000 entries and `list_truncated` says whether that cap was reached;
`total` and `by_reason` count everything either way.

`unreadable` also covers a directory link whose target lies outside the scan.
Such a link is not followed, because following it would pull in a tree the scan
was not pointed at, and the entry is what keeps the scan from calling itself
complete. A link pointing inside the scan is followed by its real path and is not
listed.

An empty `detections` with a non-zero `total` here means the scanner found
nothing **and could not look everywhere** — not that the tree is clean.

## Using it from a script

```python
import json, sys

log = json.load(open("scan_log.json", encoding="utf-8"))

if not log["complete"]:
    sys.exit("scan was incomplete: " + json.dumps(log["unscanned"]["by_reason"]))

blocking = [d for d in log["detections"] if d["severity"] == "critical"]
for d in blocking:
    print(d["id"], d["file"], d["line_number"], d["hint"], sep=" | ")
sys.exit(1 if blocking else 0)
```

For a pass/fail gate the exit code alone is enough: `0` clean, `1` findings,
`2` error, `3` nothing found but incomplete. Treat `3` as a failure in CI.
