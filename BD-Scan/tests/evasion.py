r"""One backdoor, many disguises. Every disguise must still be reported.

The pattern tests ask whether a rule matches. The mutation pass asks whether it
survives reformatting. The fuzzers ask whether the scanner crashes. None of them
ask the question an attacker asks: can I make this scanner stay quiet?

Both of the worst defects found in this project so far -- an archive entry that
named itself past a whitelist, and a string continuation that hid code behind a
comment -- were found by asking that question by hand. This file asks it on every
push.

Why each disguise works, since the names alone will not tell you:

  z_escape            \z swallows the whitespace that follows it, so the string
                      runs past the line break and the -- sits inside it rather
                      than starting a comment.
  backslash_newline   A backslash before a newline keeps a short string open the
                      same way.
  escaped_quote       An escaped quote must not be read as the end of the string.
  long_string_comment A [[ ]] string may contain anything, including --.
  closed_long_comment A long comment that is closed does not hide what follows.
  window_boundary     The payload sits where the 64 KiB scan windows meet.
  fake_long_open      --[= looks like a long comment opener but is not one.
  level_mismatch      --[==[ closes only at ]==]. A ]] in between does nothing,
                      so Lua never runs what is between them and neither should
                      a report mention it.

  cr_only_*           Lua ends a line at a carriage return as readily as at a
                      line feed, so `-- comment<CR>payload` runs the payload. The
                      comment stripper looked for the line feed alone, found none
                      in a file saved with classic Mac endings, and blanked the
                      rest of the file: one harmless first line made everything
                      below it invisible while Lua still ran it.

  nul_bytes           Reading the file as bytes rather than as a C string; a
                      NUL must not truncate everything after it.
  utf8_bom            A byte order mark must not shift the first rule.

  name_charcode_*     Lua accepts leading zeros in a numeral, so string.char(0082)
                      is string.char(82). Folding that bounded each argument to
                      three digits, so the padded spelling was never folded and
                      the reconstructed name never appeared.

  name_*              The payload calls RunString without the word RunString ever
                      appearing: through the global table, through an alias, through
                      a table field, or through a name rebuilt from pieces at runtime.
                      A scanner that greps for the function name misses all of them,
                      so each must still come out CRITICAL, whichever rule gets there.

  entry_*             A .gma stores a path for every file it holds, and the
                      author of the archive picks it. None of those names may
                      satisfy a whitelist written for a real addon.
  nested              An archive inside an archive. Used to be dropped without
                      a word: not scanned, and not counted as unscanned either.
  native              A binary Lua module inside an archive. The scanner reports
                      one sitting on disk, so it must report one packed away.

Out of scope: UTF-16 source. LuaJIT cannot load it, so a payload encoded that way
never runs and the scanner is right to stay quiet about it.

Usage: evasion.py <scanner> <rule directory>
"""

import io
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from integration import gma

BS = chr(92)
NL = chr(10)
CR = chr(13)
PAYLOAD = "RunString(net.ReadString())"


def lua_disguises():
    """Source-level hiding. Each entry must still produce LUA-001."""
    return {
        "plain": PAYLOAD + NL,

        "z_escape": 'local s = "' + BS + 'z' + NL + '   --" ' + PAYLOAD + NL,

        "backslash_newline": 'local s = "' + BS + NL + '--" ' + PAYLOAD + NL,

        "escaped_quote": 'local s = "a' + BS + '"b" ' + PAYLOAD + NL,

        "long_string_comment": 'local s = [[ -- ]] ' + PAYLOAD + NL,

        "closed_long_comment": '--[[ hidden ]] ' + PAYLOAD + NL,

        "window_boundary": ("-- filler" + NL) * 6400 + PAYLOAD + NL,

        # Lua calls a function with one string or table argument without
        # parentheses. Four spellings of the same call, none of which the rules
        # saw until they were taught to.
        "no_parens_double": 'RunString"net.ReadString()"' + NL,

        "no_parens_single": "RunString'net.ReadString()'" + NL,

        "no_parens_long": "RunString[[net.ReadString()]]" + NL,

        "no_parens_long_level": "RunString[==[net.ReadString()]==]" + NL,

        "no_parens_spaced": 'RunString  "net.ReadString()"' + NL,

        "no_parens_at_file_start": 'RunString[[x]]' + NL + "local rest = 1" + NL,

        "fake_long_open": "--[=" + NL + PAYLOAD + NL,

        "crlf": "-- comment" + chr(13) + NL + PAYLOAD + chr(13) + NL,

        "cr_only_comment": "-- comment" + CR + PAYLOAD + CR,

        "cr_only_plain": PAYLOAD + CR,

        "cr_only_string": 'local s = "open' + CR + PAYLOAD + CR,

        "cr_mixed_with_lf": "-- a" + CR + "-- b" + NL + PAYLOAD + NL,

        "no_trailing_newline": "--[[ x ]]" + PAYLOAD,

        "nul_bytes": "local x = 1" + chr(0) * 3 + NL + PAYLOAD + NL,

        "utf8_bom": chr(0xFEFF) + PAYLOAD + NL,
    }


def lua_name_disguises():
    """The name of the call is hidden rather than the code around it.

    Each entry must still be reported as CRITICAL. Which rule fires is not fixed
    here on purpose: the point is that the file does not get through quietly.
    """
    return {
        # The same name built in ways the folder did not read: a different
        # number base, a Unicode escape, a table joined back together.
        "char_hex": 'local f = _G[string.char(0x52,0x75,0x6e,0x53,0x74,0x72,0x69,0x6e,0x67)]'
                    + NL + 'f("net.ReadString()")' + NL,

        "char_float": 'local f = _G[string.char(82.0,117.0,110.0,83.0,116.0,114.0,105.0,110.0,103.0)]'
                      + NL + 'f("net.ReadString()")' + NL,

        "unicode_escape": 'local f = _G["' + BS + 'u{52}' + BS + 'u{75}' + BS + 'u{6e}' + BS
                          + 'u{53}' + BS + 'u{74}' + BS + 'u{72}' + BS + 'u{69}' + BS + 'u{6e}'
                          + BS + 'u{67}"]' + NL + 'f("net.ReadString()")' + NL,

        "table_concat": 'local f = _G[table.concat({"R","u","n","S","t","r","i","n","g"})]'
                        + NL + 'f("net.ReadString()")' + NL,

        "table_concat_sep": 'local f = _G[table.concat({"Run","String"}, "")]'
                            + NL + 'f("net.ReadString()")' + NL,

        "name_global_table": '_G["RunString"](net.ReadString())' + NL,

        "name_alias": "local rs = RunString" + NL + "rs(net.ReadString())" + NL,

        "name_table_field": "local t = { go = RunString }" + NL + "t.go(net.ReadString())" + NL,

        "name_rebuilt": 'local n = ("RunXtring"):gsub("X", "S")' + NL +
                        "_G[n](net.ReadString())" + NL,

        "name_environment": 'local f = getfenv(0)["Run" .. "String"]' + NL +
                            "f(net.ReadString())" + NL,

        "name_registry": 'local f = _R["RunString"]' + NL + "f(payload)" + NL,

        "name_charcode": "local f = _G[string.char("
                         + ",".join(str(ord(c)) for c in "RunString")
                         + ")]" + NL + "f(net.ReadString())" + NL,

        "name_charcode_padded": "local f = _G[string.char("
                                + ",".join("%04d" % ord(c) for c in "RunString")
                                + ")]" + NL + "f(net.ReadString())" + NL,
    }

def lua_not_code():
    """Source that Lua itself never executes. These must stay unreported."""
    return {
        "level_mismatch": "--[==[" + NL + "]]" + NL + PAYLOAD + NL + "--]==]" + NL,
        "line_comment": "-- " + PAYLOAD + NL,
        "long_comment": "--[[" + NL + PAYLOAD + NL + "]]" + NL,
    }


def main():
    scanner = Path(sys.argv[1]).resolve()
    rules = Path(sys.argv[2]).resolve()
    failures = []
    checks = 0

    with tempfile.TemporaryDirectory(prefix="bdscan-evasion-") as temporary:
        work = Path(temporary)
        ruledir = work / "rules"
        ruledir.mkdir()
        for name in ("lua_patterns.txt", "binary_patterns.txt", "data_patterns.txt", "module_patterns.txt", "composite_rules.txt",
                     "known_hashes.txt"):
            shutil.copy(rules / name, ruledir / name)
        (ruledir / "whitelist.txt").write_text("*/addons/trusted/*" + NL, encoding="utf-8")

        tree = work / "tree"
        tree.mkdir()

        for name, body in lua_disguises().items():
            io.open(tree / (name + ".lua"), "w", encoding="utf-8", newline="").write(body)
        for name, body in lua_name_disguises().items():
            io.open(tree / (name + ".lua"), "w", encoding="utf-8", newline="").write(body)
        for name, body in lua_not_code().items():
            io.open(tree / ("quiet_" + name + ".lua"), "w", encoding="utf-8", newline="").write(body)

        hostile = PAYLOAD.encode() + b"\n"
        archives = {
            "entry_traversal": "../addons/trusted/x.lua",
            "entry_absolute": "/addons/trusted/x.lua",
            "entry_nested_traversal": "lua/../../addons/trusted/x.lua",
            "entry_drive_letter": "C:/addons/trusted/x.lua",
            "entry_plain_lookalike": "addons/trusted/x.lua",
            "entry_backslashes": BS.join(["lua", "autorun", "x.lua"]),
        }
        for name, entry in archives.items():
            (tree / (name + ".gma")).write_bytes(gma([(entry, hostile)]))

        (tree / "compressed.gma").write_bytes(
            lzma.compress(gma([("lua/x.lua", hostile)]), format=lzma.FORMAT_ALONE))

        (tree / "nested.gma").write_bytes(gma([
            ("lua/inner.gma", gma([("lua/x.lua", hostile)])),
            ("data/filler.dat", b"\0" * 32),
        ]))

        (tree / "native.gma").write_bytes(gma([
            ("lua/bin/gmsv_hidden_win64.dll", b"MZ\x90\x00 native payload"),
        ]))

        output = work / "out"
        output.mkdir()
        result = subprocess.run(
            [str(scanner), "--rules", str(ruledir), "-d", str(tree), "-o", str(output), "-q"],
            capture_output=True, text=True)
        if result.returncode not in (1, 3):
            print("evasion: scanner exited " + str(result.returncode))
            print(result.stdout)
            print(result.stderr)
            return 1

        data = json.loads((output / "scan_log.json").read_text(encoding="utf-8"))
        reported = {}
        for item in data["detections"]:
            path = item["file"].replace(BS, "/")
            stem = path.split("/tree/")[-1].split("/")[0]
            reported.setdefault(stem, set()).add(item["id"])

        for name in lua_disguises():
            checks += 1
            if "LUA-001" not in reported.get(name + ".lua", set()):
                failures.append(name + ".lua hid the payload from LUA-001")

        severities = {}
        for item in data["detections"]:
            path = item["file"].replace(BS, "/")
            stem = path.split("/tree/")[-1].split("/")[0]
            severities.setdefault(stem, set()).add(item["severity"])

        for name in lua_name_disguises():
            checks += 1
            if "critical" not in severities.get(name + ".lua", set()):
                failures.append(name + ".lua hid the call behind a name, nothing critical reported")

        for name in lua_not_code():
            checks += 1
            if reported.get("quiet_" + name + ".lua"):
                failures.append("quiet_" + name + ".lua reported code Lua never runs: "
                                + ", ".join(sorted(reported["quiet_" + name + ".lua"])))

        for name in archives:
            checks += 1
            if "LUA-001" not in reported.get(name + ".gma", set()):
                failures.append(name + ".gma hid the payload from LUA-001")

        checks += 1
        if "LUA-001" not in reported.get("compressed.gma", set()):
            failures.append("compressed.gma was not decompressed and scanned")

        checks += 1
        if "LUA-001" not in reported.get("nested.gma", set()):
            failures.append("nested.gma hid its payload one archive deeper")

        checks += 1
        if "MOD-001" not in reported.get("native.gma", set()):
            failures.append("native.gma hid a binary module that would be reported on disk")

        checks += 1
        if data["whitelisted"] != 0:
            failures.append("a name chosen inside an archive satisfied a path whitelist ("
                            + str(data["whitelisted"]) + " suppressed)")

        for name in ("entry_traversal", "entry_absolute",
                     "entry_nested_traversal", "entry_drive_letter"):
            checks += 1
            if "GMA-001" not in reported.get(name + ".gma", set()):
                failures.append(name + ".gma escaped its archive without being reported")

        for item in data["detections"]:
            if ".." in item["file"]:
                failures.append("a reported path still contains .. : " + item["file"])

    if failures:
        print("evasion: " + str(len(failures)) + " of " + str(checks) + " checks failed")
        for failure in failures:
            print("  " + failure)
        return 1

    print("evasion: " + str(checks) + " disguises defeated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
