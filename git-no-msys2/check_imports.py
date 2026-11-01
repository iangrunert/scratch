"""List the DLL imports of every PE file under a directory and fail if any
of them pull in an MSYS2/Cygwin runtime."""
import pathlib
import sys

import pefile

BAD = ("msys-", "cygwin1.dll", "cyg")
root = pathlib.Path(sys.argv[1])
all_dlls = {}
bad = []
for path in sorted(root.rglob("*")):
    if path.suffix.lower() not in (".exe", ".dll"):
        continue
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    dlls = sorted({e.dll.decode().lower() for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])})
    for d in dlls:
        all_dlls.setdefault(d, []).append(path.relative_to(root).as_posix())
        if d.startswith(BAD):
            bad.append((path, d))

print(f"{'DLL':40} used by")
for d, users in sorted(all_dlls.items()):
    print(f"{d:40} {len(users)} file(s), e.g. {users[0]}")
if bad:
    for p, d in bad:
        print(f"MSYS2/Cygwin runtime import: {p} -> {d}")
    sys.exit(1)
print("No MSYS2/Cygwin runtime imports.")
