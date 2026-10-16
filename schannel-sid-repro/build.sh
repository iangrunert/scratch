#!/bin/sh
# Cross-build from Linux with mingw-w64 (apt install mingw-w64).
set -e
CC=${CC:-x86_64-w64-mingw32-gcc}
CFLAGS="-O2 -Wall -Wextra -Wno-unused-parameter"
$CC $CFLAGS -o schantest.exe schantest.c -lsecur32 -lcrypt32 -lws2_32 -ladvapi32
$CC $CFLAGS -o runrestricted.exe runrestricted.c childio.c -ladvapi32
$CC $CFLAGS -o runappcontainer.exe runappcontainer.c childio.c -luserenv -ladvapi32 -lole32
echo "Built schantest.exe, runrestricted.exe and runappcontainer.exe"
