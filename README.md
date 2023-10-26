# boringssl
[![BoringSSL Builder](https://github.com/crispy-strawberry/boringssl/actions/workflows/ci.yml/badge.svg)](https://github.com/crispy-strawberry/boringssl/actions/workflows/ci.yml)

BoringSSL ported to the zig build system. 
Builds for Linux, MacOS and Windows. (You can get binaries for linux and windows
in the [build artifacts](https://github.com/crispy-strawberry102938/boringssl/actions))

Uses ASM by default. It can be turned off by passing `-Dasm=false` to
zig build.
Use of `-Dasm=false` drastically reduces the performance of the library.
I would recommend using `-Doptimize=ReleaseFast` if you are turning
asm off.

Curently, for Windows, `-Dasm=false` needs to be passed
as I haven't yet ported the assembly files for msvc.
Also, the target should be `x86_64-windows-msvc` as it
fails due to some reason on `x86_64-windows-gnu`. (not about missing pthread.h)
