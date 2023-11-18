# boringssl
[![BoringSSL Builder](https://github.com/crispy-strawberry/boringssl/actions/workflows/ci.yml/badge.svg)](https://github.com/crispy-strawberry/boringssl/actions/workflows/ci.yml)

BoringSSL ported to the zig build system. 
Builds for Linux, MacOS and Windows. (You can get binaries for windows, linux and macos
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

## Note for Users
While I try to manually pull from source every now and then, it is clear that
I will probably forget about it at some point of time.
However, the `build.zig` would still remain useful as it does not hardcode any
paths (those that are currently present are left over relics). So, just clone
`google/boringssl`, switch to `main-with-bazel` branch and copy the `build.zig`
to the respository root. Run `zig build` and enjoy!
