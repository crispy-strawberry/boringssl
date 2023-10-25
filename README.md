# boringssl
BoringSSL ported to the zig build system. 
Builds for Linux, MacOS and Windows.

Uses ASM by default. It can be turned off by passing `-Dasm=false` to
zig build.

Curently, for Windows, `-Dasm=false` needs to be passed
as I haven't yet ported the assembly files for msvc.
Also, the target should be `x86_64-windows-msvc` as it
fails due to some reason on `x86_64-windows-gnu`. (not missing pthread.h)
