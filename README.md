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

## Using with package manager
1. Create `build.zig.zon` in the project root if you don't already have one.
2. Add the barebones skeleton. ([this](https://pastebin.com/Kkf6KfRi) if you don't know what it looks like)
3. Inside the dependencies section add -
  ```
  .string = .{
    .url = "git+https://github.com/crispy-strawberry/boringssl#pkg-manager",
  }
  ```
4. Run `zig build` and wait for zig to complain about the hash
5. Copy the provided hash and add it besides the url like -
  ```
  .boringssl = .{
    .url = "<repo url>",
    .hash = "<the provided hash>"
  }
  ```
6. In your `build.zig`, add -
  ```zig
  const boringssl = b.dependency("boringssl", .{ .optimize = optimize, .target = target });

  // Replace exe with whatever you are using.
  exe.addModule("boringssl", boringssl.module("boringssl"));

  // use "crypto_shared" if you want to link against dynamic library
  exe.linkLibrary(boringssl.artifact("crypto_static")); 
  ```
7. Now, in your source files, you can use `String` by-
  ```zig
  const boringssl = @import("boringssl");
  ```
8. Enjoy :)

## Note for Users
While I try to manually pull from source every now and then, it is clear that
I will probably forget about it at some point of time.
However, the `build.zig` would still remain useful as it does not hardcode any
paths (those that are currently present are left over relics). So, just clone
`google/boringssl`, switch to `main-with-bazel` branch and copy the `build.zig`
to the respository root. Run `zig build` and enjoy!
