const std = @import("std");

const boringssl_source = struct {
    bcm_crypto: []const []const u8,
    crypto: []const []const u8,
    crypto_asm: []const []const u8,
    crypto_headers: []const []const u8,
    crypto_internal_headers: []const []const u8,
    crypto_nasm: []const []const u8,
    crypto_test: []const []const u8,
    crypto_test_data: []const []const u8,
    fips_fragments: []const []const u8,
    fuzz: []const []const u8,
    pki: []const []const u8,
    pki_internal_headers: []const []const u8,
    pki_test: []const []const u8,
    pki_test_data: []const []const u8,
    ssl: []const []const u8,
    ssl_headers: []const []const u8,
    ssl_internal_headers: []const []const u8,
    ssl_test: []const []const u8,
    test_support: []const []const u8,
    test_support_headers: []const []const u8,
    tool: []const []const u8,
    tool_headers: []const []const u8,
    urandom_test: []const []const u8,
};

pub fn build(b: *std.Build) !void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});
    const @"asm" = b.option(bool, "asm", "Specify whether to use asm or not. Not using asm comes at a huge performance penalty.") orelse true;

    const upstream = b.dependency("boring_upstream", .{});

    const sources_json = upstream.path("sources.json").getPath(b);

    const file = try std.fs.cwd().openFile(sources_json, .{});
    defer file.close();

    const source_str = try file.readToEndAlloc(b.allocator, 4294967296);
    defer b.allocator.free(source_str);

    const source_files = (try std.json.parseFromSlice(boringssl_source, b.allocator, source_str, .{})).value;

    // b.installDirectory(.{ .source_dir = upstream.path("src/include"), .install_dir = .prefix, .install_subdir = "include" });

    _ = b.addModule("boringssl", .{ .source_file = .{ .path = "boringssl.zig" } });

    const crypto_static_lib = b.addStaticLibrary(.{
        .name = "crypto_static",
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(crypto_static_lib);
    crypto_static_lib.installHeadersDirectoryOptions(.{
        .source_dir = upstream.path("src/include"),
        .install_dir = .header,
        .install_subdir = "",
        .include_extensions = &.{".h"},
    });
    crypto_static_lib.linkLibC();

    if (target.isLinux()) {
        crypto_static_lib.defineCMacroRaw("_XOPEN_SOURCE=700");
    } else if (target.isDarwin() and target.getCpuArch() == .aarch64) {
        crypto_static_lib.defineCMacro("__ARM_NEON", null);
        crypto_static_lib.defineCMacro("__ARM_FEATURE_CRYPTO", null);
    } else if (target.isWindows()) {
        crypto_static_lib.defineCMacro("_HAS_EXCEPTIONS", "0");
        crypto_static_lib.defineCMacro("WIN32_LEAN_AND_MEAN", null);
        crypto_static_lib.defineCMacro("NOMINMAX", null);
        crypto_static_lib.defineCMacro("_CRT_SECURE_NO_WARNINGS", null);
        crypto_static_lib.defineCMacro("strdup", "_strdup");
        crypto_static_lib.linkSystemLibrary("ws2_32");
    }
    crypto_static_lib.defineCMacro("BORINGSSL_IMPLEMENTATION", null);
    if (!@"asm") {
        crypto_static_lib.defineCMacro("OPENSSL_NO_ASM", null);
    }
    crypto_static_lib.addIncludePath(upstream.path("src/include"));
    if (@"asm") {
        for (source_files.crypto_asm) |asm_src| {        
            crypto_static_lib.addCSourceFile(.{
                .file = .{ .path = upstream.path(asm_src).getPath(b) },
                .flags = &.{
                    "-fvisibility=hidden",
                    "-fno-common",
                },
            });
        }
    }
    for (source_files.crypto) |src| {
        crypto_static_lib.addCSourceFile(.{
            .file = .{ .path = upstream.path(src).getPath(b) },
            .flags = &.{
                "-fvisibility=hidden",
                "-fno-common",
            },
        });
    }

    const crypto_shared_lib = b.addSharedLibrary(.{
        .name = "crypto_shared",
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(crypto_shared_lib);

    crypto_shared_lib.installHeadersDirectoryOptions(.{
        .source_dir = upstream.path("src/include"),
        .install_dir = .header,
        .install_subdir = "",
        .include_extensions = &.{".h"},
    });
    crypto_shared_lib.linkLibC();
    if (target.isLinux()) {
        crypto_shared_lib.defineCMacroRaw("_XOPEN_SOURCE=700");
    } else if (target.isDarwin() and target.getCpuArch() == .aarch64) {
        crypto_shared_lib.defineCMacro("__ARM_NEON", null);
        crypto_shared_lib.defineCMacro("__ARM_FEATURE_CRYPTO", null);
    } else if (target.isWindows()) {
        crypto_shared_lib.defineCMacro("_HAS_EXCEPTIONS", "0");
        crypto_shared_lib.defineCMacro("WIN32_LEAN_AND_MEAN", null);
        crypto_shared_lib.defineCMacro("NOMINMAX", null);
        crypto_shared_lib.defineCMacro("_CRT_SECURE_NO_WARNINGS", null);
        crypto_shared_lib.defineCMacro("strdup", "_strdup");
        crypto_shared_lib.linkSystemLibrary("ws2_32");
    }

    crypto_shared_lib.defineCMacro("BORINGSSL_IMPLEMENTATION", null);
    crypto_shared_lib.defineCMacro("BORINGSSL_SHARED_LIBRARY", null);
    if (!@"asm") {
        crypto_shared_lib.defineCMacro("OPENSSL_NO_ASM", null);
    }
    crypto_shared_lib.addIncludePath(upstream.path("src/include"));
    if (@"asm") {
        for (source_files.crypto_asm) |asm_src| {
            crypto_shared_lib.addCSourceFile(.{
                .file = .{ .path = upstream.path(asm_src).getPath(b) },
                .flags = &.{
                    "-fvisibility=hidden",
                    "-fno-common",
                },
            });
        }
    }
    for (source_files.crypto) |src| {
        crypto_shared_lib.addCSourceFile(.{
            .file = .{ .path = upstream.path(src).getPath(b) },
            .flags = &.{
                "-fvisibility=hidden",
                "-fno-common",
            },
        });
    }

    const ssl_static_lib = b.addStaticLibrary(.{
        .name = "ssl_static",
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(ssl_static_lib);
    ssl_static_lib.linkLibC();
    if (!target.isWindows()) {
        ssl_static_lib.linkLibCpp();
    } else {
        ssl_static_lib.defineCMacro("_HAS_EXCEPTIONS", "0");
        ssl_static_lib.defineCMacro("WIN32_LEAN_AND_MEAN", null);
        ssl_static_lib.defineCMacro("NOMINMAX", null);
        ssl_static_lib.defineCMacro("_CRT_SECURE_NO_WARNINGS", null);
        ssl_static_lib.defineCMacro("strdup", "_strdup");
        ssl_static_lib.linkSystemLibrary("ws2_32");
    }
    ssl_static_lib.defineCMacro("BORINGSSL_IMPLEMENTATION", null);
    ssl_static_lib.linkLibrary(crypto_static_lib);
    ssl_static_lib.addIncludePath(upstream.path("src/include"));

    ssl_static_lib.installHeadersDirectoryOptions(.{
        .source_dir = upstream.path("src/include"),
        .install_dir = .header,
        .install_subdir = "",
        .include_extensions = &.{".h"},
    });

    for (source_files.ssl) |src| {
        ssl_static_lib.addCSourceFile(.{ 
            .file = .{ .path = upstream.path(src).getPath(b) }, 
            .flags = &.{
            "-fvisibility=hidden",
            "-fno-common",
            "-fno-exceptions",
            "-fno-rtti",
        } });
    }

    const ssl_shared_lib = b.addSharedLibrary(.{
        .name = "ssl_shared",
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(ssl_shared_lib);

    ssl_shared_lib.linkLibC();
    if (!target.isWindows()) {
        ssl_shared_lib.linkLibCpp();
    } else {
        ssl_shared_lib.defineCMacro("_HAS_EXCEPTIONS", "0");
        ssl_shared_lib.defineCMacro("WIN32_LEAN_AND_MEAN", null);
        ssl_shared_lib.defineCMacro("NOMINMAX", null);
        ssl_shared_lib.defineCMacro("_CRT_SECURE_NO_WARNINGS", null);
        ssl_shared_lib.defineCMacro("strdup", "_strdup");
        ssl_shared_lib.linkSystemLibrary("ws2_32");
    }
    ssl_shared_lib.defineCMacro("BORINGSSL_IMPLEMENTATION", null);
    ssl_shared_lib.defineCMacro("BORINGSSL_SHARED_LIBRARY", null);

    ssl_shared_lib.linkLibrary(crypto_static_lib);
    ssl_shared_lib.addIncludePath(upstream.path("src/include"));

    ssl_shared_lib.installHeadersDirectoryOptions(.{
        .source_dir = upstream.path("src/include"),
        .install_dir = .header,
        .install_subdir = "",
        .include_extensions = &.{".h"},
    });

    for (source_files.ssl) |src| {
        ssl_shared_lib.addCSourceFile(.{ .file = .{ .path = upstream.path(src).getPath(b) }, .flags = &.{
            "-fvisibility=hidden",
            "-fno-common",
            "-fno-exceptions",
            "-fno-rtti",
        } });
    }

    const bssl = b.addExecutable(.{
        .name = "bssl",
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(bssl);
    bssl.linkLibC();
    if (!target.isWindows()) {
        bssl.linkLibCpp();
    } else {
        bssl.defineCMacro("_HAS_EXCEPTIONS", "0");
        bssl.defineCMacro("WIN32_LEAN_AND_MEAN", null);
        bssl.defineCMacro("NOMINMAX", null);
        bssl.defineCMacro("_CRT_SECURE_NO_WARNINGS", null);
        bssl.defineCMacro("strdup", "_strdup");
        bssl.linkSystemLibrary("ws2_32");
    }
    bssl.defineCMacro("BORINGSSL_IMPLEMENTATION", null);
    bssl.linkLibrary(crypto_static_lib);
    bssl.linkLibrary(ssl_static_lib);
    bssl.addIncludePath(upstream.path("src/include"));
    bssl.addIncludePath(upstream.path("src/tool"));
    for (source_files.tool) |src| {
        bssl.addCSourceFile(.{ 
            .file = .{ .path = upstream.path(src).getPath(b) },
            .flags = &.{
            "-fvisibility=hidden",
            "-fno-common",
            "-fno-exceptions",
            "-fno-rtti",
        } });
    }
}
