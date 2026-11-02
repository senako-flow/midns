const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSafe,
    });

    const pg_module = b.dependency("pg", .{}).module("pg");

    const toml_module = b.dependency("toml", .{}).module("toml");

    const config = b.addModule("config", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/config/_.zig"),
        .imports = &.{
            .{ .name = "toml", .module = toml_module },
        },
    });

    const dns = b.addModule("dns", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/dns/_.zig"),
    });

    const db = b.addModule("db", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/db/_.zig"),
        .imports = &.{
            .{ .name = "dns", .module = dns },
            .{ .name = "pg", .module = pg_module },
        },
    });

    const router = b.addModule("router", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/router/_.zig"),
        .imports = &.{
            .{ .name = "db", .module = db },
            .{ .name = "dns", .module = dns },
            .{ .name = "config", .module = config },
        },
    });

    const exe = b.addExecutable(.{
        .name = "midns",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("src/main.zig"),
            .imports = &.{
                .{ .name = "db", .module = db },
                .{ .name = "router", .module = router },
                .{ .name = "config", .module = config },
            },
        }),
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    run_cmd.addPassthruArgs();
}
