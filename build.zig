const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSafe,
    });

    const dns = b.addModule("dns", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/dns/_.zig"),
    });

    const router = b.addModule("router", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/router/_.zig"),
        .imports = &.{
            .{ .name = "dns", .module = dns },
        },
    });

    const exe = b.addExecutable(.{
        .name = "midns",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("src/main.zig"),
            .imports = &.{
                .{ .name = "router", .module = router },
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
