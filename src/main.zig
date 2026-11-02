const std = @import("std");

const config = @import("config");
const router = @import("router");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    var cfg = try config.Loader.init(gpa, io, "./config.toml");
    defer cfg.deinit();

    var r = try router.Listener.new(gpa, io, cfg.parsed.value);
    defer r.deinit();

    try r.serve(0);
}
