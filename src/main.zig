const std = @import("std");
const router = @import("router");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    var r = try router.Listener.new(io, gpa, "0.0.0.0", 1153);
    defer r.deinit();

    try r.serve(0);
}
