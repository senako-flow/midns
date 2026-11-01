const std = @import("std");

const router = @import("router");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const pg_url = "postgresql://username:password@localhost:5432/database_name";

    var r = try router.Listener.new(gpa, io, pg_url, "0.0.0.0", 1153);
    defer r.deinit();

    try r.serve(0);
}
