const std = @import("std");

const toml = @import("toml");
const config = @import("_.zig");

pub const Loader = struct {
    parser: toml.Parser(config.Config),
    parsed: toml.Parsed(config.Config),

    pub fn init(allocator: std.mem.Allocator, io: std.Io, filename: []const u8) !Loader {
        var parser = toml.Parser(config.Config).init(allocator);
        const parsed = try parser.parseFile(io, filename);

        return .{
            .parser = parser,
            .parsed = parsed,
        };
    }

    pub fn deinit(self: *Loader) void {
        self.parser.deinit();
        self.parsed.deinit();
    }
};
