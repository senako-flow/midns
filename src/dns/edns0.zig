const std = @import("std");

const dns = @import("_.zig");

pub const Edns0 = struct {
    size: u16,
    rcode: u8,
    version: u8,
    dnssec_ok: bool,
    options: []const u8,

    pub const Error = error{
        InvalidLength,
        InvalidName,
        NotOptRecord,
        RdlenMismatch,
        TrailingGarbage,
    };

    pub fn decode(v: []const u8) Error!Edns0 {
        if (v.len < 11) {
            return Error.InvalidLength;
        }

        if (v[0] != 0) {
            return Error.InvalidName;
        }

        const record: dns.Record = @fromBackingInt(@intCast(std.mem.readInt(u16, v[1..3], .big)));
        if (record != .OPT) {
            return Error.NotOptRecord;
        }

        const size = std.mem.readInt(u16, v[3..5], .big);
        const rcode = v[5];
        const version = v[6];
        const flags = std.mem.readInt(u16, v[7..9], .big);
        const rdlen: usize = @intCast(std.mem.readInt(u16, v[9..11], .big));

        if (v.len < 11 + rdlen) {
            return Error.RdlenMismatch;
        }

        if (v.len > 11 + rdlen) {
            return Error.TrailingGarbage;
        }

        var dnssec_ok = false;
        if ((flags & 0x8000) != 0) {
            dnssec_ok = true;
        }

        const options = v[11..][0..rdlen];

        return .{
            .size = @max(size, 512),
            .rcode = rcode,
            .version = version,
            .dnssec_ok = dnssec_ok,
            .options = options,
        };
    }

    pub fn encode(self: Edns0, writer: *std.Io.Writer) !void {
        var buffer: [11]u8 = undefined;

        var flags: u16 = 0;
        if (self.dnssec_ok) {
            flags = 0x8000;
        }

        buffer[0] = 0;
        std.mem.writeInt(u16, buffer[1..3], @backingInt(dns.Record.OPT), .big);
        std.mem.writeInt(u16, buffer[3..5], self.size, .big);
        buffer[5] = self.rcode;
        buffer[6] = self.version;
        std.mem.writeInt(u16, buffer[7..9], flags, .big);
        std.mem.writeInt(u16, buffer[9..11], @intCast(self.options.len), .big);

        try writer.writeAll(&buffer);
        try writer.writeAll(self.options);
    }
};
