const std = @import("std");

const dns = @import("_.zig");

pub const Flags = struct {
    qr: dns.QR,
    opcode: dns.Opcode,
    aa: dns.AA,
    tc: dns.TC,
    rd: dns.RD,
    ra: dns.RA,
    z: u3,
    rcode: dns.Rcode,

    pub fn decode(v: u16) Flags {
        const qr: u1 = @truncate(v >> 15);
        const op: u4 = @truncate(v >> 11);
        const aa: u1 = @truncate(v >> 10);
        const tc: u1 = @truncate(v >> 9);
        const rd: u1 = @truncate(v >> 8);
        const ra: u1 = @truncate(v >> 7);
        const z: u3 = @truncate(v >> 4);
        const rc: u4 = @truncate(v);

        return .{
            .qr = @fromBackingInt(@intCast(qr)),
            .opcode = @fromBackingInt(@intCast(op)),
            .aa = @fromBackingInt(@intCast(aa)),
            .tc = @fromBackingInt(@intCast(tc)),
            .rd = @fromBackingInt(@intCast(rd)),
            .ra = @fromBackingInt(@intCast(ra)),
            .z = z,
            .rcode = @fromBackingInt(@intCast(rc)),
        };
    }

    pub fn encode(self: Flags) u16 {
        const qr: u16 = @intCast(@backingInt(self.qr));
        const op: u16 = @intCast(@backingInt(self.opcode));
        const aa: u16 = @intCast(@backingInt(self.aa));
        const tc: u16 = @intCast(@backingInt(self.tc));
        const rd: u16 = @intCast(@backingInt(self.rd));
        const ra: u16 = @intCast(@backingInt(self.ra));
        const z: u16 = @intCast(self.z);
        const rc: u16 = @intCast(@backingInt(self.rcode));

        return qr << 15 | op << 11 | aa << 10 | tc << 9 | rd << 8 | ra << 7 | z << 4 | rc;
    }
};

pub const Header = struct {
    id: u16,
    flags: Flags,
    qd: u16,
    an: u16,
    ns: u16,
    ar: u16,

    pub fn decode(v: []const u8) Header {
        const id = std.mem.readInt(u16, v[0..2], .big);
        const fl = std.mem.readInt(u16, v[2..4], .big);
        const qd = std.mem.readInt(u16, v[4..6], .big);
        const an = std.mem.readInt(u16, v[6..8], .big);
        const ns = std.mem.readInt(u16, v[8..10], .big);
        const ar = std.mem.readInt(u16, v[10..12], .big);

        return .{
            .id = id,
            .flags = Flags.decode(fl),
            .qd = qd,
            .an = an,
            .ns = ns,
            .ar = ar,
        };
    }

    pub fn encode(self: Header, writer: *std.Io.Writer) !void {
        var buffer: [12]u8 = undefined;

        std.mem.writeInt(u16, buffer[0..2], self.id, .big);
        std.mem.writeInt(u16, buffer[2..4], self.flags.encode(), .big);
        std.mem.writeInt(u16, buffer[4..6], self.qd, .big);
        std.mem.writeInt(u16, buffer[6..8], self.an, .big);
        std.mem.writeInt(u16, buffer[8..10], self.ns, .big);
        std.mem.writeInt(u16, buffer[10..12], self.ar, .big);

        try writer.writeAll(&buffer);
    }
};

pub const Question = struct {
    raw: []const u8,
    class: dns.Class,
    record: dns.Record,

    pub fn decode(v: []const u8) ?Question {
        var i: usize = 0;
        var len: usize = 0;

        while (true) {
            if (i >= v.len) {
                return null;
            }

            const label = v[i];

            if (label > 63) {
                return null;
            }

            i += 1;
            len += 1;

            if (label == 0) {
                break;
            }

            if (len + label > 255) {
                return null;
            }

            if (i + label > v.len) {
                return null;
            }

            i += label;
            len += label;
        }

        if (len + 4 > v.len) {
            return null;
        }

        const record = v[len..][0..2];
        const class = v[len + 2 ..][0..2];

        return .{
            .raw = v[0..len],
            .class = @fromBackingInt(@intCast(std.mem.readInt(u16, class, .big))),
            .record = @fromBackingInt(@intCast(std.mem.readInt(u16, record, .big))),
        };
    }

    pub fn encode(self: Question, writer: *std.Io.Writer) !void {
        var buffer: [4]u8 = undefined;

        std.mem.writeInt(u16, buffer[0..2], @backingInt(self.record), .big);
        std.mem.writeInt(u16, buffer[2..4], @backingInt(self.class), .big);

        try writer.writeAll(self.raw);
        try writer.writeAll(&buffer);
    }

    pub fn get_size(self: Question) usize {
        return self.raw.len + 4;
    }

    pub fn get_name(self: Question, buffer: *[255]u8) []const u8 {
        var out_len: usize = 0;
        var i: usize = 0;

        while (i < self.raw.len) {
            const label = self.raw[i];

            if (label == 0) {
                break;
            }

            i += 1;

            if (out_len > 0 and out_len < buffer.len) {
                buffer[out_len] = '.';
                out_len += 1;
            }

            for (self.raw[i .. i + label]) |c| {
                if (out_len < buffer.len) {
                    buffer[out_len] = std.ascii.toLower(c);
                    out_len += 1;
                }
            }

            i += label;
        }

        return buffer[0..out_len];
    }
};

pub const Answer = struct {
    ttl: u32,
    name: []const u8,
    class: dns.Class,
    record: dns.Record,

    raw_data: []const u8,

    pub fn decode(v: []const u8) ?Answer {
        var offset: usize = 0;

        while (true) {
            if (offset >= v.len) {
                return null;
            }

            const label = v[offset];

            if ((label & 0xc0) == 0xc0) {
                if (offset + 2 > v.len) {
                    return null;
                }

                offset += 2;
                break;
            }

            offset += 1;

            if (label == 0) {
                break;
            }

            if (offset + label > v.len) {
                return null;
            }

            offset += label;
        }

        if (offset + 10 > v.len) {
            return null;
        }

        const record: dns.Record = @fromBackingInt(@intCast(std.mem.readInt(u16, v[offset..][0..2], .big)));
        const class: dns.Class = @fromBackingInt(@intCast(std.mem.readInt(u16, v[offset..][2..4], .big)));

        const ttl = std.mem.readInt(u32, v[offset..][4..8], .big);
        const len = std.mem.readInt(u16, v[offset..][8..10], .big);

        if (offset + 10 + len > v.len) {
            return null;
        }

        const raw_data = v[offset + 10 .. offset + 10 + len];

        return .{
            .ttl = ttl,
            .name = v[0..offset],
            .class = class,
            .record = record,
            .raw_data = raw_data,
        };
    }

    pub fn encode(self: Answer, writer: *std.Io.Writer) !void {
        if (self.raw_data.len > std.math.maxInt(u16)) {
            return error.DataTooLong;
        }

        var buffer: [10]u8 = undefined;

        std.mem.writeInt(u16, buffer[0..2], @backingInt(self.record), .big);
        std.mem.writeInt(u16, buffer[2..4], @backingInt(self.class), .big);
        std.mem.writeInt(u32, buffer[4..8], self.ttl, .big);
        std.mem.writeInt(u16, buffer[8..10], @truncate(self.raw_data.len), .big);

        try writer.writeAll(self.name);
        try writer.writeAll(&buffer);
        try writer.writeAll(self.raw_data);
    }

    pub fn get_size(self: Answer) usize {
        return self.name.len + self.raw_data.len + 10;
    }
};
