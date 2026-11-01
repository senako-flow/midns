const std = @import("std");

const pg = @import("pg");
const dns = @import("dns");

pub const Postgre = struct {
    io: std.Io,
    allocator: std.mem.Allocator,

    pool: *pg.Pool,

    pub const Error = error{
        NxDomain,
        NameExists,
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io, pg_url: []const u8) !Postgre {
        const uri = try std.Uri.parse(pg_url);

        const size: usize = std.Thread.getCpuCount() catch 16;

        const pool = try pg.Pool.initUri(io, allocator, uri, .{
            .size = @intCast(size),
        });

        return .{
            .io = io,
            .allocator = allocator,
            .pool = pool,
        };
    }

    pub fn deinit(self: *Postgre) void {
        self.pool.deinit();
    }

    pub fn get(self: *Postgre, name: []const u8, record: dns.Record) ![]dns.Answer {
        if (try self.fetch_records(name, record)) |answers| {
            return answers;
        }

        var exists = try self.pool.query("SELECT 1 FROM records WHERE name = $1 LIMIT 1", .{name});
        defer exists.deinit();

        if (try exists.next()) |_| {
            return Error.NameExists;
        }

        return Error.NxDomain;
    }

    fn fetch_records(self: *Postgre, name: []const u8, record: dns.Record) !?[]dns.Answer {
        var result = try self.pool.query("SELECT ttl, raw_data FROM records WHERE name = $1 AND record = $2", .{ name, @as(i32, @intCast(@backingInt(record))) });
        defer result.deinit();

        var list: std.ArrayList(dns.Answer) = .empty;
        errdefer {
            for (list.items) |item| {
                self.allocator.free(item.raw_data);
            }

            list.deinit(self.allocator);
        }

        while (try result.next()) |row| {
            const ttl = try row.get(i32, 0);
            const raw_data = try row.get([]const u8, 1);

            const duped_raw = try self.allocator.dupe(u8, raw_data);
            errdefer self.allocator.free(duped_raw);

            try list.append(self.allocator, .{
                .ttl = @intCast(ttl),
                .name = &[_]u8{ 0xc0, 0x0c },
                .class = .IN,
                .record = record,
                .raw_data = duped_raw,
            });
        }

        if (list.items.len == 0) {
            list.deinit(self.allocator);
            return null;
        }

        return try list.toOwnedSlice(self.allocator);
    }
};
