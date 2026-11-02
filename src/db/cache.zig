const std = @import("std");

const dns = @import("dns");

pub const CacheKey = struct {
    name: []const u8,
    record: dns.Record,
};

pub const CacheKeyContext = struct {
    seed: u64,

    pub fn hash(self: @This(), key: CacheKey) u64 {
        var hasher = std.hash.Wyhash.init(self.seed);

        hasher.update(key.name);
        std.hash.autoHash(&hasher, @as(u16, @backingInt(key.record)));

        return hasher.final();
    }

    pub fn eql(_: @This(), a: CacheKey, b: CacheKey) bool {
        return a.record == b.record and std.mem.eql(u8, a.name, b.name);
    }
};

pub const CacheResult = union(enum) {
    nodata,
    nxdomain,
    answers: []dns.Answer,
};

pub const PositiveEntry = struct {
    answers: std.ArrayList(dns.Answer),
    expires_at: i64,
};

pub const NegativeStatus = enum {
    nodata,
    nxdomain,
};

pub const NegativeEntry = struct {
    status: NegativeStatus,
    expires_at: i64,
};

pub const PositiveMap = std.HashMap(CacheKey, PositiveEntry, CacheKeyContext, std.hash_map.default_max_load_percentage);
pub const NegativeMap = std.HashMap(CacheKey, NegativeEntry, CacheKeyContext, std.hash_map.default_max_load_percentage);

pub const Cache = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    mutex: std.Io.RwLock,

    positive_entries: PositiveMap,
    negative_entries: NegativeMap,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, seed: u64) Cache {
        return .{
            .io = io,
            .allocator = allocator,
            .mutex = .init,
            .positive_entries = PositiveMap.initContext(allocator, .{ .seed = seed }),
            .negative_entries = NegativeMap.initContext(allocator, .{ .seed = seed }),
        };
    }

    pub fn deinit(self: *Cache) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        var pos_it = self.positive_entries.iterator();
        while (pos_it.next()) |entry| {
            for (entry.value_ptr.answers.items) |answer| {
                self.allocator.free(answer.raw_data);
            }

            entry.value_ptr.answers.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.name);
        }

        self.positive_entries.deinit();

        var neg_it = self.negative_entries.iterator();
        while (neg_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.name);
        }

        self.negative_entries.deinit();
    }

    pub fn delete(self: *Cache, name: []const u8, record: dns.Record) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const pos = self.delete_positive_locked(name, record);
        const neg = self.delete_negative_locked(name, record);

        return pos or neg;
    }

    fn delete_positive_locked(self: *Cache, name: []const u8, record: dns.Record) bool {
        const key = CacheKey{ .name = name, .record = record };
        const kv = self.positive_entries.fetchRemove(key) orelse {
            return false;
        };

        for (kv.value.answers.items) |answer| {
            self.allocator.free(answer.raw_data);
        }

        var answers = kv.value.answers;

        answers.deinit(self.allocator);
        self.allocator.free(kv.key.name);

        return true;
    }

    fn delete_negative_locked(self: *Cache, name: []const u8, record: dns.Record) bool {
        const key = CacheKey{ .name = name, .record = record };
        const kv = self.negative_entries.fetchRemove(key) orelse {
            return false;
        };

        self.allocator.free(kv.key.name);

        return true;
    }

    pub fn get(self: *Cache, name: []const u8, record: dns.Record) !?CacheResult {
        self.mutex.lockSharedUncancelable(self.io);
        defer self.mutex.unlockShared(self.io);

        const key = CacheKey{ .name = name, .record = record };
        const now = std.Io.Timestamp.now(self.io, .real).toSeconds();

        if (self.positive_entries.get(key)) |pos_entry| {
            if (now >= pos_entry.expires_at) {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);

                _ = self.delete_positive_locked(name, record);

                return null;
            }

            const duped = try self.allocator.alloc(dns.Answer, pos_entry.answers.items.len);
            errdefer self.allocator.free(duped);

            var count: usize = 0;
            errdefer {
                for (duped[0..count]) |item| {
                    self.allocator.free(item.raw_data);
                }
            }

            for (pos_entry.answers.items, 0..) |item, i| {
                const owned_value = try self.allocator.dupe(u8, item.raw_data);
                duped[i] = item;
                duped[i].raw_data = owned_value;
                count += 1;
            }

            return .{ .answers = duped };
        }

        if (self.negative_entries.get(key)) |neg_entry| {
            if (now >= neg_entry.expires_at) {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);

                _ = self.delete_negative_locked(name, record);

                return null;
            }

            return switch (neg_entry.status) {
                .nodata => .nodata,
                .nxdomain => .nxdomain,
            };
        }

        return null;
    }

    pub fn put_negative(self: *Cache, name: []const u8, record: dns.Record, status: NegativeStatus, ttl: u32) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        _ = self.delete_positive_locked(name, record);

        const now = std.Io.Timestamp.now(self.io, .real).toSeconds();
        const key = CacheKey{ .name = name, .record = record };

        const result = try self.negative_entries.getOrPut(key);

        if (!result.found_existing) {
            const owned_name = self.allocator.dupe(u8, name) catch |err| {
                self.negative_entries.removeByPtr(result.key_ptr);
                return err;
            };

            result.key_ptr.* = .{ .name = owned_name, .record = record };
        }

        result.value_ptr.status = status;
        result.value_ptr.expires_at = now + @as(i64, @intCast(ttl));
    }

    pub fn put_slice(self: *Cache, name: []const u8, record: dns.Record, answers: []const dns.Answer) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        _ = self.delete_negative_locked(name, record);

        const now = std.Io.Timestamp.now(self.io, .real).toSeconds();
        const key = CacheKey{ .name = name, .record = record };

        const result = try self.positive_entries.getOrPut(key);

        if (result.found_existing) {
            for (result.value_ptr.answers.items) |answer| {
                self.allocator.free(answer.raw_data);
            }

            result.value_ptr.answers.clearRetainingCapacity();
        }

        if (!result.found_existing) {
            const owned_name = self.allocator.dupe(u8, name) catch |err| {
                self.positive_entries.removeByPtr(result.key_ptr);
                return err;
            };

            result.key_ptr.* = .{ .name = owned_name, .record = record };
            result.value_ptr.answers = .empty;
        }

        var min_ttl: u32 = std.math.maxInt(u32);

        for (answers) |answer| {
            const owned_value = try self.allocator.dupe(u8, answer.raw_data);
            errdefer self.allocator.free(owned_value);

            var cached = answer;
            cached.name = &[_]u8{ 0xc0, 0x0c };
            cached.raw_data = owned_value;

            try result.value_ptr.answers.append(self.allocator, cached);

            if (answer.ttl < min_ttl) {
                min_ttl = answer.ttl;
            }
        }

        result.value_ptr.expires_at = now + @as(i64, @intCast(min_ttl));
    }
};
