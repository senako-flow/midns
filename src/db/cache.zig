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

pub const CacheEntry = struct {
    answers: std.ArrayList(dns.Answer),
    expires_at: i64,
};

pub const CacheMap = std.HashMap(CacheKey, CacheEntry, CacheKeyContext, std.hash_map.default_max_load_percentage);

pub const Cache = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    mutex: std.Io.RwLock,

    entries: CacheMap,
    max_entries: usize,

    pub const default_max_entries: usize = 65536;

    pub fn init(allocator: std.mem.Allocator, io: std.Io, seed: u64) Cache {
        return initWithLimit(allocator, io, seed, default_max_entries);
    }

    pub fn initWithLimit(allocator: std.mem.Allocator, io: std.Io, seed: u64, max_entries: usize) Cache {
        return .{
            .io = io,
            .allocator = allocator,
            .mutex = .init,
            .entries = CacheMap.initContext(allocator, .{ .seed = seed }),
            .max_entries = max_entries,
        };
    }

    pub fn deinit(self: *Cache) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.answers.items) |answer| {
                self.allocator.free(answer.raw_data);
            }

            entry.value_ptr.answers.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.name);
        }

        self.entries.deinit();
    }

    pub fn delete(self: *Cache, name: []const u8, record: dns.Record) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        return self.delete_locked(name, record);
    }

    fn delete_locked(self: *Cache, name: []const u8, record: dns.Record) bool {
        const key = CacheKey{ .name = name, .record = record };
        const kv = self.entries.fetchRemove(key) orelse return false;

        for (kv.value.answers.items) |answer| {
            self.allocator.free(answer.raw_data);
        }

        var answers = kv.value.answers;
        answers.deinit(self.allocator);
        self.allocator.free(kv.key.name);

        return true;
    }

    pub fn get(self: *Cache, name: []const u8, record: dns.Record) !?[]dns.Answer {
        var expired = false;

        inner: {
            self.mutex.lockSharedUncancelable(self.io);
            defer self.mutex.unlockShared(self.io);

            const key = CacheKey{ .name = name, .record = record };
            const entry = self.entries.get(key) orelse {
                return null;
            };

            const now = std.Io.Timestamp.now(self.io, .real).toSeconds();
            if (now >= entry.expires_at) {
                expired = true;
                break :inner;
            }

            const duped = try self.allocator.alloc(dns.Answer, entry.answers.items.len);
            errdefer self.allocator.free(duped);

            var count: usize = 0;
            errdefer {
                for (duped[0..count]) |item| {
                    self.allocator.free(item.raw_data);
                }
            }

            for (entry.answers.items, 0..) |item, i| {
                const owned_value = try self.allocator.dupe(u8, item.raw_data);
                duped[i] = item;
                duped[i].raw_data = owned_value;
                count += 1;
            }

            return duped;
        }

        if (expired) {
            _ = self.delete(name, record);
        }

        return null;
    }

    fn prune_one_locked(self: *Cache, now: i64) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (now >= entry.value_ptr.expires_at) {
                const name = entry.key_ptr.name;
                const rec = entry.key_ptr.record;
                _ = self.delete_locked(name, rec);
                return;
            }
        }

        var reset_it = self.entries.iterator();
        if (reset_it.next()) |entry| {
            const name = entry.key_ptr.name;
            const rec = entry.key_ptr.record;
            _ = self.delete_locked(name, rec);
        }
    }

    pub fn put_slice(self: *Cache, name: []const u8, record: dns.Record, answers: []const dns.Answer) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const now = std.Io.Timestamp.now(self.io, .real).toSeconds();

        const key = CacheKey{ .name = name, .record = record };

        if (!self.entries.contains(key) and self.entries.count() >= self.max_entries) {
            self.prune_one_locked(now);
        }

        const result = try self.entries.getOrPut(key);

        if (result.found_existing) {
            for (result.value_ptr.answers.items) |answer| {
                self.allocator.free(answer.raw_data);
            }

            result.value_ptr.answers.clearRetainingCapacity();
        }

        if (!result.found_existing) {
            const owned_name = self.allocator.dupe(u8, name) catch |err| {
                self.entries.removeByPtr(result.key_ptr);
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
