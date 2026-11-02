const std = @import("std");

const db = @import("db");
const dns = @import("dns");
const config = @import("config");

pub const Listener = struct {
    io: std.Io,
    allocator: std.mem.Allocator,

    addr: std.Io.net.IpAddress,
    socket: std.Io.net.Socket,

    cache: db.Cache,
    postgre: db.Postgre,

    config: config.Config,

    pub fn new(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config) !Listener {
        const addr = try std.Io.net.IpAddress.parse(cfg.local.host, cfg.local.port);

        const socket = try std.Io.net.IpAddress.bind(&addr, io, .{
            .mode = .dgram,
            .protocol = .udp,
        });

        var bytes: [8]u8 = undefined;
        try std.Io.randomSecure(io, &bytes);

        const seed = std.mem.readInt(u64, &bytes, .little);

        const cache = db.Cache.init(allocator, io, seed);

        const postgre = try db.Postgre.init(allocator, io, cfg.connect.postgre_url);

        return .{
            .io = io,
            .allocator = allocator,
            .addr = addr,
            .socket = socket,
            .cache = cache,
            .postgre = postgre,
            .config = cfg,
        };
    }

    pub fn deinit(self: *Listener) void {
        self.cache.deinit();
        self.postgre.deinit();
        self.socket.close(self.io);
    }

    pub fn serve(self: *Listener, core: usize) !void {
        var spawn: usize = core;

        if (spawn == 0) {
            spawn = try std.Thread.getCpuCount();
        }

        const threads = try self.allocator.alloc(std.Thread, spawn);
        defer self.allocator.free(threads);

        for (threads, 0..) |*thread, i| {
            std.debug.print("worker spawn: {d}\n", .{i + 1});
            thread.* = try std.Thread.spawn(.{}, Listener.worker, .{self});
        }

        for (threads) |thread| {
            thread.join();
        }
    }

    fn worker(self: *Listener) void {
        var buffer: [4096]u8 = undefined;
        while (true) {
            const packet = self.socket.receive(self.io, &buffer) catch |err| {
                std.debug.print("worker receive failed: {any}\n", .{err});
                continue;
            };

            self.handler(packet) catch |err| {
                if (err != error.TooShortPacketSize) {
                    std.debug.print("worker handler failed: {any}\n", .{err});
                }
            };
        }
    }

    fn handler(self: *Listener, packet: std.Io.net.IncomingMessage) !void {
        if (packet.data.len < 12) {
            return error.TooShortPacketSize;
        }

        var header = dns.Header.decode(packet.data[0..12]);
        if (header.flags.qr == .Response) {
            return;
        }

        if (header.flags.opcode != .Query) {
            return try self.respond_with_error(&packet.from, &header, null, null, .NotImp, .NotTruncated);
        }

        if (header.qd != 1 or header.an != 0 or header.ns != 0 or header.ar > 1) {
            return try self.respond_with_error(&packet.from, &header, null, null, .FormatError, .NotTruncated);
        }

        const question = dns.Question.decode(packet.data[12..]) orelse {
            return try self.respond_with_error(&packet.from, &header, null, null, .FormatError, .NotTruncated);
        };

        const question_end = 12 + question.get_size();

        var edns0: ?dns.EDns0 = null;
        if (header.ar == 1) {
            if (packet.data.len < question_end + 11) {
                return try self.respond_with_error(&packet.from, &header, question, null, .FormatError, .NotTruncated);
            }

            edns0 = dns.EDns0.decode(packet.data[question_end..]) catch |err| {
                switch (err) {
                    dns.EDns0.Error.InvalidLength, dns.EDns0.Error.InvalidName, dns.EDns0.Error.NotOptRecord, dns.EDns0.Error.RdlenMismatch, dns.EDns0.Error.TrailingGarbage => {
                        return try self.respond_with_error(&packet.from, &header, question, null, .FormatError, .NotTruncated);
                    },
                }
            };

            if (edns0.?.version != 0) {
                return try self.respond_with_error(&packet.from, &header, question, edns0, .NoError, .NotTruncated);
            }
        }

        if (header.ar != 1 and packet.data.len > question_end) {
            return try self.respond_with_error(&packet.from, &header, question, null, .FormatError, .NotTruncated);
        }

        if (question.class != .IN) {
            return try self.respond_with_error(&packet.from, &header, question, edns0, .NotImp, .NotTruncated);
        }

        if (!question.record.is_supported()) {
            return try self.respond_with_error(&packet.from, &header, question, edns0, .NotImp, .NotTruncated);
        }

        var buffer: [255]u8 = undefined;
        const name = question.get_name(&buffer);

        const cached = try self.cache.get(name, question.record);
        if (cached) |result| {
            switch (result) {
                .nodata => {
                    return try self.respond_with_answers(&packet.from, &header, question, edns0, &.{});
                },
                .nxdomain => {
                    return try self.respond_with_error(&packet.from, &header, question, edns0, .NxDomain, .NotTruncated);
                },
                .answers => |answers| {
                    defer {
                        for (answers) |answer| {
                            self.allocator.free(answer.raw_data);
                        }
                        self.allocator.free(answers);
                    }
                    return try self.respond_with_answers(&packet.from, &header, question, edns0, answers);
                },
            }
        }

        const answers = self.postgre.get(name, question.record) catch |err| {
            switch (err) {
                db.Postgre.Error.NameExists => {
                    try self.cache.put_negative(name, question.record, .nodata, self.config.security.nodata_ttl);
                    return try self.respond_with_answers(&packet.from, &header, question, edns0, &.{});
                },
                db.Postgre.Error.NxDomain => {
                    try self.cache.put_negative(name, question.record, .nxdomain, self.config.security.nxdomain_ttl);
                    return try self.respond_with_error(&packet.from, &header, question, edns0, .NxDomain, .NotTruncated);
                },
                else => {
                    return try self.respond_with_error(&packet.from, &header, question, edns0, .ServFail, .NotTruncated);
                },
            }
        };

        defer {
            for (answers) |answer| {
                self.allocator.free(answer.raw_data);
            }

            self.allocator.free(answers);
        }

        try self.respond_with_answers(&packet.from, &header, question, edns0, answers);

        try self.cache.put_slice(name, question.record, answers);
    }

    fn respond_with_error(self: *Listener, from: *const std.Io.net.IpAddress, header: *dns.Header, question: ?dns.Question, edns0: ?dns.EDns0, rcode: dns.Rcode, tc: dns.TC) !void {
        header.an = 0;
        header.ar = 0;
        header.ns = 0;
        header.qd = 0;

        header.flags.qr = .Response;
        header.flags.rcode = rcode;

        header.flags.z = 0;
        header.flags.tc = tc;
        header.flags.aa = .Authoritative;
        header.flags.ra = .RecursionNotAvailable;

        var buffer: [1232]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);

        if (question != null) {
            header.qd = 1;
        }

        var option = dns.EDns0{
            .size = 1232,
            .rcode = 0,
            .version = 0,
            .dnssec_ok = false,
            .options = &.{},
        };

        if (edns0) |e| {
            header.ar = 1;

            if (e.version != 0) {
                header.flags.rcode = .NoError;
                option.rcode = 1;
            }
        }

        try header.encode(&writer);

        if (question) |q| {
            try q.encode(&writer);
        }

        if (edns0) |_| {
            try option.encode(&writer);
        }

        try self.socket.send(self.io, from, writer.buffered());
    }

    fn respond_with_answers(self: *Listener, from: *const std.Io.net.IpAddress, header: *dns.Header, question: dns.Question, edns0: ?dns.EDns0, records: []const dns.Answer) !void {
        header.ar = 0;
        header.ns = 0;
        header.qd = 1;

        if (records.len > std.math.maxInt(u16)) {
            return try self.respond_with_error(from, header, question, edns0, .ServFail, .NotTruncated);
        }

        header.an = @truncate(records.len);

        header.flags.qr = .Response;
        header.flags.rcode = .NoError;

        header.flags.z = 0;
        header.flags.tc = .NotTruncated;
        header.flags.aa = .Authoritative;
        header.flags.ra = .RecursionNotAvailable;

        var max_payload: usize = 512;
        if (edns0) |e| {
            max_payload = @min(@max(e.size, 512), 1232);
        }

        var option = dns.EDns0{
            .size = 1232,
            .rcode = 0,
            .version = 0,
            .dnssec_ok = false,
            .options = &.{},
        };

        if (edns0) |e| {
            header.ar = 1;

            if (e.version != 0) {
                header.an = 0;
                header.flags.rcode = .NoError;
                option.rcode = 1;
            }
        }

        var buffer: [1232]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);

        try header.encode(&writer);
        try question.encode(&writer);

        if (header.an > 0) {
            const limit = @min(max_payload, buffer.len);

            var opt_size: usize = 0;
            if (edns0) |_| {
                opt_size = 11;
            }

            for (records) |record| {
                if (writer.end + record.get_size() + opt_size > limit) {
                    return try self.respond_with_error(from, header, question, edns0, .NoError, .Truncated);
                }

                try record.encode(&writer);
            }
        }

        if (edns0) |_| {
            try option.encode(&writer);
        }

        const output = writer.buffered();
        if (output.len > max_payload) {
            return try self.respond_with_error(from, header, question, edns0, .NoError, .Truncated);
        }

        try self.socket.send(self.io, from, output);
    }
};
