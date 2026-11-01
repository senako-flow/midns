const std = @import("std");

const dns = @import("dns");

pub const Listener = struct {
    io: std.Io,
    allocator: std.mem.Allocator,

    addr: std.Io.net.IpAddress,
    socket: std.Io.net.Socket,

    pub fn new(io: std.Io, allocator: std.mem.Allocator, ip: []const u8, port: u16) !Listener {
        const addr = try std.Io.net.IpAddress.parse(ip, port);

        const socket = try std.Io.net.IpAddress.bind(&addr, io, .{
            .mode = .dgram,
            .protocol = .udp,
        });

        return .{
            .io = io,
            .allocator = allocator,
            .addr = addr,
            .socket = socket,
        };
    }

    pub fn deinit(self: *Listener) void {
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

        if (header.qd != 1) {
            return try self.respond_with_error(&packet.from, &header, null, null, .FormatError, .NotTruncated);
        }

        const question = dns.Question.decode(packet.data[12..]) orelse {
            return try self.respond_with_error(&packet.from, &header, null, null, .FormatError, .NotTruncated);
        };

        var edns0: ?dns.EDns0 = null;
        if (header.ar > 0 and packet.data.len >= 12 + question.get_size()) {
            edns0 = dns.EDns0.decode(packet.data[12 + question.get_size() ..]);
        }

        if (question.class != .IN) {
            return try self.respond_with_error(&packet.from, &header, question, edns0, .NotImp, .NotTruncated);
        }

        switch (question.record) {
            .A => {
                return try self.respond_with_value(&packet.from, &header, question, edns0, &[_]u8{ 127, 0, 0, 1 });
            },
            .AAAA => {
                return try self.respond_with_value(&packet.from, &header, question, edns0, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
            },
            else => {
                return try self.respond_with_error(&packet.from, &header, question, edns0, .NotImp, .NotTruncated);
            },
        }
    }

    fn respond_with_error(self: *Listener, from: *const std.Io.net.IpAddress, header: *dns.Header, question: ?dns.Question, edns0: ?dns.EDns0, rcode: dns.Rcode, tc: dns.TC) !void {
        header.an = 0;
        header.ar = 0;
        header.ns = 0;
        header.qd = 0;

        header.flags.qr = .Response;
        header.flags.rcode = rcode;

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

    fn respond_with_value(self: *Listener, from: *const std.Io.net.IpAddress, header: *dns.Header, question: dns.Question, edns0: ?dns.EDns0, value: []const u8) !void {
        header.an = 1;
        header.ar = 0;
        header.ns = 0;
        header.qd = 1;

        header.flags.qr = .Response;
        header.flags.rcode = .NoError;

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
                option.rcode = 1;
            }
        }

        const answer = dns.Answer{
            .ttl = 300,
            .name = &[_]u8{ 0xc0, 0x0c },
            .class = question.class,
            .record = question.record,
            .value = value,
        };

        var buffer: [1232]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);

        try header.encode(&writer);
        try question.encode(&writer);

        if (header.an > 0) {
            try answer.encode(&writer);
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
