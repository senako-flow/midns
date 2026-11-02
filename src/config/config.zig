const std = @import("std");

const toml = @import("toml");

pub const Local = struct {
    port: u16,
    host: []const u8,
};

pub const Connect = struct {
    postgre_url: []const u8,
};

pub const Security = struct {
    nodata_ttl: u32,
    nxdomain_ttl: u32,
};

pub const Config = struct {
    local: Local,
    connect: Connect,
    security: Security,
};
