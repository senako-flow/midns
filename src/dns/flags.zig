pub const QR = enum(u1) {
    Query = 0,
    Response = 1,
};

pub const Opcode = enum(u4) {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    _,
};

pub const AA = enum(u1) {
    NonAuthoritative = 0,
    Authoritative = 1,
};

pub const TC = enum(u1) {
    NotTruncated = 0,
    Truncated = 1,
};

pub const RD = enum(u1) {
    RecursionNotDesired = 0,
    RecursionDesired = 1,
};

pub const RA = enum(u1) {
    RecursionNotAvailable = 0,
    RecursionAvailable = 1,
};

pub const Rcode = enum(u4) {
    NoError = 0,
    FormatError = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
    YxDomain = 6,
    YxRrset = 7,
    NotAuth = 8,
    NotZone = 9,
    _,
};
