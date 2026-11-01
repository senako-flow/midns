pub const Record = enum(u16) {
    A = 1,
    AAAA = 28,
    OPT = 41,
    _,

    pub fn is_supported(self: Record) bool {
        return switch (self) {
            .A, .AAAA => true,
            .OPT, _ => false,
        };
    }
};
