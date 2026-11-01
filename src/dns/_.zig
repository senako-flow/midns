pub const Class = @import("class.zig").Class;
pub const Record = @import("record.zig").Record;

const flags = @import("flags.zig");

pub const QR = flags.QR;
pub const Opcode = flags.Opcode;
pub const AA = flags.AA;
pub const TC = flags.TC;
pub const RD = flags.RD;
pub const RA = flags.RA;
pub const Rcode = flags.Rcode;

const parser = @import("parser.zig");

pub const Flags = parser.Flags;
pub const Header = parser.Header;
pub const Question = parser.Question;
pub const Answer = parser.Answer;

pub const EDns0 = @import("edns0.zig").Edns0;
