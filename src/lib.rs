#![deny(unsafe_code)]

pub(crate) mod common;
pub(crate) mod header;
pub(crate) mod packet;
pub(crate) mod reader;
#[cfg(test)]
mod tests;
pub(crate) mod writer;

pub use common::{
    DataLink,
    Endianness,
    PcapError,
    ReadEndian,
    TsResolution,
};
pub use header::PcapHeader;
pub use packet::PcapPacket;
pub use reader::PcapReader;
pub use writer::{
    PcapFileWriter,
    PcapWriter,
};
