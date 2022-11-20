//! The header is based on the following structure from C
//!
//! ```c
//! typedef struct pcap_hdr_s {
//!     guint32 magic_number;   /* magic number */
//!     guint16 version_major;  /* major version number */
//!     guint16 version_minor;  /* minor version number */
//!     gint32  thiszone;       /* GMT to local correction */
//!     guint32 sigfigs;        /* accuracy of timestamps */
//!     guint32 snaplen;        /* max length of captured packets, in octets */
//!     guint32 network;        /* data link type */
//! } pcap_hdr_t;
//! ```
//! where:
//!
//! * magic_number: used to detect the file format itself and the byte ordering. The writing
//!   application writes 0xa1b2c3d4 with it's native byte ordering format into this field. The
//!   reading application will read either 0xa1b2c3d4 (identical) or 0xd4c3b2a1 (swapped). If
//!   the reading application reads the swapped 0xd4c3b2a1 value, it knows that all the following
//!   fields will have to be swapped too.
//! * version_major, version_minor: the version number of this file format (current version is 2.4).
//! * thiszone: the correction time in seconds between GMT (UTC) and the local timezone of the
//!   following packet header timestamps. Examples: If the timestamps are in GMT (UTC), thiszone
//!   is simply 0. If the timestamps are in Central European time (Amsterdam, Berlin, …) which is
//!   GMT + 1:00, thiszone must be -3600. In practice, time stamps are always in GMT, so thiszone
//!   is always 0.
//! * sigfigs: in theory, the accuracy of time stamps in the capture; in practice, all tools set
//!   it to 0.
//! * snaplen: an upper limit for a captured packet (typically 65535 or even more, but might be
//!   limited by the user).
//! * network: link-layer header type, specifying the type of headers at the beginning of the packet
//!   (e.g. 1 for Ethernet, see tcpdump.org's link-layer header types page for details); this can be
//!   various types such as 802.11, 802.11 with various radio information, PPP, Token Ring, FDDI,
//!   etc. See list at <https://www.tcpdump.org/linktypes.html>.
//!
//! The data above is taken from: <https://wiki.wireshark.org/Development/LibpcapFileFormat>

use crate::common::{
    BigEndianReader,
    BigEndianWriter,
    DataLink,
    Endianness,
    LittleEndianReader,
    LittleEndianWriter,
    PcapError,
    PcapResult,
    ReadEndian,
    TsResolution,
    WriteEndian,
};
use std::io::{
    Read,
    Write,
};

/// Pcap file global header.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PcapHeader {
    /// Major version number.
    pub version_major: u16,

    /// Minor version number.
    pub version_minor: u16,

    /// GMT to local timezone correction, should always be 0.
    pub ts_correction: i32,

    /// Timestamp accuracy, should always be 0.
    pub ts_accuracy: u32,

    /// Max length of captured packet, typically 65535.
    pub snaplen: u32,

    /// DataLink type (the first layer in the packets).
    pub datalink: DataLink,

    /// Timestamp resolution of the pcap (microsecond or nanosecond).
    pub ts_resolution: TsResolution,

    /// Endianness of the pcap (excluding the packet data).
    pub endianness: Endianness,
}

impl PcapHeader {
    /// The size of the header.
    pub const LEN: u32 = 24;

    /// Creates a new [`PcapHeader`] from a bytes reader.
    ///
    /// Returns an error if the reader doesn't contain a valid pcap
    /// or if there is a reading error.
    ///
    /// `PcapError::IncompleteBuffer` indicates that there is not enough data in the buffer.
    pub fn read<R>(reader: R) -> PcapResult<PcapHeader>
    where
        R: Read,
    {
        // Inner function used for the initialization of the `PcapHeader`.
        fn _read(
            mut reader: impl ReadEndian,
            ts_resolution: TsResolution,
        ) -> PcapResult<PcapHeader> {
            let header = PcapHeader {
                version_major: reader.read_u16()?,
                version_minor: reader.read_u16()?,
                ts_correction: reader.read_i32()?,
                ts_accuracy: reader.read_u32()?,
                snaplen: reader.read_u32()?,
                datalink: DataLink::from(reader.read_u32()?),
                ts_resolution,
                endianness: reader.endianness(),
            };

            Ok(header)
        }

        let mut reader = BigEndianReader::from(reader);
        match reader.read_u32()? {
            0xA1B2C3D4 => _read(reader, TsResolution::MicroSecond),
            0xA1B23C4D => _read(reader, TsResolution::NanoSecond),
            0xD4C3B2A1 => _read(LittleEndianReader::from(reader), TsResolution::MicroSecond),
            0x4D3CB2A1 => _read(LittleEndianReader::from(reader), TsResolution::NanoSecond),
            _ => Err(PcapError::IncorrectMagicNumber),
        }
    }

    /// Write a [`PcapHeader`] to a writer.
    ///
    /// Uses the endianness of the header.
    pub fn write<W: Write>(&self, writer: &mut W) -> PcapResult<u32> {
        fn _write(header: &PcapHeader, mut writer: impl WriteEndian) -> PcapResult<u32> {
            let magic_number = match header.ts_resolution {
                TsResolution::MicroSecond => 0xA1B2C3D4,
                TsResolution::NanoSecond => 0xA1B23C4D,
            };

            writer.write_u32(magic_number)?;
            writer.write_u16(header.version_major)?;
            writer.write_u16(header.version_minor)?;
            writer.write_i32(header.ts_correction)?;
            writer.write_u32(header.ts_accuracy)?;
            writer.write_u32(header.snaplen)?;
            writer.write_u32(header.datalink.into())?;

            Ok(PcapHeader::LEN)
        }

        match self.endianness {
            Endianness::Big => _write(self, BigEndianWriter::from(writer)),
            Endianness::Little => _write(self, LittleEndianWriter::from(writer)),
        }
    }
}

/// Creates a new [`PcapHeader`] with the default parameters.
impl Default for PcapHeader {
    fn default() -> Self {
        PcapHeader {
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: 65535,
            datalink: DataLink::ETHERNET,
            ts_resolution: TsResolution::MicroSecond,
            endianness: Endianness::Big,
        }
    }
}
