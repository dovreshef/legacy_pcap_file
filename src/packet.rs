use crate::common::{
    PcapError,
    PcapResult,
    ReadEndian,
    WriteEndian,
};
use std::io::Read;

/// Pcap packet with its header and data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapPacket {
    /// Timestamp in seconds.
    pub ts_sec: u32,
    /// Nanosecond or microsecond part of the timestamp.
    pub ts_frac: u32,
    /// Length of the packet saved that is saved in the file (Length of the data field).
    pub incl_len: u32,
    /// Original length of the packet on the wire.
    pub orig_len: u32,
    /// Payload.
    pub data: Vec<u8>,
}

impl PcapPacket {
    /// Parse a new [`PcapPacket`] from a reader.
    pub fn read<R>(reader: R) -> PcapResult<Self>
    where
        R: ReadEndian,
    {
        let data = vec![];
        Self::read_with(reader, data)
    }

    /// Parse a new [`PcapPacket`] from a reader. Use the supplied Vec as a backing storage
    /// for the payload data.
    pub fn read_with<R>(mut reader: R, mut data: Vec<u8>) -> PcapResult<Self>
    where
        R: ReadEndian,
    {
        // Read packet header.
        let ts_sec = reader.read_u32()?;
        let ts_frac = reader.read_u32()?;
        let incl_len = reader.read_u32()?;
        let orig_len = reader.read_u32()?;

        let mut data_reader = reader.take(incl_len as u64);
        data.clear();
        data_reader.read_to_end(&mut data)?;
        if data.len() != incl_len as usize {
            return Err(PcapError::IncompleteBuffer);
        }

        let packet = PcapPacket {
            ts_sec,
            ts_frac,
            incl_len,
            orig_len,
            data,
        };
        Ok(packet)
    }

    /// Write a [`PcapPacket`] to a WriteEndian writer.
    /// The fields of the packet are not validated.
    #[inline]
    pub fn write<W>(&self, writer: W) -> PcapResult<u32>
    where
        W: WriteEndian,
    {
        write_packet(
            writer,
            self.ts_sec,
            self.ts_frac,
            self.incl_len,
            self.orig_len,
            &self.data,
        )
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        16 + self.incl_len
    }
}

/// Helper method to write a packet to a writer.
#[inline]
pub(crate) fn write_packet<W>(
    mut writer: W,
    ts_sec: u32,
    ts_frac: u32,
    incl_len: u32,
    orig_len: u32,
    data: impl AsRef<[u8]>,
) -> PcapResult<u32>
where
    W: WriteEndian,
{
    let data = data.as_ref();
    if data.len() != incl_len as usize {
        return Err(PcapError::PacketPayloadMismatch);
    }

    writer.write_u32(ts_sec)?;
    writer.write_u32(ts_frac)?;
    writer.write_u32(incl_len)?;
    writer.write_u32(orig_len)?;
    writer.write_all(data)?;
    Ok(16 + incl_len)
}
