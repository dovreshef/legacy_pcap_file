use crate::{
    common::{
        BigEndianReader,
        Endianness,
        LittleEndianReader,
        PcapResult,
    },
    header::PcapHeader,
    packet::PcapPacket,
};
use std::io::{
    BufRead,
    BufReader,
    Read,
    Result as IoResult,
};

/// A reader of a Pcap file. Can target any `std::io::Read` implementor.
#[derive(Debug)]
pub struct PcapReader<R>
where
    R: Read,
{
    header: PcapHeader,
    reader: BufReader<R>,
}

impl<R> PcapReader<R>
where
    R: Read,
{
    pub fn new(reader: R) -> PcapResult<Self> {
        let mut reader = BufReader::new(reader);
        let header = PcapHeader::read(&mut reader)?;
        Ok(Self { header, reader })
    }

    /// return the next packet, reusing the passed vec for its payload.
    pub fn next_with(&mut self, data: Vec<u8>) -> Option<PcapResult<PcapPacket>> {
        match self.has_data_left() {
            Ok(true) => {
                let res = match self.header.endianness {
                    Endianness::Big => {
                        PcapPacket::read_with(BigEndianReader::from(&mut self.reader), data)
                    }
                    Endianness::Little => {
                        PcapPacket::read_with(LittleEndianReader::from(&mut self.reader), data)
                    }
                };
                Some(res)
            }
            Ok(false) => None,
            Err(e) => Some(Err(e.into())),
        }
    }

    /// Check for eof by checking the inner buffer without consuming.
    /// TODO: once this function hit stable on BuffRead move to using their version.
    #[inline]
    fn has_data_left(&mut self) -> IoResult<bool> {
        self.reader.fill_buf().map(|b| !b.is_empty())
    }

    /// Consumes the `PcapReader`, returning the wrapped reader.
    pub fn into_reader(self) -> R {
        self.reader.into_inner()
    }

    /// Return the pcap file header.
    pub fn header(&self) -> PcapHeader {
        self.header
    }
}

impl<R> Iterator for PcapReader<R>
where
    R: Read,
{
    type Item = PcapResult<PcapPacket>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.has_data_left() {
            Ok(true) => {
                let res = match self.header.endianness {
                    Endianness::Big => PcapPacket::read(BigEndianReader::from(&mut self.reader)),
                    Endianness::Little => {
                        PcapPacket::read(LittleEndianReader::from(&mut self.reader))
                    }
                };
                Some(res)
            }
            Ok(false) => None,
            Err(e) => Some(Err(e.into())),
        }
    }
}
