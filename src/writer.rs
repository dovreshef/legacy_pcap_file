use crate::{
    common::{
        BigEndianWriter,
        Endianness,
        LittleEndianWriter,
        PcapResult,
    },
    header::PcapHeader,
    packet::{
        write_packet,
        PcapPacket,
    },
    reader::PcapReader,
};
use std::{
    fs::File,
    io::{
        BufWriter,
        Seek,
        Write,
    },
    path::Path,
};

/// A writer of a Pcap file. Can target any `std::io::Write` implementor.
///
/// # Examples
///
/// ```
/// use legacy_pcap_file::{PcapWriter, PcapHeader, PcapPacket};
///
/// let mut buffer = Vec::new();
/// let mut pcap_writer = PcapWriter::new_with_header(&mut buffer, PcapHeader::default()).unwrap();
/// let packet = PcapPacket {
///     ts_sec: 0,
///     ts_frac: 0,
///     incl_len: 10,
///     orig_len: 10,
///     data: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
/// };
/// let wrote = pcap_writer.write_packet(&packet).unwrap();
/// assert_eq!(wrote, 26);
/// let packet_data_starts = PcapHeader::LEN as usize + 16;
/// assert_eq!(&buffer[packet_data_starts..(packet_data_starts + 10)], &packet.data);
/// ```
#[derive(Debug)]
pub struct PcapWriter<W>
where
    W: Write,
{
    header: PcapHeader,
    writer: W,
}

impl<W> PcapWriter<W>
where
    W: Write,
{
    /// Creates a new `PcapWriter` from an existing writer.
    /// Defaults to the native endianness of the CPU.
    ///
    /// # Errors
    /// Return an error if the writer can't be written to.
    ///
    /// # Assumptions
    /// The function assumes that the buffer it receives is empty, and it starts by writing a
    /// default pcap header into it.
    pub fn new(writer: W) -> PcapResult<Self> {
        let endianness = if cfg!(target_endian = "big") {
            Endianness::Big
        } else {
            Endianness::Little
        };
        let header = PcapHeader {
            endianness,
            ..Default::default()
        };
        Self::new_with_header(writer, header)
    }

    /// Create a new `PcapWriter` from an existing writer with a user defined pcap header.
    /// The endianness and the timestamp resolution are defined by the magic number of the header.
    /// It writes the pcap header to the file.
    ///
    /// # Errors
    /// Return an error if the writer can't be written to.
    ///
    /// # Assumptions
    /// The function assumes that the buffer it receives is empty, and it starts by writing a
    /// the provided pcap header into it.
    ///
    /// # Examples
    ///
    /// ```
    /// use legacy_pcap_file::{PcapWriter, PcapHeader, DataLink, TsResolution, Endianness};
    ///
    /// let pcap_header = PcapHeader {
    ///     version_major: 2,
    ///     version_minor: 4,
    ///     ts_correction: 0,
    ///     ts_accuracy: 0,
    ///     snaplen: 100,
    ///     datalink: DataLink::ETHERNET,
    ///     ts_resolution: TsResolution::NanoSecond,
    ///     endianness: Endianness::Little,
    /// };
    /// let mut pcap_writer = PcapWriter::new_with_header(Vec::new(), pcap_header).unwrap();
    /// assert_eq!(pcap_writer.header(), pcap_header);
    /// ```
    pub fn new_with_header(mut writer: W, header: PcapHeader) -> PcapResult<Self> {
        header.write(&mut writer)?;
        Ok(Self { header, writer })
    }

    /// Open an existing writer. The header must be supplied.
    ///
    /// # Assumptions
    /// The function assumes that the buffer it receives has valid pcap header + possibly some
    /// packets written fully. It also assumes that the header of the file is the one it receives.
    pub fn open_with_header(writer: W, header: PcapHeader) -> Self {
        Self { header, writer }
    }

    /// Consumes the `PcapWriter`, returning the wrapped writer.
    ///
    /// # Examples
    ///
    /// ```
    /// use legacy_pcap_file::{PcapWriter, PcapHeader};
    ///
    /// let pcap_writer = PcapWriter::new(Vec::new()).unwrap();
    /// let writer = pcap_writer.into_writer();
    /// assert_eq!(writer.len(), PcapHeader::LEN as usize);
    /// ```
    pub fn into_writer(self) -> W {
        self.writer
    }

    /// Return the pcap file header.
    ///
    /// # Examples
    ///
    /// ```
    /// use legacy_pcap_file::{PcapWriter, PcapHeader};
    ///
    /// let mut buffer = Vec::new();
    /// let mut pcap_writer = PcapWriter::new_with_header(&mut buffer, PcapHeader::default()).unwrap();
    /// assert_eq!(pcap_writer.header(), PcapHeader::default());
    /// ```
    pub fn header(&self) -> PcapHeader {
        self.header
    }

    /// Writes a [`PcapPacket`].
    ///
    /// # Arguments
    /// * `packet`: a reference to a `PcapPacket`.
    pub fn write_packet(&mut self, packet: &PcapPacket) -> PcapResult<u32> {
        match self.header.endianness {
            Endianness::Big => packet.write(BigEndianWriter::from(&mut self.writer)),
            Endianness::Little => packet.write(LittleEndianWriter::from(&mut self.writer)),
        }
    }

    /// Writes a packet from its constituent parts.
    ///
    /// # Arguments
    /// * `ts_sec`: timestamp in seconds.
    /// * `ts_frac`: nanosecond or microsecond part of the timestamp. (Will be interpreted based on
    ///              the writer header config).
    /// * `incl_len`: number of octets of the packet to be saved. Should match `data.len()`.
    /// * `orig_len`: original length of the packet on the wire.
    /// * `data`: The payload.
    pub fn write_packet_data(
        &mut self,
        ts_sec: u32,
        ts_frac: u32,
        incl_len: u32,
        orig_len: u32,
        data: impl AsRef<[u8]>,
    ) -> PcapResult<u32> {
        match self.header.endianness {
            Endianness::Big => write_packet(
                BigEndianWriter::from(&mut self.writer),
                ts_sec,
                ts_frac,
                incl_len,
                orig_len,
                data,
            ),
            Endianness::Little => write_packet(
                LittleEndianWriter::from(&mut self.writer),
                ts_sec,
                ts_frac,
                incl_len,
                orig_len,
                data,
            ),
        }
    }

    /// Flush the data to disk, making sure that all of the data has been written.
    /// Data will be flushed on drop as well, but then we'll not be able to tell if the flush
    /// succeeded.
    pub fn flush(&mut self) -> PcapResult<()> {
        self.writer.flush().map_err(Into::into)
    }
}

/// A convenience wrapper around `PcapWriter` for buffered files on disk.
/// Keeps a file length and the packet count property.
///
/// When opening existing files, the header + packets will be loaded & validated (most length).
pub struct PcapFileWriter {
    writer: PcapWriter<BufWriter<File>>,
    packet_count: u64,
    len: u64,
}

impl PcapFileWriter {
    /// An ease of use function to create a new pcap file at the location pointed at by `path`.
    /// Uses the default pcap header with the endianness of the processor executing the code.
    ///
    /// # Arguments:
    /// * `path`: a value which can serve as a reference to a path on disk.
    pub fn new(path: impl AsRef<Path>) -> PcapResult<Self> {
        let file = File::create(path.as_ref())?;
        let writer = PcapWriter::new(BufWriter::new(file))?;
        Ok(Self {
            writer,
            packet_count: 0,
            len: PcapHeader::LEN.into(),
        })
    }

    /// An ease of use function to create a new pcap file at the location pointed at by `path` with
    /// a specified header.
    ///
    /// # Arguments:
    /// * `path`: a value which can serve as a reference to a path on disk.
    /// * `header`: a specific pcap header to use with the file.
    pub fn new_with_header(path: impl AsRef<Path>, header: PcapHeader) -> PcapResult<Self> {
        let file = File::create(path.as_ref())?;
        let writer = PcapWriter::new_with_header(BufWriter::new(file), header)?;
        Ok(Self {
            writer,
            packet_count: 0,
            len: PcapHeader::LEN.into(),
        })
    }

    /// An ease of use function to open an existing pcap file at the location pointed at by `path`.
    ///
    /// # Arguments:
    /// * `path`: a value which can serve as a reference to a path on disk.
    /// * `create`: if set, the file will be created if it does not exist.
    pub fn open(path: impl AsRef<Path>, create: bool) -> PcapResult<PcapFileWriter> {
        let mut file = File::options()
            .read(true)
            .append(true)
            .create(create)
            .open(path.as_ref())?;
        let mut len = file.metadata().map(|md| md.len())?;
        let mut packet_count = 0;
        // If the file has data - validate, else - create new
        let writer = match len > 0 {
            true => {
                file.rewind()?;
                let mut reader = PcapReader::new(&mut file)?;
                let header = reader.header();
                let mut data = vec![];
                while let Some(res) = reader.next_with(data) {
                    let packet = res?;
                    packet_count += 1;
                    data = packet.data;
                }
                let writer = BufWriter::new(file);
                PcapWriter::open_with_header(writer, header)
            }
            false => {
                len += PcapHeader::LEN as u64;
                PcapWriter::new(BufWriter::new(file))?
            }
        };
        Ok(Self {
            writer,
            packet_count,
            len,
        })
    }

    /// Return the number of packets written to file.
    pub fn packet_count(&self) -> u64 {
        self.packet_count
    }

    /// Return the size of the file.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Writes a `PcapPacket`.
    pub fn write_packet(&mut self, packet: &PcapPacket) -> PcapResult<()> {
        let packet_len = self.writer.write_packet(packet)?;
        self.len += u64::from(packet_len);
        self.packet_count += 1;
        Ok(())
    }

    /// Writes a packet from its constituent parts.
    ///
    /// # Arguments
    /// * `ts_sec`: timestamp in seconds.
    /// * `ts_frac`: nanosecond or microsecond part of the timestamp.
    /// * `incl_len`: number of octets of the packet saved in file.
    /// * `orig_len`: original length of the packet on the wire.
    /// * `data`: The payload.
    pub fn write_packet_data(
        &mut self,
        ts_sec: u32,
        ts_frac: u32,
        incl_len: u32,
        orig_len: u32,
        data: impl AsRef<[u8]>,
    ) -> PcapResult<()> {
        let packet_len = self
            .writer
            .write_packet_data(ts_sec, ts_frac, incl_len, orig_len, data)?;
        self.len += u64::from(packet_len);
        self.packet_count += 1;
        Ok(())
    }

    /// Flush the data to disk, making sure that all of the data has been written.
    /// Data will be flushed on drop as well, but then we'll not be able to tell if the flush
    /// succeeded.
    pub fn flush(&mut self) -> PcapResult<()> {
        self.writer.flush()
    }

    /// Attempt to flush all data to disk and close the disk, returning any errors that may occur
    /// in the process.
    pub fn close(mut self) -> PcapResult<()> {
        self.flush()?;
        let file = self
            .writer
            .into_writer()
            .into_inner()
            .map_err(|e| e.into_error())?;
        file.sync_all()?;
        Ok(())
    }
}
