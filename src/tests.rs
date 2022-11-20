use super::*;
use parameterized::parameterized;
use std::{
    fs::File,
    io::Read,
};
use tempfile::NamedTempFile;

const LITTLE_ENDIAN_DATA: &[u8] = include_bytes!("../test_data/little_endian.pcap");
const LITTLE_ENDIAN_PKT_COUNT: usize = 10;
const BIG_ENDIAN_DATA: &[u8] = include_bytes!("../test_data/big_endian.pcap");
const BIG_ENDIAN_PKT_COUNT: usize = 2;

/// Test reading of valid pcap data from file
#[parameterized(
    data = { LITTLE_ENDIAN_DATA, BIG_ENDIAN_DATA },
    size = { LITTLE_ENDIAN_PKT_COUNT, BIG_ENDIAN_PKT_COUNT }
)]
fn read(data: &[u8], size: usize) {
    let pcap_reader = PcapReader::new(data).unwrap();

    // Global header len
    let mut data_len = 24;
    let mut pkt_count = 0;

    for res in pcap_reader {
        let pkt = res.unwrap();
        data_len += pkt.len() as usize;
        pkt_count += 1;
    }

    assert_eq!(pkt_count, size);
    assert_eq!(data_len, data.len());
}

/// Test reading & writing of valid pcap data does not modify the data
#[parameterized(data = { LITTLE_ENDIAN_DATA, BIG_ENDIAN_DATA })]
fn read_write(data: &[u8]) {
    let pcap_reader = PcapReader::new(data).unwrap();
    let header = pcap_reader.header();

    let mut out = Vec::new();
    let mut pcap_writer = PcapWriter::new_with_header(out, header).unwrap();

    for res in pcap_reader {
        let pkt = res.unwrap();
        pcap_writer.write_packet(&pkt).unwrap();
    }
    out = pcap_writer.into_writer();

    assert_eq!(data, &out);
}

/// Test reading of big endian pcap file
#[test]
fn validate_big_endian_reader() {
    let expected_pcap_header = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 0xFFFF,
        datalink: DataLink::ETHERNET,
        ts_resolution: TsResolution::MicroSecond,
        endianness: Endianness::Big,
    };

    let mut pcap_reader = PcapReader::new(BIG_ENDIAN_DATA).unwrap();
    let pcap_header = pcap_reader.header();
    assert_eq!(pcap_header, expected_pcap_header);

    let data = hex::decode("00005e0001b10021280529ba08004500005430a70000ff010348c0a8b1a00a400b3108000afb43a800004\
    fa11b290002538d08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637").unwrap();

    let expected_pkt = PcapPacket {
        ts_sec: 1335958313,
        ts_frac: 152630,
        incl_len: 98,
        orig_len: 98,
        data,
    };
    let pkt = pcap_reader.next().unwrap().unwrap();

    assert_eq!(pkt.ts_sec, expected_pkt.ts_sec);
    assert_eq!(pkt.ts_frac, expected_pkt.ts_frac);
    assert_eq!(pkt.incl_len, expected_pkt.incl_len);
    assert_eq!(pkt.orig_len, expected_pkt.orig_len);
    assert_eq!(pkt.data, expected_pkt.data);
}

/// Test reading of little endian pcap file
#[test]
fn validate_little_endian_reader() {
    let expected_pcap_header = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 4096,
        datalink: DataLink::ETHERNET,
        ts_resolution: TsResolution::MicroSecond,
        endianness: Endianness::Little,
    };

    let mut pcap_reader = PcapReader::new(LITTLE_ENDIAN_DATA).unwrap();
    let pcap_header = pcap_reader.header();
    assert_eq!(pcap_header, expected_pcap_header);

    let data = hex::decode("000c29414be70016479df2c2810000780800450000638d2c0000fe06fdc8c0a8e5fec0a8ca4f01bbb4258\
    0e634d3fa9b15fc8018800019da00000101080a130d62b200000000140301000101160301002495776bd4f33faea1aacaf1fbe6026c262fcc2f8cd0f828216dc4aba5bcc1a8e03b496e82").unwrap();

    let expected_pkt = PcapPacket {
        ts_sec: 1331901000,
        ts_frac: 0,
        incl_len: 117,
        orig_len: 117,
        data,
    };

    let pkt = pcap_reader.next().unwrap().unwrap();

    assert_eq!(pkt.ts_sec, expected_pkt.ts_sec);
    assert_eq!(pkt.ts_frac, expected_pkt.ts_frac);
    assert_eq!(pkt.incl_len, expected_pkt.incl_len);
    assert_eq!(pkt.orig_len, expected_pkt.orig_len);
    assert_eq!(pkt.data, expected_pkt.data);
}

/// Test writing in batches
#[parameterized(data = { LITTLE_ENDIAN_DATA, BIG_ENDIAN_DATA })]
fn test_writing_in_batches(data: &[u8]) {
    let mut pcap_reader = PcapReader::new(data).unwrap();
    let header = pcap_reader.header();

    let path = NamedTempFile::new().unwrap().into_temp_path();
    let mut pcap_file = PcapFileWriter::new_with_header(&path, header).unwrap();
    assert_eq!(pcap_file.packet_count(), 0);
    assert_eq!(pcap_file.len(), PcapHeader::LEN as u64);

    let packet = pcap_reader.next().unwrap().unwrap();
    pcap_file.write_packet(&packet).unwrap();
    let expected_len = PcapHeader::LEN as u64 + packet.len() as u64;
    assert_eq!(pcap_file.packet_count(), 1);
    assert_eq!(pcap_file.len(), expected_len);
    pcap_file.close().unwrap();

    let mut pcap_file = PcapFileWriter::open(&path, false).unwrap();
    assert_eq!(pcap_file.packet_count(), 1);
    assert_eq!(pcap_file.len(), expected_len);
    for packet in pcap_reader {
        let packet = packet.unwrap();
        pcap_file.write_packet(&packet).unwrap();
    }
    pcap_file.close().unwrap();

    let mut written_data = Vec::new();
    File::open(&path)
        .unwrap()
        .read_to_end(&mut written_data)
        .unwrap();

    // Assert that the data we ended up with is the same as the data we started with.
    assert_eq!(&written_data, data);

    drop(path);
}

#[test]
fn test_pcap_file_open() {
    // Get a path to a dropped file
    let path = NamedTempFile::new().unwrap().into_temp_path().to_path_buf();
    // Can't open a non-existent file for writing
    assert!(PcapFileWriter::open(path, false).is_err());

    let path = NamedTempFile::new().unwrap().into_temp_path();
    // Open new file
    let mut pcap_file = PcapFileWriter::open(&path, true).unwrap();
    assert_eq!(pcap_file.packet_count(), 0);
    assert_eq!(pcap_file.len(), PcapHeader::LEN as u64);

    let mut pcap_reader = PcapReader::new(LITTLE_ENDIAN_DATA).unwrap();
    let packet = pcap_reader.next().unwrap().unwrap();
    pcap_file.write_packet(&packet).unwrap();
    let expected_len = PcapHeader::LEN as u64 + packet.len() as u64;
    assert_eq!(pcap_file.packet_count(), 1);
    assert_eq!(pcap_file.len(), expected_len);
    pcap_file.close().unwrap();
}
