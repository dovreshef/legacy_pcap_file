# Legacy Pcap parsing & writing

![GitHub Workflow Status](https://img.shields.io/github/workflow/status/dovreshef/legacy_pcap_file/Rust)

A modified version of [courvoif/pcap-file](https://github.com/courvoif/pcap-file) that supports only
the old legacy pcap file format (`.pcap` extension).

The PCAP format  is very simple. see [here](https://wiki.wireshark.org/Development/LibpcapFileFormat)
for a description of its structure. This crate provides some abstractions over it for reading
and writing, including streaming variants. It is also non-async.

This crate has no external dependencies (apart from std). It has also no unsafe code.

All abstractions use the standard library [`Read`](https://doc.rust-lang.org/std/io/trait.Read.html)
 and [`Write`](https://doc.rust-lang.org/std/io/trait.Write.html) traits. 

## Examples

Reading data the easy way:
```rust
    use legacy_pcap_file::PcapReader;

    // Let's assume this is some pcap data. It can also be a file.
    // Anything implementing `Read`.
    let some_buffer = vec![];
    let pcap_reader = PcapReader::new(&some_buffer).unwrap();

    // Packets can be iterated on.
    for res in pcap_reader {
        // For each packet we get a result, since there are a few errors that
        // can pop up:
        // * The data source can be exhausted mid packet.
        // * The packet header length may be shorter than actual data length. 
        let pkt = res.unwrap();
        // Use the packet.
        ...
    }
```

Reading data while reusing the packet buffer.
(This is a bit of a hack).
```rust
    use legacy_pcap_file::PcapReader;

    // Let's assume this is some pcap data. It can also be a file.
    // Anything implementing `Read`.
    let some_buffer = vec![];
    let pcap_reader = PcapReader::new(&some_buffer).unwrap();

    // Define some backing data for the packets payload.
    let mut backing_data = vec![]; 
    // Iterate manually.
    while let Some(Ok(pkt)) = pcap_reader.next_with(backing_data) {
        // here you can use the packet, clone it, etc..
        ...
        // reuse the data.
        backing_data = pkt.data;
    }
```

Writing data:
```rust
    use legacy_pcap_file::{PcapHeader, PcapPacket, PcapFileWriter};

    // Let's say you have a pcap header defined
    let header: PcapHeader = ...
    // and some supply of packets
    let packets: Vec<PcapPacket> = ...
    // They can be written like so
    let path = Path::from("/some/file/path");
    let mut pcap_file_writer = PcapFileWriter::new_with_header(&path, header).unwrap();
    for packet in packets {
        // Some errors that can occur:
        // * The backing storage maybe error in some way (IO error).
        // * The packets are not well formed (mostly declared payload length 
        //   does not match real length).
        pcap_file_writer.write_packet(&packet).unwrap();
    }
    pcap_file_writer.close().unwrap();

```

## License

Licensed under MIT/Apache-2.0 license.
