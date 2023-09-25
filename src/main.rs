mod pcap;

use std::fs;
use std::io;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::mem;
use std::ops::Shl;
use std::slice;
use std::{thread, time::Duration};


fn main() -> io::Result<()> {
    let mut file = fs::File::open("class_tcpdump.log")?;

    let pcap_header: pcap::FileHeader = read(&mut file)?;
    if pcap_header.magic != 2712847316 {
        println!("Invalid pcap file.");
        return Ok(());
    }

    const SIZE_LINK_HEADER: usize = 14;
    match pcap_header.linktype {
        1 => {
            // size_link_header = 14_u32;
        },
        
        _ => {
            println!("Invalid link type.");
            return Ok(());
        }
    }

    let mut packets = Vec::new();
    let mut is_eof = false;
    while !is_eof {
        let mut ignore_packet = false;
        let mut packet: pcap::Packet = Default::default();

        match read::<pcap::PacketHeader>(&mut file) {
            Ok(header) => {
                packet.header = header;
            },
            Err(err) => {
                if err.kind() == ErrorKind::UnexpectedEof { is_eof = true }
                else { println!("Che-to poshlo ne tak..."); return Ok(()) }
            }
        }
        
        if is_eof { break }

        match read::<[u8; SIZE_LINK_HEADER]>(&mut file) {
            Ok(buffer) => {
                let t = (buffer[buffer.len() - 2] as u16).shl(8) + (buffer[buffer.len() - 1] as u16);
                ignore_packet = t != 0x0800_u16
            },
            Err(err) => {
                if err.kind() == ErrorKind::UnexpectedEof { is_eof = true }
                else { println!("Che-to poshlo ne tak..."); return Ok(()) }
            }
        }

        if is_eof { break }

        let mut event: pcap::Event = unsafe { mem::zeroed() };
        unsafe {
            let caplen = packet.header.caplen as usize;
            let struct_slice = slice::from_raw_parts_mut(&mut event as *mut _ as *mut u8, caplen - SIZE_LINK_HEADER);
            let result = file.read_exact(struct_slice);
            match result {
                Ok(()) => {
                    packet.event = event;
                }

                Err(err) => {
                    if err.kind() == ErrorKind::UnexpectedEof { is_eof = true }
                    else { println!("Che-to poshlo ne tak... {}", err.kind()); return Ok(()) }
                },
            }
        }

        if ignore_packet { continue }
        packets.push(packet);
    }

    println!("N = {}", packets.len());
    thread::sleep(Duration::from_secs_f32(1.0));

    let mut syn_count = 0;
    let mut ack_count = 0;

    for packet in packets {
        // let id = packet.event.ip.id.to_be();
        // println!("Id -> {}", id);
        let flags = unsafe { packet.event.proto.tcp.flags }.to_be();
        let syn = (flags & 0b00000001) > 0;
        let ack = (flags & 0b00010000) > 0;
        if syn { syn_count += 1 }
        if ack { ack_count += 1 }
        // println!("{flags:08b} -> {ack}, {syn}\n");
        // thread::sleep(Duration::from_secs_f32(0.1));
    }

    println!("SYN: {}, ACK: {}", syn_count, ack_count);


    // let first_packet = packets[0];
    // let begin_timestamp = first_packet.header.timestamp;
    // let begin_sec = begin_timestamp.sec; let begin_usec = begin_timestamp.usec;
    
    // for i in 0..(packets.len()-1) {
    //     let packets = [packets[i], packets[i + 1]];
    //     let timestamps = packets.map(|p| {p.header.timestamp});
    //     // println!("{:#?}, {:#?}", timestamps[0], timestamps[1]);
    //     let mut sec = timestamps[1].sec - timestamps[0].sec;
    //     let mut usec = 0_u32;
    //     if timestamps[0].usec > timestamps[1].usec {
    //         sec -= 1;
    //         usec = (1000000 + timestamps[1].usec) - timestamps[0].usec;
    //     } else {usec = timestamps[1].usec - timestamps[0].usec }
        
    //     println!("{} <-T-> {} = {}.{:06}", i, i + 1, sec, usec);
    // }

    Ok(())
}

fn read<T>(file: &mut fs::File) -> Result<T, Error> {
    let mut buffer: T = unsafe { mem::zeroed() };
    let size = mem::size_of::<T>();
    unsafe {
        let struct_slice = slice::from_raw_parts_mut(&mut buffer as *mut _ as *mut u8, size);
        let result = file.read_exact(struct_slice);
        if let Some(err) = result.err() {
            return Err(err);
        }
    }
    return Ok(buffer);
}
