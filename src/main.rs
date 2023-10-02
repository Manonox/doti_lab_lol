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

    let mut time_axis = Vec::<i64>::default();
    time_axis.push(0);
    let mut syn_axis = Vec::<i32>::default();
    let mut syn_count = 0;
    let mut synack_axis = Vec::<i32>::default();
    let mut synack_count = 0;
    syn_axis.push(syn_count); synack_axis.push(synack_count);
    let mut csv_content = String::new();

    let mut begin_time_option: Option<i64> = None;

    packets.iter().for_each(|x| {
        if x.event.ip.protocol != 6_u8 { return }
        if x.is_syn() { syn_count += 1 }
        if x.is_synack() { synack_count += 1 }

        let mut time = x.header.timestamp.as_usec();
        if begin_time_option.is_none() {
            begin_time_option = Some(time);
        }

        time -= begin_time_option.unwrap();

        time_axis.push(time);
        syn_axis.push(syn_count);
        synack_axis.push(synack_count);

        csv_content.push_str(format!("{},{}\n", time, syn_count - synack_count).as_str());
        // thread::sleep(Duration::from_secs_f32(1.0));
    });

    fs::write("plot.csv", csv_content)?;
    println!("Saved plot");
    println!("[SYN]: {}, [SYN, ACK]: {}", syn_count, synack_count);


    let mut csv_time_between_packets = String::new();
    thread::sleep(Duration::from_secs_f32(1.0));
    let mut i = 0;
    for w in packets.windows(2) {
        let p1 = &w[0]; let p2 = &w[1];
        let usec = p2.header.timestamp.as_usec() - p1.header.timestamp.as_usec();
        let sec = (usec as f64) / 1000000.0;
        csv_time_between_packets.push_str(format!("{},{:.6}\n", i, sec).as_str());
        i += 1;
    }
    fs::write("time_between_packets.csv", csv_time_between_packets)?;

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
