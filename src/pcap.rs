#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileHeader {
    pub magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: u32,
    pub sigfigs: u32,
    pub snap_len: u32,
    pub linktype: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TimeValue {
    pub sec: u32,
    pub usec: u32,
}

impl TimeValue {
    pub fn as_usec(&self) -> i64 {
        return (self.sec as i64) * 1000000 + (self.usec as i64)
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketHeader {
    pub timestamp: TimeValue,
    pub caplen: u32,
    pub len: u32,
}


#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IPHeader {
    pub ihl_version: u8,
    pub tos: u8,
    pub total_length: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub source_addr: u32,
    pub destination_addr: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ICMPEcho {
    pub echo_id: u16,
    pub echo_sequence: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ICMPFrag {
    pub frag_reserved: u16,
    pub frag_mtu: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub union ICMPHeaderType {
    pub echo: ICMPEcho,
    pub gateway: u32,
    pub frag: ICMPFrag
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ICMPHeader {
    pub header_type: u8,
    pub code: u8,
    pub checksum: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TCPHeader {
    pub source_port: u16,
	pub dest_port: u16,
	pub seq: u32,
	pub ack_seq: u32,
	pub res: u8,
	pub flags: u8,
	pub window: u16,
	pub check: u16,
	pub urg_ptr: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyHeader {
    trash: [u8; 20]
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub union ProtoHeader {
    pub empty: EmptyHeader,
    pub icmp: ICMPHeader,
    pub tcp: TCPHeader,
    // udp: UDPHeader,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Event {
    pub ip: IPHeader,
    pub proto: ProtoHeader,

    pub reserved: [u8; 1024],
}


#[derive(Clone, Copy)]
pub struct Packet {
    pub header: PacketHeader,
    pub event: Event,
}

impl Packet {
    pub fn is_syn(&self) -> bool {
        let flags = unsafe { self.event.proto.tcp.flags }.to_be();
        //return (flags & 0b00000010) > 0;
        return flags == 0b00000010;
    }

    pub fn is_synack(&self) -> bool {
        let flags = unsafe { self.event.proto.tcp.flags };
        //return (flags & 0b00010000) > 0 && (flags & 0b00000010) > 0;
        return flags == 0b00010010;
    }
}

impl Default for Packet {
    fn default() -> Self {
        Packet {
            header: Default::default(),
            event: Event {
                ip: Default::default(),
                proto: ProtoHeader {
                    empty: EmptyHeader::default()
                },
                reserved: [0; 1024],
            }
        }
    }
}
