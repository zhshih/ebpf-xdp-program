#![no_std]
use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct ProtoStats {
    pub packets: u64,
    pub bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProtoStats {}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ProtoIndex {
    Icmp = 0,
    Tcp = 1,
    Udp = 2,
    Ipv6 = 3,
    Other = 4,
}

impl ProtoIndex {
    pub const COUNT: u32 = 5;

    pub fn label(self) -> &'static str {
        match self {
            ProtoIndex::Icmp => "ICMP",
            ProtoIndex::Tcp => "TCP",
            ProtoIndex::Udp => "UDP",
            ProtoIndex::Ipv6 => "IPv6",
            ProtoIndex::Other => "OTHER",
        }
    }
}
