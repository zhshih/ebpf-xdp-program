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

impl TryFrom<usize> for ProtoIndex {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Icmp),
            1 => Ok(Self::Tcp),
            2 => Ok(Self::Udp),
            3 => Ok(Self::Ipv6),
            4 => Ok(Self::Other),
            _ => Err(()),
        }
    }
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

    pub fn from_index(idx: usize) -> Option<Self> {
        Self::try_from(idx).ok()
    }
}
