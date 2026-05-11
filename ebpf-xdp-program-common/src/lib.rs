#![no_std]
use bytemuck::{Pod, Zeroable};

/// Cumulative packet and byte counters for a single protocol bucket.
///
/// Shared between kernel-space (eBPF) and user-space via a `PerCpuArray` BPF map.
/// The `#[repr(C)]` layout must remain stable — any reordering breaks the ABI.
#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct ProtoStats {
    pub packets: u64,
    pub bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProtoStats {}

/// Protocol bucket discriminant used as a BPF map index.
///
/// Indices 0–4 are stable across the kernel/user boundary and must not be reordered.
/// `COUNT = 5` is the total number of tracked protocols.
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
    /// Total number of tracked protocol buckets. Must equal the BPF map capacity.
    pub const COUNT: u32 = 5;

    /// Human-readable label used in logging and Prometheus metric labels.
    pub fn label(self) -> &'static str {
        match self {
            ProtoIndex::Icmp => "ICMP",
            ProtoIndex::Tcp => "TCP",
            ProtoIndex::Udp => "UDP",
            ProtoIndex::Ipv6 => "IPv6",
            ProtoIndex::Other => "OTHER",
        }
    }

    /// Fallible index-to-variant conversion, safe to call in loops over `0..COUNT`.
    /// Returns `None` for any index >= 5.
    pub fn from_index(idx: usize) -> Option<Self> {
        Self::try_from(idx).ok()
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Zeroable;

    use super::*;

    #[test]
    fn proto_index_from_index_valid() {
        assert_eq!(ProtoIndex::from_index(0), Some(ProtoIndex::Icmp));
        assert_eq!(ProtoIndex::from_index(1), Some(ProtoIndex::Tcp));
        assert_eq!(ProtoIndex::from_index(2), Some(ProtoIndex::Udp));
        assert_eq!(ProtoIndex::from_index(3), Some(ProtoIndex::Ipv6));
        assert_eq!(ProtoIndex::from_index(4), Some(ProtoIndex::Other));
    }

    #[test]
    fn proto_index_from_index_invalid() {
        assert_eq!(ProtoIndex::from_index(5), None);
        assert_eq!(ProtoIndex::from_index(100), None);
    }

    #[test]
    fn proto_index_label() {
        assert_eq!(ProtoIndex::Icmp.label(), "ICMP");
        assert_eq!(ProtoIndex::Tcp.label(), "TCP");
        assert_eq!(ProtoIndex::Udp.label(), "UDP");
        assert_eq!(ProtoIndex::Ipv6.label(), "IPv6");
        assert_eq!(ProtoIndex::Other.label(), "OTHER");
    }

    #[test]
    fn proto_index_count() {
        assert_eq!(ProtoIndex::COUNT, 5);
    }

    #[test]
    fn proto_index_tryfrom_roundtrip() {
        for i in 0..ProtoIndex::COUNT as usize {
            let proto = ProtoIndex::try_from(i).expect("valid index should convert");
            assert_eq!(proto as usize, i);
        }
    }

    #[test]
    fn proto_stats_zeroed() {
        let s = ProtoStats::zeroed();
        assert_eq!(s.packets, 0);
        assert_eq!(s.bytes, 0);
    }
}
