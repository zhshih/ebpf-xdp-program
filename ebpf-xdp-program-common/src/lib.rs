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

/// Cumulative SYN-packet and byte counters for one source IPv4 address.
///
/// Shared between kernel-space (eBPF) and user-space via an
/// `LruPerCpuHashMap<u32, SynCounter>` BPF map named `SYN_TRACKER`, keyed by
/// the big-endian u32 representation of the source address
/// (`u32::from_be_bytes(ip.src_addr)` in the kernel, `Ipv4Addr::from(key)`
/// in user-space — both treat the 4 bytes as big-endian octets).
#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct SynCounter {
    pub packets: u64,
    pub bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SynCounter {}

/// Fixed capacity of the `SYN_TRACKER` LRU hash map.
///
/// BPF map sizes are set at program-load time, so this is a compile-time
/// constant shared by both crates, not a runtime config option like the
/// alert thresholds in `ebpf-xdp-program`'s `config.rs`.
pub const SYN_TRACKER_MAX_ENTRIES: u32 = 8192;

/// Compound key for the `PORT_SCAN_TRACKER` map, one entry per distinct
/// (source IP, destination port) pair touched by a bare TCP SYN.
///
/// Same byte-order convention as `SynCounter`'s key: `src_addr` is
/// big-endian, `dst_port` is host-order. `_pad` keeps the derived
/// `Hash`/`Eq` from seeing uninitialized padding bytes — construct via
/// `new()`, not a struct literal.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Pod, Zeroable)]
pub struct PortScanKey {
    pub src_addr: u32,
    pub dst_port: u16,
    pub _pad: u16,
}

impl PortScanKey {
    pub fn new(src_addr: u32, dst_port: u16) -> Self {
        Self {
            src_addr,
            dst_port,
            _pad: 0,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PortScanKey {}

/// Last-touch timestamp for one `PortScanKey`, from `bpf_ktime_get_ns()`.
///
/// Always overwritten, never incremented, so — unlike `SynCounter` —
/// there's no read-modify-write race across CPUs and no need for a
/// per-CPU map.
#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct PortTouch {
    pub last_seen_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PortTouch {}

/// Fixed capacity of the `PORT_SCAN_TRACKER` LRU hash map.
///
/// Larger than `SYN_TRACKER_MAX_ENTRIES` since this key space is
/// (IP × port), not just IP.
pub const PORT_SCAN_TRACKER_MAX_ENTRIES: u32 = 16384;

/// Protocol bucket discriminant used as a BPF map index.
///
/// Indices 0–4 are stable across the kernel/user boundary and must not be reordered.
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

    #[test]
    fn syn_counter_zeroed() {
        let s = SynCounter::zeroed();
        assert_eq!(s.packets, 0);
        assert_eq!(s.bytes, 0);
    }

    #[test]
    fn port_touch_zeroed() {
        let t = PortTouch::zeroed();
        assert_eq!(t.last_seen_ns, 0);
    }

    #[test]
    fn port_scan_key_new_zeroes_pad() {
        let k = PortScanKey::new(0x0102_0304, 443);
        assert_eq!(k.src_addr, 0x0102_0304);
        assert_eq!(k.dst_port, 443);
        assert_eq!(k._pad, 0);
    }

    #[test]
    fn port_scan_key_equality_ignores_construction_path() {
        let a = PortScanKey::new(1, 80);
        let b = PortScanKey {
            src_addr: 1,
            dst_port: 80,
            _pad: 0,
        };
        assert_eq!(a, b);
    }
}
