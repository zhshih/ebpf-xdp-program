#![no_std]
#![no_main]

use core::{mem, ptr};

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{LruPerCpuHashMap, PerCpuArray},
    programs::XdpContext,
};
use ebpf_xdp_program_common::{ProtoIndex, ProtoStats, SYN_TRACKER_MAX_ENTRIES, SynCounter};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
};

#[map(name = "PROTO_STATS")]
static mut PROTO_STATS: PerCpuArray<ProtoStats> = PerCpuArray::<ProtoStats>::with_max_entries(5, 0);

/// Per-source-IPv4 SYN/byte counters, keyed by the big-endian u32 form of
/// the source address. LRU-evicting so inserts never fail regardless of how
/// many distinct source IPs are seen — bounds kernel memory even under an
/// attacker deliberately rotating source addresses. Per-CPU (like
/// `PROTO_STATS`) so concurrent updates from different RX queues never race
/// on the same counter; user-space sums across CPUs when reading.
#[map(name = "SYN_TRACKER")]
static mut SYN_TRACKER: LruPerCpuHashMap<u32, SynCounter> =
    LruPerCpuHashMap::<u32, SynCounter>::with_max_entries(SYN_TRACKER_MAX_ENTRIES, 0);

#[inline(always)]
fn packet_len(ctx: &XdpContext) -> u64 {
    (ctx.data_end() - ctx.data()) as u64
}

#[inline(always)]
fn ptr_at<T>(ctx: &aya_ebpf::programs::XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

/// Result of parsing the Ethernet + IP layers of a frame.
///
/// `src_addr`/`ip_hdr_len` are only meaningful for `IpProto::Ipv6`'s sibling
/// IPv4 case — the Ipv6 branch below sets them to 0 since SYN-flood tracking
/// is IPv4-only (the `SYN_TRACKER` map is keyed by a 32-bit address).
struct L3Info {
    proto: IpProto,
    src_addr: u32,
    ip_hdr_len: usize,
}

fn parse_l4_protocol(ctx: &XdpContext) -> Option<L3Info> {
    let eth = parse_ethhdr(ctx)?;
    if eth == EtherType::Ipv4.into() {
        parse_ipv4hdr(ctx)
    } else if eth == EtherType::Ipv6.into() {
        // Bounds-check the IPv6 header; count the frame in the IPv6 bucket.
        ptr_at::<Ipv6Hdr>(ctx, mem::size_of::<EthHdr>())?;
        Some(L3Info {
            proto: IpProto::Ipv6,
            src_addr: 0,
            ip_hdr_len: 0,
        })
    } else {
        None
    }
}

fn parse_ethhdr(ctx: &XdpContext) -> Option<u16> {
    let eth = ptr_at::<EthHdr>(ctx, 0)?;
    let ether_type = unsafe { (*eth).ether_type };
    Some(ether_type)
}

fn parse_ipv4hdr(ctx: &XdpContext) -> Option<L3Info> {
    let offset = mem::size_of::<EthHdr>();
    let ip = ptr_at::<Ipv4Hdr>(ctx, offset)?;

    let proto = unsafe { (*ip).proto };
    // Network-order octets; `from_be_bytes` keeps the numeric value
    // consistent with how user-space reconstructs `Ipv4Addr::from(u32)`.
    let src_addr = unsafe { u32::from_be_bytes((*ip).src_addr) };
    let ip_hdr_len = unsafe { (*ip).ihl() } as usize;
    Some(L3Info {
        proto,
        src_addr,
        ip_hdr_len,
    })
}

/// Returns `Some(true)` for a bare SYN (SYN=1, ACK=0) — the half-open-
/// connection-exhaustion signature a SYN flood relies on — `Some(false)`
/// for any other flag combination, `None` if the TCP header doesn't fit.
///
/// SYN-ACK responses are deliberately excluded: counting them would also
/// flag hosts that are merely the target of return traffic from a
/// reflection/amplification attack aimed elsewhere, a different attack
/// shape than what this detector targets.
#[inline(always)]
fn is_syn_packet(ctx: &XdpContext, ip_hdr_len: usize) -> Option<bool> {
    let offset = mem::size_of::<EthHdr>() + ip_hdr_len;
    let tcp = ptr_at::<TcpHdr>(ctx, offset)?;
    let (syn, ack) = unsafe { ((*tcp).syn(), (*tcp).ack()) };
    Some(syn != 0 && ack == 0)
}

#[inline(always)]
fn record_syn(src_addr: u32, bytes: u64) {
    unsafe {
        if let Some(counter) = (*ptr::addr_of_mut!(SYN_TRACKER)).get_ptr_mut(src_addr) {
            (*counter).packets += 1;
            (*counter).bytes += bytes;
        } else {
            let fresh = SynCounter { packets: 1, bytes };
            // Best-effort: with an LRU map `insert` practically never fails
            // (the kernel evicts an existing entry instead of returning
            // ENOSPC). Even if it did, a lost counter update must never
            // propagate into a dropped/aborted packet — this program stays
            // observe-only.
            let _ = (*ptr::addr_of_mut!(SYN_TRACKER)).insert(src_addr, fresh, 0);
        }
    }
}

fn proto_to_index(proto: IpProto) -> u32 {
    match proto {
        IpProto::Icmp => ProtoIndex::Icmp as u32,
        IpProto::Tcp => ProtoIndex::Tcp as u32,
        IpProto::Udp => ProtoIndex::Udp as u32,
        IpProto::Ipv6 => ProtoIndex::Ipv6 as u32,
        _ => ProtoIndex::Other as u32,
    }
}

#[xdp]
pub fn ebpf_xdp_program(ctx: XdpContext) -> u32 {
    match try_ebpf_xdp_program(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_ebpf_xdp_program(ctx: XdpContext) -> Result<u32, u32> {
    let bytes = packet_len(&ctx);

    if let Some(l3) = parse_l4_protocol(&ctx) {
        let idx = proto_to_index(l3.proto);

        unsafe {
            if let Some(stat) = (*ptr::addr_of_mut!(PROTO_STATS)).get_ptr_mut(idx) {
                (*stat).packets += 1;
                (*stat).bytes += bytes;
            }
        }

        if l3.proto == IpProto::Tcp && is_syn_packet(&ctx, l3.ip_hdr_len) == Some(true) {
            record_syn(l3.src_addr, bytes);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
