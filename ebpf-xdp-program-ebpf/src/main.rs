#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerCpuArray,
    programs::XdpContext,
};
use core::{mem, ptr};
use ebpf_xdp_program_common::{ProtoIndex, ProtoStats};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};

#[map(name = "PROTO_STATS")]
static mut PROTO_STATS: PerCpuArray<ProtoStats> = PerCpuArray::<ProtoStats>::with_max_entries(5, 0);

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

fn parse_l4_protocol(ctx: &XdpContext) -> Option<IpProto> {
    let eth = parse_ethhdr(ctx)?;
    if eth != EtherType::Ipv4.into() {
        return None;
    }

    let ip = parse_ipv4hdr(ctx)?;
    Some(ip)
}

fn parse_ethhdr(ctx: &XdpContext) -> Option<u16> {
    let eth = ptr_at::<EthHdr>(ctx, 0)?;
    let ether_type = unsafe { (*eth).ether_type };
    Some(ether_type)
}

fn parse_ipv4hdr(ctx: &XdpContext) -> Option<IpProto> {
    let offset = mem::size_of::<EthHdr>();
    let ip = ptr_at::<Ipv4Hdr>(ctx, offset)?;

    let proto = unsafe { (*ip).proto };
    Some(proto)
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

    if let Some(proto) = parse_l4_protocol(&ctx) {
        let idx = proto_to_index(proto);

        unsafe {
            if let Some(stat) = (*ptr::addr_of_mut!(PROTO_STATS)).get_ptr_mut(idx) {
                (*stat).packets += 1;
                (*stat).bytes += bytes;
            }
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
