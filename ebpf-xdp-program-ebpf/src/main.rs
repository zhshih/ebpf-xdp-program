#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerCpuArray,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::ptr;

#[map(name = "PKT_CNT")]
static mut PKT_CNT: PerCpuArray<u64> = PerCpuArray::<u64>::with_max_entries(1, 0);

#[xdp]
pub fn ebpf_xdp_program(ctx: XdpContext) -> u32 {
    match try_ebpf_xdp_program(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_ebpf_xdp_program(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    let key: u32 = 0;

    let cnt = unsafe {
        let map = ptr::addr_of_mut!(PKT_CNT);
        (*map).get_ptr_mut(key)
    };

    unsafe {
        if let Some(counter) = cnt {
            *counter += 1;
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
