use anyhow::Context as _;
use aya::{
    maps::PerCpuArray,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use std::time::Duration;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlo1")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let opt = Opt::parse();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf-xdp-program"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("ebpf_xdp_program").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let pkt_cnt = PerCpuArray::try_from(ebpf.map("PKT_CNT").context("PKT_CNT map not found")?)?;

    let mut ticker = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let key: u32 = 0;

                let values = pkt_cnt
                    .get(&key, 0)
                    .context("failed to read PKT_CNT")?;

                let total: u64 = values.iter().sum();
                tracing::info!("packets: {}", total);
            }
            _ = signal::ctrl_c() => {
                tracing::info!("Exiting...");
                break;
            }
        }
    }

    Ok(())
}
