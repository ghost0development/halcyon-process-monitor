use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{Ebpf, Pod};
use bytes::BytesMut;
use chrono::Local;
use clap::Parser;
use colored::*;
use log::{error, info};
use serde::Serialize;
use tokio::sync::broadcast;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "target/bpfel-unknown-none/release/process-monitor-ebpf")]
    bpf: String,

    #[arg(long, default_value_t = 50)]
    alert_threshold: u32,

    #[arg(long, default_value_t = false)]
    json: bool,

    #[arg(long, default_value_t = false)]
    serve: bool,

    #[arg(long, default_value_t = 3030)]
    port: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct ProcessEvent {
    event_type: u32,
    pid: u32,
    uid: u32,
    comm: [u8; 16],
    filename: [u8; 64],
}

unsafe impl Pod for ProcessEvent {}

#[derive(Clone, Serialize)]
struct EventJson {
    time: String,
    event: String,
    pid: u32,
    uid: u32,
    comm: String,
    file: String,
    ransomware: bool,
}

struct RansomwareDetector {
    open_counts: std::collections::HashMap<u32, (u64, u32)>,
    alert_cooldown: std::collections::HashMap<u32, u64>,
    threshold: u32,
}

impl RansomwareDetector {
    fn new(threshold: u32) -> Self {
        Self {
            open_counts: std::collections::HashMap::new(),
            alert_cooldown: std::collections::HashMap::new(),
            threshold,
        }
    }

    fn record_open(&mut self, pid: u32, now_secs: u64) -> bool {
        let window = 5;
        let entry = self.open_counts.entry(pid).or_insert((now_secs, 0));
        if now_secs - entry.0 > window {
            entry.0 = now_secs;
            entry.1 = 0;
        }
        entry.1 += 1;
        if entry.1 > self.threshold {
            let can_warn = self
                .alert_cooldown
                .get(&pid)
                .map(|last| now_secs - *last > 30)
                .unwrap_or(true);
            if can_warn {
                self.alert_cooldown.insert(pid, now_secs);
                return true;
            }
        }
        false
    }
}

fn comm_str(comm: &[u8; 16]) -> String {
    String::from_utf8_lossy(&comm[..comm.iter().position(|&c| c == 0).unwrap_or(16)]).to_string()
}

fn filename_str(name: &[u8; 64]) -> String {
    String::from_utf8_lossy(&name[..name.iter().position(|&c| c == 0).unwrap_or(64)]).to_string()
}

fn event_to_json(event: &ProcessEvent, risk: bool) -> EventJson {
    let ts = Local::now().format("%H:%M:%S%.3f");
    let kind = match event.event_type {
        1 => "EXEC",
        2 => "OPEN",
        _ => "UNKN",
    };
    EventJson {
        time: ts.to_string(),
        event: kind.to_string(),
        pid: event.pid,
        uid: event.uid,
        comm: comm_str(&event.comm),
        file: filename_str(&event.filename),
        ransomware: risk,
    }
}

fn print_event(event: &ProcessEvent, risk: bool, json: bool) {
    let ts = Local::now().format("%H:%M:%S%.3f");
    let comm = comm_str(&event.comm);
    let file = filename_str(&event.filename);
    let kind = match event.event_type {
        1 => "EXEC",
        2 => "OPEN",
        _ => "UNKN",
    };

    if json {
        println!(
            r#"{{"time":"{ts}","event":"{kind}","pid":{},"uid":{},"comm":"{comm}","file":"{file}","ransomware":{risk}}}"#,
            event.pid, event.uid,
        );
        return;
    }

    let color = if risk {
        format!("{kind}").red().bold()
    } else {
        match event.event_type {
            1 => format!("{kind}").green(),
            _ => format!("{kind}").cyan(),
        }
    };

    println!(
        "[{ts}] {color:<6} pid={pid:<7} uid={uid:<4} {comm} {file}",
        color = color,
        pid = event.pid,
        uid = event.uid,
        comm = comm,
        file = file,
    );

    if risk {
        eprintln!("[ALERT] pid={} comm={} opened {} files in 5s window", event.pid, comm, 50);
    }
}

async fn handle_perf_buffer(
    mut buf: aya::maps::perf::AsyncPerfEventArrayBuffer<aya::maps::MapData>,
    mut detector: RansomwareDetector,
    json: bool,
    serve: bool,
    tx: Option<broadcast::Sender<EventJson>>,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let mut out_bufs = (0..10)
        .map(|_| BytesMut::with_capacity(4096))
        .collect::<Vec<_>>();

    while running.load(Ordering::Relaxed) {
        let events = buf.read_events(&mut out_bufs).await?;

        for i in 0..events.read {
            let buf = &out_bufs[i];
            if buf.len() < std::mem::size_of::<ProcessEvent>() {
                continue;
            }

            let event: ProcessEvent =
                unsafe { std::ptr::read(buf.as_ptr() as *const ProcessEvent) };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let risk = if event.event_type == 2 {
                detector.record_open(event.pid, now)
            } else {
                false
            };

            let ej = event_to_json(&event, risk);

            if serve {
                if let Some(ref tx) = tx {
                    let _ = tx.send(ej.clone());
                }
            } else {
                print_event(&event, risk, json);
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .context("failed to set Ctrl-C handler")?;

    // -- eBPF setup --
    info!("Loading eBPF program from {}", args.bpf);
    let mut bpf = Ebpf::load_file(&args.bpf).context("failed to load eBPF object")?;

    info!("Attaching sys_enter_execve tracepoint");
    let program: &mut TracePoint = bpf
        .program_mut("sys_enter_execve")
        .context("failed to get sys_enter_execve program")?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    info!("Attaching sys_enter_openat tracepoint");
    let program: &mut TracePoint = bpf
        .program_mut("sys_enter_openat")
        .context("failed to get sys_enter_openat program")?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_openat")?;

    info!("Opening perf event array");
    let mut perf_array: AsyncPerfEventArray<_> =
        AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").context("failed to get EVENTS map")?)?;

    // -- broadcast channel for serve mode --
    let (tx, _rx) = broadcast::channel::<EventJson>(256);

    let mut tasks = Vec::new();

    for cpu_id in online_cpus().map_err(|(_, e)| e)? {
        let buf = perf_array
            .open(cpu_id, None)
            .context(format!("failed to open perf buffer for CPU {cpu_id}"))?;

        let detector = RansomwareDetector::new(args.alert_threshold);
        let running = running.clone();
        let tx = if args.serve { Some(tx.clone()) } else { None };

        tasks.push(tokio::spawn(async move {
            if let Err(e) =
                handle_perf_buffer(buf, detector, args.json, args.serve, tx, running).await
            {
                error!("Perf buffer task error: {e}");
            }
        }));
    }

    // -- serve mode: HTTP dashboard --
    if args.serve {
        let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
        info!("Starting web dashboard on http://{addr}");

        let app = axum::Router::new()
            .route("/", axum::routing::get(dashboard_handler))
            .route("/events", axum::routing::get(sse_handler))
            .with_state(tx.clone());

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        return Ok(());
    }

    // -- CLI mode --
    info!("Process monitor started. Press Ctrl+C to stop.");
    println!("{}", "=".repeat(80));
    println!("{:<9} {:<6} {:<12} {:<6} {:<16} {:<10}", "TIME", "EVENT", "PID", "UID", "COMM", "FILE");
    println!("{}", "=".repeat(80));

    for task in tasks {
        task.await?;
    }

    Ok(())
}

async fn dashboard_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../dashboard/index.html"))
}

use axum::extract::State;
use axum::response::sse::{Event, Sse};
use futures::stream::Stream;
use std::convert::Infallible;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

async fn sse_handler(
    State(tx): State<broadcast::Sender<EventJson>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let data = serde_json::to_string(&event).unwrap_or_default();
            Some(Ok(Event::default().data(data)))
        }
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(5))
            .text("ping"),
    )
}
