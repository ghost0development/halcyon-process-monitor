#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{tracepoint, map},
    programs::TracePointContext,
    maps::PerfEventArray,
    helpers::{
        bpf_get_current_comm,
        bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
        bpf_probe_read_user_buf,
    },
};

pub const EVENT_EXECVE: u32 = 1;
pub const EVENT_OPENAT: u32 = 2;
pub const EVENT_FILENAME_LEN: usize = 64;
pub const EVENT_COMM_LEN: usize = 16;

#[repr(C)]
pub struct ProcessEvent {
    pub event_type: u32,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; EVENT_COMM_LEN],
    pub filename: [u8; EVENT_FILENAME_LEN],
}

#[map]
pub static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[tracepoint(name = "sys_enter_execve", category = "syscalls")]
pub fn sys_enter_execve(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_execve(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_execve(ctx: TracePointContext) -> Result<i32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let mut event = ProcessEvent {
        event_type: EVENT_EXECVE,
        pid,
        uid,
        comm: [0u8; EVENT_COMM_LEN],
        filename: [0u8; EVENT_FILENAME_LEN],
    };

    let raw_comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    event.comm.copy_from_slice(&raw_comm);

    let filename_ptr: *const u8 = ctx.read_at(16)?;
    if !filename_ptr.is_null() {
        bpf_probe_read_user_buf(filename_ptr, &mut event.filename)?;
    }

    EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

#[tracepoint(name = "sys_enter_openat", category = "syscalls")]
pub fn sys_enter_openat(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_openat(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_openat(ctx: TracePointContext) -> Result<i32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let mut event = ProcessEvent {
        event_type: EVENT_OPENAT,
        pid,
        uid,
        comm: [0u8; EVENT_COMM_LEN],
        filename: [0u8; EVENT_FILENAME_LEN],
    };

    let raw_comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    event.comm.copy_from_slice(&raw_comm);

    let filename_ptr: *const u8 = ctx.read_at(24)?;
    if !filename_ptr.is_null() {
        bpf_probe_read_user_buf(filename_ptr, &mut event.filename)?;
    }

    EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
