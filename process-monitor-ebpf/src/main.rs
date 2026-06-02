#![no_std]
#![no_main]

use core::ptr::addr_of_mut;

use aya_ebpf::{
    macros::{btf_tracepoint, map},
    programs::BtfTracePointContext,
    maps::PerfEventArray,
    helpers::{
        bpf_get_current_comm,
        bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
    },
};

pub const EVENT_EXECVE: u8 = 0;
pub const EVENT_OPENAT: u8 = 1;
pub const EVENT_FILENAME_LEN: usize = 64;
pub const EVENT_COMM_LEN: usize = 16;

#[repr(C)]
pub struct ProcessEvent {
    pub event_type: u8,
    pub pid: u32,
    pub uid: u32,
    pub comm: [i8; EVENT_COMM_LEN],
    pub filename: [i8; EVENT_FILENAME_LEN],
}

#[map]
pub static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[btf_tracepoint(function = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: BtfTracePointContext) -> i32 {
    match unsafe { try_sys_enter_execve(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_execve(ctx: BtfTracePointContext) -> Result<i32, i32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let mut event = ProcessEvent {
        event_type: EVENT_EXECVE,
        pid,
        uid,
        comm: [0i8; EVENT_COMM_LEN],
        filename: [0i8; EVENT_FILENAME_LEN],
    };

    let raw_comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    for (i, &b) in raw_comm.iter().enumerate() {
        event.comm[i] = b as i8;
    }

    let filename_ptr: *const i8 = ctx.arg(0);
    if !filename_ptr.is_null() {
        core::ptr::copy_nonoverlapping(
            filename_ptr,
            addr_of_mut!(event.filename).cast(),
            EVENT_FILENAME_LEN,
        );
    }

    EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

#[btf_tracepoint(function = "sys_enter_openat")]
pub fn sys_enter_openat(ctx: BtfTracePointContext) -> i32 {
    match unsafe { try_sys_enter_openat(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_openat(ctx: BtfTracePointContext) -> Result<i32, i32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let mut event = ProcessEvent {
        event_type: EVENT_OPENAT,
        pid,
        uid,
        comm: [0i8; EVENT_COMM_LEN],
        filename: [0i8; EVENT_FILENAME_LEN],
    };

    let raw_comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    for (i, &b) in raw_comm.iter().enumerate() {
        event.comm[i] = b as i8;
    }

    let filename_ptr: *const i8 = ctx.arg(1);
    if !filename_ptr.is_null() {
        core::ptr::copy_nonoverlapping(
            filename_ptr,
            addr_of_mut!(event.filename).cast(),
            EVENT_FILENAME_LEN,
        );
    }

    EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
