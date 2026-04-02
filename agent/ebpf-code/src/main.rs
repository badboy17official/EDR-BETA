#![no_std]
#![no_main]

use aya_bpf::{
    helpers::bpf_get_current_pid_tgid,
    helpers::bpf_get_current_uid_gid,
    helpers::bpf_get_current_comm,
    macros::{tracepoint, map},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use ebpf_common::ExecveEvent;

// Create a perf event array ring buffer to send events to userspace
#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<ExecveEvent> = PerfEventArray::with_max_entries(1024, 0);

#[tracepoint(name = "ebpf_code")]
pub fn ebpf_code(ctx: TracePointContext) -> u32 {
    match try_ebpf_code(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ebpf_code(ctx: TracePointContext) -> Result<u32, u32> {
    // bpf_get_current_pid_tgid returns tgid (pid) in upper 32 bits, pid (tid) in lower 32
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    let mut event = ExecveEvent {
        pid,
        ppid: 0, // Simplified for now, getting PPID in eBPF requires task_struct walking
        uid,
        filename: [0; 128],
        comm: [0; 16],
    };

    // Grab current task name (the process calling execve)
    let _ = bpf_get_current_comm(&mut event.comm);

    // Read the filename from the tracepoint argument. 
    // In sys_enter_execve, filename pointer is usually argument 1 (offset 16 on x86_64 after common fields)
    let filename_ptr: u64 = unsafe { ctx.read_at(16).unwrap_or(0) };
    if filename_ptr != 0 {
        // Read string from user space memory
        let _ = unsafe { aya_bpf::helpers::bpf_probe_read_user_str(event.filename.as_mut_ptr() as *mut u8, 128, filename_ptr as *const u8) };
    }

    // Ship the event to User-space
    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
