#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub filename: [u8; 128], // Path to the executable
    pub comm: [u8; 16],      // Command name of the caller
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecveEvent {}
