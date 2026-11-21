//! rustos-process — process management for a Rust OS.
//!
//! * `pcb` — [`ProcessControlBlock`]: pid, state, priority, stacks,
//!   address-space id, exit code, children, saved CPU context.
//! * `table` — [`ProcessTable`]: fixed-capacity table; PID 0 = idle,
//!   PID 1 = init. PID allocation reuses the lowest free PID.
//! * `scheduler` — round-robin [`Scheduler`] over the process table.
//! * `elf` — ELF64 loader: validation (same checks as
//!   `rustos-bootloader`) + `PT_LOAD` parsing, loading through a
//!   caller-supplied [`SegmentWriter`] so it is host-testable.
//! * `address_space` — per-process address space: user/kernel split,
//!   user-stack mapping, `switch_to` (loads CR3 on real hardware).
//! * `syscall` — syscall numbers, **identical to `rustos-shell`**:
//!   read=0, write=1, open=2, close=3, yield=24, exit=60, plus
//!   spawn=57, wait=61, getpid=39 — and a pure [`dispatch`] function
//!   testable on the host against a fake kernel state.
//!
//! The crate is `#![no_std]` outside tests (`core` + `alloc` only, no
//! external crates) so it can link into the kernel. Tests run on the
//! host with std.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod address_space;
pub mod elf;
pub mod pcb;
pub mod scheduler;
pub mod syscall;
pub mod table;

pub use address_space::{AddressSpace, MapError, PageMapper};
pub use elf::{ElfError, ParsedElf, ProgramHeader, SegmentWriter};
pub use pcb::{CpuContext, ProcessControlBlock, ProcessState};
pub use scheduler::Scheduler;
pub use syscall::{
    dispatch, syscall_name, FakeKernelState, SyscallOutcome, ALL_SYSCALLS, FD_STDERR, FD_STDIN,
    FD_STDOUT, SYS_CLOSE, SYS_EXIT, SYS_GETPID, SYS_OPEN, SYS_READ, SYS_SPAWN, SYS_WAIT,
    SYS_WRITE, SYS_YIELD,
};
pub use table::{ProcessError, ProcessTable, MAX_PROCESSES};
