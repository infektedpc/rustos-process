//! Syscall numbers and dispatch.
//!
//! Numbers **must match `rustos-shell/src/syscall.rs` exactly**:
//!
//! | number | name   | signature |
//! |--------|--------|-----------|
//! | 0      | read   | `read(fd, buf, len)` |
//! | 1      | write  | `write(fd, buf, len)` |
//! | 2      | open   | `open(path, flags)` |
//! | 3      | close  | `close(fd)` |
//! | 24     | yield  | `yield()` |
//! | 39     | getpid | `getpid()` |
//! | 57     | spawn  | `spawn(path, ...)` |
//! | 60     | exit   | `exit(code)` — never returns |
//! | 61     | wait   | `wait(pid)` |
//! | 1000   | uptime | `uptime()` -> ms since boot (RustOS-private) |
//!
//! (39 = Linux's `getpid`, 57 = Linux's `fork` slot reused here for
//! `spawn` — RustOS has no `fork` (no COW yet), so `spawn` takes the
//! free slot — 60 = Linux's `exit`, 61 = Linux's `wait4` slot.)
//!
//! [`dispatch`] is pure and host-testable: it takes the syscall
//! number + three register args and a [`FakeKernelState`] standing
//! in for the real kernel (process table, open files, output). The
//! real kernel's handler will call the same logic with real state;
//! the numbers and the return-value conventions (-errno on error)
//! are the contract between the two.

/// read(fd, buf, len) -> bytes read, or negative errno.
pub const SYS_READ: u64 = 0;
/// write(fd, buf, len) -> bytes written, or negative errno.
pub const SYS_WRITE: u64 = 1;
/// open(path, flags) -> fd, or negative errno.
pub const SYS_OPEN: u64 = 2;
/// close(fd) -> 0, or negative errno.
pub const SYS_CLOSE: u64 = 3;
/// yield() -> 0. Voluntarily give up the CPU.
pub const SYS_YIELD: u64 = 24;
/// getpid() -> pid.
pub const SYS_GETPID: u64 = 39;
/// spawn(path, ...) -> new pid, or negative errno.
pub const SYS_SPAWN: u64 = 57;
/// exit(code) -> never returns.
pub const SYS_EXIT: u64 = 60;
/// wait(pid) -> exit code, or negative errno; blocks if not exited.
pub const SYS_WAIT: u64 = 61;

/// uptime() -> milliseconds since boot (PIT ticks * 10 at 100 Hz).
/// RustOS-private number: the low numbers are Linux's, and Linux has
/// no uptime syscall (`sysinfo` is 99 and returns a struct), so the
/// RustOS-private range starts at 1000 and uptime takes the first
/// slot. Added in Batch 9 for the userspace shell's `uptime` builtin.
pub const SYS_UPTIME: u64 = 1000;

/// Standard file descriptors.
pub const FD_STDIN: u64 = 0;
pub const FD_STDOUT: u64 = 1;
pub const FD_STDERR: u64 = 2;

/// Errno values returned as negative numbers (Linux-compatible).
pub const ERR_BADF: i64 = -9; // EBADF: bad file descriptor
pub const ERR_AGAIN: i64 = -11; // EAGAIN: try again (would block)
pub const ERR_NOSYS: i64 = -38; // ENOSYS: unknown syscall
pub const ERR_INVAL: i64 = -22; // EINVAL: invalid argument

/// Human-readable name for a syscall number, or "unknown".
pub fn syscall_name(n: u64) -> &'static str {
    match n {
        SYS_READ => "read",
        SYS_WRITE => "write",
        SYS_OPEN => "open",
        SYS_CLOSE => "close",
        SYS_YIELD => "yield",
        SYS_GETPID => "getpid",
        SYS_SPAWN => "spawn",
        SYS_EXIT => "exit",
        SYS_WAIT => "wait",
        SYS_UPTIME => "uptime",
        _ => "unknown",
    }
}

/// All defined syscalls, in number order.
pub const ALL_SYSCALLS: &[(u64, &str)] = &[
    (SYS_READ, "read"),
    (SYS_WRITE, "write"),
    (SYS_OPEN, "open"),
    (SYS_CLOSE, "close"),
    (SYS_YIELD, "yield"),
    (SYS_GETPID, "getpid"),
    (SYS_SPAWN, "spawn"),
    (SYS_EXIT, "exit"),
    (SYS_WAIT, "wait"),
    (SYS_UPTIME, "uptime"),
];

/// What a syscall did. `Returned` carries the value that goes in
/// `rax`; `Exited` means the calling process is finished (the
/// dispatcher must switch away, never return to it); `Blocked`
/// means the process must sleep until the waited-on event happens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallOutcome {
    Returned(i64),
    Exited(i32),
    Blocked,
}

/// Fake kernel state for host tests: stands in for the process
/// table + file table + console output the real kernel owns.
#[derive(Clone, Debug, Default)]
pub struct FakeKernelState {
    /// Pid of the "current" (calling) process.
    pub current_pid: u32,
    /// Next pid to hand out on `spawn`.
    pub next_pid: u32,
    /// Next fd to hand out on `open`.
    pub next_fd: u64,
    /// Bytes written to stdout/stderr via `write`.
    pub output: alloc::vec::Vec<u8>,
    /// True once the current process called `exit`.
    pub exited: bool,
    /// Exit code from `exit`, if any.
    pub exit_code: Option<i32>,
    /// True once the current process called `yield`.
    pub yielded: bool,
    /// Pids spawned by this process, in order.
    pub spawned: alloc::vec::Vec<u32>,
    /// Zombie children available to `wait`: (pid, exit code).
    pub zombies: alloc::vec::Vec<(u32, i32)>,
}

impl FakeKernelState {
    pub fn new(current_pid: u32) -> Self {
        Self {
            current_pid,
            next_pid: 100,
            next_fd: 3,
            ..Default::default()
        }
    }
}

/// Dispatch one syscall. Pure: all effects land in `state`.
/// `a0`, `a1`, `a2` are the syscall's register arguments
/// (fd / pointer / length, depending on the call).
pub fn dispatch(n: u64, a0: u64, a1: u64, a2: u64, state: &mut FakeKernelState) -> SyscallOutcome {
    use SyscallOutcome::*;
    match n {
        SYS_READ => {
            // No keyboard input wired up in the fake state: stdin
            // reads return 0 (EOF); any other fd is an error.
            if a0 == FD_STDIN {
                Returned(0)
            } else {
                Returned(ERR_BADF)
            }
        }
        SYS_WRITE => {
            if a0 != FD_STDOUT && a0 != FD_STDERR {
                return Returned(ERR_BADF);
            }
            if a2 > 1024 * 1024 {
                return Returned(ERR_INVAL);
            }
            // a1 is a user pointer to `a2` bytes. On the host test
            // this is a real pointer into test memory; in the kernel
            // the handler validates it against the caller's address
            // space first (same convention, different validator).
            let bytes = unsafe { core::slice::from_raw_parts(a1 as *const u8, a2 as usize) };
            state.output.extend_from_slice(bytes);
            Returned(a2 as i64)
        }
        SYS_OPEN => {
            let fd = state.next_fd;
            state.next_fd += 1;
            Returned(fd as i64)
        }
        SYS_CLOSE => {
            if a0 < 3 {
                Returned(ERR_BADF) // cannot close stdin/out/err
            } else {
                Returned(0)
            }
        }
        SYS_YIELD => {
            state.yielded = true;
            Returned(0)
        }
        SYS_GETPID => Returned(state.current_pid as i64),
        SYS_SPAWN => {
            let pid = state.next_pid;
            state.next_pid += 1;
            state.spawned.push(pid);
            Returned(pid as i64)
        }
        SYS_EXIT => {
            state.exited = true;
            state.exit_code = Some(a0 as i32);
            Exited(a0 as i32)
        }
        SYS_WAIT => {
            let pid = a0 as u32;
            if let Some(pos) = state.zombies.iter().position(|(p, _)| *p == pid) {
                let (_, code) = state.zombies.remove(pos);
                Returned(code as i64)
            } else if state.spawned.contains(&pid) {
                // Child exists but has not exited: block.
                Blocked
            } else {
                Returned(ERR_BADF)
            }
        }
        _ => Returned(ERR_NOSYS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_match_rustos_shell_exactly() {
        // These are the six numbers rustos-shell defines; a drift
        // here would silently break every userspace program.
        assert_eq!(SYS_READ, 0);
        assert_eq!(SYS_WRITE, 1);
        assert_eq!(SYS_OPEN, 2);
        assert_eq!(SYS_CLOSE, 3);
        assert_eq!(SYS_YIELD, 24);
        assert_eq!(SYS_EXIT, 60);
        // New numbers must not collide with the old ones.
        assert_eq!(SYS_GETPID, 39);
        assert_eq!(SYS_SPAWN, 57);
        assert_eq!(SYS_WAIT, 61);
        // RustOS-private range: uptime is the first slot (1000).
        assert_eq!(SYS_UPTIME, 1000);
        assert_eq!(ALL_SYSCALLS.len(), 10);
        // ALL_SYSCALLS is in number order and matches syscall_name.
        let mut prev = 0u64;
        for (i, (n, name)) in ALL_SYSCALLS.iter().enumerate() {
            assert_eq!(syscall_name(*n), *name);
            if i > 0 {
                assert!(*n > prev);
            }
            prev = *n;
        }
        assert_eq!(syscall_name(999), "unknown");
    }

    #[test]
    fn dispatch_write_read_open_close() {
        let mut st = FakeKernelState::new(2);
        let msg = b"hello";
        let out = dispatch(SYS_WRITE, FD_STDOUT, msg.as_ptr() as u64, msg.len() as u64, &mut st);
        assert_eq!(out, SyscallOutcome::Returned(5));
        assert_eq!(st.output, b"hello");
        assert_eq!(dispatch(SYS_WRITE, 9, msg.as_ptr() as u64, 1, &mut st), SyscallOutcome::Returned(ERR_BADF));
        assert_eq!(dispatch(SYS_READ, FD_STDIN, 0, 0, &mut st), SyscallOutcome::Returned(0));
        assert_eq!(dispatch(SYS_READ, 9, 0, 0, &mut st), SyscallOutcome::Returned(ERR_BADF));
        assert_eq!(dispatch(SYS_OPEN, 0, 0, 0, &mut st), SyscallOutcome::Returned(3));
        assert_eq!(dispatch(SYS_OPEN, 0, 0, 0, &mut st), SyscallOutcome::Returned(4));
        assert_eq!(dispatch(SYS_CLOSE, 3, 0, 0, &mut st), SyscallOutcome::Returned(0));
        assert_eq!(dispatch(SYS_CLOSE, 1, 0, 0, &mut st), SyscallOutcome::Returned(ERR_BADF));
    }

    #[test]
    fn dispatch_yield_getpid_spawn_exit() {
        let mut st = FakeKernelState::new(5);
        assert_eq!(dispatch(SYS_GETPID, 0, 0, 0, &mut st), SyscallOutcome::Returned(5));
        assert_eq!(dispatch(SYS_YIELD, 0, 0, 0, &mut st), SyscallOutcome::Returned(0));
        assert!(st.yielded);
        assert_eq!(dispatch(SYS_SPAWN, 0, 0, 0, &mut st), SyscallOutcome::Returned(100));
        assert_eq!(dispatch(SYS_SPAWN, 0, 0, 0, &mut st), SyscallOutcome::Returned(101));
        assert_eq!(st.spawned, vec![100, 101]);
        assert_eq!(dispatch(SYS_EXIT, 3, 0, 0, &mut st), SyscallOutcome::Exited(3));
        assert!(st.exited);
        assert_eq!(st.exit_code, Some(3));
    }

    #[test]
    fn dispatch_wait_reaps_zombie_blocks_on_live_child_errors_on_unknown() {
        let mut st = FakeKernelState::new(2);
        st.spawned.push(100);
        // Live child: block.
        assert_eq!(dispatch(SYS_WAIT, 100, 0, 0, &mut st), SyscallOutcome::Blocked);
        // Child exits: wait returns its code and forgets it.
        st.zombies.push((100, 7));
        assert_eq!(dispatch(SYS_WAIT, 100, 0, 0, &mut st), SyscallOutcome::Returned(7));
        assert!(st.zombies.is_empty());
        // Unknown pid: error.
        assert_eq!(dispatch(SYS_WAIT, 999, 0, 0, &mut st), SyscallOutcome::Returned(ERR_BADF));
    }

    #[test]
    fn dispatch_unknown_syscall_is_enosys() {
        let mut st = FakeKernelState::new(2);
        assert_eq!(dispatch(999, 0, 0, 0, &mut st), SyscallOutcome::Returned(ERR_NOSYS));
        assert_eq!(dispatch(4, 0, 0, 0, &mut st), SyscallOutcome::Returned(ERR_NOSYS));
    }
}
