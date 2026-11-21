//! Process Control Block (PCB).
//!
//! One PCB per process. It is the kernel's whole picture of a process:
//! identity, lifecycle state, scheduling priority, both stacks, which
//! address space it runs in, how it exited, and its children (for
//! reaping / reparenting). The saved CPU context is what the scheduler
//! restores when it switches back to this process.

use alloc::string::String;
use alloc::vec::Vec;

/// Lifecycle states. The diagram in the README walks through these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProcessState {
    /// Created, runnable, waiting for the scheduler to pick it.
    Ready,
    /// Currently executing on a CPU.
    Running,
    /// Waiting on something (e.g. a child, or I/O); not runnable.
    Blocked,
    /// Finished, exit code recorded, waiting for its parent to `wait()`.
    Zombie,
    /// Reaped by its parent (or by init); the slot is free again.
    Exited,
}

impl ProcessState {
    /// True for states the scheduler may pick (`Ready` only — a
    /// `Running` process is already on a CPU).
    pub fn is_runnable(self) -> bool {
        matches!(self, ProcessState::Ready)
    }
    /// True once the process has finished executing.
    pub fn is_finished(self) -> bool {
        matches!(self, ProcessState::Zombie | ProcessState::Exited)
    }
}

/// Saved CPU context: the registers the scheduler restores on a
/// switch back to this process. (On x86-64 the real switch also
/// restores segment registers / CR3 — CR3 lives in the address space,
/// see `address_space`.)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuContext {
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rflags: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

impl CpuContext {
    /// A fresh context: entry point in `rip`, top of stack in `rsp`,
    /// interrupts enabled (`rflags` bit 9).
    pub fn new(entry: u64, stack_top: u64) -> Self {
        Self {
            rip: entry,
            rsp: stack_top,
            rflags: 0x202,
            ..Default::default()
        }
    }
}

/// The process control block.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessControlBlock {
    /// Process id. 0 = idle, 1 = init; user processes start at 2.
    pub pid: u32,
    /// Parent's pid (0 for idle/init).
    pub parent_pid: u32,
    /// Human-readable name, e.g. `"init"` or `"/bin/sh"`.
    pub name: String,
    /// Lifecycle state.
    pub state: ProcessState,
    /// Scheduling priority: higher runs first within round-robin.
    /// 0 is the lowest; idle is priority 0, init is 10 by convention.
    pub priority: u8,
    /// Top of the kernel stack (kernel-mode stack pointer).
    pub kernel_stack_top: u64,
    /// Top of the user stack (user-mode stack pointer).
    pub user_stack_top: u64,
    /// Physical address of this process's level-4 page table
    /// (the value loaded into CR3 when switching to it).
    pub page_table_root: u64,
    /// Id of the address space (same numbering as the page-table
    /// root owner); 0 = the kernel's own address space.
    pub address_space_id: u32,
    /// Exit code, once the process has finished (`None` while alive).
    pub exit_code: Option<i32>,
    /// Pids of this process's children (for `wait()` / reaping).
    pub children: Vec<u32>,
    /// Saved registers, restored by the scheduler on a switch-in.
    pub context: CpuContext,
    /// CPU time consumed, in scheduler ticks.
    pub cpu_ticks: u64,
}

impl ProcessControlBlock {
    /// Create a PCB. The caller supplies the stacks and page-table
    /// root (allocated by the kernel / frame allocator); this only
    /// records them and builds the initial CPU context.
    pub fn new(
        pid: u32,
        parent_pid: u32,
        name: &str,
        priority: u8,
        entry: u64,
        kernel_stack_top: u64,
        user_stack_top: u64,
        page_table_root: u64,
        address_space_id: u32,
    ) -> Self {
        Self {
            pid,
            parent_pid,
            name: String::from(name),
            state: ProcessState::Ready,
            priority,
            kernel_stack_top,
            user_stack_top,
            page_table_root,
            address_space_id,
            exit_code: None,
            children: Vec::new(),
            context: CpuContext::new(entry, user_stack_top),
            cpu_ticks: 0,
        }
    }

    /// The idle process (PID 0): never exits, lowest priority, runs
    /// the kernel's idle loop (`hlt` until the next timer interrupt).
    pub fn idle() -> Self {
        let mut pcb = Self::new(0, 0, "idle", 0, 0, 0, 0, 0, 0);
        pcb.state = ProcessState::Ready;
        pcb
    }

    /// The init process (PID 1): the first user process, parent of
    /// orphans, starts the shell (`/bin/sh`).
    pub fn init(entry: u64, kernel_stack_top: u64, user_stack_top: u64, page_table_root: u64) -> Self {
        Self::new(1, 0, "init", 10, entry, kernel_stack_top, user_stack_top, page_table_root, 1)
    }

    /// True while the process is alive (not finished).
    pub fn is_alive(&self) -> bool {
        !self.state.is_finished()
    }

    /// Mark the process finished with `code`: it becomes a zombie
    /// holding its exit code until its parent reaps it with `wait()`.
    pub fn mark_exited(&mut self, code: i32) {
        self.state = ProcessState::Zombie;
        self.exit_code = Some(code);
    }

    /// Reap a zombie: the slot can be reused. Only valid on zombies.
    pub fn reap(&mut self) {
        debug_assert_eq!(self.state, ProcessState::Zombie);
        self.state = ProcessState::Exited;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcb_new_and_idle_and_init() {
        let p = ProcessControlBlock::new(2, 1, "/bin/sh", 5, 0x4000_00, 0x1000, 0x2000, 0x3000, 2);
        assert_eq!(p.pid, 2);
        assert_eq!(p.parent_pid, 1);
        assert_eq!(p.name, "/bin/sh");
        assert_eq!(p.state, ProcessState::Ready);
        assert!(p.state.is_runnable());
        assert!(p.is_alive());
        assert_eq!(p.context.rip, 0x4000_00);
        assert_eq!(p.context.rsp, 0x2000);
        assert_eq!(p.context.rflags, 0x202);
        assert_eq!(p.exit_code, None);

        let idle = ProcessControlBlock::idle();
        assert_eq!(idle.pid, 0);
        assert_eq!(idle.priority, 0);

        let init = ProcessControlBlock::init(0x4000_00, 0x1000, 0x2000, 0x3000);
        assert_eq!(init.pid, 1);
        assert_eq!(init.priority, 10);
        assert_eq!(init.name, "init");
    }

    #[test]
    fn exit_becomes_zombie_then_reaped() {
        let mut p = ProcessControlBlock::new(2, 1, "x", 5, 0, 0, 0, 0, 2);
        p.mark_exited(42);
        assert_eq!(p.state, ProcessState::Zombie);
        assert_eq!(p.exit_code, Some(42));
        assert!(!p.is_alive());
        assert!(p.state.is_finished());
        p.reap();
        assert_eq!(p.state, ProcessState::Exited);
    }

    #[test]
    fn state_runnable_only_for_ready() {
        assert!(ProcessState::Ready.is_runnable());
        assert!(!ProcessState::Running.is_runnable());
        assert!(!ProcessState::Blocked.is_runnable());
        assert!(!ProcessState::Zombie.is_runnable());
    }
}
