//! Round-robin scheduler.
//!
//! The scheduler owns no processes itself: it asks the
//! [`ProcessTable`] for the next runnable pid. One tick = one
//! time-slice; on each tick the scheduler advances to the next
//! runnable process in pid order (wrapping), falling back to the
//! idle process (PID 0) when nothing else is runnable. Priority is
//! recorded on the PCB for a future priority scheduler — round-robin
//! here treats every runnable process equally, by design.
//!
//! A real kernel calls [`Scheduler::tick`] from the timer interrupt
//! (PIT) and then switches stacks / CR3 to the returned pid.

use crate::pcb::ProcessState;
use crate::table::ProcessTable;

/// Round-robin scheduler state.
#[derive(Clone, Copy, Debug, Default)]
pub struct Scheduler {
    /// Pid currently on the CPU (0 = idle at boot).
    pub current: u32,
    /// Total ticks scheduled so far.
    pub ticks: u64,
}

impl Scheduler {
    pub fn new() -> Self {
        Self { current: 0, ticks: 0 }
    }

    /// Pick the next process to run and mark it `Running`.
    /// The previously running process (if any, and still alive)
    /// goes back to `Ready`. Returns the new current pid.
    pub fn tick(&mut self, table: &mut ProcessTable) -> Option<u32> {
        self.ticks += 1;
        let prev = self.current;
        let next = table.next_ready(prev)?;
        // Previous process yields the CPU.
        if prev != next {
            if let Some(p) = table.get_mut(prev) {
                if p.state == ProcessState::Running {
                    p.state = ProcessState::Ready;
                }
            }
        }
        if let Some(p) = table.get_mut(next) {
            p.state = ProcessState::Running;
            p.cpu_ticks += 1;
        }
        self.current = next;
        Some(next)
    }

    /// Voluntary yield: same as a tick, but the current process
    /// asked for it (e.g. via the `yield` syscall) rather than the
    /// timer firing.
    pub fn yield_now(&mut self, table: &mut ProcessTable) -> Option<u32> {
        self.tick(table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_with_two() -> (ProcessTable, u32, u32) {
        let mut t = ProcessTable::new(0x4000_00, 0x8000, 0x7000_0000, 0x1000);
        let a = t.spawn(1, "a", 5, 0x4000_00, 0x8000, 0x7000_0000, 0x2000, 2).unwrap();
        let b = t.spawn(1, "b", 5, 0x4000_00, 0x8000, 0x7000_0000, 0x3000, 3).unwrap();
        (t, a, b)
    }

    #[test]
    fn round_robin_cycles_through_ready_processes() {
        let (mut t, a, b) = table_with_two();
        let mut s = Scheduler::new();
        // Order from idle: init(1), a(2), b(3), init, a, b, ...
        assert_eq!(s.tick(&mut t), Some(1));
        assert_eq!(s.tick(&mut t), Some(a));
        assert_eq!(s.tick(&mut t), Some(b));
        assert_eq!(s.tick(&mut t), Some(1));
        assert_eq!(s.tick(&mut t), Some(a));
        assert_eq!(s.ticks, 5);
        // Only one process is Running at a time.
        assert_eq!(t.list_in_state(ProcessState::Running), vec![a]);
        assert_eq!(t.get(a).unwrap().cpu_ticks, 2);
    }

    #[test]
    fn scheduler_falls_back_to_idle_when_nothing_ready() {
        let mut t = ProcessTable::new(0x4000_00, 0x8000, 0x7000_0000, 0x1000);
        for pid in [0, 1] {
            t.get_mut(pid).unwrap().state = ProcessState::Blocked;
        }
        // Idle is blocked too in this artificial setup; next_ready
        // still returns idle as the fallback when it is present.
        let mut s = Scheduler::new();
        assert_eq!(s.tick(&mut t), Some(0));
    }

    #[test]
    fn yield_now_advances_like_a_tick() {
        let (mut t, a, _b) = table_with_two();
        let mut s = Scheduler::new();
        assert_eq!(s.yield_now(&mut t), Some(1));
        assert_eq!(s.yield_now(&mut t), Some(a));
    }

    #[test]
    fn exited_process_is_never_scheduled() {
        let (mut t, a, b) = table_with_two();
        t.exit(a, 0).unwrap();
        let mut s = Scheduler::new();
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(s.tick(&mut t).unwrap());
        }
        assert!(!seen.contains(&a));
        assert!(seen.contains(&b));
        assert!(seen.contains(&1));
    }
}
