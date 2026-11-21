//! Process table: the kernel's registry of all processes.
//!
//! Fixed capacity (`MAX_PROCESSES` slots). PID 0 is the idle process
//! and PID 1 is init; both are created by [`ProcessTable::new`].
//! PIDs are allocated as the lowest free PID >= 2, so a PID is reused
//! once its slot has been reaped — matching the `alloc_pid` contract
//! the kernel relies on. `wait()` reaps a zombie child and returns
//! its exit code; exiting reparents the dead process's children to
//! init (PID 1) so no process is ever parentless.

use crate::pcb::{ProcessControlBlock, ProcessState};
use alloc::vec::Vec;

/// Maximum number of processes alive at once (including idle + init).
pub const MAX_PROCESSES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessError {
    /// The table is full: no free slot.
    TableFull,
    /// No process with that pid exists (or its slot is empty).
    NotFound,
    /// That pid is already in use.
    AlreadyExists,
    /// The pid is out of range for the table.
    InvalidPid,
    /// The process is in the wrong state for the operation
    /// (e.g. waiting on a process that is not your child).
    InvalidState,
    /// The caller tried to remove / exit a reserved process
    /// (idle or init) in a way that is not allowed.
    Reserved,
}

impl core::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl core::error::Error for ProcessError {}

/// The process table.
pub struct ProcessTable {
    /// Slot per pid: `slots[pid]` is the PCB for that pid, if any.
    /// Index 0 = idle, 1 = init, always present.
    slots: Vec<Option<ProcessControlBlock>>,
}

impl ProcessTable {
    /// Create a table containing only idle (PID 0) and init (PID 1).
    /// The caller supplies init's entry point / stacks / page table.
    pub fn new(init_entry: u64, init_kernel_stack: u64, init_user_stack: u64, init_page_table_root: u64) -> Self {
        let mut slots: Vec<Option<ProcessControlBlock>> = Vec::with_capacity(MAX_PROCESSES);
        for _ in 0..MAX_PROCESSES {
            slots.push(None);
        }
        slots[0] = Some(ProcessControlBlock::idle());
        slots[1] = Some(ProcessControlBlock::init(
            init_entry,
            init_kernel_stack,
            init_user_stack,
            init_page_table_root,
        ));
        Self { slots }
    }

    /// Number of live (non-empty, non-`Exited`) slots.
    pub fn count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| matches!(s, Some(p) if p.state != ProcessState::Exited))
            .count()
    }

    /// Lowest free pid >= 2, or `TableFull`.
    pub fn alloc_pid(&self) -> Result<u32, ProcessError> {
        for pid in 2..MAX_PROCESSES as u32 {
            if self.slots[pid as usize].is_none() {
                return Ok(pid);
            }
            // A reaped (Exited) slot is reusable too.
            if let Some(p) = &self.slots[pid as usize] {
                if p.state == ProcessState::Exited {
                    return Ok(pid);
                }
            }
        }
        Err(ProcessError::TableFull)
    }

    /// Spawn a process as a child of `parent_pid`. Returns the new pid.
    /// The parent's `children` list is updated.
    pub fn spawn(
        &mut self,
        parent_pid: u32,
        name: &str,
        priority: u8,
        entry: u64,
        kernel_stack_top: u64,
        user_stack_top: u64,
        page_table_root: u64,
        address_space_id: u32,
    ) -> Result<u32, ProcessError> {
        if (parent_pid as usize) >= MAX_PROCESSES || self.slots[parent_pid as usize].is_none() {
            return Err(ProcessError::NotFound);
        }
        let pid = self.alloc_pid()?;
        let pcb = ProcessControlBlock::new(
            pid,
            parent_pid,
            name,
            priority,
            entry,
            kernel_stack_top,
            user_stack_top,
            page_table_root,
            address_space_id,
        );
        self.slots[pid as usize] = Some(pcb);
        if let Some(parent) = self.slots[parent_pid as usize].as_mut() {
            parent.children.push(pid);
        }
        Ok(pid)
    }

    pub fn get(&self, pid: u32) -> Option<&ProcessControlBlock> {
        self.slots.get(pid as usize)?.as_ref()
    }

    pub fn get_mut(&mut self, pid: u32) -> Option<&mut ProcessControlBlock> {
        self.slots.get_mut(pid as usize)?.as_mut()
    }

    /// Remove a process entirely (freeing its slot / pid for reuse).
    /// Idle and init cannot be removed. Children of the removed
    /// process are reparented to init first.
    pub fn remove(&mut self, pid: u32) -> Result<ProcessControlBlock, ProcessError> {
        if pid < 2 {
            return Err(ProcessError::Reserved);
        }
        let Some(pcb) = self.slots.get(pid as usize).and_then(|s| s.as_ref()) else {
            return Err(ProcessError::NotFound);
        };
        let children = pcb.children.clone();
        let parent_pid = pcb.parent_pid;
        // Reparent children to init (PID 1).
        for child in &children {
            if let Some(c) = self.get_mut(*child) {
                c.parent_pid = 1;
            }
        }
        if let Some(init) = self.slots[1].as_mut() {
            for child in &children {
                if !init.children.contains(child) {
                    init.children.push(*child);
                }
            }
        }
        // Drop this pid from its parent's children list.
        if let Some(parent) = self.slots.get_mut(parent_pid as usize).and_then(|s| s.as_mut()) {
            parent.children.retain(|c| *c != pid);
        }
        Ok(self.slots[pid as usize].take().unwrap())
    }

    /// All pids currently in the table, in pid order.
    pub fn list(&self) -> Vec<u32> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|_| i as u32))
            .collect()
    }

    /// Pids of processes in `state`, in pid order.
    pub fn list_in_state(&self, state: ProcessState) -> Vec<u32> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().filter(|p| p.state == state).map(|_| i as u32))
            .collect()
    }

    /// Mark a process exited with `code`. It becomes a zombie until
    /// its parent reaps it. Its children are reparented to init.
    pub fn exit(&mut self, pid: u32, code: i32) -> Result<(), ProcessError> {
        if pid < 2 {
            return Err(ProcessError::Reserved);
        }
        let Some(pcb) = self.get_mut(pid) else {
            return Err(ProcessError::NotFound);
        };
        let children = pcb.children.clone();
        pcb.mark_exited(code);
        for child in &children {
            if let Some(c) = self.get_mut(*child) {
                c.parent_pid = 1;
            }
        }
        if let Some(init) = self.slots[1].as_mut() {
            for child in &children {
                if !init.children.contains(child) {
                    init.children.push(*child);
                }
            }
        }
        Ok(())
    }

    /// `wait()`: a parent collects a zombie child's exit code.
    ///
    /// * `Ok(Some(code))` — the child was a zombie; it has been reaped
    ///   (removed from the table) and `code` is its exit code.
    /// * `Ok(None)` — the child exists but has not exited yet; the
    ///   caller should block (or poll again) instead of reaping.
    /// * `Err(NotFound)` — no such child; `Err(InvalidState)` — the
    ///   pid exists but is not a child of `parent_pid`.
    pub fn wait_for(&mut self, parent_pid: u32, child_pid: u32) -> Result<Option<i32>, ProcessError> {
        let Some(child) = self.get(child_pid) else {
            return Err(ProcessError::NotFound);
        };
        if child.parent_pid != parent_pid {
            return Err(ProcessError::InvalidState);
        }
        match child.state {
            ProcessState::Zombie => {
                let code = child.exit_code.unwrap_or(0);
                self.remove(child_pid)?;
                Ok(Some(code))
            }
            _ => Ok(None),
        }
    }

    /// Next runnable pid after `after_pid` (exclusive), wrapping
    /// around, in pid order. Idle (PID 0) is only returned when
    /// nothing else is runnable. `None` if the table is empty
    /// (cannot happen: idle is always present).
    pub fn next_ready(&self, after_pid: u32) -> Option<u32> {
        // Scan pids after `after_pid`, then wrap to the start.
        for offset in 1..=MAX_PROCESSES {
            let pid = ((after_pid as usize + offset) % MAX_PROCESSES) as u32;
            if pid == 0 {
                continue; // idle is the fallback, checked last
            }
            if let Some(p) = self.get(pid) {
                if p.state.is_runnable() {
                    return Some(pid);
                }
            }
        }
        // Nothing runnable: idle.
        if self.get(0).is_some() {
            return Some(0);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> ProcessTable {
        ProcessTable::new(0x4000_00, 0x8000, 0x7000_0000, 0x1000)
    }

    #[test]
    fn new_table_has_idle_and_init() {
        let t = table();
        assert_eq!(t.count(), 2);
        assert_eq!(t.list(), vec![0, 1]);
        assert_eq!(t.get(0).unwrap().name, "idle");
        assert_eq!(t.get(1).unwrap().name, "init");
        assert_eq!(t.get(99), None);
    }

    #[test]
    fn pid_allocation_reuses_lowest_free() {
        let mut t = table();
        let a = t.spawn(1, "a", 5, 0x4000_00, 0x8000, 0x7000_0000, 0x2000, 2).unwrap();
        let b = t.spawn(1, "b", 5, 0x4000_00, 0x8000, 0x7000_0000, 0x3000, 3).unwrap();
        assert_eq!((a, b), (2, 3));
        assert_eq!(t.get(1).unwrap().children, vec![2, 3]);
        // Remove pid 2: the next spawn reuses pid 2.
        t.remove(2).unwrap();
        let c = t.spawn(1, "c", 5, 0x4000_00, 0x8000, 0x7000_0000, 0x4000, 4).unwrap();
        assert_eq!(c, 2);
        assert_eq!(t.count(), 4); // idle + init + b + c
    }

    #[test]
    fn spawn_exit_wait_reaps_and_returns_code() {
        let mut t = table();
        let child = t.spawn(1, "worker", 5, 0x4000_00, 0x8000, 0x7000_0000, 0x2000, 2).unwrap();
        // Not exited yet: wait reports "not yet".
        assert_eq!(t.wait_for(1, child).unwrap(), None);
        t.exit(child, 7).unwrap();
        assert_eq!(t.get(child).unwrap().state, ProcessState::Zombie);
        // Now wait reaps it and returns the code.
        assert_eq!(t.wait_for(1, child).unwrap(), Some(7));
        assert_eq!(t.get(child), None);
        // Waiting again: child is gone.
        assert_eq!(t.wait_for(1, child), Err(ProcessError::NotFound));
    }

    #[test]
    fn wait_rejects_non_child_and_unknown() {
        let mut t = table();
        let a = t.spawn(1, "a", 5, 0x4000_00, 0x8000, 0x7000_0000, 0x2000, 2).unwrap();
        let b = t.spawn(1, "b", 5, 0x4000_00, 0x8000, 0x7000_0000, 0x3000, 3).unwrap();
        // `a` is not a child of `b`.
        assert_eq!(t.wait_for(b, a), Err(ProcessError::InvalidState));
        assert_eq!(t.wait_for(1, 99), Err(ProcessError::NotFound));
    }

    #[test]
    fn exit_reparents_children_to_init() {
        let mut t = table();
        let parent = t.spawn(1, "parent", 5, 0x4000_00, 0x8000, 0x7000_0000, 0x2000, 2).unwrap();
        let grandchild = t
            .spawn(parent, "grandchild", 5, 0x4000_00, 0x8000, 0x7000_0000, 0x3000, 3)
            .unwrap();
        t.exit(parent, 0).unwrap();
        assert_eq!(t.get(grandchild).unwrap().parent_pid, 1);
        assert!(t.get(1).unwrap().children.contains(&grandchild));
    }

    #[test]
    fn reserved_processes_cannot_be_removed_or_exited() {
        let mut t = table();
        assert_eq!(t.remove(0), Err(ProcessError::Reserved));
        assert_eq!(t.remove(1), Err(ProcessError::Reserved));
        assert_eq!(t.exit(0, 0), Err(ProcessError::Reserved));
        assert_eq!(t.exit(1, 0), Err(ProcessError::Reserved));
        assert_eq!(t.remove(99), Err(ProcessError::NotFound));
        assert_eq!(t.spawn(99, "x", 5, 0, 0, 0, 0, 9), Err(ProcessError::NotFound));
    }

    #[test]
    fn next_ready_round_robins_and_falls_back_to_idle() {
        let mut t = table();
        // Only idle + init (init is Ready): after 0 comes 1.
        assert_eq!(t.next_ready(0), Some(1));
        let a = t.spawn(1, "a", 5, 0x4000_00, 0x8000, 0x7000_0000, 0x2000, 2).unwrap();
        let b = t.spawn(1, "b", 5, 0x4000_00, 0x8000, 0x7000_0000, 0x3000, 3).unwrap();
        assert_eq!(t.next_ready(1), Some(a));
        assert_eq!(t.next_ready(a), Some(b));
        assert_eq!(t.next_ready(b), Some(1)); // wraps to init
        // Block them all: only idle is left.
        for pid in [1, a, b] {
            t.get_mut(pid).unwrap().state = ProcessState::Blocked;
        }
        assert_eq!(t.next_ready(0), Some(0));
        assert_eq!(t.list_in_state(ProcessState::Blocked), vec![1, a, b]);
    }
}
