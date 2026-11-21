//! Per-process address spaces.
//!
//! Layout (x86-64, canonical addresses):
//!
//! ```text
//! 0x0000_0000_0000_0000  +------------------+
//!                         | user code/data   |  USER_BASE = 0x400000
//!                         | (ELF segments)   |
//!                         +------------------+
//!                         | user stack       |  grows down from
//!                         | (map_user_stack) |  USER_STACK_TOP
//! 0x0000_7fff_ffff_ffff  +------------------+  end of user space
//! 0xffff_8000_0000_0000  +------------------+
//!                         | kernel (shared,  |  KERNEL_BASE
//!                         |  mapped in every |
//!                         |  address space)  |
//! 0xffff_ffff_ffff_ffff  +------------------+
//! ```
//!
//! Each process owns a level-4 page table; switching processes means
//! loading its root into CR3 ([`AddressSpace::switch_to`]). The
//! kernel half is shared, so a switch only changes the user half.
//! Mapping itself goes through the [`PageMapper`] trait so host tests
//! can use a mock mapper instead of real page tables.

/// Page size: 4 KiB (matches `rustos-memory`).
pub const PAGE_SIZE: u64 = 4096;
/// Where user ELF segments are loaded (matches the ELF test program
/// and the usual Linux default).
pub const USER_BASE: u64 = 0x4000_00;
/// Top of the user address space (canonical low half).
pub const USER_SPACE_END: u64 = 0x0000_7fff_ffff_ffff;
/// Top of the user stack; the stack grows down from here.
pub const USER_STACK_TOP: u64 = 0x0000_7fff_ffff_0000;
/// Default user stack size: 8 pages (32 KiB).
pub const USER_STACK_PAGES: u64 = 8;
/// Start of the kernel half (canonical high half).
pub const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;

/// Page-table entry flags (same bit positions as `rustos-memory`).
pub const FLAG_PRESENT: u64 = 1 << 0;
pub const FLAG_WRITABLE: u64 = 1 << 1;
pub const FLAG_USER: u64 = 1 << 2;
pub const FLAG_NO_EXECUTE: u64 = 1 << 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    AlreadyMapped,
    InvalidAddress,
    NotMapped,
    OutOfMemory,
}

impl core::fmt::Display for MapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl core::error::Error for MapError {}

/// Something that can map / unmap / translate pages in one address
/// space. The kernel implements this over `rustos-memory`'s `Mapper`;
/// host tests implement it over a `BTreeMap`.
pub trait PageMapper {
    fn map(&mut self, virt: u64, phys: u64, flags: u64) -> Result<(), MapError>;
    fn unmap(&mut self, virt: u64) -> Result<u64, MapError>;
    fn translate(&self, virt: u64) -> Option<u64>;
}

/// One process's address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressSpace {
    /// Address-space id (same as the owning pid, by convention).
    pub id: u32,
    /// Physical address of the level-4 page table (CR3 value).
    pub page_table_root: u64,
    /// Top of the user stack.
    pub user_stack_top: u64,
    /// Number of stack pages currently mapped.
    pub stack_pages: u64,
}

impl AddressSpace {
    /// Create an address space over an already-allocated (zeroed)
    /// level-4 page table. The kernel half is mapped by the caller.
    pub fn new(id: u32, page_table_root: u64) -> Self {
        Self {
            id,
            page_table_root,
            user_stack_top: USER_STACK_TOP,
            stack_pages: 0,
        }
    }

    /// True for addresses in the user half (below the canonical gap).
    pub fn is_user_addr(addr: u64) -> bool {
        addr <= USER_SPACE_END
    }

    /// True for addresses in the kernel half.
    pub fn is_kernel_addr(addr: u64) -> bool {
        addr >= KERNEL_BASE
    }

    /// Map `pages` stack pages directly below `USER_STACK_TOP`,
    /// writable + user-accessible. Returns the lowest stack address.
    /// `next_phys` supplies one physical frame per page (the caller
    /// allocates them, e.g. from `rustos-memory`'s frame allocator).
    pub fn map_user_stack(
        &mut self,
        mapper: &mut impl PageMapper,
        pages: u64,
        mut next_phys: impl FnMut() -> Option<u64>,
    ) -> Result<u64, MapError> {
        let flags = FLAG_PRESENT | FLAG_WRITABLE | FLAG_USER;
        let mut lowest = self.user_stack_top;
        for i in 0..pages {
            let virt = self.user_stack_top - (i + 1) * PAGE_SIZE;
            let phys = next_phys().ok_or(MapError::OutOfMemory)?;
            if !phys.is_multiple_of(PAGE_SIZE) {
                return Err(MapError::InvalidAddress);
            }
            mapper.map(virt, phys, flags)?;
            lowest = virt;
        }
        self.stack_pages += pages;
        Ok(lowest)
    }

    /// Map one user segment (e.g. an ELF `PT_LOAD`): `pages` pages
    /// starting at `vaddr` (page-aligned), user-accessible, writable
    /// iff `writable`, executable iff `executable` (NX otherwise).
    pub fn map_segment(
        &self,
        mapper: &mut impl PageMapper,
        vaddr: u64,
        pages: u64,
        writable: bool,
        executable: bool,
        mut next_phys: impl FnMut() -> Option<u64>,
    ) -> Result<(), MapError> {
        if !Self::is_user_addr(vaddr) || vaddr % PAGE_SIZE != 0 {
            return Err(MapError::InvalidAddress);
        }
        let mut flags = FLAG_PRESENT | FLAG_USER;
        if writable {
            flags |= FLAG_WRITABLE;
        }
        if !executable {
            flags |= FLAG_NO_EXECUTE;
        }
        for i in 0..pages {
            let phys = next_phys().ok_or(MapError::OutOfMemory)?;
            mapper.map(vaddr + i * PAGE_SIZE, phys, flags)?;
        }
        Ok(())
    }

    /// The CR3 value to load to switch to this address space.
    /// Pure: returns the root so the caller (or `activate`) can
    /// load it. Keeping the load out of the pure function is what
    /// lets host tests call this safely.
    pub fn switch_to(&self) -> u64 {
        self.page_table_root
    }

    /// Actually switch to this address space: load CR3.
    ///
    /// # Safety
    /// The page table at `page_table_root` must be a valid, fully
    /// mapped level-4 table for this process (kernel half mapped),
    /// or the CPU will fault on the next instruction fetch.
    /// x86-64 only; never call on the host.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn activate(&self) {
        let root = self.page_table_root;
        unsafe {
            core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    /// Mock mapper: a map from page-aligned virt -> (phys, flags).
    #[derive(Default)]
    struct MockMapper {
        pages: BTreeMap<u64, (u64, u64)>,
    }
    impl PageMapper for MockMapper {
        fn map(&mut self, virt: u64, phys: u64, flags: u64) -> Result<(), MapError> {
            if virt % PAGE_SIZE != 0 || phys % PAGE_SIZE != 0 {
                return Err(MapError::InvalidAddress);
            }
            if self.pages.contains_key(&virt) {
                return Err(MapError::AlreadyMapped);
            }
            self.pages.insert(virt, (phys, flags));
            Ok(())
        }
        fn unmap(&mut self, virt: u64) -> Result<u64, MapError> {
            self.pages.remove(&virt).map(|(p, _)| p).ok_or(MapError::NotMapped)
        }
        fn translate(&self, virt: u64) -> Option<u64> {
            let page = virt & !(PAGE_SIZE - 1);
            let off = virt & (PAGE_SIZE - 1);
            self.pages.get(&page).map(|(p, _)| p + off)
        }
    }

    #[test]
    fn user_kernel_split() {
        assert!(AddressSpace::is_user_addr(0x4000_00));
        assert!(AddressSpace::is_user_addr(USER_SPACE_END));
        assert!(!AddressSpace::is_user_addr(KERNEL_BASE));
        assert!(AddressSpace::is_kernel_addr(KERNEL_BASE));
        assert!(!AddressSpace::is_kernel_addr(0x4000_00));
    }

    #[test]
    fn map_user_stack_grows_down_and_translates() {
        let mut space = AddressSpace::new(2, 0x1000);
        let mut mapper = MockMapper::default();
        let mut next = 0x2000u64;
        let lowest = space
            .map_user_stack(&mut mapper, 2, || {
                let p = next;
                next += PAGE_SIZE;
                Some(p)
            })
            .unwrap();
        assert_eq!(lowest, USER_STACK_TOP - 2 * PAGE_SIZE);
        assert_eq!(space.stack_pages, 2);
        // i=0 maps the top page (TOP-0x1000) to the first frame 0x2000,
        // i=1 maps TOP-0x2000 to 0x3000.
        assert_eq!(mapper.translate(USER_STACK_TOP - 1), Some(0x2000 + PAGE_SIZE - 1));
        assert_eq!(mapper.translate(USER_STACK_TOP - PAGE_SIZE), Some(0x2000));
        assert_eq!(mapper.translate(USER_STACK_TOP - 2 * PAGE_SIZE), Some(0x3000));
        // Stack pages are user + writable, not executable (NX is set
        // only via map_segment; here flags are PRESENT|WRITABLE|USER).
        let (_, flags) = mapper.pages[&(USER_STACK_TOP - PAGE_SIZE)];
        assert_eq!(flags & FLAG_USER, FLAG_USER);
        assert_eq!(flags & FLAG_WRITABLE, FLAG_WRITABLE);
        // Mapping the same stack again fails (already mapped).
        assert_eq!(
            space.map_user_stack(&mut mapper, 1, || Some(0x9000)),
            Err(MapError::AlreadyMapped)
        );
    }

    #[test]
    fn map_segment_flags_and_kernel_rejected() {
        let space = AddressSpace::new(2, 0x1000);
        let mut mapper = MockMapper::default();
        let mut next = 0x5000u64;
        // Executable, read-only code segment.
        space
            .map_segment(&mut mapper, 0x4000_00, 1, false, true, || {
                let p = next;
                next += PAGE_SIZE;
                Some(p)
            })
            .unwrap();
        let (_, flags) = mapper.pages[&0x4000_00];
        assert_eq!(flags & FLAG_NO_EXECUTE, 0);
        assert_eq!(flags & FLAG_WRITABLE, 0);
        // Writable data segment gets NX.
        space
            .map_segment(&mut mapper, 0x4010_00, 1, true, false, || Some(0x6000))
            .unwrap();
        let (_, flags) = mapper.pages[&0x4010_00];
        assert_ne!(flags & FLAG_NO_EXECUTE, 0);
        // Kernel addresses and unaligned addresses are rejected.
        assert_eq!(
            space.map_segment(&mut mapper, KERNEL_BASE, 1, true, false, || Some(0x7000)),
            Err(MapError::InvalidAddress)
        );
        assert_eq!(
            space.map_segment(&mut mapper, 0x4000_01, 1, true, false, || Some(0x7000)),
            Err(MapError::InvalidAddress)
        );
        // Running out of frames is reported, not panicked.
        assert_eq!(
            space.map_segment(&mut mapper, 0x4020_00, 1, true, false, || None),
            Err(MapError::OutOfMemory)
        );
    }

    #[test]
    fn switch_to_returns_cr3_root() {
        let space = AddressSpace::new(3, 0xabcd_000);
        assert_eq!(space.switch_to(), 0xabcd_000);
    }
}
