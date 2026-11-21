//! ELF64 loader.
//!
//! Validates a kernel / userspace program the same way
//! `rustos-bootloader` validates a kernel ELF — magic, 64-bit class,
//! little-endian, `EM_X86_64` machine, non-zero entry point — then
//! parses the program headers and hands each `PT_LOAD` segment to a
//! caller-supplied [`SegmentWriter`].
//!
//! The writer trait is what makes this host-testable and kernel-usable
//! with the same code: on the host a test writer copies segments into
//! a `Vec`; in the kernel the writer maps pages in the new process's
//! address space (via `rustos-memory`) and copies the file bytes in,
//! zero-filling the `memsz - filesz` (BSS) tail.

use alloc::vec::Vec;

/// ELF64 header layout (little-endian).
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EM_X86_64: u16 = 0x3e;
/// `PT_LOAD` — a segment to load into memory.
pub const PT_LOAD: u32 = 1;
/// Segment flags: readable / writable / executable.
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// Fewer than 64 bytes — not even a full ELF64 header.
    TooShort(usize),
    /// First four bytes are not `0x7F 'E' 'L' 'F'`.
    BadMagic([u8; 4]),
    /// `EI_CLASS` is not `ELFCLASS64` (2).
    Not64Bit(u8),
    /// `EI_DATA` is not little-endian (1).
    NotLittleEndian(u8),
    /// `e_machine` is not `EM_X86_64` (0x3E).
    WrongMachine(u16),
    /// `e_entry` is zero — there is nowhere to jump to.
    ZeroEntryPoint,
    /// Program-header table runs past the end of the file, or a
    /// segment's file range runs past the end of the file.
    Truncated,
    /// `e_phentsize` is not 56 (the size of an ELF64 program header).
    BadProgramHeaderSize(u16),
    /// A `PT_LOAD` segment has `memsz < filesz` (nonsense).
    BadSegmentSize,
    /// The writer failed to place a segment.
    WriteFailed,
}

impl core::fmt::Display for ElfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl core::error::Error for ElfError {}

/// One program header (ELF64, 56 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

impl ProgramHeader {
    pub fn is_loadable(&self) -> bool {
        self.p_type == PT_LOAD
    }
    pub fn is_readable(&self) -> bool {
        self.flags & PF_R != 0
    }
    pub fn is_writable(&self) -> bool {
        self.flags & PF_W != 0
    }
    pub fn is_executable(&self) -> bool {
        self.flags & PF_X != 0
    }
    /// Bytes past `filesz` that must be zero-filled (BSS).
    pub fn bss_size(&self) -> u64 {
        self.memsz.saturating_sub(self.filesz)
    }
}

/// A validated ELF with its loadable segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedElf {
    /// Entry-point virtual address (`e_entry`).
    pub entry_point: u64,
    /// All `PT_LOAD` segments, in program-header order.
    pub segments: Vec<ProgramHeader>,
}

impl ParsedElf {
    /// Lowest virtual address loaded, or `None` with no segments.
    pub fn lowest_vaddr(&self) -> Option<u64> {
        self.segments.iter().map(|s| s.vaddr).min()
    }
    /// Highest virtual address loaded (end of the last segment).
    pub fn highest_vaddr(&self) -> Option<u64> {
        self.segments.iter().map(|s| s.vaddr + s.memsz).max()
    }
    /// Total bytes of virtual address space the segments occupy.
    pub fn total_load_size(&self) -> u64 {
        match (self.lowest_vaddr(), self.highest_vaddr()) {
            (Some(lo), Some(hi)) => hi - lo,
            _ => 0,
        }
    }
}

/// Destination for loaded segments. The kernel implementation maps
/// pages and copies bytes; a test implementation records them.
pub trait SegmentWriter {
    /// Place one segment: copy `data` (`filesz` bytes) at `vaddr`,
    /// and zero-fill `memsz - data.len()` bytes after it.
    /// `memsz` is always `>= data.len()` (checked by the loader).
    fn write_segment(&mut self, vaddr: u64, data: &[u8], memsz: u64) -> Result<(), ElfError>;
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Validate the ELF64 header (same checks as `rustos-bootloader`).
pub fn validate_elf(bytes: &[u8]) -> Result<u64, ElfError> {
    if bytes.len() < 64 {
        return Err(ElfError::TooShort(bytes.len()));
    }
    if bytes[0..4] != ELF_MAGIC {
        return Err(ElfError::BadMagic([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }
    if bytes[4] != ELFCLASS64 {
        return Err(ElfError::Not64Bit(bytes[4]));
    }
    if bytes[5] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian(bytes[5]));
    }
    let machine = u16_at(bytes, 18);
    if machine != EM_X86_64 {
        return Err(ElfError::WrongMachine(machine));
    }
    let entry = u64_at(bytes, 24);
    if entry == 0 {
        return Err(ElfError::ZeroEntryPoint);
    }
    Ok(entry)
}

/// Parse the program headers of a validated ELF.
pub fn parse_elf(bytes: &[u8]) -> Result<ParsedElf, ElfError> {
    let entry_point = validate_elf(bytes)?;
    // e_phoff @32, e_phentsize @54, e_phnum @56.
    let phoff = u64_at(bytes, 32) as usize;
    let phentsize = u16_at(bytes, 54);
    let phnum = u16_at(bytes, 56) as usize;
    if phentsize != 56 {
        return Err(ElfError::BadProgramHeaderSize(phentsize));
    }
    if phnum > 0 && phoff.checked_add(phnum * 56).map_or(true, |end| end > bytes.len()) {
        return Err(ElfError::Truncated);
    }
    let mut segments = Vec::new();
    for i in 0..phnum {
        let off = phoff + i * 56;
        let p_type = u32_at(bytes, off);
        if p_type != PT_LOAD {
            continue;
        }
        let flags = u32_at(bytes, off + 4);
        let offset = u64_at(bytes, off + 8);
        let vaddr = u64_at(bytes, off + 16);
        let paddr = u64_at(bytes, off + 24);
        let filesz = u64_at(bytes, off + 32);
        let memsz = u64_at(bytes, off + 40);
        let align = u64_at(bytes, off + 48);
        if memsz < filesz {
            return Err(ElfError::BadSegmentSize);
        }
        let end = (offset as usize).checked_add(filesz as usize).ok_or(ElfError::Truncated)?;
        if end > bytes.len() {
            return Err(ElfError::Truncated);
        }
        segments.push(ProgramHeader {
            p_type,
            flags,
            offset,
            vaddr,
            paddr,
            filesz,
            memsz,
            align,
        });
    }
    Ok(ParsedElf { entry_point, segments })
}

/// Validate, parse, and load an ELF into `writer`.
/// Returns the parsed ELF (entry point + segments).
pub fn load_elf(bytes: &[u8], writer: &mut impl SegmentWriter) -> Result<ParsedElf, ElfError> {
    let parsed = parse_elf(bytes)?;
    for seg in &parsed.segments {
        let start = seg.offset as usize;
        let end = start + seg.filesz as usize;
        writer
            .write_segment(seg.vaddr, &bytes[start..end], seg.memsz)
            .map_err(|_| ElfError::WriteFailed)?;
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory writer: records each segment as a zero-filled
    /// `memsz`-byte buffer with the file bytes copied in.
    #[derive(Default, Debug)]
    struct MemoryWriter {
        segments: Vec<(u64, Vec<u8>)>,
    }
    impl SegmentWriter for MemoryWriter {
        fn write_segment(&mut self, vaddr: u64, data: &[u8], memsz: u64) -> Result<(), ElfError> {
            let mut buf = vec![0u8; memsz as usize];
            buf[..data.len()].copy_from_slice(data);
            self.segments.push((vaddr, buf));
            Ok(())
        }
    }

    /// Build a minimal ELF: 64-byte header + 2 program headers
    /// (one PT_LOAD, one PT_NULL) + segment bytes.
    fn fake_elf() -> Vec<u8> {
        let mut b = vec![0u8; 64 + 2 * 56 + 16];
        b[0..4].copy_from_slice(&ELF_MAGIC);
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&0x4010_00u64.to_le_bytes()); // entry
        b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum
        // PT_LOAD at phoff 64: R+X, offset 176, vaddr 0x400000,
        // filesz 8, memsz 16 (8 bytes BSS).
        let ph = 64;
        b[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        b[ph + 4..ph + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        b[ph + 8..ph + 16].copy_from_slice(&176u64.to_le_bytes());
        b[ph + 16..ph + 24].copy_from_slice(&0x4000_00u64.to_le_bytes());
        b[ph + 24..ph + 32].copy_from_slice(&0x4000_00u64.to_le_bytes());
        b[ph + 32..ph + 40].copy_from_slice(&8u64.to_le_bytes());
        b[ph + 40..ph + 48].copy_from_slice(&16u64.to_le_bytes());
        b[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        // PT_NULL at phoff 120: ignored.
        // Segment bytes at offset 176.
        b[176..184].copy_from_slice(b"RustOS!\0");
        b
    }

    #[test]
    fn parse_and_load_valid_elf() {
        let elf = fake_elf();
        let parsed = parse_elf(&elf).unwrap();
        assert_eq!(parsed.entry_point, 0x4010_00);
        assert_eq!(parsed.segments.len(), 1);
        let seg = parsed.segments[0];
        assert!(seg.is_loadable() && seg.is_readable() && seg.is_executable());
        assert!(!seg.is_writable());
        assert_eq!(seg.bss_size(), 8);
        assert_eq!(parsed.lowest_vaddr(), Some(0x4000_00));
        assert_eq!(parsed.highest_vaddr(), Some(0x4000_10));
        assert_eq!(parsed.total_load_size(), 16);

        let mut w = MemoryWriter::default();
        let loaded = load_elf(&elf, &mut w).unwrap();
        assert_eq!(loaded.entry_point, 0x4010_00);
        assert_eq!(w.segments.len(), 1);
        assert_eq!(w.segments[0].0, 0x4000_00);
        // File bytes copied, BSS tail zero-filled.
        assert_eq!(&w.segments[0].1[..8], b"RustOS!\0");
        assert_eq!(&w.segments[0].1[8..], &[0u8; 8]);
    }

    #[test]
    fn validation_rejects_bad_elves_like_bootloader() {
        let mut e = fake_elf();
        e[1] = b'X';
        assert_eq!(validate_elf(&e), Err(ElfError::BadMagic([0x7f, b'X', b'L', b'F'])));
        let mut e = fake_elf();
        e[4] = 1;
        assert_eq!(validate_elf(&e), Err(ElfError::Not64Bit(1)));
        let mut e = fake_elf();
        e[5] = 2;
        assert_eq!(validate_elf(&e), Err(ElfError::NotLittleEndian(2)));
        let mut e = fake_elf();
        e[18..20].copy_from_slice(&0x28u16.to_le_bytes()); // EM_ARM
        assert_eq!(validate_elf(&e), Err(ElfError::WrongMachine(0x28)));
        let mut e = fake_elf();
        e[24..32].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(validate_elf(&e), Err(ElfError::ZeroEntryPoint));
        assert_eq!(validate_elf(&[0x7f, b'E']), Err(ElfError::TooShort(2)));
    }

    #[test]
    fn truncated_and_bad_segment_sizes_rejected() {
        // Program-header table past the end of the file.
        let mut e = fake_elf();
        e[32..40].copy_from_slice(&10_000u64.to_le_bytes());
        assert_eq!(parse_elf(&e), Err(ElfError::Truncated));
        // memsz < filesz.
        let mut e = fake_elf();
        e[64 + 40..64 + 48].copy_from_slice(&4u64.to_le_bytes());
        assert_eq!(parse_elf(&e), Err(ElfError::BadSegmentSize));
        // Wrong phentsize.
        let mut e = fake_elf();
        e[54..56].copy_from_slice(&32u16.to_le_bytes());
        assert_eq!(parse_elf(&e), Err(ElfError::BadProgramHeaderSize(32)));
        // Segment file range past EOF.
        let mut e = fake_elf();
        e[64 + 8..64 + 16].copy_from_slice(&10_000u64.to_le_bytes());
        assert_eq!(parse_elf(&e), Err(ElfError::Truncated));
    }

    #[test]
    fn elf_with_no_load_segments_parses() {
        let mut e = fake_elf();
        e[64..68].copy_from_slice(&0u32.to_le_bytes()); // PT_LOAD -> PT_NULL
        let parsed = parse_elf(&e).unwrap();
        assert!(parsed.segments.is_empty());
        assert_eq!(parsed.total_load_size(), 0);
    }
}
