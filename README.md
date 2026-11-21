# rustos-process

Process management for RustOS: the process control block, the process
table, a round-robin scheduler, an ELF64 program loader, per-process
address spaces, and the syscall dispatch table.

No `std`, no external crates (`core` + `alloc` only), so this links
into the kernel. Tests run on the host.

## Layout

```
src/lib.rs           re-exports
src/pcb.rs           ProcessControlBlock, CpuContext, ProcessState
src/table.rs         ProcessTable (MAX_PROCESSES = 64), alloc_pid, spawn, exit, wait
src/scheduler.rs     round-robin Scheduler (tick / yield_now)
src/elf.rs           ELF64 validation + PT_LOAD parsing + SegmentWriter loading
src/address_space.rs AddressSpace, PageMapper trait, user/kernel split, CR3 switch
src/syscall.rs       syscall numbers + pure dispatch() over FakeKernelState
```

## Process lifecycle

```text
           spawn()
  (none) ----------> Ready --tick()--> Running --tick()/yield()--> Ready
                       |                  |
                       |                  | exit(code)
                       |                  v
                       +-------------> Zombie --wait() by parent--> (reaped, slot freed)
                       |
                       +-- Blocked (waiting on child / I/O) --wake--> Ready
```

- PID 0 = idle (runs when nothing else is runnable, lowest priority).
- PID 1 = init (priority 10, parent of orphans, starts the shell).
- PIDs are the lowest free PID >= 2, so a reaped PID is reused.
- `exit()` turns a process into a zombie holding its exit code;
  `wait()` by the parent reaps it and returns the code. Waiting on
  a live child reports "not yet" (the caller blocks in the kernel).
- Exiting reparents the dead process's children to init, so no
  process is ever parentless.

## How init starts the shell

1. The bootloader loads the kernel; the kernel creates the table
   with idle (PID 0) and init (PID 1, entry = the init program).
2. Init's address space is built (`AddressSpace::new`, stack mapped
   with `map_user_stack`, ELF segments mapped with `map_segment`).
3. Init loads `/bin/sh` with `elf::load_elf` (segments copied into
   its address space, BSS zero-filled) and jumps to its entry point.
4. The shell runs as a normal process and uses syscalls to talk to
   the kernel; `spawn` creates further processes the same way.

## ELF loading

`elf::parse_elf` validates the header with the same checks as
`rustos-bootloader` (magic, ELFCLASS64, little-endian, `EM_X86_64`,
non-zero entry), then parses the program headers and returns only
the `PT_LOAD` segments. `elf::load_elf` hands each segment to a
`SegmentWriter`: in the kernel the writer maps pages in the new
process's address space and copies the file bytes in, zero-filling
`memsz - filesz` (BSS). In tests a `MemoryWriter` records them.

## Address spaces

User code lives below `0x0000_7fff_ffff_ffff` (`USER_BASE =
0x400000`, stack grows down from `USER_STACK_TOP =
0x0000_7fff_ffff_0000`); the kernel lives above
`0xffff_8000_0000_0000` and is mapped in every address space.
Switching processes loads the new level-4 page table into CR3
(`AddressSpace::switch_to` returns the CR3 value; `activate()`
loads it — real hardware only, never call on the host).
Mapping goes through the `PageMapper` trait; the kernel implements
it over `rustos-memory`'s `Mapper`, host tests use a mock map.

## Syscalls

Numbers match `rustos-shell/src/syscall.rs` **exactly**:

| # | name | # | name |
|---|------|---|------|
| 0 | read | 39 | getpid |
| 1 | write | 57 | spawn |
| 2 | open | 60 | exit |
| 3 | close | 61 | wait |
| 24 | yield | | |

`dispatch(n, a0, a1, a2, state)` is pure and host-testable; it
returns `Returned(i64)` (negative = -errno), `Exited(code)`, or
`Blocked`. Unknown numbers return `-ENOSYS` (-38).

## Build and test

```sh
cargo test
```

## Limitations (honest)

- No `fork()` / copy-on-write yet — `spawn` creates a fresh process
  from an ELF file; there is no address-space cloning.
- No real page-table switching on the host: `activate()` is
  x86-64-only and must only run in the kernel; host tests exercise
  the mock mapper, not CR3.
- No timer-interrupt wiring: `Scheduler::tick` is called by the
  kernel's timer handler (not yet written in `rustos-kernel`);
  priority is recorded on the PCB but round-robin here treats all
  runnable processes equally.
- No signals, no process groups / sessions, no resource limits.
- Not live-boot-tested: QEMU is not installed on this VM, so no
  image has actually booted with this crate in it.
