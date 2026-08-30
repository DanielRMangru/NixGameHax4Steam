# Memory Backend Deep Dive

## Overview

This documents how `src/memory.rs` works — the core engine that reads and writes another process's memory on Linux.

## The Two Key Files

### `/proc/[pid]/maps`

This file describes the virtual memory layout of process `[pid]`. Each line looks like:

```
7f1234000000-7f1234021000 rw-p 00000000 00:00 0
7f1234021000-7f1234022000 r--p 00021000 08:01 12345 /lib/ld-linux.so.2
```

Fields:
1. **Address range**: `start-end` (hex)
2. **Permissions**: `rwxp` — read, write, execute, private/shared
3. **Offset**: Offset into the mapped file (or 0 for anonymous mappings)
4. **Device**: Major:minor device number (or `00:00` for anonymous)
5. **Inode**: Filesystem inode (or 0 for anonymous)
6. **Path**: File backing this mapping (empty for anonymous)

### `/proc/[pid]/mem`

This is a file descriptor representing the process's entire virtual address space. You can:

- `seek()` to any address (within mapped regions)
- `read()` bytes from that address
- `write()` bytes to that address (if the region is writable)

Attempting to read an unmapped region returns `EIO`. Writing to a non-writable region returns `EIO` (or ` EACCES` depending on kernel).

## MemoryMap Struct

```rust
pub struct MemoryMap {
    pub pid: u32,
    pub regions: Vec<MemoryRegion>,
}
```

Parsed from `/proc/[pid]/maps`. Each `MemoryRegion`:

```rust
pub struct MemoryRegion {
    pub start: u64,      // Virtual address start
    pub end: u64,        // Virtual address end (exclusive)
    pub size: u64,       // end - start
    pub perms: String,   // "rw-p", "r--p", etc.
    pub offset: u64,     // Offset into backing file
    pub dev: String,     // "major:minor" or "00:00"
    pub inode: u64,      // Filesystem inode
    pub path: String,    // Backing file path (empty if anonymous)
}
```

## MemHandle

```rust
pub struct MemHandle {
    pid: u32,
    maps: MemoryMap,
    mem_file: File,      // Open /proc/[pid]/mem fd
}
```

### Opening

```rust
let maps = MemoryMap::load(pid)?;   // Parse /proc/[pid]/maps
let mem_file = File::open("/proc/{pid}/mem")?;  // Open mem fd
```

### Reading

```rust
pub fn read(&self, addr: u64, size: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    self.read_into(addr, &mut buf)?;
    Ok(buf)
}

pub fn read_into(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
    let fd = self.mem_file.as_raw_fd();
    unsafe {
        // Seek to the address
        let ret = libc::lseek(fd, addr as libc::off_t, libc::SEEK_SET);
        if ret < 0 { return Err(io::Error::from_raw_os_error(-ret)); }
        
        // Read bytes
        let ret = libc::read(fd, buf.as_mut_ptr() as libc::c_void, buf.len() as libc::size_t);
        if ret < 0 { return Err(io::Error::from_raw_os_error(-ret)); }
        if ret as usize != buf.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Short read"));
        }
    }
    Ok(())
}
```

**Key implementation notes:**
- Uses raw `libc` calls via `unsafe` because Rust's standard `File::seek` and `File::read` don't expose the raw fd in a way that gives us the control we need
- `lseek` with `SEEK_SET` positions the fd at the absolute address
- `read` reads directly into the buffer

### Writing

```rust
pub fn write(&self, addr: u64, buf: &[u8]) -> io::Result<()> {
    let fd = self.mem_file.as_raw_fd();
    unsafe {
        let ret = libc::lseek(fd, addr as libc::off_t, libc::SEEK_SET);
        if ret < 0 { return Err(io::Error::from_raw_os_error(-ret)); }
        
        let ret = libc::write(fd, buf.as_ptr() as libc::c_void, buf.len() as libc::size_t);
        if ret < 0 { return Err(io::Error::from_raw_os_error(-ret)); }
        if ret as usize != buf.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "Short write"));
        }
    }
    Ok(())
}
```

### Typed Read/Write

Convenience methods for reading/writing typed values:

```rust
// Write a u32 value
handle.write_value(addr, 42u32)?;

// Read a f32 value
let health: f32 = handle.read_value(addr)?;
```

These methods:
1. Convert the value to bytes using `std::slice::from_raw_parts`
2. Call the underlying `read`/`write`
3. Handle endianness as the target platform's native endian (x86/x86_64 is little-endian, which matches Windows game expectations under Proton)

### String Reading

```rust
pub fn read_string(&self, addr: u64, max_len: usize) -> io::Result<String> {
    let buf = self.read(addr, max_len)?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}
```

Reads up to `max_len` bytes, stops at null terminator, converts to UTF-8 String.

## Permission Considerations

The `perms` field in `MemoryRegion` uses the format `rwxp` where:
- First char: `r` (readable) or `-` (not readable)
- Second char: `w` (writable) or `-` (not writable)
- Third char: `x` (executable) or `-` (not executable)
- Fourth char: `p` (private/copy-on-write) or `s` (shared)

To safely write, check that the target region has `w` in its permissions:

```rust
let region = maps.region_for_addr(addr);
if let Some(r) = region {
    if !r.perms.contains('w') {
        // Can't write — region is not writable
        // Would need ptrace+mprotect to change permissions
    }
}
```

## Error Handling

Common errors:
- `ESRCH` — Process doesn't exist (PID changed, process exited)
- `EACCES` / `EPERM` — No permission (ptrace scope, ownership)
- `EIO` — Address unmapped or not accessible
- `EFAULT` — Bad address

The `read_into` and `write` methods return `io::Error` with the raw OS error code preserved.

## Performance

- `/proc/[pid]/mem` seeks and reads are relatively fast for small operations
- For large scans (scanning entire address space), this is I/O bound
- The current implementation does one `lseek` + one `read`/`write` per operation
- For bulk operations, consider `process_vm_readv`/`process_vm_writev` (not implemented yet)

---

*See also: `src/memory.rs` for the implementation.*
