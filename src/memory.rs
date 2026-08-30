//! Memory I/O for Linux `/proc/[pid]/mem` access.
//! Provides `MemHandle` for reading/writing process memory and scanning for values.

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;

/// A single mapped region from `/proc/[pid]/maps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub size: u64,
    pub perms: String,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub path: String,
}

/// A parsed memory map for a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryMap {
    pub pid: u32,
    pub regions: Vec<MemoryRegion>,
}

impl MemoryMap {
    pub fn load(pid: u32) -> io::Result<Self> {
        let path = format!("/proc/{}/maps", pid);
        let content = fs::read_to_string(&path)?;
        let regions = parse_maps(&content);
        Ok(MemoryMap { pid, regions })
    }

    pub fn region_for_addr(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions
            .iter()
            .find(|r| addr >= r.start && addr < r.end)
    }

    pub fn writable_regions(&self) -> Vec<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.perms.contains('w'))
            .collect()
    }
}

fn parse_maps(content: &str) -> Vec<MemoryRegion> {
    content.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<MemoryRegion> {
    // Split on any whitespace run (split_whitespace) up to 6 fields.
    // We collect lazily so we can handle lines with or without a path.
    let mut iter = line.split_whitespace();
    let addr_range = iter.next()?;
    let perms     = iter.next()?;
    let offset_s  = iter.next()?;
    let dev       = iter.next()?;
    let inode_s   = iter.next()?;
    // Path is optional — anonymous regions (heap, stack, game data) have none.
    let path = iter.next().unwrap_or("").trim_start().to_string();

    let addr_parts: Vec<&str> = addr_range.split('-').collect();
    if addr_parts.len() != 2 {
        return None;
    }

    // /proc/pid/maps addresses and offsets are in hexadecimal.
    let start  = u64::from_str_radix(addr_parts[0], 16).ok()?;
    let end    = u64::from_str_radix(addr_parts[1], 16).ok()?;
    let offset = u64::from_str_radix(offset_s, 16).ok()?;
    let inode: u64 = inode_s.parse().ok()?;

    Some(MemoryRegion {
        start,
        end,
        size: end - start,
        perms: perms.to_string(),
        offset,
        dev: dev.to_string(),
        inode,
        path,
    })
}

/// Memory I/O handle — wraps an open `/proc/[pid]/mem` fd.
pub struct MemHandle {
    pid: u32,
    maps: MemoryMap,
    mem_file: std::fs::File,
}

impl MemHandle {
    pub fn open(pid: u32) -> io::Result<Self> {
        let maps = MemoryMap::load(pid)?;
        let mem_path = format!("/proc/{}/mem", pid);
        let mem_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&mem_path)?;
        Ok(MemHandle { pid, maps, mem_file })
    }

    pub fn maps(&self) -> &MemoryMap {
        &self.maps
    }

    pub fn readable_regions(&self) -> Vec<&MemoryRegion> {
        self.maps.writable_regions()
            .iter()
            .filter(|r| r.perms.contains('r'))
            .copied()
            .collect()
    }

    pub fn read(&self, addr: u64, size: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; size];
        self.read_into(addr, &mut buf)?;
        Ok(buf)
    }

    pub fn read_into(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        let fd = self.mem_file.as_raw_fd();
        unsafe {
            // lseek returns -1 on error; errno holds the actual error code.
            let ret = libc::lseek(fd, addr as libc::off_t, libc::SEEK_SET);
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            let ret = libc::read(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            if ret as usize != buf.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Short read"));
            }
        }
        Ok(())
    }

    pub fn write(&self, addr: u64, buf: &[u8]) -> io::Result<()> {
        let fd = self.mem_file.as_raw_fd();
        unsafe {
            // lseek returns -1 on error; errno holds the actual error code.
            let ret = libc::lseek(fd, addr as libc::off_t, libc::SEEK_SET);
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            let ret = libc::write(
                fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len() as libc::size_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            if ret as usize != buf.len() {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "Short write"));
            }
        }
        Ok(())
    }

    pub fn write_value<T: Sized>(&self, addr: u64, val: T) -> io::Result<()> {
        let buf = unsafe {
            std::slice::from_raw_parts(
                &val as *const T as *const u8,
                std::mem::size_of::<T>(),
            )
        };
        self.write(addr, buf)
    }

    pub fn read_value<T: Sized>(&self, addr: u64) -> io::Result<T> {
        let size = std::mem::size_of::<T>();
        let buf = self.read(addr, size)?;
        if buf.len() != size {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Truncated read"));
        }
        let mut val: T = unsafe { std::mem::zeroed() };
        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), &mut val as *mut T as *mut u8, size);
        }
        Ok(val)
    }

    /// Scan all writable+readable regions for a byte pattern.
    /// Returns sorted list of matching addresses.
    pub fn scan_for_value(&self, value: &[u8]) -> Vec<u64> {
        let mut results = Vec::new();
        for region in self.maps.writable_regions() {
            if !region.perms.contains('r') {
                continue;
            }
            let chunk_size = 65536u64;
            let mut offset = region.start;
            while offset < region.end {
                // Read extra bytes to catch values spanning chunk boundaries
                let extra = if value.len() > 1 { (value.len() - 1) as u64 } else { 0 };
                let read_target = std::cmp::min(chunk_size + extra, region.end - offset) as usize;
                match self.read(offset, read_target) {
                    Ok(buf) => {
                        let mut search_off = 0;
                        while search_off + value.len() <= buf.len() {
                            if buf[search_off..search_off + value.len()] == value[..] {
                                results.push(offset + search_off as u64);
                            }
                            search_off += 1;
                        }
                    }
                    Err(_) => {}
                }
                offset += chunk_size as u64;
            }
        }
        results.sort();
        results.dedup();
        results
    }

    /// Scan a specific address range for a byte pattern.
    pub fn scan_range(&self, value: &[u8], start: u64, end: u64) -> Vec<u64> {
        let mut results = Vec::new();
        let chunk_size = 65536u64;
        if start >= end {
            return results;
        }
        let mut offset = start;
        while offset < end {
            // Read extra bytes to catch values spanning chunk boundaries
            let extra = if value.len() > 1 {
                (value.len() - 1) as u64
            } else {
                0
            };
            let read_target = std::cmp::min(chunk_size + extra, end - offset) as usize;
            match self.read(offset, read_target) {
                Ok(buf) => {
                    let mut search_off = 0;
                    while search_off + value.len() <= buf.len() {
                        if buf[search_off..search_off + value.len()] == value[..] {
                            results.push(offset + search_off as u64);
                        }
                        search_off += 1;
                    }
                }
                Err(_) => {}
            }
            offset += chunk_size as u64;
        }
        results.sort();
        results.dedup();
        results
    }
}

/// Parse a user-entered value string into bytes based on type.
/// Supports: u8, u16, u32, u64, f32, f64, hex bytes.
pub fn parse_value_bytes(value_type: &str, value_str: &str) -> Result<Vec<u8>, String> {
    let trimmed = value_str.trim();
    match value_type {
        "u8" => {
            let radix = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                16
            } else {
                10
            };
            let clean = trimmed.trim_start_matches("0x").trim_start_matches("0X");
            u8::from_str_radix(clean, radix)
                .map(|v| vec![v])
                .map_err(|e| format!("Invalid u8 value '{}': {}", value_str, e))
        }
        "u16" => {
            let radix = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                16
            } else {
                10
            };
            let clean = trimmed.trim_start_matches("0x").trim_start_matches("0X");
            u16::from_str_radix(clean, radix)
                .map(|v| v.to_le_bytes().to_vec())
                .map_err(|e| format!("Invalid u16 value '{}': {}", value_str, e))
        }
        "u32" => {
            let radix = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                16
            } else {
                10
            };
            let clean = trimmed.trim_start_matches("0x").trim_start_matches("0X");
            u32::from_str_radix(clean, radix)
                .map(|v| v.to_le_bytes().to_vec())
                .map_err(|e| format!("Invalid u32 value '{}': {}", value_str, e))
        }
        "u64" => {
            let radix = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                16
            } else {
                10
            };
            let clean = trimmed.trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(clean, radix)
                .map(|v| v.to_le_bytes().to_vec())
                .map_err(|e| format!("Invalid u64 value '{}': {}", value_str, e))
        }
        "f32" => {
            trimmed
                .parse::<f32>()
                .map(|v| v.to_le_bytes().to_vec())
                .map_err(|e| format!("Invalid f32 value '{}': {}", value_str, e))
        }
        "f64" => {
            trimmed
                .parse::<f64>()
                .map(|v| v.to_le_bytes().to_vec())
                .map_err(|e| format!("Invalid f64 value '{}': {}", value_str, e))
        }
        "hex" => {
            // Interpret hex string as a number and convert to little-endian bytes
            let clean = trimmed.trim_start_matches("0x").trim_start_matches("0X");
            if clean.is_empty() {
                return Err("Empty hex value".into());
            }
            if clean.len() % 2 != 0 {
                return Err(format!("Hex string must have even length: {}", value_str));
            }
            // Parse as u64 to handle up to 8 bytes
            let val = u64::from_str_radix(clean, 16)
                .map_err(|e| format!("Invalid hex value '{}': {}", value_str, e))?;
            // Determine minimum bytes needed (1, 2, 4, or 8)
            let num_bytes = if clean.len() <= 2 {
                1
            } else if clean.len() <= 4 {
                2
            } else if clean.len() <= 8 {
                4
            } else {
                8
            };
            Ok(val.to_le_bytes()[..num_bytes].to_vec())
        }
        "bytes" => {
            // Raw bytes — exact order as entered
            let clean = trimmed.trim_start_matches("0x").trim_start_matches("0X");
            if clean.is_empty() {
                return Err("Empty hex value".into());
            }
            if clean.len() % 2 != 0 {
                return Err(format!("Hex string must have even length: {}", value_str));
            }
            (0..clean.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(&clean[i..i + 2], 16)
                        .map_err(|e| format!("Invalid hex byte at position {}: {}", i, e))
                })
                .collect()
        }
        _ => Err(format!(
            "Unknown type '{}'. Use: u8, u16, u32, u64, f32, f64, bytes",
            value_type
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanPhase {
    Idle,
    FirstScan {
        results: Vec<ScanResult>,
    },
    NextScan {
        results: Vec<ScanResult>,
        history: Vec<Vec<ScanResult>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub address: u64,
    pub size: usize,
    pub value_type: ValueType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    Hex,
    Bytes,
}

impl std::fmt::Display for ValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValueType::U8 => write!(f, "U8"),
            ValueType::U16 => write!(f, "U16"),
            ValueType::U32 => write!(f, "U32"),
            ValueType::U64 => write!(f, "U64"),
            ValueType::F32 => write!(f, "F32"),
            ValueType::F64 => write!(f, "F64"),
            ValueType::Hex => write!(f, "Hex"),
            ValueType::Bytes => write!(f, "Bytes"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_maps() {
        // Anonymous region (no path, 5 fields) must be included.
        let sample = "7f1234000000-7f1234021000 rw-p 00000000 00:00 0\n\
                      7f1234021000-7f1234022000 r--p 00021000 08:01 12345 /lib/ld-linux.so.2\n";
        let regions = parse_maps(sample);
        assert_eq!(regions.len(), 2, "both regions (anonymous + named) must be parsed");
        assert_eq!(regions[0].start, 0x7f1234000000, "addresses are hex");
        assert_eq!(regions[0].end,   0x7f1234021000);
        assert_eq!(regions[0].perms, "rw-p");
        assert_eq!(regions[0].path,  "", "anonymous region has empty path");
        assert_eq!(regions[1].path,  "/lib/ld-linux.so.2");
    }

    #[test]
    fn test_parse_maps_heap() {
        // Heap line from a real kernel: inode is 0, no path.
        let sample = "55f6a2000000-55f6a2021000 rw-p 00000000 00:00 0 \n";
        let regions = parse_maps(sample);
        assert_eq!(regions.len(), 1, "heap/anonymous region must not be skipped");
        assert_eq!(regions[0].start, 0x55f6a2000000);
    }

    #[test]
    fn test_parse_u32_hex() {
        let bytes = parse_value_bytes("u32", "0xDEADBEEF").unwrap();
        assert_eq!(bytes, vec![0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn test_parse_u32_dec() {
        let bytes = parse_value_bytes("u32", "2100").unwrap();
        // 2100 = 0x834, little-endian: [0x34, 0x08, 0x00, 0x00]
        assert_eq!(bytes, vec![0x34, 0x08, 0x00, 0x00]);
    }
}
