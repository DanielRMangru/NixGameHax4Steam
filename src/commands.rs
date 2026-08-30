use anyhow::{Context, Result};
use nixgamehax4steam::{enumerate_processes, parse_value_bytes, MemHandle};

pub fn cmd_list(filter: Option<String>) -> Result<()> {
    let procs = enumerate_processes();
    let filter_lower = filter.as_deref().unwrap_or("").to_lowercase();

    println!("{:<8} {:<25} {}", "PID", "NAME", "CMDLINE");
    println!("{}", "-".repeat(80));

    for p in procs {
        if filter_lower.is_empty()
            || p.name.to_lowercase().contains(&filter_lower)
            || p.cmdline.to_lowercase().contains(&filter_lower)
            || p.pid.to_string().contains(&filter_lower)
        {
            let cmd_short = if p.cmdline.len() > 50 {
                format!("{}...", &p.cmdline[..47])
            } else {
                p.cmdline.clone()
            };
            println!("{:<8} {:<25} {}", p.pid, p.name, cmd_short);
        }
    }
    Ok(())
}

pub fn cmd_find(name: &str) -> Result<()> {
    cmd_list(Some(name.to_string()))
}

pub fn cmd_read(pid: u32, address_str: &str, length: usize) -> Result<()> {
    let addr = parse_address(address_str)?;
    let handle = MemHandle::open(pid).context(format!("Failed to open /proc/{}/mem", pid))?;
    let data = handle.read(addr, length).context("Failed to read memory")?;
    print_hex_dump(&data, addr);
    Ok(())
}

pub fn cmd_write(pid: u32, address_str: &str, value_str: &str, type_str: &str) -> Result<()> {
    let addr = parse_address(address_str)?;
    let bytes = parse_value_bytes(type_str, value_str)
        .map_err(|e| anyhow::anyhow!("Invalid value: {}", e))?;
    let handle = MemHandle::open(pid).context(format!("Failed to open /proc/{}/mem", pid))?;
    handle.write(addr, &bytes).context("Failed to write memory")?;
    println!("Successfully wrote {} bytes to {:#x}", bytes.len(), addr);
    Ok(())
}

pub fn cmd_scan(pid: u32, value_str: &str, type_str: &str, _region: Option<String>) -> Result<()> {
    let bytes = parse_value_bytes(type_str, value_str)
        .map_err(|e| anyhow::anyhow!("Invalid scan value: {}", e))?;
    let handle = MemHandle::open(pid).context(format!("Failed to open /proc/{}/mem", pid))?;
    let regions: Vec<_> = handle
        .maps()
        .writable_regions()
        .into_iter()
        .filter(|r| r.perms.contains('r'))
        .cloned()
        .collect();

    println!("Scanning PID {} ({} writable regions) for {} ({:02X?})...", pid, regions.len(), value_str, bytes);

    let mut matches = 0;
    for region in &regions {
        let chunk_size = 524288u64;
        let mut offset = region.start;
        while offset < region.end {
            let read_len = std::cmp::min(chunk_size + bytes.len() as u64, region.end - offset) as usize;
            if let Ok(buf) = handle.read(offset, read_len) {
                let mut search = 0;
                while search + bytes.len() <= buf.len() {
                    if buf[search..search + bytes.len()] == bytes[..] {
                        let match_addr = offset + search as u64;
                        println!("  Match: {:#x}", match_addr);
                        matches += 1;
                        if matches >= 100 {
                            println!("  ... (capped at 100 matches)");
                            return Ok(());
                        }
                    }
                    search += 1;
                }
            }
            offset += chunk_size;
        }
    }
    println!("Scan complete: found {} matches.", matches);
    Ok(())
}

pub fn cmd_maps(pid: u32) -> Result<()> {
    let handle = MemHandle::open(pid).context(format!("Failed to open /proc/{}/mem", pid))?;
    for r in &handle.maps().regions {
        println!("{:#012x}-{:#012x} {} {:>8} {}", r.start, r.end, r.perms, r.size, r.path);
    }
    Ok(())
}

pub fn cmd_probe(pid: u32) -> Result<()> {
    match MemHandle::open(pid) {
        Ok(h) => {
            let maps = h.maps();
            println!("✅ Successfully opened /proc/{}/mem", pid);
            println!("  Total regions: {}", maps.regions.len());
            println!("  Writable regions: {}", maps.writable_regions().len());
        }
        Err(e) => {
            println!("❌ Failed to open /proc/{}/mem: {}", pid, e);
            println!("  Check if ptrace_scope is 0 or run with sudo.");
        }
    }
    Ok(())
}

fn parse_address(s: &str) -> Result<u64> {
    let clean = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(clean, 16).context("Failed to parse hex address")
}

fn print_hex_dump(data: &[u8], base_addr: u64) {
    println!();
    println!("  {:016}  {:48}  {}", "ADDRESS", "HEX", "ASCII");
    println!("{}", "-".repeat(90));

    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base_addr + i as u64 * 16;
        let hex_part: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let mut hex_padded = hex_part;
        while hex_padded.len() < 16 {
            hex_padded.push("  ".to_string());
        }
        let ascii: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();

        println!(
            "  {:016x}  {:48}  {}",
            addr,
            hex_padded.join(" "),
            ascii
        );
    }
    println!();
}
