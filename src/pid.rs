//! PID discovery for Proton games.
//! Finds the actual game process running under Wine/Proton.

use std::fs;

/// Information about a discovered process.
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub is_wine: bool,
    pub is_steam: bool,
    pub parent_pid: u32,
}

/// Get the PID of the current process.
pub fn current_pid() -> u32 {
    std::process::id()
}

/// Enumerate all processes from /proc.
pub fn enumerate_processes() -> Vec<ProcInfo> {
    let mut procs = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path();
            let pid_str = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !pid_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let pid: u32 = pid_str.parse().ok().unwrap_or(0);
            if pid == 0 {
                continue;
            }
            if let Some(info) = read_proc_entry(pid) {
                procs.push(info);
            }
        }
    }
    procs
}

fn read_proc_entry(pid: u32) -> Option<ProcInfo> {
    let comm_path = format!("/proc/{}/comm", pid);
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    let stat_path = format!("/proc/{}/stat", pid);

    let name = fs::read_to_string(&comm_path).ok().unwrap_or_default();
    let cmdline_raw = fs::read_to_string(&cmdline_path).ok().unwrap_or_default();
    let cmdline = cmdline_raw
        .split('\0')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    let parent_pid = read_parent_pid(&stat_path);

    let is_wine = name.to_lowercase().contains("wine")
        || cmdline.to_lowercase().contains("wine")
        || cmdline.to_lowercase().contains("proton");
    let is_steam = cmdline.to_lowercase().contains("steam")
        || cmdline.to_lowercase().contains("steamdks");

    Some(ProcInfo {
        pid,
        name: name.trim().to_string(),
        cmdline: cmdline.trim().to_string(),
        is_wine,
        is_steam,
        parent_pid,
    })
}

fn read_parent_pid(stat_path: &str) -> u32 {
    let content = match fs::read_to_string(stat_path) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let stripped = content.trim();
    let paren_end = stripped.find(')').unwrap_or(stripped.len());
    if paren_end == 0 {
        return 0;
    }
    let after_comm = &stripped[paren_end + 2..];
    // /proc/pid/stat after comm: state ppid pgrp ...
    // fields[0] = state (e.g. 'R'), fields[1] = ppid
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    if fields.len() >= 2 {
        fields[1].parse().unwrap_or(0)
    } else {
        0
    }
}

pub fn children_of(pid: u32) -> Vec<u32> {
    let mut children = Vec::new();
    for info in enumerate_processes() {
        if info.parent_pid == pid {
            children.push(info.pid);
        }
    }
    children
}

/// Known Wine-internal process names that are infrastructure, not games.
/// These run under every Wine/Proton prefix and should never be treated as
/// the target game executable.
const WINE_SYSTEM_PROCS: &[&str] = &[
    "services.exe",
    "plugplay.exe",
    "svchost.exe",
    "explorer.exe",
    "rpcss.exe",
    "winedevice.exe",
    "wineserver",
    "conhost.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "tabtip.exe",
    "winemenubuilder.exe",
    "start.exe",
    "wineboot.exe",
    "dllhost.exe",
    "taskhost.exe",
    "spoolsv.exe",
    "lsass.exe",
    "ctfmon.exe",
];

/// Find processes that look like Proton game processes.
/// Returns children of Wine/Steam parent processes, excluding known Wine
/// infrastructure executables.
pub fn find_proton_game_processes() -> Vec<ProcInfo> {
    let all = enumerate_processes();

    // Collect the PIDs of processes that are themselves Wine or Steam instances.
    let wine_parent_pids: Vec<u32> = all
        .iter()
        .filter(|p| p.is_wine || p.is_steam)
        .map(|p| p.pid)
        .collect();

    let mut candidates = Vec::new();
    for info in &all {
        // Must be a direct child of a Wine/Steam process.
        if !wine_parent_pids.contains(&info.parent_pid) {
            continue;
        }
        // Skip if the process itself is Wine/Steam infrastructure.
        if info.is_wine || info.is_steam {
            continue;
        }
        // Skip known Wine system services — these are never the game.
        let name_lower = info.name.to_lowercase();
        if WINE_SYSTEM_PROCS.iter().any(|&n| name_lower == n) {
            continue;
        }
        candidates.push(info.clone());
    }

    candidates
}

/// Find a process by exact name match (case-insensitive).
pub fn find_by_name(name: &str) -> Vec<ProcInfo> {
    let lower = name.to_lowercase();
    enumerate_processes()
        .into_iter()
        .filter(|p| {
            p.name.to_lowercase() == lower
                || p.cmdline.to_lowercase().contains(&lower)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_self() {
        let procs = enumerate_processes();
        let my_pid = current_pid();
        assert!(
            procs.iter().any(|p| p.pid == my_pid),
            "Should find self"
        );
    }

    #[test]
    fn test_read_parent_pid() {
        let my_pid = current_pid();
        let stat_path = format!("/proc/{}/stat", my_pid);
        let ppid = read_parent_pid(&stat_path);
        assert!(ppid > 0, "Parent PID should be non-zero");
    }
}
