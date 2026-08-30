# Proton Process Detection

## Overview

Finding the right process to attach to is the first step. Under Proton, the game doesn't run as a native Linux process — it runs inside a Wine process. This document describes how `src/pid.rs` finds game processes.

## The Process Tree

When Steam launches a game via Proton, the process hierarchy looks approximately like:

```
steam (PID 1234)
  └─ proton-launch.sh (PID 1235)
       └─ wine-preloader (PID 1236)
            └─ wine (PID 1237)  ← this is the actual Wine server/process
                 └─ gamename.exe (PID 1238)  ← the game's Windows executable running under Wine
```

The **PID we want** is the one running the game's `.exe` (e.g., `gamename.exe`). That's PID 1238 in the example.

## How We Find It

### Step 1: Enumerate All Processes

We read `/proc` — every numeric subdirectory is a PID:

```rust
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
            if pid == 0 { continue; }
            if let Some(info) = read_proc_entry(pid) {
                procs.push(info);
            }
        }
    }
    procs
}
```

### Step 2: Read Per-Process Info

For each PID, we read:

- **`/proc/[pid]/comm`** — The command name (e.g., `gamename.exe`, `wine-preloader`, `steam`)
- **`/proc/[pid]/cmdline`** — Full command line (null-byte separated args)
- **`/proc/[pid]/stat`** — Process status, including parent PID

```rust
fn read_proc_entry(pid: u32) -> Option<ProcInfo> {
    let comm_path = format!("/proc/{}/comm", pid);
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    let stat_path = format!("/proc/{}/stat", pid);

    let name = fs::read_to_string(&comm_path).ok().unwrap_or_default();
    let cmdline_raw = fs::read_to_string(&cmdline_path).ok().unwrap_or_default();
    // cmdline is null-byte separated; convert to spaces
    let cmdline = cmdline_raw
        .split('\0')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    let parent_pid = read_parent_pid(&stat_path);
    // ...
}
```

### Step 3: Identify Wine/Steam Processes

We flag processes that are likely part of the Wine/Proton infrastructure:

```rust
let is_wine = name.to_lowercase().contains("wine")
    || cmdline.to_lowercase().contains("wine")
    || cmdline.to_lowercase().contains("proton");
let is_steam = cmdline.to_lowercase().contains("steam")
    || cmdline.to_lowercase().contains("steamdks");
```

### Step 4: Find Children of Wine/Steam

The game process is typically a child of a Wine or Steam process:

```rust
pub fn find_proton_game_processes() -> Vec<ProcInfo> {
    let all = enumerate_processes();

    // Collect PIDs of Wine/Steam processes
    let wine_parents: Vec<u32> = all
        .iter()
        .filter(|p| p.is_wine || p.is_steam)
        .map(|p| p.pid)
        .collect();

    // Find children of those parents that are NOT themselves Wine/Steam
    let mut candidates = Vec::new();
    for info in &all {
        if wine_parents.contains(&info.parent_pid) {
            if info.is_wine || info.is_steam {
                continue; // Skip the Wine/Steam process itself
            }
            candidates.push(info.clone());
        }
    }
    candidates
}
```

This gives us the game processes — the `.exe` files running under Wine.

## The ProcInfo Struct

```rust
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,       // From /proc/[pid]/comm
    pub cmdline: String,    // From /proc/[pid]/cmdline
    pub is_wine: bool,
    pub is_steam: bool,
    pub parent_pid: u32,
}
```

## Edge Cases

### Multiple Wine Processes
A single Wine installation can run multiple processes. `find_proton_game_processes` returns all of them — the user must pick the right one in the GUI.

### Games Running Under Different Proton Versions
Different Proton versions may have different process names. Our detection relies on "wine" and "steam" appearing in the name/cmdline — this should cover most cases.

### Games Not Running Under Proton
If the game is running natively (not under Proton), it won't be detected by `find_proton_game_processes`. Use `enumerate_processes` and look for the game by name manually.

### PID Changes
PIDs are not stable — they change every time a process restarts. Don't cache PIDs between sessions.

---

*See also: `src/pid.rs` for the implementation.*
