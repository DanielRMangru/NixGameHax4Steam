// CheatEngine-style memory scanner GUI
// Uses egui 0.33 + eframe 0.33, with the proton_mem library for all memory operations.

use eframe::egui;
use nixgamehax4steam::{
    enumerate_processes, parse_value_bytes, MemHandle, MemoryMap,
    ScanPhase, ScanResult, ValueType,
};
use std::collections::HashSet;
use std::sync::mpsc;
use std::thread;

/// Full user guide shown in the Help window and printed by `nixgamehax4steam-gui --guide`.
const GUIDE: &str = r#"
╔══════════════════════════════════════════════════════╗
║                 NixGameHax4Steam                     ║
║         CheatEngine-style scanner for Linux          ║
╚══════════════════════════════════════════════════════╝

REQUIREMENTS
  • Ubuntu 24.04 (or any Linux with /proc/pid/mem)
  • ptrace_scope = 0  (check: cat /proc/sys/kernel/yama/ptrace_scope)
    If it shows 1, run as root or set it temporarily:
      sudo sysctl kernel.yama.ptrace_scope=0
  • Run the game through Steam/Proton before opening this tool.
  • Run with sudo (or as a user with ptrace permission).

──────────────────────────────────────────────────────
QUICK-START
──────────────────────────────────────────────────────
 1. Launch your game in Steam (Proton/Wine).
 2. Open NixGameHax4Steam.
 3. Type the game's name in the Filter box (e.g. "legion").
 4. Select the matching process in the Process dropdown.
 5. Click Connect.
 6. In the Scanner panel, choose a Type (usually U32 for
    gold, health, score — whole numbers 0–4 billion).
 7. Type the current in-game value in the Value box.
 8. Click First Scan and wait for the progress bar to finish.
    → The Results list shows up to 2,000 matching addresses.
 9. Change the value in-game (spend gold, take damage, etc.).
10. Type the new value, click Next Scan.
    → Repeat until 1–5 results remain.
11. Click each remaining address to highlight it.
    The Read/Write panel shows its current live value.
12. Confirm it tracks the in-game value, then:
    • Click "🔒 Lock" to freeze the selected address, OR
    • Click "🔒 Lock All" to freeze every remaining result.

──────────────────────────────────────────────────────
SCANNER TYPES
──────────────────────────────────────────────────────
  U8    Unsigned 8-bit  (0 – 255)        — small flags, bytes
  U16   Unsigned 16-bit (0 – 65535)      — rarely used
  U32   Unsigned 32-bit (0 – 4.3B)       — health, gold, score ← most common
  U64   Unsigned 64-bit                  — very large values
  F32   32-bit float                     — speed, position, timers
  F64   64-bit float                     — high-precision values
  Hex   Search for a hex byte sequence
  Bytes Raw byte pattern

──────────────────────────────────────────────────────
RESULTS LIST
──────────────────────────────────────────────────────
  Address column  Click any address to select it.
  Value column    Live value read from memory every frame.
  Lock button     Immediately freeze that single address.
  🔒 Lock All     Freeze every result in one click (≤100 results).

──────────────────────────────────────────────────────
VALIDATOR & MEMORY DIAGNOSTICS
──────────────────────────────────────────────────────
  Why did locked values not change an in-game purchase?
  Modern games employ several protection/caching layers:

  🟢 Stable (Local)
     The value holds in memory with 0% resistance. Direct
     writes and freezes work immediately (standard offline games).

  🟡 UI Display Cache
     The game overwrites this address rapidly every frame.
     This indicates you locked a visual HUD/text buffer rather
     than the true underlying game balance.
     → Search while switching menus or trace parent pointers.

  🔴 Reverted on Action / Purchase
     The value held steady while idle, but snapped back when
     making an in-game purchase. This indicates:
     1. Server-Side Validation (e.g. 2K VC / online microtransactions)
     2. Dual-Storage / Shadow checksum verification
     → Use the "Scan Nearby Shadows" tool to locate mirrored values.

  🟣 Dynamic Heap / Anon Memory
     Address is located in dynamic heap memory. Pointers may
     change if you reload scenes or restart the game.

──────────────────────────────────────────────────────
LOCKED VALUES TABLE
──────────────────────────────────────────────────────
  ☑ checkbox    Enable/disable the freeze for that entry.
  Address       Click to jump to it in the Read/Write panel.
  Frozen        The value that gets re-written every frame.
  Live          The value actually in memory right now.
  Diagnosis     Live validator badge & stability indicator.
  ❌ button     Remove this entry from the locked list.

──────────────────────────────────────────────────────
READ / WRITE PANEL
──────────────────────────────────────────────────────
  Current value   Refreshed each time you select an address.
  New value       Edit this field then click Write to patch memory.
  🔒 Lock         Locks the *current New value* field — NOT the
                  Current value. Edit New value first if you want
                  to freeze a specific number (e.g. 9999 gold).
  Diagnostics     Inspects memory region type (Module vs Heap),
                  monitors write stability, and scans for nearby
                  shadow/mirrored values.

──────────────────────────────────────────────────────
SCAN BUTTONS
──────────────────────────────────────────────────────
  First Scan   Search all writable memory for the typed value.
               Stops early if > 5 million matches are found.
               Shows the first 2,000; use Next Scan to narrow.
  Next Scan    Re-check only the previous results; keep matches.
  New Scan     Clear all results and start fresh.
  Undo Scan    Step back to the previous scan's result set.

──────────────────────────────────────────────────────
TIPS
──────────────────────────────────────────────────────
  • Scan for the *exact* current value — avoid round numbers
    like 100 or 1000 that appear everywhere in memory.
  • Do 3–5 Next Scans to get down to < 10 results before locking.
  • If a frozen value shows 🟡 constantly, the game overwrites
    it from another thread faster than the freeze loop. Try
    locking the address that writes it instead (a pointer).
  • U32 covers most Unity / Unreal / custom engine games.
    If you can't find a value with U32, try F32 (floats are
    common for health bars) or U64 (64-bit counters).
  • The HEX VIEWER tab shows raw memory around the selected
    address — useful for finding nearby related values.

──────────────────────────────────────────────────────
CLI USAGE  (proton-gui binary)
──────────────────────────────────────────────────────
  proton-gui                Launch the graphical interface.
  proton-gui --guide        Print this guide and exit.
  proton-gui --test-scan <pid> <value>
                            Quick CLI scan (debug/testing).
"#;

/// Messages sent from the background scan thread to the GUI.
enum ScanMsg {
    /// Scan is in progress: (regions_done, regions_total).
    Progress(usize, usize),
    /// First-scan finished with all matching addresses.
    FirstDone(Vec<u64>, usize /* value_size */),
    /// Next-scan finished with the narrowed result set.
    NextDone(Vec<ScanResult>),
    /// The scan thread encountered an error.
    Error(String),
}

/// Size of the hex dump window around a selected address.
const HEX_WINDOW_BYTES: usize = 4096;

/// Diagnostic state evaluated for a locked memory value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorDiagnosis {
    /// Holds stably without pushback from the game.
    Stable,
    /// Constantly overwritten every frame -> UI/HUD display render cache.
    UiDisplayCache,
    /// Held the value while idle, but rejected/reverted when a game transaction/action occurred.
    TransactionRejection,
    /// Dynamic heap memory (could reallocate or change across scenes).
    DynamicHeap,
    /// Unknown / Still evaluating.
    Evaluating,
}

impl ValidatorDiagnosis {
    pub fn badge(&self) -> (&'static str, egui::Color32, &'static str) {
        match self {
            ValidatorDiagnosis::Stable => (
                "🟢 Stable",
                egui::Color32::from_rgb(80, 220, 100),
                "Value holds stably without pushback from game. Standard local variable.",
            ),
            ValidatorDiagnosis::UiDisplayCache => (
                "🟡 UI Cache",
                egui::Color32::from_rgb(255, 210, 60),
                "Constantly overwritten every frame. You may have found a HUD/UI display buffer rather than the true variable.",
            ),
            ValidatorDiagnosis::TransactionRejection => (
                "🔴 Reverted on Action",
                egui::Color32::from_rgb(255, 90, 90),
                "Value held while idle, but snapped back upon making an in-game action/purchase. Server-side validation or shadow checksum detected.",
            ),
            ValidatorDiagnosis::DynamicHeap => (
                "🟣 Dynamic Heap",
                egui::Color32::from_rgb(200, 140, 255),
                "Address is inside dynamic heap/anon memory. Pointers may change on scene transitions.",
            ),
            ValidatorDiagnosis::Evaluating => (
                "⚪ Evaluating...",
                egui::Color32::from_rgb(180, 180, 180),
                "Monitoring memory write/read stability...",
            ),
        }
    }
}

/// Memory region categorization for an address.
#[derive(Debug, Clone)]
pub struct RegionDiagnosis {
    pub name: String,
    pub detail: String,
    pub color: egui::Color32,
    pub is_static: bool,
}

/// Result of scanning proximity memory for potential shadow/mirrored values.
#[derive(Debug, Clone)]
pub struct ShadowScanResult {
    pub offset_bytes: i64,
    pub address: u64,
    pub description: String,
    pub value_str: String,
}

/// A locked (frozen) memory value.
struct LockedEntry {
    address: u64,
    value_type: ValueType,
    bytes: Vec<u8>,
    enabled: bool,
    label: String,
    // Diagnostics metrics
    writes_total: u64,
    drift_count: u64,
    held_streak: usize,
    drift_streak: usize,
    diagnosis: ValidatorDiagnosis,
}

impl LockedEntry {
    fn new(address: u64, value_type: ValueType, bytes: Vec<u8>, label: String) -> Self {
        Self {
            address,
            value_type,
            bytes,
            enabled: true,
            label,
            writes_total: 0,
            drift_count: 0,
            held_streak: 0,
            drift_streak: 0,
            diagnosis: ValidatorDiagnosis::Evaluating,
        }
    }
}

/// Our main GUI state.
pub struct ProtonMemApp {
    handle: Option<MemHandle>,
    memory_map: Option<MemoryMap>,
    processes: Vec<nixgamehax4steam::ProcInfo>,
    selected_pid: u32,
    scan_phase: ScanPhase,
    selected_address: u64,
    hex_buf: Vec<u8>,
    scan_value_text: String,
    scan_value_type: ValueType,
    rw_value_text: String,
    status_message: String,
    /// True while a background scan thread is running.
    scanning: bool,
    /// Scan progress: (regions_done, regions_total). Updated from the bg thread.
    scan_progress: (usize, usize),
    value_size: usize,
    process_filter: String,
    active_tab: usize,
    last_write_result: Option<String>,
    converter_input: String,
    /// Locked (frozen) values — written every frame.
    locked_values: Vec<LockedEntry>,
    /// Receiver end of the background scan channel.
    scan_rx: Option<mpsc::Receiver<ScanMsg>>,
    /// Stored history snapshot for next-scan completion (built before spawning the thread).
    _pending_next_history: Option<Vec<Vec<ScanResult>>>,
    /// Addresses checked in the results list (for Lock Selected).
    #[allow(dead_code)]
    selected_results: HashSet<u64>,
    /// Whether the Help window is open.
    show_help: bool,
    /// Proximity shadow scan candidates found in memory window around selected_address.
    shadow_scan_results: Option<Vec<ShadowScanResult>>,
}

impl Default for ProtonMemApp {
    fn default() -> Self {
        Self {
            handle: None,
            memory_map: None,
            processes: Vec::new(),
            selected_pid: 0,
            scan_phase: ScanPhase::Idle,
            selected_address: 0,
            hex_buf: Vec::new(),
            scan_value_text: String::new(),
            scan_value_type: ValueType::U32,
            rw_value_text: String::new(),
            status_message: String::from("Disconnect or select a process to begin."),
            scanning: false,
            scan_progress: (0, 0),
            value_size: 4,
            process_filter: String::new(),
            active_tab: 0,
            last_write_result: None,
            converter_input: String::new(),
            locked_values: Vec::new(),
            scan_rx: None,
            _pending_next_history: None,
            selected_results: HashSet::new(),
            show_help: false,
            shadow_scan_results: None,
        }
    }
}

impl ProtonMemApp {
    fn refresh_processes(&mut self) {
        // Always load the full process list so every process is reachable.
        self.processes = enumerate_processes();
        // Leave the filter as-is — the user types to narrow down.
        // (We do not auto-populate the filter; find_proton_game_processes() is
        // available via the type-ahead search in the filter box instead.)
    }

    fn connect(&mut self) {
        if self.selected_pid == 0 {
            self.status_message = "No process selected.".into();
            return;
        }
        match MemHandle::open(self.selected_pid) {
            Ok(h) => {
                self.handle = Some(h);
                if let Some(ref h) = self.handle {
                    self.memory_map = Some(h.maps().clone());
                }
                self.scan_phase = ScanPhase::Idle;
                self.selected_address = 0;
                self.hex_buf.clear();
                self.status_message = format!("Connected to PID {}.", self.selected_pid);
            }
            Err(e) => {
                self.status_message =
                    format!("Failed to open /proc/{}/mem: {}", self.selected_pid, e);
                self.handle = None;
                self.memory_map = None;
            }
        }
    }

    fn disconnect(&mut self) {
        self.handle = None;
        self.memory_map = None;
        self.scan_phase = ScanPhase::Idle;
        self.selected_address = 0;
        self.hex_buf.clear();
        self.status_message = "Disconnected.".into();
    }

    fn value_type_to_str(vt: &ValueType) -> &'static str {
        match vt {
            ValueType::U8 => "u8",
            ValueType::U16 => "u16",
            ValueType::U32 => "u32",
            ValueType::U64 => "u64",
            ValueType::F32 => "f32",
            ValueType::F64 => "f64",
            ValueType::Hex => "hex",
            ValueType::Bytes => "bytes",
        }
    }

    /// Perform a first scan on a background thread.
    fn first_scan(&mut self) {
        if self.scanning {
            self.status_message = "A scan is already in progress.".into();
            return;
        }
        let pid = match self.handle.as_ref() {
            Some(_) => self.selected_pid,
            None => {
                self.status_message = "Not connected to a process.".into();
                return;
            }
        };

        let bytes = match parse_value_bytes(
            Self::value_type_to_str(&self.scan_value_type),
            &self.scan_value_text,
        ) {
            Ok(b) => b,
            Err(e) => {
                self.status_message = format!("Invalid scan value: {}", e);
                return;
            }
        };

        let value_size = bytes.len();
        self.value_size = value_size;
        self.scanning = true;
        self.scan_progress = (0, 0);
        self.status_message = format!("Scanning for {}…", self.scan_value_text);

        let (tx, rx) = mpsc::channel::<ScanMsg>();
        self.scan_rx = Some(rx);

        thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // Open a fresh handle on the worker thread.
                let handle = match MemHandle::open(pid) {
                    Ok(h) => h,
                    Err(e) => {
                        let _ = tx.send(ScanMsg::Error(format!("Cannot open /proc/{}/mem: {}", pid, e)));
                        return;
                    }
                };

                let regions: Vec<_> = handle.maps().writable_regions()
                    .into_iter()
                    .filter(|r| r.perms.contains('r'))
                    .cloned()
                    .collect();
                let total = regions.len();
                let mut results: Vec<u64> = Vec::new();

                // Hard cap inside the thread so we never OOM-abort before
                // sending FirstDone. 5 million addresses @ 8 bytes = 40 MB.
                const MAX_RESULTS: usize = 5_000_000;

                'outer: for (i, region) in regions.iter().enumerate() {
                    if i % 64 == 0 {
                        let _ = tx.send(ScanMsg::Progress(i, total));
                    }

                    // Use 512 KB read chunks to minimize syscall overhead
                    let chunk_size: u64 = 524288;
                    let extra = if bytes.len() > 1 { (bytes.len() - 1) as u64 } else { 0 };
                    let mut offset = region.start;
                    while offset < region.end {
                        let read_len = std::cmp::min(chunk_size + extra, region.end - offset) as usize;
                        if let Ok(buf) = handle.read(offset, read_len) {
                            let mut search = 0usize;
                            while search + bytes.len() <= buf.len() {
                                if buf[search..search + bytes.len()] == bytes[..] {
                                    results.push(offset + search as u64);
                                    if results.len() >= MAX_RESULTS {
                                        // Hit the cap — stop immediately.
                                        break 'outer;
                                    }
                                }
                                search += 1;
                            }
                        }
                        offset += chunk_size;
                    }
                }

                results.sort();
                results.dedup();
                let _ = tx.send(ScanMsg::FirstDone(results, value_size));
            }));

            if result.is_err() {
                let _ = tx.send(ScanMsg::Error("Scan thread panicked".into()));
            }
        });
    }

    /// Perform a next scan on a background thread: narrow down existing results.
    fn next_scan(&mut self) {
        if self.scanning {
            self.status_message = "A scan is already in progress.".into();
            return;
        }
        let pid = match self.handle.as_ref() {
            Some(_) => self.selected_pid,
            None => {
                self.status_message = "Not connected to a process.".into();
                return;
            }
        };

        let bytes = match parse_value_bytes(
            Self::value_type_to_str(&self.scan_value_type),
            &self.scan_value_text,
        ) {
            Ok(b) => b,
            Err(e) => {
                self.status_message = format!("Invalid scan value: {}", e);
                return;
            }
        };

        self.value_size = bytes.len();

        let prev_results: Vec<ScanResult> = match &self.scan_phase {
            ScanPhase::FirstScan { results } => results.clone(),
            ScanPhase::NextScan { results, .. } => results.clone(),
            _ => {
                self.status_message = "Nothing to scan — perform a first scan first.".into();
                return;
            }
        };

        if prev_results.is_empty() {
            self.status_message = "No previous scan results to narrow down.".into();
            return;
        }

        // Build the new history now (before moving prev_results into the thread).
        let new_history: Vec<Vec<ScanResult>> = match &self.scan_phase {
            ScanPhase::FirstScan { .. } => vec![prev_results.clone()],
            ScanPhase::NextScan { history, .. } => {
                let mut h = history.clone();
                h.push(prev_results.clone());
                h
            }
            _ => vec![prev_results.clone()],
        };

        let prev_len = prev_results.len();
        self.scanning = true;
        self.scan_progress = (0, prev_len);
        self.status_message = format!("Narrowing {} candidates…", prev_len);

        let (tx, rx) = mpsc::channel::<ScanMsg>();
        self.scan_rx = Some(rx);

        thread::spawn(move || {
            let handle = match MemHandle::open(pid) {
                Ok(h) => h,
                Err(e) => {
                    let _ = tx.send(ScanMsg::Error(format!("Cannot open /proc/{}/mem: {}", pid, e)));
                    return;
                }
            };

            let mut matched: Vec<ScanResult> = Vec::new();
            for (i, sr) in prev_results.iter().enumerate() {
                if i % 1024 == 0 {
                    let _ = tx.send(ScanMsg::Progress(i, prev_len));
                }
                if let Ok(buf) = handle.read(sr.address, sr.size) {
                    if buf == bytes[..] {
                        matched.push(ScanResult {
                            address: sr.address,
                            size: bytes.len(),
                            value_type: sr.value_type,
                        });
                    }
                }
            }

            let _ = tx.send(ScanMsg::NextDone(matched));
        });

        // Store the history snapshot built before spawning so update() can
        // assemble ScanPhase::NextScan when the thread reports NextDone.
        self._pending_next_history = Some(new_history);
    }

    /// Lock (freeze) the current address with the current write value.
    fn lock_current(&mut self) {
        if self.selected_address == 0 {
            self.status_message = "No address selected to lock.".into();
            return;
        }
        let bytes = match parse_value_bytes(
            Self::value_type_to_str(&self.scan_value_type),
            &self.rw_value_text,
        ) {
            Ok(b) => b,
            Err(e) => {
                self.status_message = format!("Invalid lock value: {}", e);
                return;
            }
        };
        // Write immediately to memory
        if let Some(ref handle) = self.handle {
            let _ = handle.write(self.selected_address, &bytes);
        }
        // Check if already locked
        for entry in &mut self.locked_values {
            if entry.address == self.selected_address {
                entry.bytes = bytes.clone();
                entry.value_type = self.scan_value_type;
                entry.enabled = true;
                entry.writes_total = 0;
                entry.drift_count = 0;
                entry.held_streak = 0;
                entry.drift_streak = 0;
                entry.diagnosis = ValidatorDiagnosis::Evaluating;
                self.status_message = format!("Locked {:#x} at {}", self.selected_address, self.rw_value_text);
                return;
            }
        }
        self.locked_values.push(LockedEntry::new(
            self.selected_address,
            self.scan_value_type,
            bytes.clone(),
            format!("{:#x}", self.selected_address),
        ));
        self.status_message = format!(
            "Locked {} at {:#x}",
            self.rw_value_text,
            self.selected_address
        );
    }

    /// Unlock a previously locked address.
    fn unlock(&mut self, index: usize) {
        if index < self.locked_values.len() {
            self.locked_values.remove(index);
        }
    }

    /// Write all enabled locked values to the target process and update stability diagnostics.
    fn write_locked_values(&mut self) {
        let handle = match self.handle.as_ref() {
            Some(h) => h,
            None => return,
        };
        for entry in &mut self.locked_values {
            if !entry.enabled {
                continue;
            }

            // Diagnostic pre-read: check if game engine has overwritten the value since last frame
            if let Ok(live_bytes) = handle.read(entry.address, entry.bytes.len()) {
                entry.writes_total = entry.writes_total.saturating_add(1);
                if live_bytes != entry.bytes {
                    entry.drift_count = entry.drift_count.saturating_add(1);
                    entry.drift_streak = entry.drift_streak.saturating_add(1);

                    // If it held steady for >=12 frames (idle stability), but then drifted,
                    // an in-game action (purchase/damage/scene change) triggered a rollback/validator.
                    if entry.held_streak >= 12 && entry.drift_streak >= 1 {
                        entry.diagnosis = ValidatorDiagnosis::TransactionRejection;
                    } else if entry.drift_count >= 5
                        && (entry.drift_count as f64 / entry.writes_total as f64) > 0.35
                    {
                        // Rapid continuous frame-by-frame overwrite -> UI render display buffer
                        entry.diagnosis = ValidatorDiagnosis::UiDisplayCache;
                    }
                    entry.held_streak = 0;
                } else {
                    entry.held_streak = entry.held_streak.saturating_add(1);
                    entry.drift_streak = 0;

                    // If steady for >20 frames and not flagged as transaction rollback, it is stable local memory
                    if entry.held_streak >= 20 && entry.diagnosis != ValidatorDiagnosis::TransactionRejection {
                        entry.diagnosis = ValidatorDiagnosis::Stable;
                    }
                }
            }

            let _ = handle.write(entry.address, &entry.bytes);
        }
    }

    /// Look up the memory region for an address and categorize it.
    fn get_region_diagnosis(&self, addr: u64) -> RegionDiagnosis {
        if addr == 0 {
            return RegionDiagnosis {
                name: "None".into(),
                detail: "No address selected".into(),
                color: egui::Color32::GRAY,
                is_static: false,
            };
        }
        if let Some(ref map) = self.memory_map {
            if let Some(region) = map.region_for_addr(addr) {
                let offset_in_region = addr.saturating_sub(region.start);
                let path = &region.path;

                if path.ends_with(".exe") || path.contains(".exe") {
                    let file_name = std::path::Path::new(path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(path);
                    return RegionDiagnosis {
                        name: format!("Static Module: {} + {:#X}", file_name, offset_in_region),
                        detail: format!("Range: {:#X}..{:#X} | Perms: {}", region.start, region.end, region.perms),
                        color: egui::Color32::from_rgb(90, 220, 110),
                        is_static: true,
                    };
                } else if path.ends_with(".dll") || path.ends_with(".so") || path.contains(".dll") || path.contains(".so") {
                    let file_name = std::path::Path::new(path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(path);
                    return RegionDiagnosis {
                        name: format!("Shared Lib: {} + {:#X}", file_name, offset_in_region),
                        detail: format!("Range: {:#X}..{:#X} | Perms: {}", region.start, region.end, region.perms),
                        color: egui::Color32::from_rgb(110, 190, 255),
                        is_static: true,
                    };
                } else if path == "[heap]" {
                    return RegionDiagnosis {
                        name: format!("[heap] + {:#X} (Dynamic Heap)", offset_in_region),
                        detail: format!("Range: {:#X}..{:#X} | Perms: {} (Dynamic Allocation)", region.start, region.end, region.perms),
                        color: egui::Color32::from_rgb(255, 180, 70),
                        is_static: false,
                    };
                } else if path.starts_with("[stack") {
                    return RegionDiagnosis {
                        name: format!("[stack] + {:#X} (Thread Stack)", offset_in_region),
                        detail: format!("Range: {:#X}..{:#X} | Perms: {}", region.start, region.end, region.perms),
                        color: egui::Color32::from_rgb(100, 240, 240),
                        is_static: false,
                    };
                } else if path.is_empty() {
                    return RegionDiagnosis {
                        name: format!("Anonymous mmap + {:#X} (Proton Dynamic Heap)", offset_in_region),
                        detail: format!("Range: {:#X}..{:#X} | Perms: {} (Heap memory)", region.start, region.end, region.perms),
                        color: egui::Color32::from_rgb(200, 140, 255),
                        is_static: false,
                    };
                } else {
                    return RegionDiagnosis {
                        name: format!("{} + {:#X}", path, offset_in_region),
                        detail: format!("Range: {:#X}..{:#X} | Perms: {}", region.start, region.end, region.perms),
                        color: egui::Color32::LIGHT_GRAY,
                        is_static: false,
                    };
                }
            }
        }
        RegionDiagnosis {
            name: "Unmapped / Unknown Region".into(),
            detail: "Address not found in /proc/[pid]/maps".into(),
            color: egui::Color32::GRAY,
            is_static: false,
        }
    }

    /// Scan surrounding hex window memory for candidate shadow / mirrored variables.
    fn scan_proximity_shadows(&mut self) {
        if self.selected_address == 0 || self.hex_buf.is_empty() {
            self.shadow_scan_results = None;
            return;
        }
        let start_addr = (self.selected_address / 16) * 16;
        let vt = self.scan_value_type;
        let mut results = Vec::new();

        let target_bytes = match self.handle.as_ref().and_then(|h| {
            let size = match vt {
                ValueType::U8 => 1,
                ValueType::U16 => 2,
                ValueType::U32 => 4,
                ValueType::U64 => 8,
                ValueType::F32 => 4,
                ValueType::F64 => 8,
                _ => 4,
            };
            h.read(self.selected_address, size).ok()
        }) {
            Some(b) => b,
            None => {
                self.shadow_scan_results = Some(Vec::new());
                return;
            }
        };

        if target_bytes.iter().all(|&b| b == 0) {
            self.shadow_scan_results = Some(Vec::new());
            return;
        }

        let step = match vt {
            ValueType::U8 => 1,
            ValueType::U16 => 2,
            ValueType::U32 | ValueType::F32 => 4,
            ValueType::U64 | ValueType::F64 => 8,
            _ => 1,
        };

        let target_offset_in_buf = self.selected_address.saturating_sub(start_addr) as usize;

        // Check for exact matching values at other nearby offsets (Dual-Storage / Mirrored variables)
        let mut idx = 0;
        while idx + target_bytes.len() <= self.hex_buf.len() {
            if idx != target_offset_in_buf && self.hex_buf[idx..idx + target_bytes.len()] == target_bytes[..] {
                let candidate_addr = start_addr + idx as u64;
                let rel_offset = candidate_addr as i64 - self.selected_address as i64;
                results.push(ShadowScanResult {
                    offset_bytes: rel_offset,
                    address: candidate_addr,
                    description: "Exact Mirror Value (Dual-Storage Candidate)".into(),
                    value_str: fmt_bytes_as_value(&target_bytes, vt),
                });
                if results.len() >= 12 {
                    break;
                }
            }
            idx += step;
        }

        // Also check if an integer has a float mirror
        if vt == ValueType::U32 && target_bytes.len() == 4 {
            let int_val = u32::from_le_bytes([target_bytes[0], target_bytes[1], target_bytes[2], target_bytes[3]]);
            if int_val > 0 && int_val < 100_000_000 {
                let float_bytes = (int_val as f32).to_le_bytes();
                let mut f_idx = 0;
                while f_idx + 4 <= self.hex_buf.len() && results.len() < 12 {
                    if f_idx != target_offset_in_buf && self.hex_buf[f_idx..f_idx + 4] == float_bytes {
                        let candidate_addr = start_addr + f_idx as u64;
                        let rel_offset = candidate_addr as i64 - self.selected_address as i64;
                        results.push(ShadowScanResult {
                            offset_bytes: rel_offset,
                            address: candidate_addr,
                            description: "Float Mirror (F32 representation of int)".into(),
                            value_str: format!("{:.1}", int_val as f32),
                        });
                    }
                    f_idx += 4;
                }
            }
        }

        self.shadow_scan_results = Some(results);
    }

    fn new_scan(&mut self) {
        self.scan_phase = ScanPhase::Idle;
        self.selected_address = 0;
        self.hex_buf.clear();
        self.status_message = "New scan started. Enter a value and click First Scan.".into();
    }

    fn undo_scan(&mut self) {
        let (target_addr, restored_count) = match &mut self.scan_phase {
            ScanPhase::NextScan { results, history } => {
                if let Some(prev) = history.pop() {
                    *results = prev;
                    let addr = results.first().map(|r| r.address).unwrap_or(0);
                    let count = results.len();
                    (addr, count)
                } else {
                    self.status_message = "Nothing to undo.".into();
                    (0, 0)
                }
            }
            ScanPhase::FirstScan { .. } | ScanPhase::Idle => {
                self.status_message = "Nothing to undo — already at the first scan.".into();
                (0, 0)
            }
        };
        if target_addr != 0 {
            self.selected_address = target_addr;
            self.load_hex_view();
        }
        if restored_count > 0 {
            self.status_message = format!("Undid scan: {} results restored.", restored_count);
        }
    }

    fn load_hex_view(&mut self) {
        let handle = match self.handle.as_ref() {
            Some(h) => h,
            None => return,
        };
        if self.selected_address == 0 {
            self.hex_buf.clear();
            return;
        }
        let start = (self.selected_address / 16) * 16;
        let end = start.saturating_add(HEX_WINDOW_BYTES as u64);
        let size = (end - start) as usize;
        match handle.read(start, size) {
            Ok(buf) => self.hex_buf = buf,
            Err(_) => self.hex_buf.clear(),
        }
    }

    fn refresh_read_write(&mut self) {
        let handle = match self.handle.as_ref() {
            Some(h) => h,
            None => {
                self.rw_value_text = String::new();
                return;
            }
        };
        if self.selected_address == 0 {
            self.rw_value_text = String::new();
            return;
        }
        let vt = &self.scan_value_type;
        let size = match vt {
            ValueType::U8 => 1,
            ValueType::U16 => 2,
            ValueType::U32 => 4,
            ValueType::U64 => 8,
            ValueType::F32 => 4,
            ValueType::F64 => 8,
            ValueType::Hex => self.value_size.max(1),
            ValueType::Bytes => self.value_size.max(1),
        };
        match handle.read(self.selected_address, size) {
            Ok(buf) => {
                let s = match vt {
                    ValueType::U8 => {
                        if buf.len() >= 1 {
                            format!("{}", buf[0])
                        } else {
                            String::new()
                        }
                    }
                    ValueType::U16 => {
                        if buf.len() >= 2 {
                            format!("{}", u16::from_le_bytes([buf[0], buf[1]]))
                        } else {
                            String::new()
                        }
                    }
                    ValueType::U32 => {
                        if buf.len() >= 4 {
                            format!("{}", u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
                        } else {
                            String::new()
                        }
                    }
                    ValueType::U64 => {
                        if buf.len() >= 8 {
                            format!(
                                "{}",
                                u64::from_le_bytes([
                                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                                ])
                            )
                        } else {
                            String::new()
                        }
                    }
                    ValueType::F32 => {
                        if buf.len() >= 4 {
                            format!("{}", f32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
                        } else {
                            String::new()
                        }
                    }
                    ValueType::F64 => {
                        if buf.len() >= 8 {
                            format!(
                                "{}",
                                f64::from_le_bytes([
                                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                                ])
                            )
                        } else {
                            String::new()
                        }
                    }
                    ValueType::Hex => buf
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(" "),
                    ValueType::Bytes => buf
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(" "),
                };
                self.rw_value_text = s;
            }
            Err(e) => {
                self.rw_value_text = format!("[read error: {}]", e);
            }
        }
    }

    fn write_value(&mut self) {
        let handle = match self.handle.as_ref() {
            Some(h) => h,
            None => {
                self.last_write_result = Some("❌ Not connected.".into());
                self.status_message = "Not connected.".into();
                return;
            }
        };
        if self.selected_address == 0 {
            self.last_write_result = Some("❌ No address selected.".into());
            self.status_message = "No address selected.".into();
            return;
        }
        let bytes = match parse_value_bytes(
            Self::value_type_to_str(&self.scan_value_type),
            &self.rw_value_text,
        ) {
            Ok(b) => b,
            Err(e) => {
                self.last_write_result = Some(format!("❌ Invalid value: {}", e));
                self.status_message = format!("Invalid write value: {}", e);
                return;
            }
        };
        match handle.write(self.selected_address, &bytes) {
            Ok(()) => {
                let msg = format!("✅ Wrote {} bytes to {:#x}", bytes.len(), self.selected_address);
                self.last_write_result = Some(msg.clone());
                self.status_message = msg;
                // If this address is already in locked_values, update its frozen value and enable it
                for entry in &mut self.locked_values {
                    if entry.address == self.selected_address {
                        entry.bytes = bytes.clone();
                        entry.enabled = true;
                    }
                }
                self.refresh_read_write();
            }
            Err(e) => {
                let msg = format!("❌ Write failed: {}", e);
                self.last_write_result = Some(msg.clone());
                self.status_message = msg;
            }
        }
    }
}


/// Format a raw byte slice as a human-readable value string for the given type.
fn fmt_bytes_as_value(bytes: &[u8], vt: ValueType) -> String {
    match vt {
        ValueType::U8 => {
            if bytes.len() >= 1 { format!("{}", bytes[0]) } else { "?".into() }
        }
        ValueType::U16 => {
            if bytes.len() >= 2 {
                format!("{}", u16::from_le_bytes([bytes[0], bytes[1]]))
            } else { "?".into() }
        }
        ValueType::U32 => {
            if bytes.len() >= 4 {
                format!("{}", u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            } else { "?".into() }
        }
        ValueType::U64 => {
            if bytes.len() >= 8 {
                format!("{}", u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            } else { "?".into() }
        }
        ValueType::F32 => {
            if bytes.len() >= 4 {
                format!("{:.4}", f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            } else { "?".into() }
        }
        ValueType::F64 => {
            if bytes.len() >= 8 {
                format!("{:.6}", f64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            } else { "?".into() }
        }
        ValueType::Hex | ValueType::Bytes => {
            bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
        }
    }
}


impl eframe::App for ProtonMemApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Auto-refresh process list on first frame.
        if self.processes.is_empty() {
            self.refresh_processes();
        }
        // Poll the background scan channel for progress / completion.
        let mut scan_done_msg: Option<ScanMsg> = None;
        if let Some(rx) = &self.scan_rx {
            // Drain all pending messages; keep the last terminal one.
            loop {
                match rx.try_recv() {
                    Ok(ScanMsg::Progress(done, total)) => {
                        self.scan_progress = (done, total);
                    }
                    Ok(msg @ ScanMsg::FirstDone(..)) | Ok(msg @ ScanMsg::NextDone(..)) | Ok(msg @ ScanMsg::Error(..)) => {
                        scan_done_msg = Some(msg);
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        // Thread panicked without sending a result.
                        scan_done_msg = Some(ScanMsg::Error("Scan thread disconnected unexpectedly".into()));
                        break;
                    }
                }
            }
        }
        // Apply completed scan results.
        if let Some(msg) = scan_done_msg {
            self.scan_rx = None;
            self.scanning = false;
            match msg {
                ScanMsg::FirstDone(results, value_size) => {
                    self.value_size = value_size;
                    if results.is_empty() {
                        self.status_message = format!(
                            "First scan found 0 results for {}",
                            self.scan_value_text
                        );
                        self.scan_phase = ScanPhase::Idle;
                    } else {
                        let vt = self.scan_value_type;
                        let sz = value_size;
                        let total = results.len();
                        let scan_results: Vec<ScanResult> = results
                            .into_iter()
                            .map(|addr| ScanResult { address: addr, size: sz, value_type: vt })
                            .collect();
                        self.status_message = format!(
                            "First scan found {} results for {}",
                            total, self.scan_value_text
                        );
                        self.selected_address = scan_results[0].address;
                        self.scan_phase = ScanPhase::FirstScan { results: scan_results };
                        self.load_hex_view();
                    }
                }
                ScanMsg::NextDone(matched) => {
                    let history = self._pending_next_history.take().unwrap_or_default();
                    let prev_len = history.last().map(|h| h.len()).unwrap_or(0);
                    if matched.is_empty() {
                        self.status_message = format!(
                            "Next scan: 0 of {} results matched",
                            prev_len
                        );
                        self.scan_phase = ScanPhase::Idle;
                    } else {
                        let count = matched.len();
                        self.status_message = format!(
                            "Next scan: narrowed to {} results (down from {}).",
                            count, prev_len
                        );
                        if let Some(first) = matched.first() {
                            self.selected_address = first.address;
                        }
                        self.scan_phase = ScanPhase::NextScan {
                            results: matched,
                            history,
                        };
                        self.load_hex_view();
                    }
                }
                ScanMsg::Error(e) => {
                    self.status_message = format!("Scan error: {}", e);
                }
                ScanMsg::Progress(..) => {} // handled above
            }
        }

        // Write locked values every frame (to freeze them in memory).
        self.write_locked_values();
        if !self.locked_values.is_empty() || self.scanning {
            // Keep repainting: locked-value freeze loop + background scan polling.
            ctx.request_repaint();
        }

        egui::SidePanel::left("status_panel")
            .default_width(200.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Status");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("❓ Help").clicked() {
                            self.show_help = !self.show_help;
                        }
                    });
                });
                ui.separator();
                ui.label(egui::RichText::new(&self.status_message).small());
                // Show a progress bar while a background scan is running.
                if self.scanning {
                    let (done, total) = self.scan_progress;
                    let fraction = if total > 0 { done as f32 / total as f32 } else { 0.0 };
                    ui.add(
                        egui::ProgressBar::new(fraction)
                            .show_percentage()
                            .animate(true)
                            .desired_width(ui.available_width()),
                    );
                    ui.label(
                        egui::RichText::new(format!("Region {}/{}", done, total))
                            .small()
                            .weak(),
                    );
                }
                ui.add_space(8.0);
                if let Some(ref map) = self.memory_map {
                    let region_count = map.regions.len();
                    let writable = map.writable_regions().len();
                    ui.label(format!(
                        "Memory map: {} regions, {} writable",
                        region_count, writable
                    ));
                } else {
                    ui.label("No memory map loaded.".to_string());
                }

                // Show locked values status
                if !self.locked_values.is_empty() {
                    ui.add_space(12.0);
                    ui.separator();
                    ui.heading("Locked");
                    ui.separator();
                    let enabled_count = self.locked_values.iter().filter(|e| e.enabled).count();
                    ui.label(
                        egui::RichText::new(format!(
                            "{} locked ({} active)",
                            self.locked_values.len(),
                            enabled_count
                        ))
                        .small(),
                    );
                    for entry in &self.locked_values {
                        let color = if entry.enabled {
                            egui::Color32::GREEN
                        } else {
                            egui::Color32::GRAY
                        };
                        ui.label(
                            egui::RichText::new(format!(
                                "{} {} [{:?}]",
                                if entry.enabled { "✓" } else { "✗" },
                                entry.label,
                                entry.value_type
                            ))
                            .monospace()
                            .small()
                            .color(color),
                        );
                    }
                }

                ui.add_space(16.0);
                ui.separator();
                ui.label("v0.1.0 — Rust + egui");

                // ----- Converter -----
                ui.add_space(16.0);
                ui.separator();
                ui.heading("Converter");
                ui.separator();

                ui.label("Enter a number:");
                ui.text_edit_singleline(&mut self.converter_input);

                // Try to parse as integer or float
                let input_trimmed = self.converter_input.trim();
                let parsed_u64 = input_trimmed.parse::<u64>().ok();
                let parsed_f64 = input_trimmed.parse::<f64>().ok();

                if parsed_u64.is_some() || parsed_f64.is_some() {
                    ui.add_space(4.0);

                    // Show the value in different formats
                    if let Some(val) = parsed_u64 {
                        // U8
                        if val <= u8::MAX as u64 {
                            ui.label(
                                egui::RichText::new(format!(
                                    "U8: {} (0x{:02X})",
                                    val as u8, val as u8
                                ))
                                .monospace()
                                .small(),
                            );
                        }
                        // U16
                        if val <= u16::MAX as u64 {
                            let bytes = (val as u16).to_le_bytes();
                            ui.label(
                                egui::RichText::new(format!(
                                    "U16: {} (0x{:02X}{:02X}) LE",
                                    val as u16, bytes[0], bytes[1]
                                ))
                                .monospace()
                                .small(),
                            );
                        }
                        // U32
                        if val <= u32::MAX as u64 {
                            let bytes = (val as u32).to_le_bytes();
                            ui.label(
                                egui::RichText::new(format!(
                                    "U32: {} (0x{:02X}{:02X}{:02X}{:02X}) LE",
                                    val as u32, bytes[0], bytes[1], bytes[2], bytes[3]
                                ))
                                .monospace()
                                .small(),
                            );
                        }
                        // U64
                        let bytes = val.to_le_bytes();
                        ui.label(
                            egui::RichText::new(format!(
                                "U64: {} (0x{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}) LE",
                                val,
                                bytes[0], bytes[1], bytes[2], bytes[3],
                                bytes[4], bytes[5], bytes[6], bytes[7]
                            ))
                            .monospace()
                            .small(),
                        );

                        // F32 interpretation
                        let f32_val = val as f32;
                        if f32_val.is_finite() && f32_val.abs() < 1e15 {
                            let f32_bytes = f32_val.to_le_bytes();
                            ui.label(
                                egui::RichText::new(format!(
                                    "F32: {} (0x{:02X}{:02X}{:02X}{:02X}) LE",
                                    f32_val, f32_bytes[0], f32_bytes[1], f32_bytes[2], f32_bytes[3]
                                ))
                                .monospace()
                                .small(),
                            );
                        }
                    }

                    if let Some(val) = parsed_f64 {
                        if val.is_finite() {
                            // F32 from float
                            let f32_val = val as f32;
                            let f32_bytes = f32_val.to_le_bytes();
                            ui.label(
                                egui::RichText::new(format!(
                                    "F32: {} (0x{:02X}{:02X}{:02X}{:02X}) LE",
                                    f32_val, f32_bytes[0], f32_bytes[1], f32_bytes[2], f32_bytes[3]
                                ))
                                .monospace()
                                .small(),
                            );

                            // F64
                            let f64_bytes = val.to_le_bytes();
                            ui.label(
                                egui::RichText::new(format!(
                                    "F64: {} (0x{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}) LE",
                                    val,
                                    f64_bytes[0], f64_bytes[1], f64_bytes[2], f64_bytes[3],
                                    f64_bytes[4], f64_bytes[5], f64_bytes[6], f64_bytes[7]
                                ))
                                .monospace()
                                .small(),
                            );
                        }
                    }

                    ui.add_space(4.0);
                    ui.small("LE = Little Endian (byte order for x86/x64)");
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            // ----- Process Picker -----
            ui.heading("Process");
            ui.separator();

            let procs = self.processes.clone();
            let mut selected_label = String::from("Select a process...");
            if self.selected_pid != 0 {
                if let Some(p) = procs.iter().find(|p| p.pid == self.selected_pid) {
                    selected_label = format!("{} [{}]", p.name, p.pid);
                }
            }

            let filter_lower = self.process_filter.to_lowercase();
            let filtered: Vec<_> = procs
                .iter()
                .filter(|p| {
                    if filter_lower.is_empty() {
                        true
                    } else {
                        p.name.to_lowercase().contains(&filter_lower)
                            || p.cmdline.to_lowercase().contains(&filter_lower)
                            || p.pid.to_string().contains(&filter_lower)
                    }
                })
                .collect();

            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.text_edit_singleline(&mut self.process_filter);
                if ui.button("Clear").clicked() {
                    self.process_filter.clear();
                }
                if ui.button("Refresh").clicked() {
                    self.refresh_processes();
                }
            });

            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Process:");
                egui::ComboBox::from_id_salt("proc_combo")
                    .selected_text(&selected_label)
                    .show_ui(ui, |ui| {
                        for p in &filtered {
                            let label = if p.cmdline.len() > 60 {
                                format!("{} [{}] {}", p.name, p.pid, &p.cmdline[..60])
                            } else if !p.cmdline.is_empty() {
                                format!("{} [{}] ({})", p.name, p.pid, p.cmdline)
                            } else {
                                format!("{} [{}]", p.name, p.pid)
                            };
                            ui.selectable_value(&mut self.selected_pid, p.pid, label);
                        }
                    });
            });

            if !filtered.is_empty() {
                ui.small(format!("{} matching processes", filtered.len()));
            }

            ui.add_space(4.0);

            ui.horizontal(|ui| {
                if ui.button("Connect").clicked() {
                    self.connect();
                }
                if ui.button("Disconnect").clicked() {
                    self.disconnect();
                }
            });

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(5.0);

            // ----- Scanner -----
            ui.heading("Scanner");
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Type:");
                egui::ComboBox::from_id_salt("scan_type_combo")
                    .selected_text(format!("{:?}", self.scan_value_type))
                    .show_ui(ui, |ui| {
                        use ValueType::*;
                        for vt in [U8, U16, U32, U64, F32, F64, Hex, Bytes] {
                            ui.selectable_value(
                                &mut self.scan_value_type,
                                vt,
                                format!("{:?}", vt),
                            );
                        }
                    });
            });

            // Show description for the selected type
            let type_desc = match self.scan_value_type {
                ValueType::U8 => "Unsigned 8-bit: 0–255 (small counters, flags)",
                ValueType::U16 => "Unsigned 16-bit: 0–65,535 (ammo, timers)",
                ValueType::U32 => "Unsigned 32-bit: 0–4.3B (health, gold, score)",
                ValueType::U64 => "Unsigned 64-bit: very large values",
                ValueType::F32 => "Float 32-bit: decimals (speed, position, %)",
                ValueType::F64 => "Float 64-bit: high-precision decimals",
                ValueType::Hex => "Hex: raw bytes (custom patterns)",
                ValueType::Bytes => "Bytes: exact byte sequence (no conversion)",
            };
            ui.small(egui::RichText::new(type_desc).color(egui::Color32::GRAY));

            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Value:");
                ui.text_edit_singleline(&mut self.scan_value_text);
            });

            ui.add_space(4.0);

            ui.horizontal(|ui| {
                if ui.button("First Scan").clicked() {
                    self.first_scan();
                }
                if ui.button("Next Scan").clicked() {
                    self.next_scan();
                }
            });
            ui.horizontal(|ui| {
                if ui.button("New Scan").clicked() {
                    self.new_scan();
                }
                if ui.button("Undo Scan").clicked() {
                    self.undo_scan();
                }
            });

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(5.0);

            // ----- Tabbed Results / Hex Viewer -----
            ui.horizontal(|ui| {
                if ui
                    .selectable_label(self.active_tab == 0, "Results")
                    .clicked()
                {
                    self.active_tab = 0;
                }
                if ui
                    .selectable_label(self.active_tab == 1, "Hex Viewer")
                    .clicked()
                {
                    self.active_tab = 1;
                }
            });

            ui.add_space(4.0);

            // Give the tab area a fixed height so it doesn't collapse
            let tab_height = 300.0;

            if self.active_tab == 0 {
                // ----- Results Tab -----
                let (result_count, results_display, can_lock_all) = match &self.scan_phase {
                    ScanPhase::FirstScan { results } => {
                        (results.len(), results.iter().take(200).cloned().collect::<Vec<_>>(), results.len() <= 100)
                    }
                    ScanPhase::NextScan { results, .. } => {
                        (results.len(), results.iter().take(200).cloned().collect::<Vec<_>>(), results.len() <= 100)
                    }
                    ScanPhase::Idle => (0, Vec::new(), false),
                };

                ui.horizontal(|ui| {
                    if result_count > results_display.len() {
                        ui.label(format!("{} results (showing first {})", result_count, results_display.len()));
                    } else {
                        ui.label(format!("{} results", result_count));
                    }
                    if can_lock_all && result_count > 0 {
                        if ui.button("🔒 Lock All").clicked() {
                            let all_to_lock: Vec<ScanResult> = match &self.scan_phase {
                                ScanPhase::FirstScan { results } => results.clone(),
                                ScanPhase::NextScan { results, .. } => results.clone(),
                                ScanPhase::Idle => Vec::new(),
                            };
                            for sr in &all_to_lock {
                                // Read the current live value for each result.
                                let live_bytes = self.handle.as_ref()
                                    .and_then(|h| h.read(sr.address, sr.size).ok());
                                let bytes = live_bytes.unwrap_or_else(|| vec![0u8; sr.size]);
                                // Avoid duplicates.
                                if !self.locked_values.iter().any(|e| e.address == sr.address) {
                                    self.locked_values.push(LockedEntry::new(
                                        sr.address,
                                        sr.value_type,
                                        bytes.clone(),
                                        format!("{:#x}", sr.address),
                                    ));
                                }
                            }
                            self.status_message = format!("Locked {} addresses.", all_to_lock.len());
                        }
                    }
                });

                // Column headers
                egui::ScrollArea::vertical()
                    .id_salt("results_scroll")
                    .max_height(tab_height)
                    .show(ui, |ui| {
                        // Header row
                        ui.horizontal(|ui| {
                            ui.add_sized([140.0, 16.0],
                                egui::Label::new(egui::RichText::new("Address").strong().small()));
                            ui.add_sized([90.0, 16.0],
                                egui::Label::new(egui::RichText::new("Value").strong().small()));
                            ui.label(""); // Lock column header
                        });
                        ui.separator();

                        for sr in &results_display {
                            // Read live value each frame for display.
                            let live_str = self.handle.as_ref()
                                .and_then(|h| h.read(sr.address, sr.size).ok())
                                .map(|b| fmt_bytes_as_value(&b, sr.value_type))
                                .unwrap_or_else(|| "?".into());

                            let is_selected = self.selected_address == sr.address;
                            let addr = sr.address;
                            let sr_clone = sr.clone();

                            ui.horizontal(|ui| {
                                // Address label — click to select
                                let resp = ui.add_sized(
                                    [140.0, 18.0],
                                    egui::Button::new(
                                        egui::RichText::new(format!("{:#x}", addr)).monospace().small()
                                    ).selected(is_selected).small()
                                );
                                if resp.clicked() {
                                    self.selected_address = addr;
                                    self.load_hex_view();
                                    self.refresh_read_write();
                                }

                                // Live value
                                ui.add_sized([90.0, 18.0],
                                    egui::Label::new(
                                        egui::RichText::new(&live_str).monospace().small()
                                    )
                                );

                                // Per-row Lock button
                                let already_locked = self.locked_values.iter().any(|e| e.address == addr);
                                let lock_label = if already_locked { "🔒" } else { "Lock" };
                                if ui.small_button(lock_label).clicked() && !already_locked {
                                    let bytes = self.handle.as_ref()
                                        .and_then(|h| h.read(sr_clone.address, sr_clone.size).ok())
                                        .unwrap_or_else(|| vec![0u8; sr_clone.size]);
                                    self.locked_values.push(LockedEntry::new(
                                        addr,
                                        sr_clone.value_type,
                                        bytes,
                                        format!("{:#x}", addr),
                                    ));
                                    self.status_message = format!("Locked {:#x}", addr);
                                }
                            });
                        }
                    });
            } else {
                // ----- Hex Viewer Tab -----
                egui::ScrollArea::vertical()
                    .id_salt("hex_scroll")
                    .max_height(tab_height)
                    .show(ui, |ui| {
                        if self.selected_address == 0 {
                            ui.label("Select an address to view memory.");
                        } else if self.hex_buf.is_empty() {
                            ui.label("Unable to read memory at this address.");
                        } else {
                            let rows = (self.hex_buf.len() + 15) / 16;
                            for row in 0..rows {
                                let base = row * 16;
                                let addr = self.selected_address
                                    - (self.selected_address % 16)
                                    + base as u64;
                                let line_bytes: Vec<u8> =
                                    self.hex_buf.iter().skip(base).take(16).copied().collect();

                                let mut hex_part: Vec<String> =
                                    line_bytes.iter().map(|b| format!("{:02X}", b)).collect();
                                while hex_part.len() < 16 {
                                    hex_part.push("  ".to_string());
                                }

                                let ascii_part: String = line_bytes
                                    .iter()
                                    .map(|b| {
                                        if b.is_ascii_graphic() || *b == b' ' {
                                            *b as char
                                        } else {
                                            '.'
                                        }
                                    })
                                    .collect();

                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new(format!("{:#010X}", addr))
                                            .monospace()
                                            .small(),
                                    );
                                    ui.label(" │ ");
                                    for (j, hex_byte) in hex_part.iter().enumerate() {
                                        if j > 0 && j == 8 {
                                            ui.label(" ");
                                        }
                                        ui.label(
                                            egui::RichText::new(hex_byte.clone())
                                                .monospace()
                                                .small(),
                                        );
                                    }
                                    ui.label(" │ ");
                                    ui.label(
                                        egui::RichText::new(ascii_part).monospace().small(),
                                    );
                                });
                            }
                        }
                    });
            }

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(5.0);

            // ----- Read / Write Panel & Validator Diagnostics -----
            ui.heading("Read / Write & Memory Diagnostics");
            ui.separator();

            if self.selected_address == 0 {
                ui.label("Select an address from the results list to view its memory region and live diagnostics.");
            } else {
                let region_diag = self.get_region_diagnosis(self.selected_address);

                // Address + Region badge
                ui.horizontal(|ui| {
                    ui.label(format!("Address: {:#x}", self.selected_address));
                    ui.label(format!("Type: {:?}", self.scan_value_type));
                    ui.colored_label(region_diag.color, egui::RichText::new(&region_diag.name).strong().small());
                });

                ui.label(egui::RichText::new(&region_diag.detail).small().weak());
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    ui.label("Current value:");
                    ui.label(egui::RichText::new(&self.rw_value_text).monospace().strong());
                });

                ui.add_space(2.0);

                ui.horizontal(|ui| {
                    ui.label("New value:");
                    ui.text_edit_singleline(&mut self.rw_value_text);
                    if ui.button("Write").clicked() {
                        self.write_value();
                    }
                    if ui.button("🔒 Lock").clicked() {
                        self.lock_current();
                    }
                });

                // Show last write result prominently
                if let Some(ref result) = self.last_write_result {
                    let color = if result.starts_with("✅") {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::RED
                    };
                    ui.label(egui::RichText::new(result).color(color).strong().small());
                }

                ui.add_space(6.0);

                // ----- Real-time Validator & Protection Diagnostics Box -----
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.strong("🛡️ Validator & Stability Analysis:");
                        let locked_opt = self.locked_values.iter().find(|e| e.address == self.selected_address);
                        if let Some(entry) = locked_opt {
                            let (badge_str, color, tip) = entry.diagnosis.badge();
                            ui.colored_label(color, egui::RichText::new(badge_str).strong())
                                .on_hover_text(tip);
                        } else {
                            ui.colored_label(
                                egui::Color32::from_rgb(180, 180, 180),
                                "⚪ Not Locked (Lock to monitor resistance)",
                            );
                        }
                    });

                    if let Some(entry) = self.locked_values.iter().find(|e| e.address == self.selected_address) {
                        let drift_pct = if entry.writes_total > 0 {
                            (entry.drift_count as f64 * 100.0) / entry.writes_total as f64
                        } else {
                            0.0
                        };
                        ui.label(
                            egui::RichText::new(format!(
                                "Frame writes: {}  |  Overwrites (engine drift): {} ({:.1}%)",
                                entry.writes_total, entry.drift_count, drift_pct
                            ))
                            .small()
                            .weak(),
                        );

                        // Guidance box based on detected behavior
                        match entry.diagnosis {
                            ValidatorDiagnosis::TransactionRejection => {
                                ui.colored_label(
                                    egui::Color32::from_rgb(255, 120, 120),
                                    "⚠️ Transaction Rejection / Rollback Detected:\n\
                                     The value stayed frozen while idle, but snapped back when an in-game purchase or action occurred.\n\
                                     • If this is Virtual Currency (VC): 2K validates it via online servers.\n\
                                     • If this is offline currency: The game employs a shadow/dual-storage integrity check.",
                                );
                            }
                            ValidatorDiagnosis::UiDisplayCache => {
                                ui.colored_label(
                                    egui::Color32::from_rgb(255, 210, 80),
                                    "⚠️ High-Frequency Engine Pushback (UI Cache):\n\
                                     The game continuously overwrites this address every render frame. You have likely locked the HUD/text display buffer rather than the true variable.",
                                );
                            }
                            ValidatorDiagnosis::Stable => {
                                ui.colored_label(
                                    egui::Color32::from_rgb(100, 230, 120),
                                    "✅ Local Authority Confirmed: Value holds without resistance. Direct writes take effect.",
                                );
                            }
                            _ => {}
                        }
                    }

                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui.button("🔎 Scan Proximity for Shadows / Dual-Storage").clicked() {
                            self.scan_proximity_shadows();
                        }
                        if self.shadow_scan_results.is_some() {
                            if ui.small_button("Clear").clicked() {
                                self.shadow_scan_results = None;
                            }
                        }
                    });

                    let mut to_select_shadow: Option<u64> = None;
                    if let Some(ref shadows) = self.shadow_scan_results {
                        if shadows.is_empty() {
                            ui.small("No mirrored values found within ±2KB memory window.");
                        } else {
                            ui.label(egui::RichText::new(format!("Found {} potential shadow/mirror candidates:", shadows.len())).strong().small());
                            for cand in shadows {
                                ui.horizontal(|ui| {
                                    let offset_str = if cand.offset_bytes >= 0 {
                                        format!("+{:#X}", cand.offset_bytes)
                                    } else {
                                        format!("-{:#X}", -cand.offset_bytes)
                                    };
                                    ui.label(egui::RichText::new(format!("{:#X} ({})", cand.address, offset_str)).monospace().small());
                                    ui.label(egui::RichText::new(&cand.value_str).monospace().small().color(egui::Color32::YELLOW));
                                    ui.label(egui::RichText::new(&cand.description).small().weak());
                                    if ui.small_button("Select").clicked() {
                                        to_select_shadow = Some(cand.address);
                                    }
                                });
                            }
                        }
                    }
                    if let Some(addr) = to_select_shadow {
                        self.selected_address = addr;
                        self.load_hex_view();
                        self.refresh_read_write();
                    }
                });
            }

            // ----- Locked Values Table (always visible when non-empty) -----
            if !self.locked_values.is_empty() {
                ui.add_space(8.0);
                ui.separator();
                ui.horizontal(|ui| {
                    ui.heading("Locked Values & Validator Status");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let any_disabled = self.locked_values.iter().any(|e| !e.enabled);
                        if any_disabled {
                            if ui.small_button("⚡ Enable All").clicked() {
                                for e in &mut self.locked_values { e.enabled = true; }
                            }
                        } else {
                            if ui.small_button("⏸ Disable All").clicked() {
                                for e in &mut self.locked_values { e.enabled = false; }
                            }
                        }
                    });
                });
                ui.separator();

                // Table header
                ui.horizontal(|ui| {
                    ui.add_sized([16.0,  16.0], egui::Label::new(egui::RichText::new("En").strong().small()));
                    ui.add_sized([120.0, 16.0], egui::Label::new(egui::RichText::new("Address").strong().small()));
                    ui.add_sized([75.0,  16.0], egui::Label::new(egui::RichText::new("Frozen").strong().small()));
                    ui.add_sized([75.0,  16.0], egui::Label::new(egui::RichText::new("Live").strong().small()));
                    ui.add_sized([45.0,  16.0], egui::Label::new(egui::RichText::new("Type").strong().small()));
                    ui.add_sized([150.0, 16.0], egui::Label::new(egui::RichText::new("Validator Status").strong().small()));
                });
                ui.separator();

                let mut to_unlock: Vec<usize> = Vec::new();
                let mut to_select: Option<u64> = None;

                // Collect live reads before mutably borrowing locked_values.
                let live_vals: Vec<String> = self.locked_values.iter().map(|entry| {
                    self.handle.as_ref()
                        .and_then(|h| h.read(entry.address, entry.bytes.len()).ok())
                        .map(|b| fmt_bytes_as_value(&b, entry.value_type))
                        .unwrap_or_else(|| "?".into())
                }).collect();

                egui::ScrollArea::vertical()
                    .id_salt("locked_scroll")
                    .max_height(180.0)
                    .show(ui, |ui| {
                        for (i, entry) in self.locked_values.iter_mut().enumerate() {
                            let mut frozen_str = fmt_bytes_as_value(&entry.bytes, entry.value_type);
                            let live_str = live_vals.get(i).cloned().unwrap_or_else(|| "?".into());
                            let live_color = if live_str == frozen_str {
                                egui::Color32::GREEN
                            } else {
                                egui::Color32::YELLOW
                            };

                            let (badge_text, badge_color, badge_tip) = entry.diagnosis.badge();

                            ui.horizontal(|ui| {
                                ui.checkbox(&mut entry.enabled, "");
                                // Address — click to select in RW panel
                                if ui.add_sized([120.0, 18.0],
                                    egui::Button::new(
                                        egui::RichText::new(&entry.label).monospace().small()
                                    ).small()
                                ).clicked() {
                                    to_select = Some(entry.address);
                                }
                                // Editable Frozen value field
                                let edit_resp = ui.add_sized(
                                    [75.0, 18.0],
                                    egui::TextEdit::singleline(&mut frozen_str).font(egui::TextStyle::Monospace).margin(egui::vec2(2.0, 1.0))
                                );
                                if edit_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                    if let Ok(new_bytes) = parse_value_bytes(Self::value_type_to_str(&entry.value_type), &frozen_str) {
                                        entry.bytes = new_bytes.clone();
                                        entry.enabled = true;
                                    }
                                }
                                // Live value (green = freeze holding, yellow = drifted)
                                ui.add_sized([75.0, 18.0],
                                    egui::Label::new(
                                        egui::RichText::new(&live_str)
                                            .monospace()
                                            .small()
                                            .color(live_color)
                                    )
                                );
                                // Type
                                ui.add_sized([45.0, 18.0],
                                    egui::Label::new(
                                        egui::RichText::new(format!("{:?}", entry.value_type)).small()
                                    )
                                );
                                // Validator Diagnosis Badge with tooltip
                                ui.add_sized([150.0, 18.0],
                                    egui::Label::new(
                                        egui::RichText::new(badge_text).color(badge_color).small().strong()
                                    )
                                ).on_hover_text(badge_tip);

                                // Remove
                                if ui.small_button("❌").clicked() {
                                    to_unlock.push(i);
                                }
                            });
                        }
                    });

                for i in to_unlock.into_iter().rev() {
                    self.unlock(i);
                }
                if let Some(addr) = to_select {
                    self.selected_address = addr;
                    self.load_hex_view();
                    self.refresh_read_write();
                }
            }
        });

        // ----- Help & Instructions Window -----
        if self.show_help {
            egui::Window::new("📖 User Guide & Instructions")
                .open(&mut self.show_help)
                .default_size([650.0, 500.0])
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.label(egui::RichText::new(GUIDE).monospace().small());
                    });
                });
        }
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // --guide / --help: print instructions and exit.
    if args.iter().any(|a| a == "--guide" || a == "--help") {
        println!("{}", GUIDE);
        return Ok(());
    }

    // Handle --test-scan mode
    if args.len() >= 4 && args[1] == "--test-scan" {
        return test_scan(&args[2], &args[3]);
    }

    // Normal GUI launch
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1100.0, 750.0]),
        ..Default::default()
    };

    eframe::run_native(
        "NixGameHax4Steam",
        options,
        Box::new(|_cc| Ok(Box::<ProtonMemApp>::default())),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    Ok(())
}

fn test_scan(pid_str: &str, value_str: &str) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let pid: u32 = pid_str.parse().expect("Invalid PID");
    let value: u32 = value_str.parse().expect("Invalid value");
    let search_bytes = value.to_le_bytes();

    println!("Scanning PID {} for U32 {} (bytes: {:02X?})", pid, value, search_bytes);

    let mem_path = format!("/proc/{}/mem", pid);
    let mut mem_file = std::fs::OpenOptions::new().read(true).write(true).open(&mem_path)?;

    let maps_path = format!("/proc/{}/maps", pid);
    let maps_content = std::fs::read_to_string(&maps_path)?;

    let mut count = 0;
    let mut regions = 0;

    for line in maps_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let perms = parts[1];
        if !perms.contains('w') || !perms.contains('r') {
            continue;
        }

        let range: Vec<&str> = parts[0].split('-').collect();
        if range.len() != 2 {
            continue;
        }

        let start = u64::from_str_radix(range[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(range[1], 16).unwrap_or(0);
        regions += 1;

        let mut offset = start;
        while offset < end {
            let read_size = std::cmp::min(65536u64, end - offset) as usize;
            mem_file.seek(SeekFrom::Start(offset))?;
            let mut buf = vec![0u8; read_size];
            match mem_file.read_exact(&mut buf) {
                Ok(()) => {
                    let mut so = 0;
                    while so + 4 <= buf.len() {
                        if buf[so..so + 4] == search_bytes {
                            count += 1;
                            if count <= 3 {
                                println!("  Match at {:#x}", offset + so as u64);
                            }
                        }
                        so += 1;
                    }
                }
                Err(_) => {}
            }
            offset += read_size as u64;
        }
    }

    println!("Regions: {}, Matches: {}", regions, count);
    Ok(())
}
