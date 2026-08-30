# NixGameHax4Steam

A high-performance, CheatEngine-style memory editor & scanner built in Rust for Steam/Proton games running on Linux (Ubuntu 24.04+).

---

## Features

- ⚡ **Multi-Threaded Memory Scanning:** Background worker thread handles scanning with live progress bar reporting and zero UI freezing.
- 🎯 **Advanced Value Scanner:** Full support for `U8`, `U16`, `U32`, `U64`, `F32` (floats), `F64` (doubles), `Hex`, and raw `Bytes`.
- 🔄 **Incremental Next Scan & Undo:** Quickly narrow down millions of candidate addresses with multi-pass scans and undo history.
- 🔒 **Active Freeze & Memory Locking:** Continuous multi-address locking loop re-applies values every frame to prevent game engine drift, with live vs. frozen status indicators (🟢 Holding / 🟡 Drifted).
- 🛠️ **In-Table Live Editing:** Edit frozen values directly within the active locks table or use the Read/Write panel for targeted offsets.
- 🔍 **Dynamic Hex Viewer:** Interactive memory inspector with side-by-side hex and ASCII view for nearby structure analysis.
- 🎮 **Steam / Proton Process Discovery:** Automated detection and filtering of Wine/Steam processes with system service blocklists.
- 📖 **In-App & CLI Documentation:** Integrated `❓ Help` modal and `--guide` terminal flag.
- 💻 **Dual Frontends:** Fully featured native GUI (`egui` / `eframe`) and scriptable command-line interface (`clap`).

---

## Requirements

- **Operating System:** Linux (Ubuntu 24.04 or any modern distribution with `/proc` filesystem)
- **Rust Toolchain:** Stable Rust 2021 edition (`cargo`, `rustc`)
- **Kernel Permissions:** `ptrace_scope` set to `0` or run with root permissions.
  ```bash
  # Check current ptrace scope:
  cat /proc/sys/kernel/yama/ptrace_scope

  # Temporarily allow ptrace memory access:
  sudo sysctl kernel.yama.ptrace_scope=0
  ```

---

## Quick Start

### 1. Build

```bash
# Build both GUI and CLI binaries
cargo build --release
```

### 2. Run the GUI

```bash
cargo run --release --bin nixgamehax4steam-gui
```

### 3. Run the CLI

```bash
# List all running processes
cargo run --release --bin nixgamehax4steam -- list --filter "game_name"

# Probe access to a PID
cargo run --release --bin nixgamehax4steam -- probe <PID>

# Scan memory for a 32-bit integer
cargo run --release --bin nixgamehax4steam -- scan <PID> <VALUE> --type u32

# Read memory hex dump
cargo run --release --bin nixgamehax4steam -- read <PID> <HEX_ADDRESS> --length 64

# Write memory
cargo run --release --bin nixgamehax4steam -- write <PID> <HEX_ADDRESS> <NEW_VALUE> --type u32
```

---

## GUI Usage Guide

1. **Attach to Game:**
   - Launch your game in Steam (Proton/Wine).
   - In **NixGameHax4Steam**, type part of the game's executable or name into the **Filter** box.
   - Select the target process from the dropdown and click **Connect**.

2. **First Scan:**
   - Select the data type (default is `U32` for whole numbers like Gold, Health, Ammo, Score).
   - Enter your current in-game value in the **Value** box.
   - Click **First Scan**. The status bar and progress indicator will track writable memory regions.

3. **Narrow Down with Next Scan:**
   - Change the value in-game (spend gold, take damage, shoot ammo).
   - Enter the updated value and click **Next Scan**.
   - Repeat until 1–5 candidate addresses remain.

4. **Edit & Freeze:**
   - Click **Lock** on individual rows or **🔒 Lock All** to add addresses to the **Locked Values** table.
   - Double-click or type directly into the **Frozen (edit)** box to change the target value (e.g. `99999`) and press <kbd>Enter</kbd>.
   - Check the **En** checkbox to activate real-time continuous memory freezing.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   GUI Layer (egui / eframe)              │
│    Process Picker · Scanner · Results · Lock Table · Hex │
└───────────────────────────┬──────────────────────────────┘
                            │ (mpsc Channel & State Machine)
┌───────────────────────────▼──────────────────────────────┐
│                  NixGameHax4Steam Core                   │
│   ┌───────────────┐ ┌───────────────┐ ┌────────────────┐ │
│   │  pid module   │ │ memory module │ │ commands (CLI) │ │
│   │  /proc parser │ │ /proc/pid/mem │ │ Subcommand     │ │
│   │  Wine filters │ │ lseek + IO    │ │ Handlers       │ │
│   └───────────────┘ └───────────────┘ └────────────────┘ │
└───────────────────────────┬──────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────┐
│                    Linux Kernel /proc                    │
│        /proc/[pid]/maps  ·  /proc/[pid]/mem              │
└──────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
├── Cargo.toml          # Package configuration and binary definitions
├── README.md           # Project overview and documentation
├── src/
│   ├── lib.rs          # Core library exports
│   ├── memory.rs       # Memory handle, region map parser, read/write primitives
│   ├── pid.rs          # Linux process discovery and Wine/Proton hierarchy filtering
│   ├── gui.rs          # Native egui application frontend & threaded worker
│   ├── cli.rs          # Command-line interface entry point
│   └── commands.rs     # CLI command execution handlers
├── docs/               # Detailed technical architecture guides
└── tests/              # Integration and end-to-end tests
```

---

## License

This project is licensed under the MIT License.
