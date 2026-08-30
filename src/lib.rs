// Proton Memory Scanner — shared library
// Re-exports the core types and functions for both CLI and GUI.

pub mod memory;
pub mod pid;

pub use memory::{MemHandle, MemoryMap, MemoryRegion, ScanResult, ValueType, parse_value_bytes, ScanPhase};
pub use pid::{ProcInfo, children_of, enumerate_processes, find_by_name, find_proton_game_processes};
