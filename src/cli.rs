//! NixGameHax4Steam — CLI Frontend
//! Memory editor & scanner for Steam/Proton games on Linux.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::List { filter } => commands::cmd_list(filter),
        Commands::Find { name } => commands::cmd_find(&name),
        Commands::Read { pid, address, length } => commands::cmd_read(pid, &address, length),
        Commands::Write {
            pid,
            address,
            value,
            r#type,
        } => commands::cmd_write(pid, &address, &value, &r#type),
        Commands::Scan {
            pid,
            value,
            r#type,
            region,
        } => commands::cmd_scan(pid, &value, &r#type, region),
        Commands::Maps { pid } => commands::cmd_maps(pid),
        Commands::Probe { pid } => commands::cmd_probe(pid),
    }
}

#[derive(Parser)]
#[command(name = "nixgamehax4steam", about = "CheatEngine-style memory editor for Steam/Proton games on Linux")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List running processes and find Proton game processes
    List {
        #[arg(short, long)]
        filter: Option<String>,
    },

    /// Find the PID of a game process by name
    Find {
        name: String,
    },

    /// Read memory from a process
    Read {
        pid: u32,
        address: String,
        #[arg(short, long)]
        length: usize,
    },

    /// Write memory to a process
    Write {
        pid: u32,
        address: String,
        value: String,
        #[arg(short, long, default_value = "u32")]
        r#type: String,
    },

    /// Scan memory for a value
    Scan {
        pid: u32,
        value: String,
        #[arg(short, long, default_value = "u32")]
        r#type: String,
        #[arg(long, short)]
        region: Option<String>,
    },

    /// Dump memory maps for a process
    Maps {
        pid: u32,
    },

    /// Probe — test if we can access a process's memory
    Probe {
        pid: u32,
    },
}
