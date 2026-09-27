use nixgamehax4steam::{
    enumerate_processes, find_by_name, find_proton_game_processes, MemHandle,
    parse_value_bytes,
};

#[test]
fn test_enumerate_processes() {
    let all = enumerate_processes();
    assert!(!all.is_empty(), "Should find running processes on the system");
}

#[test]
#[ignore = "requires live Legion TD 2 process"]
fn test_find_legion_td2() {
    let _all = enumerate_processes();
    let by_name = find_by_name("Legion TD 2");
    assert!(!by_name.is_empty(), "Should find Legion TD 2 by name");
    let game = &by_name[0];
    println!("Found Legion TD 2: PID={} name='{}'", game.pid, game.name);

    let proton = find_proton_game_processes();
    assert!(!proton.is_empty(), "Should find at least one proton game process");
    println!("Proton game processes: {}", proton.len());
    for p in &proton {
        println!("  PID={} name='{}'", p.pid, p.name);
    }
}

#[test]
#[ignore = "requires hardcoded PID to be running"]
fn test_mem_access_game() {
    let handle = MemHandle::open(392043);
    assert!(handle.is_ok(), "Should be able to open /proc/392043/mem");
    println!("OK: /proc/392043/mem opened");
}

#[test]
#[ignore = "requires hardcoded PID to be running"]
fn test_scan_game_memory() {
    let search_bytes = parse_value_bytes("u32", "2100").unwrap();
    if let Ok(handle) = MemHandle::open(392043) {
        let results = handle.scan_for_value(&search_bytes);
        println!("Scan found {} results for u32=2100", results.len());
    }
}
