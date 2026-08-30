use proton_mem::{
    enumerate_processes, find_by_name, find_proton_game_processes, MemHandle,
    parse_value_bytes, scan_for_value,
};

#[test]
fn test_find_legion_td2() {
    let all = enumerate_processes();
    let by_name = find_by_name("Legion TD 2");
    assert!(!by_name.is_empty(), "Should find Legion TD 2 by name");
    let game = &by_name[0];
    println!("Found Legion TD 2: PID={} name='{}'", game.pid, game.name);

    let proton = find_proton_game_processes();
    assert!(proton.len() >= 1, "Should find at least one proton game process");
    println!("Proton game processes: {}", proton.len());
    for p in &proton {
        println!("  PID={} name='{}'", p.pid, p.name);
    }
}

#[test]
fn test_mem_access_game() {
    let handle = MemHandle::open(392043);
    assert!(handle.is_ok(), "Should be able to open /proc/392043/mem");
    println!("OK: /proc/392043/mem opened");
}

#[test]
fn test_scan_game_memory() {
    let search_bytes = parse_value_bytes("u32", "2100").unwrap();
    let results = scan_for_value(392043, &search_bytes, 0x10000000, 0x103FF000);
    assert!(results.is_ok(), "Scan should succeed");
    let count = results.unwrap();
    println!(
        "Scan found {} results for u32=2100 in 0x10000000-0x103FF000",
        count.len()
    );
    assert!(count.len() > 0, "Should find at least one match");
}
