# Troubleshooting

## Editor Can't Find Any Processes

**Symptom:** The process list is empty or shows only a few processes.

**Possible causes:**
1. `/proc` is not accessible — extremely unlikely on a normal Linux system
2. The editor is running in a container/sandbox with restricted `/proc` view
3. The game isn't running yet

**Fix:**
- Make sure the game is actually running (check with `ps aux | grep game`)
- Run the editor with a full desktop session, not inside a restricted sandbox
- Click **Refresh** in the process panel

---

## Can't Connect to a Process

**Symptom:** Clicking a process shows "Cannot open /proc/[pid]/mem: ..."

**Error messages:**

| Error | Meaning | Fix |
|-------|---------|-----|
| `Permission denied` | Editor doesn't have permission to access the process | Run both game and editor as the same user; check ptrace scope |
| `No such file or directory` | Process exited between selecting and connecting | The game may have crashed or restarted; try again |
| `Operation not permitted` | ptrace scope restriction | See ptrace scope section below |

---

## ptrace Scope Issues

**Symptom:** Editor can read maps but can't read/write memory, or gets permission errors.

**Check current setting:**
```bash
cat /proc/sys/kernel/yama/ptrace_scope
```

**Values:**
- `0` — Any process can attach to any other (most permissive)
- `1` — Only parent/child or same-user processes (default on Ubuntu)
- `2` — Admin-only
- `3` — No attach allowed

**Fix (temporary, until reboot):**
```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

**Fix (permanent):** Add `kernel.yama.ptrace_scope=0` to `/etc/sysctl.conf` or a file in `/etc/sysctl.d/` and reboot.

**Note:** On Ubuntu 24.04, the default is typically `1`, which allows same-user attachment. If your game and editor run as the same user, this should work without changes.

---

## Write Fails with "Short write" or "EIO"

**Symptom:** Write operation returns an error.

**Possible causes:**
1. **Address is unmapped** — The address isn't in any mapped region. Verify the address against `/proc/[pid]/maps`.
2. **Region is not writable** — The memory region is read-only or executable-only. The editor currently only writes to regions that are already writable. To write to read-only regions, you'd need ptrace + `mprotect` (not yet implemented).
3. **Process exited** — The game closed between the read and write.

**Fix:**
- Double-check the address using the hex viewer first
- Ensure the game is still running
- For read-only regions, either find a writable alias or wait for `mprotect` support

---

## Game Crashes After Memory Write

**Symptom:** Game closes or freezes after a write operation.

**Possible causes:**
1. **Wrong address** — Wrote to the wrong location, corrupting critical data
2. **Wrong value** — Value out of expected range (e.g., negative health)
3. **Writing to code region** — Accidentally modified executable code
4. **Timing** — Wrote while the game was reading that memory

**Fix:**
- Use the hex viewer to verify the address contains the expected data type
- Start with small, safe modifications (e.g., changing a float from 100.0 to 99.0)
- Back up save files before experimenting
- If the game crashes consistently at a specific address, that address may be a pointer or code, not data

---

## Addresses Don't Work After Game Restart

**Symptom:** An address that worked yesterday doesn't work today.

**Cause:** ASLR (Address Space Layout Randomization) changes the base address of mappings on each launch.

**Fix:**
- Use module base + offset instead of absolute addresses
- Find the game module's base address in `/proc/[pid]/maps` each session
- Add the static offset (constant within the module)
- Or use pointer scanning to find dynamic addresses that survive restarts

---

## The Editor Freezes or Becomes Unresponsive

**Symptom:** GUI stops responding.

**Possible causes:**
1. **Scanning a very large range** — Scanning the entire address space can take time
2. **Game exited while connected** — The mem fd becomes invalid

**Fix:**
- Close and restart the editor
- For large scans, be patient — the scan runs synchronously in the current implementation
- Future versions may add async scanning

---

## Wine/Proton Detection Doesn't Find My Game

**Symptom:** The game process isn't tagged or listed.

**Possible causes:**
1. The game's process name doesn't contain "wine" or "steam" in its comm/cmdline
2. The game is running natively, not under Proton

**Fix:**
- Check the full process list (all processes are shown)
- Look for the game's `.exe` name in the list
- Or use the manual PID entry if supported in a future version

---

## Memory Values Look Wrong

**Symptom:** Reading a value shows something unexpected.

**Possible causes:**
1. **Wrong data type** — Reading a float as an integer, or vice versa
2. **Wrong address** — Off by one or pointing to padding
3. **Endianness** — Unlikely on x86_64 (little-endian matches), but worth noting
4. **Data is compressed/encrypted** — Some games obfuscate data in memory

**Fix:**
- Try different data types
- Verify the address using the hex viewer to see raw bytes
- Cross-reference with known values (e.g., if health should be 100, look for `64 00 00 00` for u32 or `00 00 27 3C` for f32 in little-endian)

---

## Engineer's Checklist

When something goes wrong, check in this order:

1. **Is the game running?** — `ps aux | grep gamename`
2. **Can I read its maps?** — `cat /proc/[pid]/maps | head`
3. **Can I read its mem?** — `cat /proc/[pid]/mem > /dev/null` (will fail, but permission error vs. EIO tells you something)
4. **What's the ptrace scope?** — `cat /proc/sys/kernel/yama/ptrace_scope`
5. **Am I the same user?** — `id` for both game and editor
6. **Is the address in a mapped region?** — Check the hex viewer's address against maps

---

*If all else fails, check the debug output and the code in `src/memory.rs` — the implementation is straightforward enough to trace.*
