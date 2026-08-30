# Security & Anti-Cheat Considerations

## Intended Use

This tool is designed for **single-player games only**. It is a learning tool for understanding:
- How Linux process memory works
- How Proton maps Windows processes onto Linux
- How memory editors find and modify game data

## Anti-Cheat Systems

### Easy Anti-Cheat (EAC)
- Used in many games (Assassin's Creed, Titanfall, some EA titles)
- Has kernel-level components on Windows; Linux support varies
- Detects memory editors by various heuristics
- **Do not use** on games with EAC active

### BattlEye
- Kernel-level anti-cheat
- Very aggressive detection
- **Do not use** on games with BattlEye

### Other Anti-Cheat
- Many other systems exist (Anti-Cheat Expert, Ricochet, etc.)
- If in doubt, research whether the specific game has anti-cheat that runs in single-player mode

## Detection Vectors

An anti-cheat system could detect this editor through:

1. **Process enumeration** — The game sees other processes running, including this editor
2. **ptrace attachment** — Some anti-cheats detect debugger attachment
3. **Memory access patterns** — Reading/writing another process's memory is observable
4. **Code injection** — Not used by this tool (we only read/write via `/proc`)
5. **Timing anomalies** — Reading memory may cause slight delays

## Mitigation (for single-player)

For games without anti-cheat:
- Run the editor as the same user as the game
- Attach only when needed, disconnect when done
- Don't leave the editor attached in the background

For games with "single-player disabled anti-cheat" modes:
- Verify that anti-cheat is actually disabled (some games only disable some checks)
- Research community knowledge about that specific game

## Disclaimer

Use this tool responsibly. The author is not responsible for any consequences of using this tool, including but not limited to:
- Game crashes from improper memory writes
- Account bans from anti-cheat systems
- Corrupted save data

---

*This document is not legal advice. Respect game terms of service and local laws.*
