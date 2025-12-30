# Windows Kernel Rootkit & Advanced RAT

![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20Kernel-0078D6?style=for-the-badge&logo=windows)
![Language](https://img.shields.io/badge/Language-C%20%2F%20C%2B%2B%20%2F%20Python-blue?style=for-the-badge)
![Type](https://img.shields.io/badge/Type-DKOM%20Rootkit-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-PoC%20%2F%20Stable-success?style=for-the-badge)

---

## ⚠️ Disclaimer
**This software is for EDUCATIONAL and RESEARCH purposes only.**
This project was developed to demonstrate advanced Windows Kernel exploitation techniques, specifically Direct Kernel Object Manipulation (DKOM). The author takes no responsibility for any misuse of this code. Do not deploy this on systems you do not own or have explicit authorization to test.

---

## 📖 Overview

This project is a sophisticated **Proof-of-Concept** (PoC) Rootkit designed to bypass modern user-mode security mechanisms by operating directly within the Windows Kernel (Ring 0).

Unlike standard malware that relies on user-mode APIs, Project Ghost leverages a custom Kernel Driver to manipulate OS structures (`EPROCESS`) directly in memory. This allows the accompanying User-Mode Agent to achieve invisibility, instant privilege escalation, and persistent remote access.

### Key Capabilities

* **👑 Kernel-Level Privilege Escalation:** Instantly elevates the agent to `NT AUTHORITY\SYSTEM` by performing a Token Stealing attack directly in kernel memory.
* **👻 Stealth (DKOM Rootkit):** Hides the running process from **Task Manager**, Process Explorer, and other monitoring tools by unlinking the process from the `ActiveProcessLinks` list.
* **🐚 Reverse System Shell:** Spawns a fully interactive `cmd.exe` shell piped over TCP, inheriting the stolen System Token.
* **💥 Kernel Panic Trigger:** Capable of intentionally crashing the system (BSOD) via `KeBugCheckEx` as a kill-switch mechanism.
* *More Functionality comming soon!*

---

## 🛠️ Technical Architecture

The solution is composed of three distinct modules:

### 1. GhostDriver (`.sys`)
The kernel-mode component responsible for the heavy lifting.
* **Communication:** Exposes a device object (`\Device\GhostDevice`) for IOCTL communication.
* **Memory Safety:** Implements `MmIsAddressValid` and Exception Handling to prevent system instability during memory patching.
* **Technique:** Locates `EPROCESS` structures via `PsLookupProcessByProcessId` and manually patches the Token and List Entry offsets.

### 2. GhostClient (`.exe`)
The client payload running on the target machine.
* **Network Stack:** Uses raw `WSASocketA` to ensure compatibility with standard input/output redirection.
* **Automation:** Automatically connects to the C2 server and waits for instructions.
* **Handle Inheritance:** Passes socket handles to spawned child processes (`cmd.exe`) for seamless reverse shell interaction.

### 3. C2_Server (`.py`)
The Command & Control server running on the attacker's machine.
* **Multi-threading:** Handles simultaneous input/output streams for the reverse shell.
* **UI:** Provides a clean CLI menu for executing rootkit functions.

---

## ⚙️ Configuration & Offsets

**CRITICAL NOTE:** This project relies on hardcoded offsets for `_EPROCESS` structures, which vary between Windows versions (especially Insider Previews).

Before compiling `GhostDriver`, you **must** verify the offsets for your target machine using **WinDbg**:

1.  **Token Offset:**
    ```text
    kd> dt nt!_EPROCESS Token
    +0x248 Token : _EX_FAST_REF  <-- Use this value
    ```
2.  **ActiveProcessLinks Offset:**
    ```text
    kd> dt nt!_EPROCESS ActiveProcessLinks
    +0x1d8 ActiveProcessLinks : _LIST_ENTRY  <-- Use this value
    ```
Update `GhostDriver/Driver.c` accordingly:
```c
#define TOKEN_OFFSET 0x248 
#define PROCESS_LINKS_OFFSET 0x1d8
```
Update `GhostClient/Secrets.h` with your C2 IP:
```
#define ATTACKER_IP "192.168.1.X"
#define ATTACKER_PORT 4444
```

## 🎮 Usage
Once the target connects, the C2 Server will display the control menu:
```
==============================
 COMMANDS MENU
==============================
1 - Use CMD with SYSTEM privilage
2 - Hide from Task Manager
3 - BSOD the Victim's computer
```
**Option 1 (System Shell):**

* Sends IOCTL to Driver -> Driver swaps Token -> Agent spawns CMD -> Pipes output to C2.

* Result: You have full control as `NT AUTHORITY\SYSTEM`.

**Option 2 (Stealth):**

* Sends IOCTL to Driver -> Driver unlinks PID from ActiveProcessLinks.

* Result: Process remains active but invisible to the OS task list.

## 🧠 Concepts Demonstrated
**Windows Internals:** Deep dive into EPROCESS, ETHREAD, and ACCESS_TOKEN.

**Kernel Programming:** Handling IRQL, DriverEntry, and IRPs.

**Network Security:** Reverse TCP connections and raw socket manipulation.

**Reverse Engineering:** analyzing kernel structures dynamically with WinDbg.
