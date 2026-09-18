# ShadowWeaver
A monolithic, version-agnostic Windows x64 shellcode loader demonstrating hardware Intel CET compliance, module overloading, and dynamic indirect syscalls for clean, fully backed call stacks.

# ShadowWeaver

An advanced, monolithic Windows x64 shellcode loader demonstrating **Intel CET (Control-flow Enforcement Technology)** compliance, **Module Overloading**, and **Dynamic Indirect Syscalls**. 

The primary objective of this project is to achieve a completely "clean," hardware-validated, and fully disk-backed call stack capable of bypassing deep structural inspections (such as manual `kv` tracing in WinDbg) and modern hardware-enforced protection environments.

## Technical Core Architecture

1. **Hardware-Enforced CET Shadow Stack Compliance**
   Traditional stack spoofing patterns corrupt or modify return addresses on the fly, which instantly triggers a `#CP` (Control Protection) exception under Intel CET hardware. `ShadowWeaver` solves this by utilizing **Fiber Local Storage (FLS) Callbacks** triggered natively via `ntdll!FlsFree`. The `CALL` instruction originates legitimately from the operating system subsystem, recording perfectly onto the hardware Shadow Stack.

2. **Native Thread Pool Dispatching (`PTP_WORK`)**
   To avoid thread creation anomalies (`CreateThread` triggers heavily scrutinized ETW telemetry), the execution pipeline is offloaded to the native Windows Thread Pool. The payload runs completely decoupled from the main process thread under a legitimate worker thread topology (`ntdll!TppWorkerThread`).

3. **Dynamic PEB Parsing & Indirect Syscalls**
   The loader features an integrated **Process Environment Block (PEB) Walking Engine**. It computes System Service Numbers (SSNs) dynamically at runtime, removing hardcoded tables and ensuring cross-version compatibility. It executes transitions by jumping to native `syscall` instructions inside `ntdll.dll` to blind user-mode EDR hooks while maintaining legitimate kernel stack traces.

4. **Module Overloading (DLL Hollowing)**
   Instead of launching code out of suspicious anonymous memory pages, the loader maps a legitimate, signed Windows binary from disk (`apphelp.dll`) and overloads its text/code execution section. Memory forensic scanners see a fully verified, disk-backed PE image file footprint.

## Visual Target Stack Walk (WinDbg `k`)

During execution, a manual trace reveals a flawless, fully-signed module topology rooted inside the native Windows threading engine:

```text
00 apphelp!SE_DllLoaded               <-- Shellcode running within signed disk-backed bounds
01 ntdll!RtlProcessFlsData+0x214      <-- Clean OS frame handling hardware-validated context setup
02 ntdll!RtlFreeFlsData+0x24         <-- OS sweeps active Fiber context table
03 kernelbase!FlsFree+0x18           <-- Legitimate API cleanup execution trace
04 loader!WorkCallback+0x32          <-- Target wrapper processing inside pool worker
05 ntdll!TppWorkAndWaitCallback+0x5a <-- Managed OS thread worker pool entry point
06 ntdll!TppWorkerThread+0x80        <-- Subsystem base loop frame
07 kernel32!BaseThreadInitThunk+0x14 <-- System process initialization frame
08 ntdll!RtlUserThreadStart+0x21     <-- Subsystem primary thread entry point
```

## Compilation Instructions

- **IDE:** Visual Studio 2022+
- **Platform/Architecture:** Windows x64
- **Configuration:** Release (Maximize optimization flags, disable optimization debug symbols if desired)
- **C++ Standard:** C++17 or C++20

## Disclaimer

This repository is strictly dedicated to computer science research, advanced memory forensics analysis, and defensive engineering. It is provided exclusively for educational purposes and authorized security evaluations.

