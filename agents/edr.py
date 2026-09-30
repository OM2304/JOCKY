r"""EDR sensor & hook analysis -- detect endpoint agents, inspect userland hooks.

Threat model
------------
Endpoint Detection & Response (EDR) / AV agents instrument userland APIs to
gain telemetry: process creation, image load, file/registry access, network
socket calls. The dominant technique on x64 Windows is *API hooking* -- the
agent overwrites the first bytes of a hot export (or an ntdll syscall stub)
with a trampoline (jmp / push+ret / mov rax,jmp rax / int3 region) so every
call flows through the sensor first.

This module is the *forensic/defensive* companion to that model. It does
NOT evade or bypass anything; it answers three questions a defender (or a
payload developer doing OPSEC planning) needs answered on a given host:

  1. WHAT is watching the machine?  -> discovery of EDR/AV products from the
     service store (HKLM\SYSTEM\CurrentControlSet\Services), Defender's own
     registry keys, SecurityCenter2 (optional, via --sc2), and best-effort
     process / in-process-module matching.
  2. WHERE are the hooks?           -> in-memory vs on-disk byte comparison
     of key exports in ntdll / kernel32 / kernelbase (pure-struct PE export
     table parsing; RVA -> file-offset mapping; zero third-party deps), with
     hook-signature classification and attribution of the trampoline target
     to the loaded module that owns it.
  3. HOW would a defender confirm?  -> --roadmap prints the canonical
     detection / verification / containment playbook (audit trail, symbol
     server cross-check, mandatory label / patch-uninstall, ...).

Design notes
------------
* Dependency-free: stdlib only (ctypes, struct, winreg on Windows).
* Reads the on-disk image from System32 and the *loaded* image straight from
  this process's own address space (module base + SizeOfImage) -- no
  ReadProcessMemory of foreign processes, no kernel handles, and the only
  side effect is what a normal process already has (ntdll/kernel32 mapped).
* An on-disk/on-memory difference is a *candidate*, not a verdict:
  benign causes exist (image updated on disk after load, Hotpatch detours,
  legitimate tamper markers). We classify the byte signature and score
  likelihood; the analyst makes the call. If the two images are byte-
  identical, nothing is flagged at all.
* Forwarded exports (export-table entries whose RVA points back inside the
  export directory) are resolved/skipped, not misreported as functions.
* psapi.dll is only probed if already mapped in this process (EnumProcesses
  / GETModuleFileName paths load it lazily in practice).

Usage
-----
    python agents/edr.py                     # discovery + hook scan (text)
    python agents/edr.py --hooks             # hook table only
    python agents/edr.py --roadmap           # print the defensive playbook
    python agents/edr.py --sc2               # also query SecurityCenter2
    python agents/edr.py --json              # machine-readable JSON
    python agents/edr.py --demo              # synthetic positives demo
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
from typing import Dict, List, Optional, Tuple

is_windows = os.name == "nt"

if is_windows:
    import ctypes
    import ctypes.wintypes as wt
    from ctypes import windll

# ---------------------------------------------------------------------------
# EDR/AV product knowledge base.
# ---------------------------------------------------------------------------
# Entry schema:
#   name      : canonical product name
#   vendor    : vendor
#   category  : AV / EDR / Endpoint-Agent / Telemetry
#   services  : substrings matched against service name AND ImagePath
#   procs     : substrings matched against running process basenames
#   dlls      : substrings matched against in-process module basenames
#   regs      : registry key subpaths under HKLM\SOFTWARE that indicate install
KNOWN_EDR: List[Dict] = [
    {"name": "Microsoft Defender Antivirus", "vendor": "Microsoft", "category": "AV",
     "services": ["WinDefend", "MDCoreSvc"], "procs": ["MsMpEng"], "dlls": [],
     "regs": [r"SOFTWARE\Microsoft\Windows Defender"]},
    {"name": "Microsoft Defender for Endpoint (Sense)", "vendor": "Microsoft", "category": "EDR",
     "services": ["Sense"], "procs": ["MsSense", "SenseCncProxy"], "dlls": [],
     "regs": []},
    {"name": "Sysmon", "vendor": "Microsoft/Sysinternals", "category": "Telemetry",
     "services": ["Sysmon"], "procs": ["Sysmon", "Sysmon64"], "dlls": [],
     "regs": []},
    {"name": "CrowdStrike Falcon", "vendor": "CrowdStrike", "category": "EDR",
     "services": ["CSAgent", "CSDeviceControl"], "procs": ["CSAgent", "Falcon"], "dlls": ["csagent"],
     "regs": [r"SOFTWARE\CrowdStrike"]},
    {"name": "SentinelOne", "vendor": "SentinelOne", "category": "EDR",
     "services": ["SentinelAgent", "SentinelServiceHost"], "procs": ["SentinelAgent", "SentinelServiceHost"],
     "dlls": ["sentinel"], "regs": [r"SOFTWARE\SentinelLabs"]},
    {"name": "VMware Carbon Black (EDR/App Control)", "vendor": "VMware", "category": "EDR",
     "services": ["CarbonBlack"], "procs": ["RepMgr", "cb"], "dlls": ["carbonblack"],
     "regs": [r"SOFTWARE\Carbon Black"]},
    {"name": "Cylance (BlackBerry) Protect", "vendor": "BlackBerry", "category": "EDR",
     "services": ["CylanceSvc"], "procs": ["CylanceSvc", "CylanceUI"], "dlls": ["cylance"],
     "regs": [r"SOFTWARE\Cylance"]},
    {"name": "Trend Micro Apex One / OfficeScan", "vendor": "Trend Micro", "category": "EDR",
     "services": ["tmccsf", "TmFilter", "TMBMSRV", "SAVService", "WSCSecurity"],
     "procs": ["TMBMSRV", "tmccsf"], "dlls": [], "regs": [r"SOFTWARE\Trend Micro"]},
    {"name": "Symantec Endpoint Protection", "vendor": "Broadcom", "category": "EDR",
     "services": ["SepMasterService", "Symantec"], "procs": ["ccSvcHst", "Rtvscan"],
     "dlls": [], "regs": [r"SOFTWARE\Symantec"]},
    {"name": "McAfee Endpoint Security", "vendor": "McAfee", "category": "EDR",
     "services": ["McAfee"], "procs": ["McTray", "mcshield", "MfeHips"], "dlls": [],
     "regs": [r"SOFTWARE\McAfee"]},
    {"name": "ESET Endpoint Security", "vendor": "ESET", "category": "EDR",
     "services": ["ekrn", "ehdrv"], "procs": ["ekrn", "eguiProxy"], "dlls": [],
     "regs": [r"SOFTWARE\ESET"]},
    {"name": "Kaspersky Endpoint Security", "vendor": "Kaspersky", "category": "EDR",
     "services": ["AVP"], "procs": ["avp", "ksde"], "dlls": [],
     "regs": [r"SOFTWARE\KasperskyLab"]},
    {"name": "Sophos Intercept X", "vendor": "Sophos", "category": "EDR",
     "services": ["Sophos"], "procs": ["SophosUI", "SophosAgent"], "dlls": [],
     "regs": [r"SOFTWARE\Sophos"]},
    {"name": "FireEye / Trellix Endpoint", "vendor": "FireEye", "category": "EDR",
     "services": ["feflow", "MfeEms"], "procs": ["xagt", "xagtnotif"], "dlls": [],
     "regs": [r"SOFTWARE\FireEye"]},
    {"name": "Bitdefender GravityZone", "vendor": "Bitdefender", "category": "EDR",
     "services": ["Bitdefender", "BdRedline"], "procs": ["bdservicehost", "bdagent"],
     "dlls": [], "regs": [r"SOFTWARE\Bitdefender"]},
    {"name": "Check Point Harmony Endpoint", "vendor": "Check Point", "category": "EDR",
     "services": ["Check Point"], "procs": ["trvServer", "ThreatEmulationClient"], "dlls": [],
     "regs": [r"SOFTWARE\Check Point"]},
    {"name": "Palo Alto Cortex XDR (Traps)", "vendor": "Palo Alto", "category": "EDR",
     "services": ["Traps", "cyserver"], "procs": ["cyserver", "cyverto"], "dlls": [],
     "regs": [r"SOFTWARE\Palo Alto Networks"]},
    {"name": "Cybereason", "vendor": "Cybereason", "category": "EDR",
     "services": ["Cybereason"], "procs": ["CrAVSvc"], "dlls": [],
     "regs": []},
    {"name": "Tanium Endpoint Platform", "vendor": "Tanium", "category": "Endpoint-Agent",
     "services": ["Tanium"], "procs": ["TaniumClient"], "dlls": ["tanium"],
     "regs": []},
    {"name": "Elastic Endpoint Security", "vendor": "Elastic", "category": "EDR",
     "services": ["elastic-endpoint"], "procs": ["elastic-agent", "elastic-endpoint"], "dlls": [],
     "regs": []},
    {"name": "Wazuh Agent", "vendor": "Wazuh", "category": "Endpoint-Agent",
     "services": ["wazuh"], "procs": ["wazuh-agent"], "dlls": [],
     "regs": []},
    {"name": "Malwarebytes Endpoint", "vendor": "Malwarebytes", "category": "AV",
     "services": ["MBAMService"], "procs": ["mbam", "MBAMWsc"], "dlls": [],
     "regs": [r"SOFTWARE\Malwarebytes"]},
    {"name": "Avast / AVG Business", "vendor": "Gen Digital", "category": "AV",
     "services": ["avast", "avg"], "procs": ["aswidsagent", "avgnt"], "dlls": [],
     "regs": [r"SOFTWARE\Avast Software"]},
    {"name": "Cisco Secure Endpoint (AMP)", "vendor": "Cisco", "category": "EDR",
     "services": ["Cisco AMP", "sfc"], "procs": ["sfc", "amp"], "dlls": [],
     "regs": [r"SOFTWARE\Cisco"]},
]

# Exports most commonly instrumented by endpoint agents, per module.
PROBE_EXPORTS = {
    "ntdll.dll": [
        "NtQuerySystemInformation", "NtQueryInformationProcess", "NtQueryObject",
        "NtOpenProcess", "NtOpenThread", "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx",
        "NtDeviceIoControlFile", "NtQueryDirectoryFile", "NtEnumerateKey",
        "NtQuerySystemTime", "NtDuplicateObject", "NtResumeThread",
        "NtCreateUserProcess", "NtQueryVirtualMemory", "NtSetInformationThread",
        "NtClose", "NtCreateFile",
    ],
    "kernel32.dll": [
        "CreateProcessInternalW", "CreateFileW", "CreateThread", "OpenProcess",
        "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "GetProcAddress", "LoadLibraryExW", "WaitForSingleObject",
    ],
    "kernelbase.dll": [
        "CreateProcessInternalW", "CreateFileW", "CreateThread", "OpenProcess",
        "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory", "GetProcAddress",
    ],
    "psapi.dll": [          # only probed when already mapped in this process
        "EnumDeviceDrivers", "GetDeviceDriverFileNameW", "EnumProcesses",
        "EnumProcessModulesEx",
    ],
}

HOOK_FIRST_N = 16

# ---------------------------------------------------------------------------
# Minimal pure-struct PE parser (PE32+ assumed; rejects PE32 gracefully).
# ---------------------------------------------------------------------------

PE_DOS_ELFANEW = 0x3C
PE32P_MAGIC = 0x20B
MACHINE_AMD64 = 0x8664


class PEImage:
    """Parsed view of one module image (disk bytes or in-memory copy)."""

    __slots__ = ("data", "image_base", "size_of_image", "sections",
                 "export_rva", "export_size", "machine", "is_pe32p")

    def __init__(self, data: bytes, image_base: int):
        self.data = data
        self.image_base = image_base
        self.size_of_image = 0
        self.sections: List[Tuple[int, int, int, int, bytes]] = []
        self.export_rva = 0
        self.export_size = 0
        self.machine = 0
        self.is_pe32p = False
        self._parse(data)

    # -- offsets ----------------------------------------------------------
    def _parse(self, d: bytes) -> None:
        if len(d) < 0x40 or d[:2] != b"MZ":
            return
        e_lfanew = struct.unpack_from("<I", d, PE_DOS_ELFANEW)[0]
        if e_lfanew + 0x18 > len(d) or d[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return
        self.machine = struct.unpack_from("<H", d, e_lfanew + 4)[0]
        n_sections = struct.unpack_from("<H", d, e_lfanew + 6)[0]
        opt_off = e_lfanew + 4 + 20
        if opt_off + 2 > len(d):
            return
        magic = struct.unpack_from("<H", d, opt_off)[0]
        if magic != PE32P_MAGIC:
            return
        self.is_pe32p = True
        self.image_base = struct.unpack_from("<Q", d, opt_off + 24)[0]
        self.size_of_image = struct.unpack_from("<I", d, opt_off + 56)[0]
        n_datadirs = struct.unpack_from("<I", d, opt_off + 108)[0]
        if n_datadirs > 0:  # export directory is index 0
            exp_rva, exp_size = struct.unpack_from("<II", d, opt_off + 112)
            self.export_rva, self.export_size = exp_rva, exp_size
        size_of_opt = struct.unpack_from("<H", d, e_lfanew + 20)[0]
        sec_off = opt_off + size_of_opt
        for i in range(n_sections):
            p = sec_off + i * 40
            if p + 40 > len(d):
                break
            name = d[p:p + 8].rstrip(b"\0")
            v_size, v_addr = struct.unpack_from("<II", d, p + 8)
            raw_size, raw_ptr = struct.unpack_from("<II", d, p + 16)
            self.sections.append((v_addr, v_size, raw_ptr, raw_size, name))

    def rva_to_offset(self, rva: int) -> Optional[int]:
        """Map an RVA to a byte offset for THIS image's data buffer."""
        if not self.is_pe32p:
            return None
        for v_addr, v_size, raw_ptr, raw_size, _name in self.sections:
            span = max(v_size, raw_size)
            if v_addr <= rva < v_addr + span:
                off = rva - v_addr + raw_ptr
                if off + 4 <= len(self.data):
                    return off
        # Headers are mapped 1:1 (pre-first-section).
        if rva < self.size_of_image and rva < len(self.data):
            return rva
        return None

    def addr(self, rva: int) -> int:
        """As-loaded virtual address of an RVA (memory mode: base+rva)."""
        if self.image_base and self.is_pe32p:
            return self.image_base + rva
        return rva

    def exports(self) -> Dict[str, Tuple[int, bool]]:
        """name -> (function RVA, is_forwarded). Pure table walk."""
        out: Dict[str, Tuple[int, bool]] = {}
        if not self.is_pe32p or not self.export_rva:
            return out
        off = self.rva_to_offset(self.export_rva)
        if off is None or off + 40 > len(self.data):
            return out
        n_funcs = struct.unpack_from("<I", self.data, off + 20)[0]
        n_names = struct.unpack_from("<I", self.data, off + 24)[0]
        addr_of_funcs = struct.unpack_from("<I", self.data, off + 28)[0]
        addr_of_names = struct.unpack_from("<I", self.data, off + 32)[0]
        addr_of_ords = struct.unpack_from("<I", self.data, off + 36)[0]
        for i in range(min(n_names, 0xFFFF)):
            name_rva_off = self.rva_to_offset(addr_of_names + i * 4)
            if name_rva_off is None:
                continue
            name_rva = struct.unpack_from("<I", self.data, name_rva_off)[0]
            name_off = self.rva_to_offset(name_rva)
            if name_off is None:
                continue
            end = self.data.find(b"\0", name_off)
            name = self.data[name_off:end if end != -1 else None].decode("ascii", "replace")
            ord_off = self.rva_to_offset(addr_of_ords + i * 2)
            if ord_off is None:
                continue
            ordinal = struct.unpack_from("<H", self.data, ord_off)[0]
            func_off = self.rva_to_offset(addr_of_funcs + ordinal * 4)
            if func_off is None:
                continue
            f_rva = struct.unpack_from("<I", self.data, func_off)[0]
            # Forwarded export: the RVA points back into the export directory.
            fwd = self.export_rva <= f_rva < self.export_rva + self.export_size
            out[name] = (f_rva, fwd)
        return out


# ---------------------------------------------------------------------------
# Hook classification (pure bytes; unit-testable without Windows).
# ---------------------------------------------------------------------------

def infer_hook_type(disk: bytes, mem: bytes, stub_addr: int,
                    modules: List[Tuple[int, int, str]]) -> Dict:
    """Classify a first-N-bytes difference between disk and memory stub.

    modules: list of (base, size, name_lower) for this process, used to
    attribute the trampoline target to the module that owns it.
    """
    i = 0
    while i < min(len(disk), len(mem)) and disk[i] == mem[i]:
        i += 1
    entry: Dict = {
        "diff_offset": i if i < min(len(disk), len(mem)) else None,
        "disk_hex": disk[:HOOK_FIRST_N].hex(" "),
        "mem_hex": mem[:HOOK_FIRST_N].hex(" "),
        "hook_type": "none", "likely_hook": False,
        "target": None, "target_module": None,
        "note": "disk == memory; no difference observed",
    }
    if disk == mem:
        return entry

    def owner(target: int) -> Optional[str]:
        for base, size, name in modules:
            if base <= target < base + size:
                return name
        return None

    b = mem
    if b[:6] == b"\xcc" * 6:
        entry.update(hook_type="int3_flood", likely_hook=True,
                     note="breakpoint-style trampoline region at stub entry")
    elif b[:2] == b"\x48\xb8" and b[10:12] == b"\xff\xe0":
        target = struct.unpack("<Q", b[2:10])[0]
        entry.update(hook_type="mov_rax_jmp_rax", likely_hook=True,
                     target=target, target_module=owner(target),
                     note="mov rax, {:#x}; jmp rax -- classic EDR trampoline".format(target))
    elif b[:1] == b"\x68" and len(b) > 5 and b[5:6] == b"\xc3":
        target = struct.unpack("<I", b[1:5])[0]
        entry.update(hook_type="push_ret", likely_hook=True,
                     target=target, target_module=owner(target),
                     note="push imm32; ret -- direct transfer stub")
    elif b[:2] == b"\xff\x25" and len(b) > 6:
        disp = struct.unpack("<i", b[2:6])[0]
        target = stub_addr + 6 + disp
        entry.update(hook_type="ff25_jmp_ptr", likely_hook=True,
                     target=target, target_module=owner(target),
                     note="jmp qword ptr [rip+{:#x}] -- indirect pointer trampoline".format(target))
    elif b[:1] == b"\xe9" and len(b) > 5:
        rel = struct.unpack("<i", b[1:5])[0]
        target = stub_addr + 5 + rel
        entry.update(hook_type="e9_jmp_rel32", likely_hook=True,
                     target=target, target_module=owner(target),
                     note="jmp rel32 -- nearest / inline-hook trampoline")
    elif disk[:6] == b"\x4c\x8b\xd1\xb8" and b[:6] == b"\x4c\x8b\xd1\xb8":
        ss_disk = struct.unpack("<I", disk[5:9])[0]
        ss_mem = struct.unpack("<I", b[5:9])[0]
        entry.update(hook_type="syscall_swap", likely_hook=True,
                     note=f"SSN rewritten {ss_disk:#x} -> {ss_mem:#x} (different native API!)")
    else:
        prefix = "canonical syscall stub (mov r10, rcx; mov eax, SSN)" \
            if disk[:5] == b"\x4c\x8b\xd1\xb8" and b[:4] == b"\x4c\x8b\xd1" \
            else "export stub"
        entry.update(hook_type="unknown_diff", likely_hook=False,
                     note=f"unclassified byte diff at offset {i} "
                          f"(disk is {prefix}) -- verify manually")

    # Intra-module targets are usually benign hotpatching, not sensor hooks.
    if entry["hook_type"].endswith("_jmp") or entry["hook_type"] in ("ff25_jmp_ptr", "e9_jmp_rel32"):
        pass
    if entry["target_module"] is None and entry.get("target") is not None:
        entry["note"] += "; unbacked address -- likely dynamically allocated "
        entry["note"] += "trampoline (PAGE_EXECUTE heap) or foreign-module hook"
    elif entry.get("target") is not None:
        entry["note"] += f"; target owned by {entry['target_module']}"
    return entry


# ---------------------------------------------------------------------------
# Live host sources (Windows only).
# ---------------------------------------------------------------------------

def _sysdir() -> str:
    if not is_windows:
        return ""
    buf = ctypes.create_unicode_buffer(260)
    windll.kernel32.GetSystemDirectoryW(buf, 260)
    return buf.value


def _load_module_image(modname: str) -> Optional[Tuple[bytes, int, str]]:
    """Return (image_bytes, loaded_base, lower_module_name) or None."""
    if not is_windows:
        return None
    try:
        # IMPORTANT: the default restype for windll calls is signed c_int,
        # which truncates 64-bit module base addresses (e.g. 0x7FFC... ->
        # negative c_int) and breaks every downstream call. Fix the prototype:
        windll.kernel32.GetModuleHandleW.restype = ctypes.c_void_p
        handle = windll.kernel32.GetModuleHandleW(modname)
        if not handle:
            return None
        base = int(handle)  # c_void_p, so this is the full 64-bit base
        path_buf = ctypes.create_unicode_buffer(1024)
        if not windll.kernel32.GetModuleFileNameW(
                ctypes.c_void_p(base), path_buf, 1024):
            return None
        on_disk = open(path_buf.value, "rb").read()
        disk_pe = PEImage(on_disk, base)
        if not disk_pe.is_pe32p:
            return None
        size = disk_pe.size_of_image
        mem = ctypes.string_at(base, size)
        return mem, base, path_buf.value.lower().rsplit("\\", 1)[-1]
    except (OSError, ValueError):
        return None


def loaded_module_map() -> List[Tuple[int, int, str]]:
    """Own-process loaded modules: (base, size, name_lower). Best effort."""
    if not is_windows:
        return []
    mods: List[Tuple[int, int, str]] = []
    try:
        hproc = windll.kernel32.GetCurrentProcess()
        psapi = windll.psapi
        buf = (wt.HMODULE * 1024)()
        needed = wt.DWORD(0)
        if not psapi.EnumProcessModulesEx(hproc, buf, ctypes.sizeof(buf),
                                          ctypes.byref(needed), 0x03):
            return mods
        n = min(needed.value // ctypes.sizeof(wt.HMODULE), 1024)
        mib = ctypes.create_string_buffer(ctypes.sizeof(wt.PROCESS_MEMORY_COUNTERS))
        for i in range(n):
            base = int(buf[i])
            info = wt.MODULEINFO = None  # placeholder to satisfy linters
            info = wt.MODULEINFO()
            if not psapi.GetModuleInformation(hproc, buf[i], ctypes.byref(info),
                                              ctypes.sizeof(info)):
                continue
            nm = ctypes.create_unicode_buffer(260)
            if not psapi.GetModuleBaseNameW(hproc, buf[i], nm, 260):
                continue
            mods.append((int(info.lpBaseOfDll), int(info.SizeOfImage),
                         nm.value.lower()))
        return mods
    except (AttributeError, OSError):
        return mods


def _match_any(text: str, needles: List[str]) -> Optional[str]:
    t = text.lower()
    for n in needles:
        if n.lower() in t:
            return n
    return None


def discover_products(modules: List[Tuple[int, int, str]]) -> List[Dict]:
    """EDR/AV products installed on this host (services + procs + dlls + regs)."""
    found: Dict[str, Dict] = {}

    def _add(entry: Dict, ev_type: str, ev_name: str, note: str = "") -> None:
        key = entry["name"]
        if key not in found:
            found[key] = {**entry, "evidence": []}
        if len(found[key]["evidence"]) < 6:
            found[key]["evidence"].append({"type": ev_type, "name": ev_name,
                                           "note": note or ev_type})

    if is_windows:
        import winreg
        # 1) Service store: name + ImagePath.
        try:
            sk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Services")
            i = 0
            while True:
                try:
                    svc = winreg.EnumKey(sk, i)
                    i += 1
                    try:
                        with winreg.OpenKey(sk, svc) as sub:
                            img_path = ""
                            try:
                                img_path = winreg.QueryValueEx(sub, "ImagePath")[0] or ""
                            except OSError:
                                pass
                            start = 0
                            try:
                                start = winreg.QueryValueEx(sub, "Start")[0] or 0
                            except OSError:
                                pass
                    except OSError:
                        continue
                    if not img_path and not start:
                        continue
                    blob = f"{svc} {img_path}"
                    for e in KNOWN_EDR:
                        hit = _match_any(svc, e["services"]) or \
                            _match_any(blob, e["services"])
                        if hit:
                            _add(e, "service", svc,
                                 f"ImagePath={img_path or '(none)'} Start={start}")
                            break
                except OSError:
                    break
            winreg.CloseKey(sk)
        except OSError:
            pass

        # 2) Defender realtime state (registry, no WMI needed).
        try:
            import winreg as _wr
            with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection") as k:
                try:
                    disabled = _wr.QueryValueEx(k, "DisableRealtimeMonitoring")[0]
                    e = "realtime DISABLED by policy" if disabled else "realtime enabled"
                except OSError:
                    e = "realtime state not overridden (enabled)"
            _add({"name": "Microsoft Defender Antivirus", "vendor": "Microsoft",
                  "category": "AV", "services": [], "procs": [], "dlls": [],
                  "regs": []}, "registry",
                 r"SOFTWARE\Microsoft\Windows Defender", e)
        except OSError:
            pass

        # 3) Install markers in HKLM\SOFTWARE.
        try:
            import winreg as _wr
            with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE, r"SOFTWARE") as root:
                names = []
                i = 0
                while True:
                    try:
                        names.append(_wr.EnumKey(root, i))
                        i += 1
                    except OSError:
                        break
            blobs = " ".join(names).lower()
            for e in KNOWN_EDR:
                for reg in e["regs"]:
                    key_tail = reg.rsplit("\\", 1)[-1].lower()
                    if key_tail and key_tail in blobs:
                        _add(e, "registry", reg)
                        break
        except OSError:
            pass

    # 4) Process names (no handle ownership, just query).
    if is_windows:
        try:
            psapi = windll.psapi
            pids = (wt.DWORD * 65536)()
            needed = wt.DWORD(0)
            if psapi.EnumProcesses(pids, ctypes.sizeof(pids), ctypes.byref(needed)):
                n = min(needed.value // 4, 65536)
                for pid in pids[:n]:
                    if pid == 0 or pid == os.getpid():
                        continue
                    h = windll.kernel32.OpenProcess(0x1000, False, pid)
                    if not h:
                        continue
                    try:
                        buf = ctypes.create_unicode_buffer(1024)
                        if windll.kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(wt.DWORD(1024))):
                            base = buf.value.lower().rsplit("\\", 1)[-1]
                            for e in KNOWN_EDR:
                                hit = _match_any(base, e["procs"])
                                if hit:
                                    _add(e, "process", base, f"pid={pid}")
                                    break
                    finally:
                        windll.kernel32.CloseHandle(h)
        except (AttributeError, OSError):
            pass

    # 5) Sensor DLLs mapped into THIS process.
    dll_blob = {m[2] for m in modules}
    for e in KNOWN_EDR:
        for d in e["dlls"]:
            hit = next((m for m in dll_blob if d.lower() in m), None)
            if hit:
                _add(e, "dll", hit, "sensor DLL mapped into current process")

    out = sorted(found.values(), key=lambda x: x["name"].lower())
    for o in out:
        o.pop("regs", None)
    return out


def scan_hooks(modules: List[Tuple[int, int, str]]) -> Dict[str, List[Dict]]:
    """Compare disk vs loaded stubs for PROBE_EXPORTS across modules."""
    results: Dict[str, List[Dict]] = {}
    if not is_windows:
        return results
    mapped_names = {m[2] for m in modules}
    for modname, exports in PROBE_EXPORTS.items():
        if modname not in mapped_names:
            continue  # only probe modules already resident in this process
        loaded = _load_module_image(modname)
        if not loaded:
            continue
        mem, base, lowname = loaded
        try:
            disk_pe = PEImage(open(os.path.join(_sysdir(), modname), "rb").read(), base)
        except OSError:
            continue
        mem_pe = PEImage(mem, base)
        if not (disk_pe.is_pe32p and mem_pe.is_pe32p):
            continue
        disk_ex = disk_pe.exports()
        mem_ex = mem_pe.exports()
        for target in exports:
            if target not in disk_ex or target not in mem_ex:
                continue
            d_rva, d_fwd = disk_ex[target]
            m_rva, m_fwd = mem_ex[target]
            if d_fwd or m_fwd:
                continue  # forwarded entries are not real stubs
            if d_rva != m_rva:
                # Export table itself was relocated -- worth one note.
                results.setdefault(modname, []).append({
                    "export": target, "offset": None,
                    "disk_hex": "", "mem_hex": "",
                    "hook_type": "export_table_relocated", "likely_hook": True,
                    "target": None, "target_module": None,
                    "note": f"export RVA differs disk {d_rva:#x} vs mem {m_rva:#x}",
                })
                continue
            d_off = disk_pe.rva_to_offset(d_rva)
            m_off = mem_pe.rva_to_offset(m_rva)
            if d_off is None or m_off is None:
                continue
            disk_bytes = disk_pe.data[d_off:d_off + HOOK_FIRST_N]
            mem_bytes = mem_pe.data[m_off:m_off + HOOK_FIRST_N]
            stub_addr = base + d_rva
            info = infer_hook_type(disk_bytes, mem_bytes, stub_addr, modules)
            if info["hook_type"] == "none":
                continue
            info["export"] = target
            info["dll"] = lowname
            results.setdefault(modname, []).append(info)
    return results


# ---------------------------------------------------------------------------
# SecurityCenter2 (optional, via PowerShell -- off by default).
# ---------------------------------------------------------------------------

def security_center2() -> List[Dict]:
    """AntiVirusProduct rows from root\\SecurityCenter2, or [] on failure."""
    if not is_windows:
        return []
    import subprocess
    cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
           "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName "
           "AntiVirusProduct | ConvertTo-Json -Compress"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if out.returncode != 0 or not out.stdout.strip():
            return []
        rows = json.loads(out.stdout)
        if isinstance(rows, dict):
            rows = [rows]
        return [{"name": r.get("displayName"), "state_hex": hex(r.get("productState", 0)),
                 "exe": r.get("pathToSignedProductExe", "")} for r in rows]
    except (OSError, ValueError, json.JSONDecodeError):
        return []


# ---------------------------------------------------------------------------
# Report formatting.
# ---------------------------------------------------------------------------

ROADMAP = r"""EDR/AV sensor defensive playbook (blue-team steps; no evasion content)
============================================================================
1. CONFIRM A CANDIDATE HOOK
   - Cross-check the flagged export on a *fresh, isolated* VM with the same
     Windows build: a clean image must be byte-identical disk vs memory.
   - Verify the module's disk hash against your own golden copy / symbol
     server (ntdll.dll ships in Windows component store; compare CAB
     contents, not just System32).
   - Check the trampoline target module (scan output names it) against the
     vendor's signing certificate (Get-AuthenticodeSignature) and whether
     the product is expected on this workload.

2. COMMON BENIGN CAUSES BEFORE DECLARING A SENSOR
   - Disk image updated by Windows Update while the process is still running
     an older loaded image -> reboot and re-scan.
   - Process created before the module was replaced (very common after
     Patch Tuesday) -> same: reboot, rescan.
   - Microsoft Hotpatch detours (rare in userland; normally nops at entry)
     -> differ at offsets >2 with no jmp/ff25 pattern.

3. IF A SENSOR IS CONFIRMED
   - Record: module, export, disk vs mem bytes, target module+offset, PID
     list, timestamp. This is chain-of-custody evidence.
   - Identify owner: scan output names the owning module; map it to the
     product via KNOWN_EDR / your asset inventory, then to the responsible
     admin (product consoles log installs).
   - Quarantine decision is a business call (tamper protection will fight
     removal) -- engage the vendor's uninstall path, never patch memory.

4. MEASURE SENSOR DENSITY BEFORE DEPLOYING NEW TOOLS
   - Run this module before hardening checks / new agent rollouts; a clean
     scan (0 products, 0 diffs) is the baseline to compare future
     changes against.

5. LIMITATIONS OF THIS MODULE
   - Kernel-mode hooks / callbacks are invisible from userland (needs
     driver-oracle cross-checks, see agents/byovd.py's psapi census test).
   - A *process that started later* than a matched hook won't re-diff (each
     scan snapshots now). Re-run per process lifecycle, not once.
   - We compare only the first 16 bytes of each probed export; deeper
     trampoline chaining (second-stage jump tables) requires a full
     disassembler tradecraft pass.
"""


def fmt_report(products: List[Dict], hooks: Dict[str, List[Dict]],
               sc2: List[Dict], summary: Dict, synthetic: bool = False) -> str:
    L = []
    L.append("=" * 72)
    L.append(" JOCKY EDR/AV sensor & userland-hook analysis")
    L.append("=" * 72)
    tag = "[synthetic demo data]" if synthetic else "[live host data]"
    L.append(f" mode: {tag}")
    if products:
        L.append(f"\n Discovered endpoint agents ({len(products)}):")
        L.append(" " + "-" * 68)
        for p in products:
            ev = ", ".join(f"{x['type']}:{x['name']}" for x in p["evidence"][:4])
            L.append(f"  * {p['name']}  [{p['category']}, {p['vendor']}]")
            L.append(f"      evidence: {ev}")
    else:
        L.append("\n No known endpoint agents detected.")
    if sc2:
        L.append("\n SecurityCenter2 (AntiVirusProduct):")
        for s in sc2:
            L.append(f"  * {s['name']}  state={s['state_hex']}")
    n_hooks = sum(len(v) for v in hooks.values())
    L.append(f"\n Userland hook diff (disk vs loaded image, first "
             f"{HOOK_FIRST_N}B of each stub):")
    L.append(" " + "-" * 68)
    if not n_hooks:
        L.append("  No differences observed across probed exports.")
    for mod, rows in hooks.items():
        for r in rows:
            likely = "LIKELY-HOOK" if r["likely_hook"] else "diff"
            L.append(f"  [{likely}] {mod}!{r['export']}")
            if r["offset"] is not None:
                L.append(f"       diff at byte {r['offset']}: "
                         f"disk {r['disk_hex']}  mem {r['mem_hex']}")
            L.append(f"       type: {r['hook_type']}  note: {r['note']}")
    L.append(f"\n Summary: products={summary['products']} "
             f"hook_diffs={summary['hook_diffs']} "
             f"likely_hooks={summary['likely_hooks']}")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Demo mode -- synthetic positives built from REAL host data.
# ---------------------------------------------------------------------------

def run_demo() -> int:
    modules = loaded_module_map()
    products = discover_products(modules)
    real_hooks = scan_hooks(modules)

    # Synthetic product(s) to visualise a fully-loaded sensor stack.
    products = [p for p in products if p["name"].lower() != "crowdstrike falcon"]
    products.insert(0, {
        "name": "CrowdStrike Falcon Sensor", "vendor": "CrowdStrike",
        "category": "EDR", "evidence": [
            {"type": "service", "name": "CSAgent", "note": "ImagePath=C:\\Program Files\\CrowdStrike\\CSAgent.exe (synthetic)"},
            {"type": "dll", "name": "csagent.dll", "note": "sensor DLL mapped into current process (synthetic)"},
        ]})
    products.insert(1, {
        "name": "Sysmon", "vendor": "Microsoft/Sysinternals", "category": "Telemetry",
        "evidence": [
            {"type": "service", "name": "Sysmon", "note": "driver+service pair SysmonDrv/Sysmon (synthetic)"},
        ]})

    # Synthetic hook: patch *real* NtQuerySystemInformation stub with an E9
    # trampoline to a real loaded module. Uses real export RVAs for realism.
    mod = None
    base = 0
    disk = b""
    try:
        loaded = _load_module_image("ntdll.dll")
        if loaded is not None:
            mod, base, _ = loaded
            disk = open(os.path.join(_sysdir(), "ntdll.dll"), "rb").read()
    except OSError:
        pass
    target_mod = next((m for m in modules if m[2] not in ("ntdll.dll",)), None)
    target_addr = (target_mod[0] + 0x2000) if target_mod else base + 0x100
    synthetic: Dict[str, List[Dict]] = {}
    info = None
    if mod is not None and target_mod is not None:
        # Live-host flavour: build the trampoline on top of the REAL export RVA.
        mem_pe = PEImage(mod, base)
        ex = mem_pe.exports()
        rva = ex.get("NtQuerySystemInformation", (None, False))[0]
        if rva:
            disk_pe = PEImage(disk, base)
            d_off = disk_pe.rva_to_offset(rva)
            stub_addr = base + rva
            rel = target_addr - (stub_addr + 5)
            mem_stub = bytes([0xE9]) + struct.pack("<i", rel) + b"\x90" * 12
            info = infer_hook_type(disk_pe.data[d_off:d_off + HOOK_FIRST_N],
                                   mem_stub, stub_addr, modules)
    if info is None:
        # Cross-platform flavour: no live ntdll needed. Use textbook prologue
        # bytes (mov rax,r10 / mov r10,rcx / syscall) as the clean stub and a
        # classic E9 rel32 trampoline as the synthetic hook.
        clean = bytes.fromhex("4889C84989CA0F05") + b"\xCD\x80" + b"\x90" * 6
        mem_stub = bytes([0xE9]) + struct.pack("<i", 0x7FFF1234) + b"\x90" * 10
        info = infer_hook_type(clean, mem_stub, 0x180000000, [])
        info.update({"synthetic": True, "cross_platform": True})
    info.update({"export": "NtQuerySystemInformation", "dll": "ntdll.dll",
                 "synthetic": True,
                 "offset": info.get("diff_offset"),
                 "note": "synthetic inline hook for demo -- disk is "
                         "clean; this stub was NOT modified"})
    synthetic.setdefault("ntdll.dll", []).append(info)

    summary = {
        "products": len(products),
        "hook_diffs": sum(len(v) for v in real_hooks.values()) + len(synthetic.get("ntdll.dll", [])),
        "likely_hooks": sum(1 for v in real_hooks.values() for r in v if r["likely_hook"])
                         + len(synthetic.get("ntdll.dll", [])),
    }
    sys.stdout.write(fmt_report(products, synthetic, [], summary, synthetic=True))
    if real_hooks:
        sys.stdout.write("\n (also observed live on this host: "
                         + "; ".join(f"{m}!{r['export']}" for m, rs in real_hooks.items() for r in rs)
                         + ")")
    if not is_windows:
        sys.stdout.write(
            "\n [platform] non-Windows host (WSL/Linux) detected: live ntdll.dll\n"
            " hook-diff needs Windows, so this run used cross-platform synthetic\n"
            " stubs. Re-run from Git Bash on Windows for the live sensor analysis.\n")
    sys.stdout.write(
        "\n\n Demo complete: no process was modified, no files written, "
        "no driver loaded.\n")
    return 0


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="jocky-edr", description=__doc__)
    p.add_argument("--hooks", action="store_true",
                   help="print hook-diff table only (skip discovery details)")
    p.add_argument("--roadmap", action="store_true",
                   help="print the defensive verification playbook and exit")
    p.add_argument("--sc2", action="store_true",
                   help="also probe SecurityCenter2 via PowerShell (off by "
                        "default: keeps the scan dependency-free)")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--demo", action="store_true",
                   help="synthetic positive-detection demo (host untouched)")
    a = p.parse_args(argv)

    if a.roadmap:
        sys.stdout.write(ROADMAP)
        return 0
    if a.demo:
        return run_demo()
    if not is_windows:
        sys.stdout.write("edr.py is Windows-only (ntdll/kernel32 stub "
                         "comparison); nothing to scan here.\n")
        return 0

    modules = loaded_module_map()
    products = discover_products(modules)
    hooks = scan_hooks(modules)
    sc2 = security_center2() if a.sc2 else []
    summary = {
        "products": len(products),
        "hook_diffs": sum(len(v) for v in hooks.values()),
        "likely_hooks": sum(1 for v in hooks.values() for r in v if r["likely_hook"]),
    }
    if a.json:
        out = {
            "host": os.environ.get("COMPUTERNAME", ""),
            "products": products,
            "security_center2": sc2,
            "hooks": {k: [{kk: (f"0x{vv:x}" if kk == "target" else vv)
                           for kk, vv in r.items()} for r in v]
                      for k, v in hooks.items()},
            "summary": summary,
        }
        print(json.dumps(out, indent=2))
        return 0
    sys.stdout.write(fmt_report(products, hooks, sc2, summary))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())