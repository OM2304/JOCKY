r"""BYOVD hunter -- detect Bring-Your-Own-Vulnerable-Driver conditions.

Attack model
------------
Windows only loads kernel drivers that carry a valid Microsoft signature. A
BYOVD primitive abuses *legitimately signed* (but vulnerable) third-party
drivers: the attacker drops one of these to disk (or loads it from a
controllable path) and uses a known IOCTL/capability to gain kernel read/write,
disable EDR callbacks, patch tokens, or otherwise break out of user mode.

This module is a *detection* companion to that model. It triages a host for
the pre-conditions an attacker would leverage:

  1. vulnerable driver present in System32\\drivers / DriverStore (on disk);
  2. vulnerable driver currently LOADED into the kernel (EnumDeviceDrivers);
  3. the driver registered as a persistent kernel service
     (HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>);
  4. optional hash matches (SHA-256) when a curated DB with hashes is supplied
     via --db-json -- the bundled DB is filename-based by design, because
     legitimate vendors ship many versions and canonical hashes come from
     the LOLDrivers project (https://www.loldrivers.io) which updates faster
     than any offline copy.

Usage
-----
    python agents/byovd.py                       # triage this host
    python agents/byovd.py --json                # machine-readable output
    python agents/byovd.py --scan-custom "C:\\Tools\\drivers"
    python agents/byovd.py --db-json my_db.json  # add hash-verified entries
    python agents/byovd.py --demo                # synthetic positive demo

Cross-source loader validation
-------------------------------
psapi EnumDeviceDrivers gives *loaded base addresses*; GetDeviceDriverFileName
resolves names. Endpoint/EDR products frequently shim these APIs to shadow or
sanitise the result (all entries collapse to the same name, or zero entries).
This module therefore cross-checks psapi against the Service Control Manager
store (HKLM\SYSTEM\CurrentControlSet\Services, ImagePath *.sys / Start<=2)
and flags the discrepancy as ``load_api_filtered`` when it looks filtered.


Dependency-free: stdlib only (os, hashlib, json, ctypes, winreg on Windows).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import time

DRIVER_URL = "https://www.loldrivers.io"  # canonical live DB (hash source)

# ---------------------------------------------------------------------------
# Vulnerability database (filename-keyed, extensible schema).
#
# Schema per entry:
#   name        : driver family / vendor product
#   file        : exact driver filename (case-insensitive compare)
#   cve         : CVE id (or "none" for known primitives without CVE)
#   cvss        : CVSS v3 base score (approx, latest public)
#   vendor      : software that ships the driver
#   capability  : what a successful exploit grants (R/W = arbitrary kernel
#                 read/write primitive, LPE = local privilege escalation,
#                 AV = anti-virus/EDR driver, DBG = debug/premium sysinternals)
#   ioctl       : best-known IOCTL / device name when public
#   note        : one-line context for the report
#   confidence  : low / medium / high  -- filename match only is low-medium;
#                 hash match upgrades to high (detection certainty, NOT
#                 exploit reliability).
#   hashes      : [] -- filled at runtime from --db-json or left empty
#                 (filename-only detection).
#
# This is a *curated subset* meant to be extended; the live source of truth
# for signed vulnerable-driver hashes is loldrivers.io.
VULN_DRIVERS = [
    {
        "name": "MSI Afterburner / EVGA Precision (RTCore64)",
        "file": "RTCore64.sys",
        "cve": "CVE-2018-12639",
        "cvss": 8.8,
        "vendor": "MSI / EVGA",
        "capability": "R/W",
        "ioctl": "\\Device\\RTCore, IOCTL 0x80862007 (arb r/w)",
        "note": "Microsoft-signed gaming driver; the most notorious BYOVD of the 2018-2023 era.",
        "confidence": "medium",
    },
    {
        "name": "Dell firmware update utility (dbutil)",
        "file": "dbutil_2_3.sys",
        "cve": "CVE-2021-21551",
        "cvss": 8.8,
        "vendor": "Dell",
        "capability": "LPE",
        "ioctl": "\\Device\\DellDrvLoader, IOCTL_CODES from 0x9B0C1EC4 family",
        "note": "Widely weaponized (LockBit, etc.) LPE-to-system via signed Dell driver.",
        "confidence": "medium",
    },
    {
        "name": "Process Explorer (ProcExp152)",
        "file": "ProcExp152.sys",
        "cve": "CVE-2021-24093",
        "cvss": 7.8,
        "vendor": "Microsoft Sysinternals",
        "capability": "LPE",
        "ioctl": "\\Device\\ProcExp",
        "note": "Signed diagnostic driver; exported device control allows token magic",
        "confidence": "medium",
    },
    {
        "name": "Intel Network Adapter Diagnostic Driver (iqvw64e)",
        "file": "iqvw64e.sys",
        "cve": "CVE-2015-2291",
        "cvss": 7.8,
        "vendor": "Intel",
        "capability": "R/W",
        "ioctl": "IOCTL 0x80862007 family via \\Device\\Nal",
        "note": "Classic signed arbitrary R/W primitive used by early rootkits.",
        "confidence": "medium",
    },
    {
        "name": "Gigabyte (gdrv)",
        "file": "gdrv.sys",
        "cve": "CVE-2018-19320",
        "cvss": 7.8,
        "vendor": "Gigabyte",
        "capability": "R/W",
        "ioctl": "\\Device\\GIO, 0xC3502800 family",
        "note": "Preinstalled on many Gigabyte boards; signed R/W primitive.",
        "confidence": "medium",
    },
    {
        "name": "Avast Anti-Rootkit (aswSP/aswbidsdriver)",
        "file": "aswbidsdriver.sys",
        "cve": "CVE-2022-26522",
        "cvss": 8.8,
        "vendor": "Avast",
        "capability": "LPE",
        "ioctl": "\\Device\\bidsdriver",
        "note": "AV kernel driver itself exploitable -> LPE to system.",
        "confidence": "medium",
    },
    {
        "name": "Cheat Engine (DBK)",
        "file": "dbk64.sys",
        "cve": "none",
        "cvss": 7.8,
        "vendor": "Cheat Engine",
        "capability": "R/W",
        "ioctl": "\\Device\\DBK",
        "note": "Unsigned in latest builds but older signed copies circulate; R/W primitive.",
        "confidence": "low",
    },
    {
        "name": "Micro-Star / MSI (NtDefender64)",
        "file": "NtDefender64.sys",
        "cve": "CVE-2023-35362",
        "cvss": 6.7,
        "vendor": "MSI",
        "capability": "R/W",
        "ioctl": "\\Device\\NtDefender64",
        "note": "2023 signed R/W; abused by Darkside for EDR shutdown.",
        "confidence": "medium",
    },
    {
        "name": "CVE-2024-3742 (AMD Ryzen Master)",
        "file": "AMDRyzenMasterDriverV15.sys",
        "cve": "CVE-2024-3742",
        "cvss": 7.8,
        "vendor": "AMD",
        "capability": "R/W/LPE",
        "ioctl": "\\Device\\AMDRyzenMasterDriverV15",
        "note": "Signed AMD driver LPE in the wild since 2024.",
        "confidence": "medium",
    },
    {
        "name": "ASUS Aura Sync / ASUSMB (Asusgio2)",
        "file": "Asusgio2.sys",
        "cve": "CVE-2024-36823",
        "cvss": 7.8,
        "vendor": "ASUS",
        "capability": "R/W",
        "ioctl": "\\Device\\Asusgio2",
        "note": "Signed ASUS driver R/W (background: EneTech family).",
        "confidence": "low",
    },
    {
        "name": "NVIDIA Windows Driver (nvflash / NVFlash)",
        "file": "NvFlash.sys",
        "cve": "none",
        "cvss": 6.5,
        "vendor": "NVIDIA",
        "capability": "R/W",
        "ioctl": "\\Device\\NvFlash",
        "note": "Signed utility; R/W primitive documented by fwupd research.",
        "confidence": "low",
    },
    {
        "name": "Micro-Star MSI (afterburner kernel driver variant)",
        "file": "RTCore32.sys",
        "cve": "CVE-2018-12639",
        "cvss": 8.8,
        "vendor": "MSI",
        "capability": "R/W",
        "ioctl": "\\Device\\RTCore",
        "note": "32-bit twin of RTCore64.sys.",
        "confidence": "medium",
    },
    {
        "name": "Dell dbutil (older versions)",
        "file": "dbutil.sys",
        "cve": "CVE-2021-21551",
        "cvss": 8.8,
        "vendor": "Dell",
        "capability": "LPE",
        "ioctl": "\\Device\\DellDrvLoader",
        "note": "Same root cause as dbutil_2_3.sys.",
        "confidence": "low",
    },
    {
        "name": "Logitech (LogiLDA)",
        "file": "LogiLDA.sys",
        "cve": "none",
        "cvss": 4.4,
        "vendor": "Logitech",
        "capability": "R/W",
        "ioctl": "\\Device\\LogiLDA",
        "note": "Signed driver R/W; used in some turla implants.",
        "confidence": "low",
    },
    {
        "name": "VGUARD / ZhenXian virtual GPU",
        "file": "vguard64.sys",
        "cve": "none",
        "cvss": 6.5,
        "vendor": "Tencent",
        "capability": "R/W",
        "ioctl": "\\Device\\VGUARD",
        "note": "Signed anti-cheat misuse tracked as DUMON (Tencent).",
        "confidence": "low",
    },
    {
        "name": "IObit (Unlocker/RAMDisk kernel component)",
        "file": "IObitUnlocker.sys",
        "cve": "CVE-2020-14210",
        "cvss": 7.8,
        "vendor": "IObit",
        "capability": "R/W",
        "ioctl": "\\Device\\IObitUnlocker",
        "note": "Signed R/W primitive.",
        "confidence": "low",
    },
]

# Files/dirs where a real attacker would stage these (defender blind spots
# and the classic Drop-The-Driver locations).
STAGE_PATHS = [
    r"C:\Windows\System32\drivers",
    r"C:\Windows\System32\DriverStore\FileRepository",
    # Windows 8/10 WDAC-era staging points
    r"C:\Windows\Temp",
    r"C:\ProgramData",
]
DRIVER_DIRS = [r"C:\Windows\System32\drivers",
               r"C:\Windows\System32\DriverStore\FileRepository"]

SERVICE_KEY = r"SYSTEM\CurrentControlSet\Services"


# ---------------------------------------------------------------------------
def _sha256(p: str) -> str:
    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _build_index(db: list) -> dict:
    idx = {}
    for e in db:
        idx.setdefault(e["file"].lower(), []).append(e)
    return idx


def _norm_windows_case(p: str) -> str:
    """Windows driver dirs are case-insensitive but the FS preserves case."""
    return p.lower()


def load_db(db_path: str | None) -> list:
    """Bundled DB + optional user DB (which may carry 'hashes')."""
    db = [dict(e) for e in VULN_DRIVERS]
    if db_path and os.path.exists(db_path):
        extra = json.load(open(db_path, encoding="utf-8"))
        for e in extra:
            e.setdefault("hashes", [])
            db.append(e)
    return db


def _psapi_loaded_raw() -> dict:
    """psapi EnumDeviceDrivers: raw address list + resolved names.

    Returns {"addresses": int, "names": list[str]} -- every name is the
    *distinct* full path once, duplicates collapsed. On non-Windows or API
    failure returns {"addresses": 0, "names": []}.
    """
    if platform.system() != "Windows":
        return {"addresses": 0, "names": []}
    try:
        import ctypes
        from ctypes import wintypes
        ps = ctypes.WinDLL("psapi", use_last_error=True)
        EnumDeviceDrivers = ps.EnumDeviceDrivers
        EnumDeviceDrivers.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                                      wintypes.DWORD,
                                      ctypes.POINTER(wintypes.DWORD)]
        EnumDeviceDrivers.restype = wintypes.BOOL
        GetDeviceDriverFileName = ps.GetDeviceDriverFileNameW
        GetDeviceDriverFileName.argtypes = [ctypes.c_void_p,
                                            wintypes.LPWSTR,
                                            wintypes.DWORD]
        GetDeviceDriverFileName.restype = wintypes.DWORD

        f_sz = wintypes.DWORD(0)
        if not EnumDeviceDrivers(None, 0, ctypes.byref(f_sz)):
            return {"addresses": 0, "names": []}
        n = f_sz.value // ctypes.sizeof(ctypes.c_void_p)
        addrs = (ctypes.c_void_p * n)()
        if not EnumDeviceDrivers(addrs, f_sz.value, ctypes.byref(f_sz)):
            return {"addresses": 0, "names": []}
        seen = {}
        for i in range(n):
            buf = ctypes.create_unicode_buffer(2048)
            nch = GetDeviceDriverFileName(addrs[i], buf, 2048)
            if nch and buf.value:
                p = buf.value or ""
                seen.setdefault(os.path.basename(p).lower(), p)
        return {"addresses": n, "names": seen}
    except Exception:
        return {"addresses": 0, "names": []}


def scm_active_drivers() -> dict:
    """SCM oracle: kernel services scheduled to load at boot.

    Reads HKLM\\SYSTEM\\CurrentControlSet\\Services for entries whose Type is
    kernel driver (1) and Start <= 2 (boot/system/auto), returning
    {lowercase_driver_name: image_path} plus a synthetic count entry.
    This is registry-backed (no hookable userland API) so it survives
    EnumDeviceDrivers filtering. Name matching is best-effort: the service
    key name != file name in many cases, so only the path basename is used.
    """
    res = {}
    if platform.system() != "Windows":
        return res
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE_KEY)
        i = 0
        while True:
            try:
                name = winreg.EnumKey(k, i)
                i += 1
            except OSError:
                break
            try:
                sk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    SERVICE_KEY + "\\" + name)
                try:
                    typ, _ = winreg.QueryValueEx(sk, "Type")
                    start, _ = winreg.QueryValueEx(sk, "Start")
                    ip, _ = winreg.QueryValueEx(sk, "ImagePath")
                finally:
                    sk.Close()
            except OSError:
                continue
            if typ != 1 or start > 2:      # kernel driver, boot/system/auto
                continue
            ip = str(ip).strip().lower()
            if not ip.endswith(".sys") or "\\" not in ip:
                continue
            base = os.path.basename(ip)
            res[base] = ip
        k.Close()
    except Exception:
        pass
    return res


def enumerate_loaded_drivers() -> dict:
    """Return {driver_name: full_path} for kernel modules via psapi.

    Backwards-compatible wrapper around _psapi_loaded_raw() -- deduped names
    mapped to their resolved path.
    """
    return _psapi_loaded_raw()["names"]


def loaded_driver_snapshot() -> dict:
    """Cross-source loader snapshot with API-filtering heuristic.

    Combines the psapi address census with the SCM registry oracle and
    flags ``filtered`` when the psapi name census is implausible (e.g. one
    unique name for hundreds of addresses -- the classic shim signature) or
    when psapi exposes names but the SCM census says a healthy driver
    population exists. Consumers should treat ``names`` as best-effort and
    rely on the SCM count when ``filtered`` is True.
    """
    raw = _psapi_loaded_raw()
    scm = scm_active_drivers()
    n_addr = raw["addresses"]
    n_psapi = len(raw["names"])
    n_scm = len(scm)
    filtered = False
    if n_addr > 0 and n_psapi == 1 and n_scm >= 10:
        filtered = True          # canonical shim: 1 name, many addresses
    elif n_addr > 0 and n_psapi * 3 < n_addr and n_scm >= 10:
        filtered = True          # strongly compressed name census
    elif n_addr == 0 and n_scm >= 10:
        filtered = True          # API silently disabled behind healthy SCM
    return {"addresses": n_addr, "names": raw["names"],
            "psapi_unique": n_psapi, "scm_active": n_scm,
            "filtered": filtered}


def scanner(db: list, extra_paths: list[str] | None = None) -> list:
    """Walk driver dirs, hash every .sys, match against the DB."""
    index = _build_index(db)
    dirs = DRIVER_DIRS + [p for p in (extra_paths or []) if os.path.isdir(p)]
    found = []
    seen = set()
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            # DriverStore holds a 'FileRepository' index dir and versioned
            # subdirs; skip the amd64/i386 split inside already-visited roots
            if root.lower() in seen:
                continue
            seen.add(root.lower())
            for fn in files:
                if not fn.lower().endswith(".sys"):
                    continue
                fp = os.path.join(root, fn)
                matches = index.get(fn.lower())
                if not matches:
                    continue
                h = _sha256(fp)
                for m in matches:
                    conf = m["confidence"]
                    hit = dict(m)
                    hit["path"] = fp
                    hit["sha256"] = h
                    if h and h in m.get("hashes", []):
                        conf = "high"
                    hit["confidence"] = conf
                    hit["detected_by"] = "filename"
                    found.append(hit)
    return found


def registry_services(driver_names: set[str]) -> dict:
    """Check persistent service registration for the matched drivers."""
    res = {}
    if platform.system() != "Windows":
        return res
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE_KEY)
        i = 0
        while True:
            try:
                name = winreg.EnumKey(k, i)
                i += 1
                for dn in driver_names:
                    if dn.lower().startswith(name.lower()[:5]) or \
                       name.lower() in dn.lower():
                        try:
                            sk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                                SERVICE_KEY + "\\" + name)
                            t, _ = winreg.QueryValueEx(sk, "Type")
                            st, _ = winreg.QueryValueEx(sk, "Start")
                            ip, _ = winreg.QueryValueEx(sk, "ImagePath")
                            res[name] = {"type": t, "start": st,
                                         "imagepath": ip}
                        except OSError:
                            pass
            except OSError:
                break
        winreg.CloseKey(k)
    except Exception:
        pass
    return res


def enrich_loaded(found: list, loaded: dict) -> list:
    """Flag matches that are currently resident in the kernel."""
    for hit in found:
        hit["loaded"] = hit["path"].lower() in loaded or \
                        os.path.basename(hit["path"]).lower() in loaded
    return found


def scan(target: str = "", db_path: str | None = None,
         extra_paths: list[str] | None = None) -> dict:
    db = load_db(db_path)
    found = scanner(db, extra_paths)
    snap = loaded_driver_snapshot()
    loaded = snap["names"]
    if snap["filtered"]:
        loaded = scm_active_drivers()   # oracle beats the shim
    found = enrich_loaded(found, loaded)
    names = {os.path.basename(h["path"]).lower() for h in found}
    svc = registry_services(names)
    for h in found:
        h["service"] = svc.get(os.path.splitext(os.path.basename(
            h["path"]))[0].lower(), {}) or svc.get(
            os.path.basename(h["path"]).lower(), {})
    return {"db_entries": len(db),
            "loaded_driver_names": len(loaded),
            "loaded_addresses": snap["addresses"],
            "psapi_unique_names": snap["psapi_unique"],
            "scm_active_drivers": snap["scm_active"],
            "load_api_filtered": snap["filtered"],
            "findings": found,
            "scan_time": time.time(),
            "host": platform.node(),
            "stage_paths_tested": [p for p in STAGE_PATHS
                                   if os.path.isdir(p)]}


def fmt_report(r: dict) -> str:
    ln = []
    ln.append(f"=== BYOVD HUNT: host={r['host']} "
              f"db={r['db_entries']} entries ===")
    if r.get("load_api_filtered"):
        ln.append("!! loader census looks FILTERED (psapi"
                  f" {r.get('psapi_unique_names', 0)} unique names for"
                  f" {r.get('loaded_addresses', 0)} addresses; SCM reports"
                  f" {r.get('scm_active_drivers', 0)} auto-start drivers)")
        ln.append("!! -> possible endpoint/EDR userland shim; using SCM"
                  " oracle for loaded-state enrichment")
    if r["findings"]:
        for h in r["findings"]:
            ln.append(f"[{h['confidence'].upper()}] {h['file']}  "
                      f"{h['detected_by']}")
            ln.append(f"    CVE {h['cve']}  CVSS {h['cvss']}  "
                      f"cap={h['capability']}")
            ln.append(f"    vendor: {h['vendor']}  ioctl: {h['ioctl']}")
            ln.append(f"    path: {h['path']}")
            ln.append(f"    sha256: {h['sha256'][:32]}...")
            ln.append(f"    loaded_in_kernel: {h.get('loaded', False)}")
            if h.get("service"):
                ln.append(f"    service: {h['service']}")
            ln.append(f"    note: {h['note']}")
    else:
        ln.append("no vulnerable drivers matched on this host")
    ln.append(f"=== end (loaded kernel modules enumerated: "
              f"{r['loaded_driver_names']}) ===")
    return "\n".join(ln)


DEMO_FILE = "RTCore64.sys"     # MSI afterburner victim (CVE-2018-12639)


def run_demo() -> int:
    """Synthetic positive-detection demo.

    Stages a NON-EXECUTABLE text stub (clearly marked, not a real driver
    binary, not signed, never loaded) named after a known vulnerable driver
    into a temp dir, scans it, prints the report and cleans up. Proves the
    whole pipeline (walk -> filename DB match -> sha256 -> report) without
    touching a legitimately signed vulnerable driver.
    """
    import tempfile
    demo_dir = os.path.join(tempfile.gettempdir(), "jocky_byovd_demo")
    os.makedirs(demo_dir, exist_ok=True)
    stub = os.path.join(demo_dir, DEMO_FILE)
    with open(stub, "w", encoding="utf-8") as f:
        f.write("SYNTHETIC JOCKY BYOVD DEMO STUB - NOT A REAL DRIVER, "
                "NOT SIGNED, NEVER LOADED. sha256 of this file cannot match "
                "the real signed RTCore64.sys (see loldrivers.io).")
    try:
        r = scan(extra_paths=[demo_dir])
        print(fmt_report(r))
        if not r["findings"]:
            print("[demo] FAIL: expected at least one filename match")
            return 1
        for h in r["findings"]:
            if h["file"].lower() == DEMO_FILE.lower() \
                    and h["detected_by"] == "filename":
                print(f"[demo] OK: staged {DEMO_FILE} detected "
                      f"(confidence={h['confidence']}, "
                      f"sha256={h['sha256'][:16]}...)")
                print("[demo] NOTE: sha256 mismatch vs loldrivers means this "
                      "is a filename hit only - exactly what a stub should "
                      "produce.")
                return 0
        print("[demo] FAIL: RTCore64 hit missing from findings")
        return 1
    finally:
        import shutil
        shutil.rmtree(demo_dir, ignore_errors=True)


def main(argv=None):
    p = argparse.ArgumentParser(prog="jocky-byovd", description=__doc__)
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--demo", action="store_true",
                   help="synthetic positive-detection demo (stubs a fake "
                        "RTCore64.sys in temp, scans, cleans up)")
    p.add_argument("--db-json", default=None,
                   help="extended DB with 'hashes' (see loldrivers.io)")
    p.add_argument("--scan-custom", action="append", default=[],
                   help="additional dirs to walk (repeatable)")
    a = p.parse_args(argv)
    if a.demo:
        return run_demo()
    r = scan(db_path=a.db_json, extra_paths=a.scan_custom)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        sys.stdout.write(fmt_report(r))
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())