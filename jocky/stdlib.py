"""JOCKY native function library (the forensic-analysis workhorse).

Every native has the signature  fn(vm, args) -> value  and returns plain
Python values (str/int/bool/None/list/dict) that the VM can push onto the
operand stack. Everything is dependency-free and works on both Windows
and Ubuntu/Linux:
  - process enumeration:   ctypes Toolhelp32 snapshot (Windows)
                            /proc parsing (Linux)
  - network connections:   netstat -ano (Windows) / ss or /proc/net (Linux)
  - file & hash primitives, sysinfo, env, small shell helper.

`log` writes to the VM's configured output stream.
"""

from __future__ import annotations

import hashlib
import os
import platform
import socket
import struct
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# basics
# ---------------------------------------------------------------------------


def _log(vm, args):
    vm.out.write(" ".join(map(str, args)) + "\n")
    vm.out.flush()
    return None


def _len(vm, args):
    return len(args[0])


def _type(vm, args):
    v = args[0]
    if v is None:
        return "none"
    return type(v).__name__


def _str(vm, args):
    return str(args[0])


def _int(vm, args):
    try:
        return int(args[0])
    except (TypeError, ValueError):
        return 0


def _join(vm, args):
    sep, items = args[0], args[1]
    return sep.join(str(x) for x in items)


def _split(vm, args):
    return args[0].split(args[1])


def _upper(vm, args):
    return str(args[0]).upper()


def _lower(vm, args):
    return str(args[0]).lower()


def _contains(vm, args):
    return args[1] in args[0]


def _get(vm, args):
    """get(dict, key [, default])"""
    d, key = args[0], args[1]
    default = args[2] if len(args) > 2 else None
    if isinstance(d, dict):
        return d.get(key, default)
    return default


def _keys(vm, args):
    if isinstance(args[0], dict):
        return list(args[0].keys())
    return []


def _now(vm, args):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _hostname(vm, args):
    return socket.gethostname()


def _cwd(vm, args):
    return os.getcwd()


def _env(vm, args):
    return os.environ.get(str(args[0]), "")


def _sysinfo(vm, args):
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def _sleep(vm, args):
    time.sleep(float(args[0]) / 1000.0)
    return None


# ---------------------------------------------------------------------------
# files & hashes
# ---------------------------------------------------------------------------


def _listdir(vm, args):
    path = str(args[0])
    try:
        return sorted(os.listdir(path))
    except OSError as e:
        return [f"<error: {e}>"]


def _fstat(vm, args):
    path = str(args[0])
    try:
        st = os.stat(path)
        return {
            "path": path,
            "size": st.st_size,
            "mtime": st.st_mtime,
            "ctime": getattr(st, "st_ctime", 0),
            "mode": oct(st.st_mode),
        }
    except OSError as e:
        return {"path": path, "error": str(e)}


def _readfile(vm, args):
    """readfile(path, limit=65536) -> str (latin-1 so any bytes survive)."""
    path = str(args[0])
    limit = int(args[1]) if len(args) > 1 else 65536
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("latin-1")
    except OSError as e:
        return f"<error: {e}>"


def _sha256_file(vm, args):
    path = str(args[0])
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        return f"<error: {e}>"


def _hexdump(vm, args):
    data = str(args[0]).encode("latin-1")[:64]
    return " ".join(f"{b:02x}" for b in data)


# ---------------------------------------------------------------------------
# process enumeration
# ---------------------------------------------------------------------------

def _procs(vm, args):
    """Return a list of {pid, name, ppid?, exe?} for running processes."""
    if sys.platform.startswith("win"):
        try:
            return _procs_windows_ctypes()
        except Exception:
            return _procs_windows_tasklist()
    return _procs_linux_proc()


def _procs_windows_ctypes():
    import ctypes
    from ctypes import wintypes

    TH32CS_SNAPPROCESS = 0x00000002
    MAX_PATH = 260

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * MAX_PATH),
        ]

    kernel32 = ctypes.windll.kernel32
    h = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h == -1:
        raise ctypes.WinError()
    result = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(h, ctypes.byref(entry))
        while ok:
            result.append({
                "pid": entry.th32ProcessID,
                "ppid": entry.th32ParentProcessID,
                "threads": entry.cntThreads,
                "name": entry.szExeFile,
            })
            ok = kernel32.Process32NextW(h, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(h)
    return result


def _procs_windows_tasklist():
    out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True, timeout=30).stdout
    result = []
    for line in out.splitlines():
        parts = line.strip().strip('"').split('","')
        if len(parts) >= 5:
            result.append({
                "name": parts[0].strip('"'),
                "pid": int(parts[1].strip('"') or 0),
                "session": parts[2].strip('"'),
                "mem_kb": parts[4].strip('"'),
            })
    return result


def _procs_linux_proc(_root="/proc"):
    """Parse /proc/<pid>/stat (and cmdline) for a full process census.

    WARNING: the comm field is wrapped in parens and may itself contain
    spaces (weird process names), so a naive str.split() shifts every later
    field by one and makes int(state-letter) explode -> empty census.
    Robust parse: cut everything after the LAST ')' -- kernel stat lines
    have no other parens -- then the tail is [state, ppid, ...].
    """
    result = []
    for pid_dir in os.listdir(_root):
        if not pid_dir.isdigit():
            continue
        try:
            with open(os.path.join(_root, pid_dir, "stat")) as f:
                raw = f.read()
            end = raw.rfind(")")
            if end < 0:
                continue
            head, tail = raw[:end], raw[end + 1:].split()
            name = head.split("(", 1)[1].strip() if "(" in head else ""
            ppid = int(tail[1]) if len(tail) >= 2 else 0
            cmdline = ""
            try:
                with open(os.path.join(_root, pid_dir, "cmdline"), "rb") as f:
                    cmdline = (f.read().replace(b"\0", b" ")
                               .decode("utf-8", "replace").strip())
            except OSError:
                pass
            exe = ""
            try:
                exe = os.readlink(os.path.join(_root, pid_dir, "exe"))
            except OSError:
                pass
            result.append({"pid": int(pid_dir), "ppid": ppid, "name": name,
                           "exe": exe, "cmdline": cmdline})
        except (OSError, ValueError, IndexError):
            continue
    return result


# ---------------------------------------------------------------------------
# network connections
# ---------------------------------------------------------------------------

def _netconns(vm, args):
    """Return a list of {proto, local, remote, state, pid} connections."""
    if sys.platform.startswith("win"):
        return _netconns_windows()
    return _netconns_linux()


def _netconns_windows():
    """Connection census without spawning netstat.exe (EDR-visible child).

    Primary path: iphlpapi GetExtendedTcpTable/GetExtendedUdpTable via
    ctypes -- the same data netstat reads, but through plain in-process
    API calls. Falls back to the legacy netstat parser only if the API
    path fails (e.g. stripped-down hosts).
    """
    try:
        return _netconns_windows_ctypes()
    except Exception:
        return _netconns_windows_netstat()


def _netconns_windows_ctypes():
    import ctypes
    from ctypes import wintypes

    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    AF_INET, AF_INET6 = 2, 23
    TCP_TABLE_OWNER_PID_ALL = 5
    UDP_TABLE_OWNER_PID = 1

    class TCPROW(ctypes.Structure):
        _fields_ = [("state", wintypes.DWORD), ("local_addr", wintypes.DWORD),
                    ("local_port", wintypes.DWORD), ("remote_addr", wintypes.DWORD),
                    ("remote_port", wintypes.DWORD), ("pid", wintypes.DWORD)]

    class TCP6ROW(ctypes.Structure):
        _fields_ = [("local_addr", ctypes.c_ubyte * 16),
                    ("local_scope", wintypes.DWORD), ("local_port", wintypes.DWORD),
                    ("remote_addr", ctypes.c_ubyte * 16),
                    ("remote_scope", wintypes.DWORD), ("remote_port", wintypes.DWORD),
                    ("state", wintypes.DWORD), ("pid", wintypes.DWORD)]

    class UDPROW(ctypes.Structure):
        _fields_ = [("local_addr", wintypes.DWORD),
                    ("local_port", wintypes.DWORD), ("pid", wintypes.DWORD)]

    class UDP6ROW(ctypes.Structure):
        _fields_ = [("local_addr", ctypes.c_ubyte * 16),
                    ("local_scope", wintypes.DWORD), ("local_port", wintypes.DWORD),
                    ("pid", wintypes.DWORD)]

    mib_states = {1: "CLOSED", 2: "LISTENING", 3: "SYN_SENT", 4: "SYN_RECV",
                  5: "ESTABLISHED", 6: "FIN_WAIT1", 7: "FIN_WAIT2",
                  8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
                  11: "TIME_WAIT", 12: "DELETE_TCB"}

    def _rows(fn, af, table_class, row_struct):
        size = wintypes.DWORD(0)
        fn(None, ctypes.byref(size), False, af, table_class, 0)
        buf = ctypes.create_string_buffer(size.value)
        rc = fn(buf, ctypes.byref(size), False, af, table_class, 0)
        if rc != 0:
            raise ctypes.WinError(rc)
        n = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0]
        return (row_struct * n).from_buffer(buf, ctypes.sizeof(wintypes.DWORD))

    def _v4(dw):
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", dw))

    def _v6(raw16):
        return socket.inet_ntop(socket.AF_INET6, bytes(raw16))

    def _port(dw):  # network byte order in the low word
        return ((dw & 0xFF) << 8) | ((dw >> 8) & 0xFF)

    get_tcp = iphlpapi.GetExtendedTcpTable
    get_udp = iphlpapi.GetExtendedUdpTable
    result = []
    for r in _rows(get_tcp, AF_INET, TCP_TABLE_OWNER_PID_ALL, TCPROW):
        result.append({"proto": "TCP",
                       "local": f"{_v4(r.local_addr)}:{_port(r.local_port)}",
                       "remote": f"{_v4(r.remote_addr)}:{_port(r.remote_port)}",
                       "state": mib_states.get(r.state, str(r.state)),
                       "pid": r.pid})
    for r in _rows(get_tcp, AF_INET6, TCP_TABLE_OWNER_PID_ALL, TCP6ROW):
        result.append({"proto": "TCP6",
                       "local": f"[{_v6(r.local_addr)}]:{_port(r.local_port)}",
                       "remote": f"[{_v6(r.remote_addr)}]:{_port(r.remote_port)}",
                       "state": mib_states.get(r.state, str(r.state)),
                       "pid": r.pid})
    for r in _rows(get_udp, AF_INET, UDP_TABLE_OWNER_PID, UDPROW):
        result.append({"proto": "UDP",
                       "local": f"{_v4(r.local_addr)}:{_port(r.local_port)}",
                       "remote": "*:*", "state": "", "pid": r.pid})
    for r in _rows(get_udp, AF_INET6, UDP_TABLE_OWNER_PID, UDP6ROW):
        result.append({"proto": "UDP6",
                       "local": f"[{_v6(r.local_addr)}]:{_port(r.local_port)}",
                       "remote": "*:*", "state": "", "pid": r.pid})
    return result


def _netconns_windows_netstat():
    out = subprocess.run(["netstat", "-ano"], capture_output=True,
                         text=True, timeout=30).stdout
    result = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[0] not in ("TCP", "TCP6", "UDP", "UDP6"):
            continue
        proto = parts[0]
        local, remote = parts[1], parts[2] if len(parts) > 2 else "*:*"
        state = ""
        pid = ""
        if proto.startswith("TCP"):
            if len(parts) >= 5:
                state = parts[3]
                pid = parts[4]
        else:
            if len(parts) >= 4:
                pid = parts[3]
        result.append({"proto": proto, "local": local, "remote": remote,
                       "state": state, "pid": pid})
    return result


def _netconns_linux():
    # /proc parsing is the primary path: read-only, no child processes.
    try:
        return _netconns_linux_proc()
    except OSError:
        return _netconns_linux_ss()


def _proc_socket_inode_map(root="/proc"):
    """Map socket inode -> owning pid by walking /proc/<pid>/fd (read-only).

    Gives the /proc-based census the per-connection pid that only `ss -p`
    (a subprocess) could provide before.
    """
    inode_to_pid = {}
    for pid_dir in os.listdir(root):
        if not pid_dir.isdigit():
            continue
        fd_dir = os.path.join(root, pid_dir, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                link = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if link.startswith("socket:[") and link.endswith("]"):
                inode_to_pid.setdefault(link[8:-1], int(pid_dir))
    return inode_to_pid


def _netconns_linux_proc():
    result = []
    inode_to_pid = _proc_socket_inode_map()
    for fname, proto in (("tcp", "TCP"), ("tcp6", "TCP6"),
                         ("udp", "UDP"), ("udp6", "UDP6")):
        try:
            with open(f"/proc/net/{fname}") as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    laddr = _hex_sockaddr(parts[1])
                    raddr = _hex_sockaddr(parts[2])
                    state = int(parts[3], 16)
                    inode = parts[9] if len(parts) > 9 else ""
                    pid = inode_to_pid.get(inode, "")
                    result.append({"proto": proto, "local": laddr,
                                   "remote": raddr,
                                   "state": _tcp_state(state), "pid": pid})
        except OSError:
            continue
    return result


def _netconns_linux_ss():
    out = subprocess.run(["ss", "-tunap"], capture_output=True,
                         text=True, timeout=15).stdout
    result = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        result.append({"proto": parts[0], "local": parts[3],
                       "remote": parts[4], "state": parts[1],
                       "pid": parts[5] if len(parts) > 5 else ""})
    return result


def _hex_sockaddr(hexstr: str) -> str:
    """'0100007F:1F90' -> '127.0.0.1:8080' (v4 or v6)."""
    addr_hex, port_hex = hexstr.rsplit(":", 1)
    port = int(port_hex, 16)
    try:
        raw = bytes.fromhex(addr_hex)
        if len(raw) == 4:
            return f"{socket.inet_ntop(socket.AF_INET, raw)}:{port}"
        if len(raw) == 16:
            return f"[{socket.inet_ntop(socket.AF_INET6, raw)}]:{port}"
    except (ValueError, OSError):
        pass
    return f"{addr_hex}:{port}"


def _tcp_state(n: int) -> str:
    states = {1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
              5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
              9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING"}
    return states.get(n, str(n))


# ---------------------------------------------------------------------------
# shell helper (bounded, for evidence collection only)
# ---------------------------------------------------------------------------

def _exec(vm, args):
    """exec(cmd, timeout_ms=10000) -> {rc, stdout, stderr} (bounded)."""
    cmd = str(args[0])
    timeout = float(args[1]) / 1000.0 if len(args) > 1 else 10.0
    cap = 200_000
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout)
        return {"rc": p.returncode,
                "stdout": p.stdout[:cap],
                "stderr": p.stderr[:cap]}
    except subprocess.TimeoutExpired:
        return {"rc": -1, "stdout": "", "stderr": "timeout"}
    except OSError as e:
        return {"rc": -1, "stdout": "", "stderr": str(e)}


# ---------------------------------------------------------------------------
# persistence sweep / process-tree anomalies / arp / dns  (read-only triage)
# ---------------------------------------------------------------------------

# Tokens that make an autostart entry worth a second look. Scored 1-3.
_SUS_PATH_TOKENS = ("\\temp\\", "/tmp/", "\\appdata\\", "\\users\\public\\",
                    "\\downloads\\", "\\programdata\\")
_SUS_INTERPRETERS = ("mshta", "wscript", "cscript", "rundll32", "regsvr32",
                     "msbuild", "installutil", "bginfo")
# Matched as whole whitespace tokens (substring "-enc" would false-positive
# on things like "ms-encodedlaunch:").
_SUS_FLAG_TOKENS = ("-enc", "-encodedcommand", "-nop", "-noprofile",
                    "iex", "invoke-expression", "downloadstring", "scrobj")
_SUS_FLAG_SUBSTR = ("javascript:", "|bash", "| sh", "curl ", "wget ")


def _suspect_score(cmdline: str):
    """Score an autostart command line: (0-3, why)."""
    low = cmdline.lower()
    score, why = 0, ""
    for tok in _SUS_PATH_TOKENS:
        if tok in low:
            score, why = 2, f"user-writable path ({tok.strip(chr(92))})"
            break
    for interp in _SUS_INTERPRETERS:
        if interp in low:
            score = max(score, 2)
            why = why or f"LOLBin interpreter ({interp})"
    tokens = set(low.replace(",", " ").replace("(", " ").split())
    for flag in _SUS_FLAG_TOKENS:
        if flag in tokens:
            return 3, f"obfuscated/dl-exec flag ({flag})"
    for flag in _SUS_FLAG_SUBSTR:
        if flag in low:
            return 3, f"obfuscated/dl-exec flag ({flag.strip()})"
    return score, why


def _persistence(vm, args):
    """persistence() -> list of {mechanism, name, detail, score, why}.

    Read-only sweep of common autostart locations:
    Windows: Run/RunOnce keys, auto-start services, Startup folders,
             scheduled-task definitions (System32\\Tasks XML).
    Linux:   cron files/dirs, systemd units + wants, rc.local, XDG autostart.
    """
    result = []
    if sys.platform.startswith("win"):
        result += _persistence_windows()
    else:
        result += _persistence_linux()
    return sorted(result, key=lambda e: -e["score"])


def _persistence_windows():
    import winreg
    out = []
    roots = [(winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")]
    subpaths = [r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"]
    for hive, hname in roots:
        for sub in subpaths:
            try:
                with winreg.OpenKey(hive, sub) as k:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        i += 1
                        cmd = str(value)
                        score, why = _suspect_score(cmd)
                        out.append({"mechanism": "run-key", "name": f"{hname}\\...\\{name}",
                                    "detail": cmd[:200], "score": score, "why": why})
            except OSError:
                continue
    # auto-start services (Start <= 2: boot/system/auto)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services") as sk:
            i = 0
            while True:
                try:
                    svc = winreg.EnumKey(sk, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(sk, svc) as k:
                        try:
                            start = winreg.QueryValueEx(k, "Start")[0]
                        except OSError:
                            continue
                        if start > 2:
                            continue
                        img = ""
                        try:
                            img = winreg.QueryValueEx(k, "ImagePath")[0]
                        except OSError:
                            pass
                        score, why = _suspect_score(img)
                        out.append({"mechanism": "service", "name": svc,
                                    "detail": img[:200], "score": score, "why": why})
                except OSError:
                    continue
    except OSError:
        pass
    # startup folders
    import os as _os
    for var, label in (("APPDATA", "user"), ("ProgramData", "common")):
        base = _os.environ.get(var)
        if not base:
            continue
        folder = _os.path.join(base, "Microsoft", "Windows", "Start Menu",
                               "Programs", "Startup")
        try:
            for name in _os.listdir(folder):
                if name.lower().endswith((".lnk", ".exe", ".bat", ".cmd",
                                          ".vbs", ".ps1", ".js")):
                    cmd = _os.path.join(folder, name)
                    score, why = _suspect_score(cmd)
                    out.append({"mechanism": "startup-folder", "name": name,
                                "detail": cmd[:200], "score": score, "why": why})
        except OSError:
            continue
    # scheduled tasks: raw XML definitions, no schtasks.exe subprocess
    out += _persistence_windows_tasks()
    return out


def _persistence_windows_tasks(root=None):
    import os as _os
    import xml.etree.ElementTree as ET
    if root is None:
        root = _os.path.join(_os.environ.get("SystemRoot", r"C:\Windows"),
                             "System32", "Tasks")
    out = []
    for dirpath, _dirnames, filenames in _os.walk(root):
        for fname in filenames:
            path = _os.path.join(dirpath, fname)
            try:
                tree = ET.parse(path)
            except (OSError, ET.ParseError):
                continue
            cmds = []
            for el in tree.iter():
                if el.tag.endswith("Command"):
                    cmds.append((el.text or "").strip())
            if not cmds:
                continue
            cmd = " ".join(c for c in cmds if c)
            rel = _os.path.relpath(path, root)
            score, why = _suspect_score(cmd)
            score = max(score, 1)  # task actions always worth listing
            out.append({"mechanism": "scheduled-task", "name": rel,
                        "detail": cmd[:200], "score": score,
                        "why": why or "task action"})
    return out


def _persistence_linux():
    import glob
    out = []
    candidates = []
    candidates += glob.glob("/etc/cron.d/*")
    candidates += glob.glob("/etc/cron.daily/*") + glob.glob("/etc/cron.hourly/*")
    candidates += glob.glob("/etc/cron.weekly/*") + glob.glob("/etc/cron.monthly/*")
    candidates += glob.glob("/var/spool/cron/crontabs/*") + glob.glob("/var/spool/cron/*")
    if os.path.isfile("/etc/crontab"):
        candidates.append("/etc/crontab")
    if os.path.isfile("/etc/rc.local"):
        candidates.append("/etc/rc.local")
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", errors="replace") as f:
                body = f.read(4096)
        except OSError:
            continue
        score, why = _suspect_score(body)
        out.append({"mechanism": "cron", "name": path, "detail": body[:200],
                    "score": score, "why": why})
    # systemd units
    for path in glob.glob("/etc/systemd/system/*.service") + \
            glob.glob("/etc/systemd/system/*.wants/*.service"):
        try:
            with open(path, "r", errors="replace") as f:
                body = f.read(4096)
        except OSError:
            continue
        exec_line = ""
        for line in body.splitlines():
            ls = line.strip()
            if ls.startswith("ExecStart="):
                exec_line = ls[len("ExecStart="):]
        score, why = _suspect_score(exec_line or body)
        out.append({"mechanism": "systemd", "name": path,
                    "detail": (exec_line or body)[:200], "score": score,
                    "why": why})
    # XDG autostart
    import os as _os
    for base in (_os.path.expanduser("~/.config/autostart"),
                 "/etc/xdg/autostart"):
        for path in glob.glob(_os.path.join(base, "*.desktop")):
            try:
                with open(path, "r", errors="replace") as f:
                    body = f.read(4096)
            except OSError:
                continue
            exec_line = ""
            for line in body.splitlines():
                if line.strip().startswith("Exec="):
                    exec_line = line.strip()[5:]
            score, why = _suspect_score(exec_line)
            out.append({"mechanism": "xdg-autostart", "name": path,
                        "detail": exec_line[:200], "score": score, "why": why})
    return out


# parent -> child name pairs that are classic intrusion artefacts
_SUS_PROC_PAIRS = (
    ("winword", "cmd"), ("excel", "cmd"), ("powerpnt", "cmd"),
    ("outlook", "cmd"), ("winword", "powershell"), ("excel", "powershell"),
    ("outlook", "powershell"), ("winword", "wscript"), ("excel", "cscript"),
    ("msedge", "powershell"), ("chrome", "powershell"),
    ("firefox", "powershell"),
)


def _proctree(vm, args):
    """proctree() -> census with parent/child view + anomaly notes."""
    ps = _procs(vm, args)
    by_pid = {}
    for p in ps:
        by_pid.setdefault(int(p.get("pid", 0)), p)
    out = []
    for p in ps:
        pid = int(p.get("pid", 0))
        ppid = int(p.get("ppid", 0))
        name = str(p.get("name", "")).lower()
        parent = by_pid.get(ppid)
        anomaly, note = False, ""
        if parent is None and ppid not in (0, 1, 2, 4):
            anomaly, note = True, f"parent {ppid} not in census (reused PPID or exited)"
        if parent is not None:
            pn = str(parent.get("name", "")).lower()
            for a, b in _SUS_PROC_PAIRS:
                if pn.startswith(a) and name.startswith(b):
                    anomaly = True
                    note = f"{pn} -> {name}: classic intrusion pattern"
                    break
        out.append({"pid": pid, "ppid": ppid, "name": p.get("name", ""),
                    "anomaly": anomaly, "note": note})
    return out


def _arp(vm, args):
    """arp() -> list of {ip, mac, iface, type} (read-only ARP table)."""
    if sys.platform.startswith("win"):
        try:
            return _arp_windows()
        except Exception:
            return []
    return _arp_linux()


def _arp_windows():
    import ctypes
    from ctypes import wintypes
    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

    class IPNETROW(ctypes.Structure):
        _fields_ = [("index", wintypes.DWORD), ("phys_len", wintypes.DWORD),
                    ("phys", ctypes.c_ubyte * 8), ("addr", wintypes.DWORD),
                    ("type", wintypes.DWORD)]

    size = wintypes.DWORD(0)
    iphlpapi.GetIpNetTable(None, ctypes.byref(size), False)
    buf = ctypes.create_string_buffer(size.value)
    rc = iphlpapi.GetIpNetTable(buf, ctypes.byref(size), False)
    if rc != 0:
        raise ctypes.WinError(rc)
    n = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0]
    rows = (IPNETROW * n).from_buffer(buf, ctypes.sizeof(wintypes.DWORD))
    kinds = {1: "other", 2: "invalid", 3: "dynamic", 4: "static"}
    out = []
    for r in rows:
        mac = ":".join(f"{b:02x}" for b in r.phys[:min(r.phys_len, 8)])
        out.append({
            "ip": socket.inet_ntop(socket.AF_INET, struct.pack("<I", r.addr)),
            "mac": mac, "iface": str(r.index),
            "type": kinds.get(r.type, str(r.type))})
    return out


def _arp_linux():
    out = []
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    out.append({"ip": parts[0], "mac": parts[3],
                                "iface": parts[5], "type": "0x" + parts[2]})
    except OSError:
        pass
    return out


def _dnscache(vm, args):
    """dnscache() -> list of {name, type} cached DNS entries (read-only).

    Windows: DnsGetCacheDataTable (dnsapi.dll) resolver cache walk.
    Linux:   no kernel-standard cache; falls back to /etc/hosts entries.
    """
    if sys.platform.startswith("win"):
        try:
            return _dnscache_windows()
        except Exception:
            return []
    return _dnscache_linux()


def _dnscache_windows():
    import ctypes
    dnsapi = ctypes.WinDLL("dnsapi", use_last_error=True)

    class CACHE_ENTRY(ctypes.Structure):
        _fields_ = [("pNext", ctypes.c_void_p),
                    ("pszName", ctypes.c_wchar_p),
                    ("wType", ctypes.c_ushort),
                    ("wDataLength", ctypes.c_ushort),
                    ("dwFlags", ctypes.c_ulong)]

    head = CACHE_ENTRY()
    if not dnsapi.DnsGetCacheDataTable(ctypes.byref(head)):
        return []
    types = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
    out, node, hops = [], head, 0
    while node is not None and hops < 4096:
        hops += 1
        if node.pszName:
            out.append({"name": node.pszName,
                        "type": types.get(node.wType, str(node.wType))})
        ptr = node.pNext
        node = ctypes.cast(ptr, ctypes.POINTER(CACHE_ENTRY)).contents if ptr else None
    return out


def _dnscache_linux():
    out = []
    try:
        with open("/etc/hosts") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    out.append({"name": parts[1], "type": f"hosts->{parts[0]}"})
    except OSError:
        pass
    return out

# ---------------------------------------------------------------------------
# registry of natives available to JOCKY scripts
# (order is load-bearing: NAT indices are baked into compiled bytecode;
#  new natives must only ever be APPENDED here)
# ---------------------------------------------------------------------------

NATIVES = [
    ("log", _log),
    ("len", _len),
    ("type", _type),
    ("str", _str),
    ("int", _int),
    ("join", _join),
    ("split", _split),
    ("upper", _upper),
    ("lower", _lower),
    ("contains", _contains),
    ("get", _get),
    ("keys", _keys),
    ("now", _now),
    ("hostname", _hostname),
    ("cwd", _cwd),
    ("env", _env),
    ("sysinfo", _sysinfo),
    ("sleep", _sleep),
    ("listdir", _listdir),
    ("fstat", _fstat),
    ("readfile", _readfile),
    ("sha256", _sha256_file),
    ("hexdump", _hexdump),
    ("procs", _procs),
    ("netconns", _netconns),
    ("exec", _exec),
    ("persistence", _persistence),
    ("proctree", _proctree),
    ("arp", _arp),
    ("dnscache", _dnscache),
]

NATIVE_NAMES = [name for name, _ in NATIVES]
NATIVE_FUNCS = [fn for _, fn in NATIVES]