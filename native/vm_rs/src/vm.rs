//! Stack VM for JY_IMG01 bytecode — a byte-for-byte behavioural port of
//! jocky/vm.py (execution core) plus the forensic native library from
//! jocky/stdlib.py. Natives are implemented with OS APIs directly
//! (Toolhelp32 / iphlpapi / dnsapi / advapi32 on Windows, /proc on Linux);
//! no child processes are ever spawned.

use crate::bytecode::{Image, OP_NAMES, OP_WIDTHS};
use crate::sha256::Sha256;
use crate::value::{bin_arith, dict_find_val, float_coerce, int_native_value, neg,
                   py_str, seq_contains, value_cmp, value_eq, Value};
use std::collections::HashMap;
use std::io::Write;
#[cfg(windows)]
use std::os::raw::c_void;

const MAX_STEPS: u64 = 20_000_000;

pub struct Vm {
    pub image: Image,
    stack: Vec<Value>,
    frames: Vec<Frame>,
    pc: usize,
    max_steps: u64,
}

struct Frame {
    locals: HashMap<String, Value>,
    iters: HashMap<String, IterState>,
    ret_addr: Option<usize>,
}

struct IterState {
    items: Vec<Value>,
    pos: usize,
}

impl IterState {
    fn next(&mut self) -> Option<Value> {
        if self.pos < self.items.len() {
            let v = self.items[self.pos].clone();
            self.pos += 1;
            Some(v)
        } else {
            None
        }
    }
}

type NatResult = Result<Value, String>;
type Native = fn(&mut Vm, Vec<Value>) -> NatResult;

/// Native registry — ORDER MUST MATCH jocky/stdlib.py NATIVES exactly
/// (indices are baked into compiled bytecode).
pub const NATIVE_NAMES: [&str; 30] = [
    "log", "len", "type", "str", "int", "join", "split", "upper", "lower",
    "contains", "get", "keys", "now", "hostname", "cwd", "env", "sysinfo",
    "sleep", "listdir", "fstat", "readfile", "sha256", "hexdump", "procs",
    "netconns", "exec", "persistence", "proctree", "arp", "dnscache",
];

const NATIVE_FUNCS: [Native; 30] = [
    n_log, n_len, n_type, n_str, n_int, n_join, n_split, n_upper, n_lower,
    n_contains, n_get, n_keys, n_now, n_hostname, n_cwd, n_env, n_sysinfo,
    n_sleep, n_listdir, n_fstat, n_readfile, n_sha256, n_hexdump, n_procs,
    n_netconns, n_exec, n_persistence, n_proctree, n_arp, n_dnscache,
];

impl Vm {
    pub fn new(image: Image) -> Self {
        Vm { image, stack: Vec::new(), frames: Vec::new(), pc: 0, max_steps: MAX_STEPS }
    }

    pub fn run(&mut self) -> Result<Value, String> {
        let entry = self.image.entry;
        if entry >= self.image.funcs.len() {
            return Err(format!("bad entry function index {entry}"));
        }
        let f = self.image.funcs[entry].clone();
        let mut locals = HashMap::new();
        for p in &f.params {
            locals.insert(p.clone(), Value::None);
        }
        self.frames = vec![Frame { locals, iters: HashMap::new(), ret_addr: None }];
        self.pc = f.addr;
        self.stack.clear();

        let mut steps: u64 = 0;
        loop {
            if steps >= self.max_steps {
                return Err("step limit exceeded (infinite loop?)".to_string());
            }
            steps += 1;
            if self.pc >= self.image.code.len() {
                return Err("program counter ran past end of code".to_string());
            }
            let enc = self.image.code[self.pc];
            let base = self.image.inv[enc as usize];
            if base >= OP_NAMES.len() {
                return Err(format!("invalid opcode {enc:#x} at {:#x}", self.pc));
            }
            let width = OP_WIDTHS[base];
            let operand: usize = if width > 0 {
                let mut v: usize = 0;
                for i in 0..width {
                    v |= (self.image.code[self.pc + 1 + i] as usize) << (8 * i);
                }
                v
            } else {
                0
            };
            let nxt = self.pc + 1 + width;
            let op = OP_NAMES[base];
            self.pc = nxt;

            match op {
                "NOP" => {}
                "PUSH" => {
                    let v = self
                        .image
                        .consts
                        .get(operand)
                        .cloned()
                        .ok_or("list index out of range")?;
                    self.stack.push(v);
                }
                "LOAD" => {
                    let name = self.const_str(operand)?;
                    let v = self
                        .frames
                        .last()
                        .unwrap()
                        .locals
                        .get(&name)
                        .cloned()
                        .unwrap_or(Value::None);
                    self.stack.push(v);
                }
                "STORE" => {
                    let name = self.const_str(operand)?;
                    let v = self.pop()?;
                    self.frames.last_mut().unwrap().locals.insert(name, v);
                }
                "POP" => {
                    self.pop()?;
                }
                "PUSHARG" => self.stack.push(Value::Mark),
                "JMP" => {
                    self.pc = operand;
                }
                "JZ" => {
                    if !self.pop()?.truthy() {
                        self.pc = operand;
                    }
                }
                "JNZ" => {
                    if self.pop()?.truthy() {
                        self.pc = operand;
                    }
                }
                "CALL" => {
                    let f = self.image.funcs.get(operand).cloned().ok_or_else(|| {
                        format!("bad function index {operand}")
                    })?;
                    if self.stack.len() < f.nparams + 1 {
                        let got = self.stack.len().saturating_sub(1);
                        return Err(format!(
                            "{}() takes {} args, got {}",
                            f.name, f.nparams, got
                        ));
                    }
                    let args: Vec<Value> = self.stack.split_off(self.stack.len() - f.nparams);
                    match self.stack.last() {
                        Some(Value::Mark) => {
                            self.stack.pop();
                        }
                        _ => return Err("CALL without PUSHARG marker".to_string()),
                    }
                    let mut args = args;
                    args.reverse();
                    let mut locals = HashMap::new();
                    for (p, a) in f.params.iter().zip(args.into_iter()) {
                        locals.insert(p.clone(), a);
                    }
                    self.frames.push(Frame {
                        locals,
                        iters: HashMap::new(),
                        ret_addr: Some(nxt),
                    });
                    self.pc = f.addr;
                }
                "NAT" => {
                    let mut args = Vec::new();
                    loop {
                        match self.stack.last() {
                            Some(Value::Mark) => break,
                            Some(_) => args.push(self.stack.pop().unwrap()),
                            None => return Err("NAT without PUSHARG marker".to_string()),
                        }
                    }
                    self.stack.pop(); // consume marker
                    args.reverse();
                    if operand >= NATIVE_FUNCS.len() {
                        return Err(format!("bad native index {operand}"));
                    }
                    let res = NATIVE_FUNCS[operand](self, args)?;
                    self.stack.push(res);
                }
                "RET" => {
                    let result = if self.stack.is_empty() {
                        Value::None
                    } else {
                        self.stack.pop().unwrap()
                    };
                    if self.frames.len() == 1 {
                        return Ok(result);
                    }
                    let fr = self.frames.pop().unwrap();
                    self.pc = fr.ret_addr.unwrap_or(0);
                    self.stack.push(result);
                }
                "ITERMK" => {
                    let name = self.const_str(operand)?;
                    let it = self.pop()?;
                    let items: Vec<Value> = match it {
                        Value::List(items) => items,
                        Value::Str(s) => {
                            s.chars().map(|c| Value::Str(c.to_string())).collect()
                        }
                        Value::Dict(pairs) => {
                            pairs.into_iter().map(|(k, _)| k).collect()
                        }
                        other => {
                            return Err(format!(
                                "'{}' object is not iterable",
                                other.type_name()
                            ))
                        }
                    };
                    self.frames
                        .last_mut()
                        .unwrap()
                        .iters
                        .insert(name, IterState { items, pos: 0 });
                }
                "ITERNX" => {
                    let name = self.const_str(operand)?;
                    let frame = self.frames.last_mut().unwrap();
                    match frame.iters.get_mut(&name) {
                        Some(it) => {
                            let v = it.next().unwrap_or(Value::None);
                            self.stack.push(v);
                        }
                        None => {
                            return Err(format!("iterator '{}' not initialized", name))
                        }
                    }
                }
                "ADD" | "SUB" | "MUL" | "DIV" | "MOD" => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    let v = bin_arith(op, &a, &b)?;
                    self.stack.push(v);
                }
                "NEG" => {
                    let v = self.pop()?;
                    self.stack.push(neg(&v));
                }
                "EQ" | "NE" => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.stack.push(Value::Bool(value_eq(&a, &b) == (op == "EQ")));
                }
                "LT" | "GT" | "LE" | "GE" => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    let sym = match op {
                        "LT" => "<",
                        "GT" => ">",
                        "LE" => "<=",
                        _ => ">=",
                    };
                    match value_cmp(&a, &b, sym)? {
                        Some(ord) => {
                            use std::cmp::Ordering::*;
                            let truth = match (op, ord) {
                                ("LT", Less) | ("GT", Greater) => true,
                                ("LE", Less) | ("LE", Equal) => true,
                                ("GE", Greater) | ("GE", Equal) => true,
                                _ => false,
                            };
                            self.stack.push(Value::Bool(truth));
                        }
                        None => self.stack.push(Value::Bool(false)), // NaN comparisons
                    }
                }
                "AND" => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.stack.push(if a.truthy() { b } else { a });
                }
                "OR" => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.stack.push(if a.truthy() { a } else { b });
                }
                "NOT" => {
                    let a = self.pop()?;
                    self.stack.push(Value::Bool(!a.truthy()));
                }
                "HALT" => {
                    return Ok(self.stack.last().cloned().unwrap_or(Value::None));
                }
                other => return Err(format!("unimplemented opcode {other}")),
            }
        }
    }

    fn pop(&mut self) -> Result<Value, String> {
        self.stack.pop().ok_or_else(|| "operand stack underflow".to_string())
    }

    fn const_str(&self, idx: usize) -> Result<String, String> {
        match self.image.consts.get(idx) {
            Some(Value::Str(s)) => Ok(s.clone()),
            _ => Err("list index out of range".to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// helpers shared by natives
// ---------------------------------------------------------------------------

fn arg_str(args: &[Value], i: usize) -> String {
    py_str(&args[i])
}

fn dict_value(pairs: Vec<(&str, Value)>) -> Value {
    Value::Dict(pairs.into_iter().map(|(k, v)| (Value::Str(k.to_string()), v)).collect())
}

fn latin1_bytes(s: &str) -> Result<Vec<u8>, String> {
    s.chars()
        .map(|c| {
            if (c as u32) <= 0xFF {
                Ok(c as u8)
            } else {
                Err(format!(
                    "'latin-1' codec can't encode character '{}' (U+{:04X})",
                    c, c as u32
                ))
            }
        })
        .collect()
}

fn bytes_to_latin1(data: &[u8]) -> String {
    data.iter().map(|b| *b as char).collect()
}

// ---------------------------------------------------------------------------
// natives 0-11: basics
// ---------------------------------------------------------------------------

fn n_log(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    let line = args
        .iter()
        .map(py_str)
        .collect::<Vec<_>>()
        .join(" ");
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(line.as_bytes());
    // Python's sys.stdout is text mode: on Windows pipes/files "\n" becomes
    // CRLF. Byte-parity with the Python VM requires the same translation.
    #[cfg(windows)]
    let _ = lock.write_all(b"\r\n");
    #[cfg(not(windows))]
    let _ = lock.write_all(b"\n");
    let _ = lock.flush();
    Ok(Value::None)
}

fn n_len(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    let v = &args[0];
    let n = match v {
        Value::Str(s) => s.chars().count(),
        Value::List(items) => items.len(),
        Value::Dict(pairs) => pairs.len(),
        other => {
            return Err(format!(
                "object of type '{}' has no len()",
                other.type_name()
            ))
        }
    };
    Ok(Value::Int(n as i64))
}

fn n_type(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    Ok(Value::Str(args[0].type_name().to_string()))
}

fn n_str(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    Ok(Value::Str(py_str(&args[0])))
}

fn n_int(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    Ok(Value::Int(int_native_value(&args[0])))
}

fn n_join(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    let sep = match &args[0] {
        Value::Str(s) => s.clone(),
        other => {
            return Err(format!(
                "sequence item 0: expected str instance, {} found",
                other.type_name()
            ))
        }
    };
    match &args[1] {
        Value::List(items) => {
            let joined = items
                .iter()
                .map(py_str)
                .collect::<Vec<_>>()
                .join(&sep);
            Ok(Value::Str(joined))
        }
        other => Err(format!(
            "can only join an iterable, got '{}'",
            other.type_name()
        )),
    }
}

fn n_split(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    let s = arg_str(&args, 0);
    let sep = arg_str(&args, 1);
    if sep.is_empty() {
        return Err("empty separator".to_string());
    }
    Ok(Value::List(
        s.split(&sep).map(|p| Value::Str(p.to_string())).collect(),
    ))
}

fn n_upper(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    Ok(Value::Str(arg_str(&args, 0).to_uppercase()))
}

fn n_lower(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    Ok(Value::Str(arg_str(&args, 0).to_lowercase()))
}

fn n_contains(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    let b = seq_contains(&args[0], &args[1])?;
    Ok(Value::Bool(b))
}

fn n_get(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    let default = if args.len() > 2 {
        args[2].clone()
    } else {
        Value::None
    };
    match &args[0] {
        Value::Dict(pairs) => Ok(dict_find_val(pairs, &args[1]).unwrap_or(default)),
        _ => Ok(default),
    }
}

fn n_keys(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    match &args[0] {
        Value::Dict(pairs) => {
            Ok(Value::List(pairs.iter().map(|(k, _)| k.clone()).collect()))
        }
        _ => Ok(Value::List(vec![])),
    }
}

// ---------------------------------------------------------------------------
// natives 12-17: host context
// ---------------------------------------------------------------------------

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn n_now(_vm: &mut Vm, _args: Vec<Value>) -> NatResult {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?;
    let secs = now.as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    Ok(Value::Str(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )))
}

fn host_name() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOSTNAME")
            .ok()
            .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "localhost".to_string())
    }
}

fn n_hostname(_vm: &mut Vm, _args: Vec<Value>) -> NatResult {
    Ok(Value::Str(host_name()))
}

fn n_cwd(_vm: &mut Vm, _args: Vec<Value>) -> NatResult {
    let p = std::env::current_dir().map_err(|e| e.to_string())?;
    Ok(Value::Str(p.to_string_lossy().into_owned()))
}

fn n_env(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    let name = arg_str(&args, 0);
    Ok(Value::Str(std::env::var(&name).unwrap_or_default()))
}

fn n_sysinfo(_vm: &mut Vm, _args: Vec<Value>) -> NatResult {
    let os = if cfg!(windows) { "Windows" } else { "Linux" };
    let machine = if cfg!(target_arch = "x86_64") {
        if cfg!(windows) { "AMD64" } else { "x86_64" }
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else {
        "unknown"
    };
    let release = sys_release();
    let version = sys_version();
    Ok(dict_value(vec![
        ("hostname", Value::Str(host_name())),
        ("os", Value::Str(os.to_string())),
        ("release", Value::Str(release)),
        ("version", Value::Str(version)),
        ("machine", Value::Str(machine.to_string())),
        // Marks which engine produced the report -- a feature, not a bug:
        // the native VM stamps itself instead of pretending to be Python.
        ("python", Value::Str(format!("native-rust/jocky-rs {}", crate::VERSION))),
    ]))
}

#[allow(unused)]
fn sys_release() -> String {
    #[cfg(windows)]
    {
        winreg_read_string(
            win_hkey_local_machine(),
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "DisplayVersion",
        )
        .or_else(|| {
            winreg_read_string(
                win_hkey_local_machine(),
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "ReleaseId",
            )
        })
        .unwrap_or_else(|| "unknown".to_string())
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }
}

#[allow(unused)]
fn sys_version() -> String {
    #[cfg(windows)]
    {
        winreg_read_string(
            win_hkey_local_machine(),
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "CurrentBuildNumber",
        )
        .map(|b| format!("10.0.{b}"))
        .unwrap_or_else(|| "unknown".to_string())
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/proc/sys/kernel/version")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }
}

fn n_sleep(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    let ms = float_coerce(&args[0])?;
    std::thread::sleep(std::time::Duration::from_millis(ms as u64));
    Ok(Value::None)
}

// ---------------------------------------------------------------------------
// natives 18-22: files & hashes
// ---------------------------------------------------------------------------

fn n_listdir(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    let path = arg_str(&args, 0);
    match std::fs::read_dir(&path) {
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            Ok(Value::List(names.into_iter().map(Value::Str).collect()))
        }
        Err(e) => Ok(Value::List(vec![Value::Str(format!("<error: {e}>"))])),
    }
}

fn n_fstat(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    let path = arg_str(&args, 0);
    match std::fs::metadata(&path) {
        Ok(md) => {
            let secs = |t: std::io::Result<std::time::SystemTime>| -> f64 {
                t.ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0)
            };
            let mtime = secs(md.modified());
            let ctime = secs(md.created()).max(mtime);
            Ok(dict_value(vec![
                ("path", Value::Str(path)),
                ("size", Value::Int(md.len() as i64)),
                ("mtime", Value::Float(mtime)),
                ("ctime", Value::Float(ctime)),
                // std::fs exposes no POSIX mode bits (STATUS.md probe table);
                // a regular-file 0o100666 placeholder is used.
                ("mode", Value::Str("0o100666".to_string())),
            ]))
        }
        Err(e) => Ok(dict_value(vec![
            ("path", Value::Str(path)),
            ("error", Value::Str(e.to_string())),
        ])),
    }
}

fn n_readfile(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    let path = arg_str(&args, 0);
    let limit = if args.len() > 1 {
        int_native_value(&args[1]).max(0) as usize
    } else {
        65_536
    };
    match std::fs::read(&path) {
        Ok(data) => Ok(Value::Str(bytes_to_latin1(&data[..limit.min(data.len())]))),
        Err(e) => Ok(Value::Str(format!("<error: {e}>"))),
    }
}

fn n_sha256(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    let path = arg_str(&args, 0);
    match std::fs::File::open(&path) {
        Ok(mut f) => {
            use std::io::Read;
            let mut h = Sha256::new();
            let mut buf = vec![0u8; 1 << 20];
            loop {
                match f.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => h.update(&buf[..n]),
                    Err(e) => return Ok(Value::Str(format!("<error: {e}>"))),
                }
            }
            Ok(Value::Str(h.hexdigest()))
        }
        Err(e) => Ok(Value::Str(format!("<error: {e}>"))),
    }
}

fn n_hexdump(_vm: &mut Vm, args: Vec<Value>) -> NatResult {
    let data = latin1_bytes(&py_str(&args[0]))?;
    let data = &data[..data.len().min(64)];
    Ok(Value::Str(
        data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
    ))
}

// ---------------------------------------------------------------------------
// natives 23-24: process / connection census
// ---------------------------------------------------------------------------

fn n_procs(_vm: &mut Vm, _args: Vec<Value>) -> NatResult {
    procs_list()
}

fn n_netconns(_vm: &mut Vm, _args: Vec<Value>) -> NatResult {
    netconns_list()
}

fn n_exec(_vm: &mut Vm, _args: Vec<Value>) -> NatResult {
    // Deliberately not implemented in the native VM: the Python VM's `exec`
    // exists for advanced evidence collection, but the native build keeps a
    // strictly read-only surface (no child processes at all).
    Err("native 'exec' is not available in this native VM build (read-only surface)".to_string())
}

// ---------------------------------------------------------------------------
// native 27: proctree
// ---------------------------------------------------------------------------

const SUS_PROC_PAIRS: [(&str, &str); 11] = [
    ("winword", "cmd"), ("excel", "cmd"), ("powerpnt", "cmd"),
    ("outlook", "cmd"), ("winword", "powershell"), ("excel", "powershell"),
    ("outlook", "powershell"), ("winword", "wscript"), ("excel", "cscript"),
    ("msedge", "powershell"), ("chrome", "powershell"),
];

fn proctree_rows() -> NatResult {
    let ps = procs_list()?;
    let items: Vec<Value> = match ps {
        Value::List(items) => items,
        _ => return Err("procs returned non-list".to_string()),
    };
    let mut by_pid: HashMap<i64, Value> = HashMap::new();
    for p in &items {
        let pid = int_of(&dict_get(p, "pid"));
        by_pid.entry(pid).or_insert_with(|| p.clone());
    }
    let mut out = Vec::new();
    for p in &items {
        let pid = int_of(&dict_get(p, "pid"));
        let ppid = int_of(&dict_get(p, "ppid"));
        let name = py_str(&dict_get(p, "name")).to_lowercase();
        let mut anomaly = false;
        let mut note = String::new();
        match by_pid.get(&ppid) {
            None => {
                if ppid != 0 && ppid != 1 && ppid != 2 && ppid != 4 {
                    anomaly = true;
                    note = format!("parent {ppid} not in census (reused PPID or exited)");
                }
            }
            Some(parent) => {
                let pn = py_str(&dict_get(parent, "name")).to_lowercase();
                for (a, b) in SUS_PROC_PAIRS.iter() {
                    if pn.starts_with(a) && name.starts_with(b) {
                        anomaly = true;
                        note = format!("{pn} -> {name}: classic intrusion pattern");
                        break;
                    }
                }
            }
        }
        out.push(dict_value(vec![
            ("pid", Value::Int(pid)),
            ("ppid", Value::Int(ppid)),
            ("name", dict_get(p, "name")),
            ("anomaly", Value::Bool(anomaly)),
            ("note", Value::Str(note)),
        ]));
    }
    Ok(Value::List(out))
}

fn n_proctree(_vm: &mut Vm, _args: Vec<Value>) -> NatResult {
    proctree_rows()
}

fn dict_get(v: &Value, key: &str) -> Value {
    match v {
        Value::Dict(pairs) => {
            dict_find_val(pairs, &Value::Str(key.to_string())).unwrap_or(Value::None)
        }
        _ => Value::None,
    }
}

fn int_of(v: &Value) -> i64 {
    match v {
        Value::Int(i) => *i,
        Value::Bool(b) => *b as i64,
        Value::Float(f) => *f as i64,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// native 26: persistence sweep
// ---------------------------------------------------------------------------

const SUS_PATH_TOKENS: [&str; 6] = ["\\temp\\", "/tmp/", "\\appdata\\",
                                    "\\users\\public\\", "\\downloads\\",
                                    "\\programdata\\"];
const SUS_INTERPRETERS: [&str; 8] = ["mshta", "wscript", "cscript", "rundll32",
                                     "regsvr32", "msbuild", "installutil", "bginfo"];
const SUS_FLAG_TOKENS: [&str; 8] = ["-enc", "-encodedcommand", "-nop",
                                    "-noprofile", "iex", "invoke-expression",
                                    "downloadstring", "scrobj"];
const SUS_FLAG_SUBSTR: [&str; 5] = ["javascript:", "|bash", "| sh", "curl ", "wget "];

fn suspect_score(cmdline: &str) -> (i64, String) {
    let low = cmdline.to_lowercase();
    let mut score = 0i64;
    let mut why = String::new();
    for tok in SUS_PATH_TOKENS.iter() {
        if low.contains(tok) {
            score = 2;
            why = format!("user-writable path ({})", tok.trim_matches('\\'));
            break;
        }
    }
    for interp in SUS_INTERPRETERS.iter() {
        if low.contains(interp) {
            score = score.max(2);
            if why.is_empty() {
                why = format!("LOLBin interpreter ({interp})");
            }
        }
    }
    let tokens: std::collections::HashSet<String> = low
        .replace(',', " ")
        .replace('(', " ")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    for flag in SUS_FLAG_TOKENS.iter() {
        if tokens.contains(*flag) {
            return (3, format!("obfuscated/dl-exec flag ({flag})"));
        }
    }
    for flag in SUS_FLAG_SUBSTR.iter() {
        if low.contains(flag) {
            return (3, format!("obfuscated/dl-exec flag ({})", flag.trim()));
        }
    }
    (score, why)
}

fn n_persistence(_vm: &mut Vm, _args: Vec<Value>) -> NatResult {
    let mut out = persistence_rows()?;
    out.sort_by(|a, b| {
        let sa = int_of(&dict_get(a, "score"));
        let sb = int_of(&dict_get(b, "score"));
        sb.cmp(&sa) // stable sort, descending score (matches Python sorted(-score))
    });
    Ok(Value::List(out))
}

fn persistence_rows() -> Result<Vec<Value>, String> {
    #[cfg(windows)]
    {
        persistence_windows()
    }
    #[cfg(not(windows))]
    {
        persistence_linux()
    }
}

// ---------------------------------------------------------------------------
// native 28: arp
// ---------------------------------------------------------------------------

fn n_arp(_vm: &mut Vm, _args: Vec<Value>) -> NatResult {
    #[cfg(windows)]
    {
        Ok(arp_windows().unwrap_or(Value::List(vec![])))
    }
    #[cfg(not(windows))]
    {
        arp_linux()
    }
}

// ---------------------------------------------------------------------------
// native 29: dnscache
// ---------------------------------------------------------------------------

fn n_dnscache(_vm: &mut Vm, _args: Vec<Value>) -> NatResult {
    #[cfg(windows)]
    {
        Ok(dnscache_windows().unwrap_or(Value::List(vec![])))
    }
    #[cfg(not(windows))]
    {
        dnscache_linux()
    }
}

// ===========================================================================
// Windows implementations
// ===========================================================================

#[cfg(windows)]
mod win {
    use std::os::raw::{c_int, c_void};

    pub type DWORD = u32;
    pub type WORD = u16;
    pub type HANDLE = *mut c_void;
    pub type HKEY = *mut c_void;
    pub type BOOL = c_int;

    pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
    pub const ERROR_NO_MORE_ITEMS: DWORD = 259;
    pub const ERROR_SUCCESS: i32 = 0;
    pub const KEY_READ: DWORD = 0x20019;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn CreateToolhelp32Snapshot(dwflags: DWORD, th32processid: DWORD) -> HANDLE;
        pub fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
        pub fn Process32NextW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
    }

    pub const TH32CS_SNAPPROCESS: DWORD = 0x0000_0002;

    #[repr(C)]
    pub struct PROCESSENTRY32W {
        pub dwSize: DWORD,
        pub cntUsage: DWORD,
        pub th32ProcessID: DWORD,
        pub th32DefaultHeapID: usize,
        pub th32ModuleID: DWORD,
        pub cntThreads: DWORD,
        pub th32ParentProcessID: DWORD,
        /// NOTE: Windows declares this as LONG (4 bytes), not a pointer-sized
        /// field -- an 8-byte field here pads sizeof to 576 and Process32FirstW
        /// rejects the entry with ERROR_BAD_LENGTH.
        pub pcPriClassBase: i32,
        pub dwFlags: DWORD,
        pub szExeFile: [WORD; 260],
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        pub fn GetExtendedTcpTable(pTcpTable: *mut c_void, pdwSize: *mut DWORD,
                                   bOrder: BOOL, ulAf: DWORD, TableClass: DWORD,
                                   Reserved: DWORD) -> DWORD;
        pub fn GetExtendedUdpTable(pUdpTable: *mut c_void, pdwSize: *mut DWORD,
                                   bOrder: BOOL, ulAf: DWORD, TableClass: DWORD,
                                   Reserved: DWORD) -> DWORD;
        pub fn GetIpNetTable(pIpNetTable: *mut c_void, pdwSize: *mut DWORD,
                             bOrder: BOOL) -> DWORD;
    }

    pub const TCP_TABLE_OWNER_PID_ALL: DWORD = 5;
    pub const UDP_TABLE_OWNER_PID: DWORD = 1;
    pub const AF_INET: DWORD = 2;
    pub const AF_INET6: DWORD = 23;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct MIB_TCPROW_OWNER_PID {
        pub dwState: DWORD,
        pub dwLocalAddr: DWORD,
        pub dwLocalPort: DWORD,
        pub dwRemoteAddr: DWORD,
        pub dwRemotePort: DWORD,
        pub dwOwningPid: DWORD,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct MIB_TCP6ROW_OWNER_PID {
        pub ucLocalAddr: [u8; 16],
        pub dwLocalScopeId: DWORD,
        pub dwLocalPort: DWORD,
        pub ucRemoteAddr: [u8; 16],
        pub dwRemoteScopeId: DWORD,
        pub dwRemotePort: DWORD,
        pub dwState: DWORD,
        pub dwOwningPid: DWORD,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct MIB_UDPROW_OWNER_PID {
        pub dwLocalAddr: DWORD,
        pub dwLocalPort: DWORD,
        pub dwOwningPid: DWORD,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct MIB_UDP6ROW_OWNER_PID {
        pub ucLocalAddr: [u8; 16],
        pub dwLocalScopeId: DWORD,
        pub dwLocalPort: DWORD,
        pub dwOwningPid: DWORD,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct MIB_IPNETROW {
        pub dwIndex: DWORD,
        pub dwPhysAddrLen: DWORD,
        pub bPhysAddr: [u8; 8],
        pub dwAddr: DWORD,
        pub dwType: DWORD,
    }

    #[link(name = "dnsapi")]
    extern "system" {
        pub fn DnsGetCacheDataTable(ppEntry: *mut DNS_CACHE_ENTRY) -> BOOL;
    }

    #[repr(C)]
    pub struct DNS_CACHE_ENTRY {
        pub pNext: *mut DNS_CACHE_ENTRY,
        pub pszName: *const WORD,
        pub wType: WORD,
        pub wDataLength: WORD,
        pub dwFlags: DWORD,
    }

    #[link(name = "advapi32")]
    extern "system" {
        pub fn RegOpenKeyExW(hKey: HKEY, lpSubKey: *const WORD, ulOptions: DWORD,
                             samDesired: DWORD, phkResult: *mut HKEY) -> i32;
        pub fn RegCloseKey(hKey: HKEY) -> i32;
        pub fn RegEnumValueW(hKey: HKEY, dwIndex: DWORD, lpValueName: *mut WORD,
                             lpcchValueName: *mut DWORD, lpReserved: *mut DWORD,
                             lpType: *mut DWORD, lpData: *mut u8,
                             lpcbData: *mut DWORD) -> i32;
        pub fn RegQueryValueExW(hKey: HKEY, lpValueName: *const WORD,
                                lpReserved: *mut DWORD, lpType: *mut DWORD,
                                lpData: *mut u8, lpcbData: *mut DWORD) -> i32;
        pub fn RegEnumKeyExW(hKey: HKEY, dwIndex: DWORD, lpName: *mut WORD,
                             lpcchName: *mut DWORD, lpReserved: *mut DWORD,
                             lpClass: *mut WORD, lpcchClass: *mut DWORD,
                             lpftLastWriteTime: *mut c_void) -> i32;
    }

    pub const HKEY_CURRENT_USER: HKEY = 0x8000_0001usize as HKEY;
    pub const HKEY_LOCAL_MACHINE: HKEY = 0x8000_0002usize as HKEY;
    pub const REG_SZ: DWORD = 1;
    pub const REG_EXPAND_SZ: DWORD = 2;
    pub const REG_DWORD: DWORD = 4;

    /// Wide-string -> String up to the first NUL.
    pub fn wide_to_string(ptr: *const WORD) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(ptr, len);
            String::from_utf16_lossy(slice)
        }
    }

    /// Fixed-length wide buffer -> String up to first NUL.
    pub fn wide_buf_to_string(buf: &[WORD]) -> String {
        let mut chars = Vec::new();
        for w in buf {
            if *w == 0 {
                break;
            }
            chars.push(*w);
        }
        String::from_utf16_lossy(&chars)
    }

    pub fn u16z(s: &str) -> Vec<WORD> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(windows)]
use win::*;

#[cfg(windows)]
fn win_hkey_local_machine() -> HKEY {
    HKEY_LOCAL_MACHINE
}

#[cfg(windows)]
fn wide_utf16_to_string(bytes: &[u8]) -> String {
    // registry string data arrives as little-endian UTF-16 bytes
    let words: Vec<u16> = bytes
        .chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|w| *w != 0)
        .collect();
    String::from_utf16_lossy(&words)
}

// ---- procs (Toolhelp32) ----------------------------------------------------

#[cfg(windows)]
fn procs_list() -> NatResult {
    unsafe {
        let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if h == INVALID_HANDLE_VALUE {
            return Err("CreateToolhelp32Snapshot failed".to_string());
        }
        let mut result = Vec::new();
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as DWORD;
        let mut ok = Process32FirstW(h, &mut entry);
        while ok != 0 {
            result.push(dict_value(vec![
                ("pid", Value::Int(entry.th32ProcessID as i64)),
                ("ppid", Value::Int(entry.th32ParentProcessID as i64)),
                ("threads", Value::Int(entry.cntThreads as i64)),
                ("name", Value::Str(wide_buf_to_string(&entry.szExeFile))),
            ]));
            ok = Process32NextW(h, &mut entry);
        }
        CloseHandle(h);
        Ok(Value::List(result))
    }
}

// ---- netconns (iphlpapi) ----------------------------------------------------

#[cfg(windows)]
fn netconns_list() -> NatResult {
    unsafe {
        fn query_rows<F>(size_fn: &F, af: DWORD, table_class: DWORD) -> Result<Vec<u8>, String>
        where
            F: Fn(*mut c_void, *mut DWORD, BOOL, DWORD, DWORD, DWORD) -> DWORD,
        {
            // first call with a null buffer returns the required size
            let mut size: DWORD = 0;
            let _ = size_fn(std::ptr::null_mut(), &mut size, 0, af, table_class, 0);
            if size == 0 {
                return Err("table size query failed".to_string());
            }
            let mut buf = vec![0u8; size as usize];
            let rc = size_fn(
                buf.as_mut_ptr() as *mut c_void,
                &mut size,
                0,
                af,
                table_class,
                0,
            );
            if rc != 0 {
                return Err(format!("table query failed rc={rc}"));
            }
            buf.truncate(size as usize);
            Ok(buf)
        }

        // The two table functions share a signature shape; wrap each closure.
        let tcp4 = |p: *mut c_void, s: *mut DWORD, o: BOOL, af: DWORD, tc: DWORD, r: DWORD| {
            unsafe { GetExtendedTcpTable(p, s, o, af, tc, r) }
        };
        let udp4 = |p: *mut c_void, s: *mut DWORD, o: BOOL, af: DWORD, tc: DWORD, r: DWORD| {
            unsafe { GetExtendedUdpTable(p, s, o, af, tc, r) }
        };

        let mib_states = [
            "CLOSED", "LISTENING", "SYN_SENT", "SYN_RECV", "ESTABLISHED",
            "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK",
            "TIME_WAIT", "DELETE_TCB",
        ];
        let port = |dw: DWORD| -> u16 {
            (((dw & 0xFF) << 8) | ((dw >> 8) & 0xFF)) as u16
        };
        let v4 = |dw: DWORD| -> String {
            format!("{}.{}.{}.{}", dw & 0xFF, (dw >> 8) & 0xFF, (dw >> 16) & 0xFF, (dw >> 24) & 0xFF)
        };
        let v6 = |bytes: &[u8; 16]| -> String { format_ipv6(bytes) };

        let mut result = Vec::new();

        // TCP v4
        let buf = query_rows(
            &tcp4,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
        )?;
        let n = DWORD::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        for i in 0..n {
            let off = 4 + i * std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
            let r = unsafe {
                std::ptr::read_unaligned(buf[off..].as_ptr() as *const MIB_TCPROW_OWNER_PID)
            };
            let state = mib_states
                .get((r.dwState as usize).saturating_sub(1))
                .map(|s| s.to_string())
                .unwrap_or_else(|| r.dwState.to_string());
            result.push(dict_value(vec![
                ("proto", Value::Str("TCP".into())),
                ("local", Value::Str(format!("{}:{}", v4(r.dwLocalAddr), port(r.dwLocalPort)))),
                ("remote", Value::Str(format!("{}:{}", v4(r.dwRemoteAddr), port(r.dwRemotePort)))),
                ("state", Value::Str(state)),
                ("pid", Value::Int(r.dwOwningPid as i64)),
            ]));
        }

        // TCP v6
        let buf = query_rows(
            &tcp4,
            AF_INET6,
            TCP_TABLE_OWNER_PID_ALL,
        )?;
        let n = DWORD::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        for i in 0..n {
            let off = 4 + i * std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
            let r = unsafe {
                std::ptr::read_unaligned(buf[off..].as_ptr() as *const MIB_TCP6ROW_OWNER_PID)
            };
            let state = mib_states
                .get((r.dwState as usize).saturating_sub(1))
                .map(|s| s.to_string())
                .unwrap_or_else(|| r.dwState.to_string());
            result.push(dict_value(vec![
                ("proto", Value::Str("TCP6".into())),
                ("local", Value::Str(format!("[{}]:{}", v6(&r.ucLocalAddr), port(r.dwLocalPort)))),
                ("remote", Value::Str(format!("[{}]:{}", v6(&r.ucRemoteAddr), port(r.dwRemotePort)))),
                ("state", Value::Str(state)),
                ("pid", Value::Int(r.dwOwningPid as i64)),
            ]));
        }

        // UDP v4 + v6
        for (af, proto) in
            [(AF_INET, "UDP"), (AF_INET6, "UDP6")]
        {
            let buf = query_rows(&udp4, af, UDP_TABLE_OWNER_PID)?;
            let n = DWORD::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            for i in 0..n {
                let off = 4 + i * if proto == "UDP" {
                    std::mem::size_of::<MIB_UDPROW_OWNER_PID>()
                } else {
                    std::mem::size_of::<MIB_UDP6ROW_OWNER_PID>()
                };
                if proto == "UDP" {
                    let r = unsafe {
                        std::ptr::read_unaligned(
                            buf[off..].as_ptr() as *const MIB_UDPROW_OWNER_PID
                        )
                    };
                    result.push(dict_value(vec![
                        ("proto", Value::Str("UDP".into())),
                        ("local", Value::Str(format!("{}:{}", v4(r.dwLocalAddr), port(r.dwLocalPort)))),
                        ("remote", Value::Str("*:*".into())),
                        ("state", Value::Str(String::new())),
                        ("pid", Value::Int(r.dwOwningPid as i64)),
                    ]));
                } else {
                    let r = unsafe {
                        std::ptr::read_unaligned(
                            buf[off..].as_ptr() as *const MIB_UDP6ROW_OWNER_PID
                        )
                    };
                    result.push(dict_value(vec![
                        ("proto", Value::Str("UDP6".into())),
                        ("local", Value::Str(format!("[{}]:{}", v6(&r.ucLocalAddr), port(r.dwLocalPort)))),
                        ("remote", Value::Str("*:*".into())),
                        ("state", Value::Str(String::new())),
                        ("pid", Value::Int(r.dwOwningPid as i64)),
                    ]));
                }
            }
        }
        Ok(Value::List(result))
    }
}

fn format_ipv6(b: &[u8; 16]) -> String {
    // inet_ntop-style output (no brackets): longest zero run >= 2 -> "::"
    let groups: Vec<u16> = (0..8)
        .map(|i| u16::from_be_bytes([b[i * 2], b[i * 2 + 1]]))
        .collect();
    let mut best_start = 0usize;
    let mut best_len = 0usize;
    let mut cur_start = 0usize;
    let mut cur_len = 0usize;
    for (i, g) in groups.iter().enumerate() {
        if *g == 0 {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_len = cur_len;
                best_start = cur_start;
            }
        } else {
            cur_len = 0;
        }
    }
    if best_len < 2 {
        return groups
            .iter()
            .map(|g| format!("{g:x}"))
            .collect::<Vec<_>>()
            .join(":");
    }
    let left: Vec<String> = groups[..best_start].iter().map(|g| format!("{g:x}")).collect();
    let right: Vec<String> = groups[best_start + best_len..]
        .iter()
        .map(|g| format!("{g:x}"))
        .collect();
    format!("{}::{}", left.join(":"), right.join(":"))
}

// ---- arp (GetIpNetTable) -----------------------------------------------------

#[cfg(windows)]
fn arp_windows() -> NatResult {
    unsafe {
        let mut size: DWORD = 0;
        let _ = GetIpNetTable(std::ptr::null_mut(), &mut size, 0);
        if size == 0 {
            return Err("GetIpNetTable size query failed".to_string());
        }
        let mut buf = vec![0u8; size as usize];
        let rc = GetIpNetTable(buf.as_mut_ptr() as *mut c_void, &mut size, 0);
        if rc != 0 {
            return Err(format!("GetIpNetTable failed rc={rc}"));
        }
        let n = DWORD::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let mut out = Vec::new();
        let kinds = ["other", "invalid", "dynamic", "static"];
        for i in 0..n {
            let off = 4 + i * std::mem::size_of::<MIB_IPNETROW>();
            let r = unsafe {
                std::ptr::read_unaligned(buf[off..].as_ptr() as *const MIB_IPNETROW)
            };
            let cnt = (r.dwPhysAddrLen as usize).min(8);
            let mac = r.bPhysAddr[..cnt]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            let ip = format!(
                "{}.{}.{}.{}",
                r.dwAddr & 0xFF,
                (r.dwAddr >> 8) & 0xFF,
                (r.dwAddr >> 16) & 0xFF,
                (r.dwAddr >> 24) & 0xFF
            );
            let kind = kinds
                .get((r.dwType as usize).saturating_sub(1))
                .map(|s| s.to_string())
                .unwrap_or_else(|| r.dwType.to_string());
            out.push(dict_value(vec![
                ("ip", Value::Str(ip)),
                ("mac", Value::Str(mac)),
                ("iface", Value::Str(r.dwIndex.to_string())),
                ("type", Value::Str(kind)),
            ]));
        }
        Ok(Value::List(out))
    }
}

// ---- dnscache (dnsapi) --------------------------------------------------------

#[cfg(windows)]
fn dnscache_windows() -> NatResult {
    const TYPES: [(WORD, &str); 10] = [
        (1, "A"), (2, "NS"), (5, "CNAME"), (6, "SOA"), (12, "PTR"), (15, "MX"),
        (16, "TXT"), (28, "AAAA"), (33, "SRV"), (255, "ANY"),
    ];
    unsafe {
        let mut head: DNS_CACHE_ENTRY = std::mem::zeroed();
        if DnsGetCacheDataTable(&mut head) == 0 {
            return Err("DnsGetCacheDataTable failed".to_string());
        }
        let mut out = Vec::new();
        let mut node: *mut DNS_CACHE_ENTRY = &mut head;
        let mut hops = 0;
        while !node.is_null() && hops < 4096 {
            hops += 1;
            let e = &*node;
            if !e.pszName.is_null() {
                let name = wide_to_string(e.pszName);
                let t = TYPES
                    .iter()
                    .find(|(w, _)| *w == e.wType)
                    .map(|(_, s)| s.to_string())
                    .unwrap_or_else(|| e.wType.to_string());
                out.push(dict_value(vec![
                    ("name", Value::Str(name)),
                    ("type", Value::Str(t)),
                ]));
            }
            node = e.pNext;
        }
        Ok(Value::List(out))
    }
}

// ---- persistence (advapi32 registry + startup folders) -------------------------
// Note: the Python VM's sweep also parses System32\Tasks XML for scheduled
// tasks; the native build covers run keys, auto-start services and startup
// folders (the XML parser is intentionally not reimplemented in v1).

#[cfg(windows)]
fn winreg_read_string(hive: HKEY, subkey: &str, value: &str) -> Option<String> {
    unsafe {
        let mut hk: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(hive, win::u16z(subkey).as_ptr(), 0, KEY_READ, &mut hk) != 0 {
            return None;
        }
        let mut vtype: DWORD = 0;
        let mut buf = [0u8; 1024];
        let mut blen: DWORD = buf.len() as DWORD;
        let rc = RegQueryValueExW(
            hk,
            win::u16z(value).as_ptr(),
            std::ptr::null_mut(),
            &mut vtype,
            buf.as_mut_ptr(),
            &mut blen,
        );
        RegCloseKey(hk);
        if rc != 0 || (vtype != REG_SZ && vtype != REG_EXPAND_SZ) {
            return None;
        }
        Some(wide_utf16_to_string(&buf[..blen as usize]))
    }
}

#[cfg(windows)]
fn persistence_windows() -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    unsafe {
        // Run / RunOnce / Wow6432Node Run under HKCU + HKLM
        let roots = [
            (HKEY_CURRENT_USER, "HKCU"),
            (HKEY_LOCAL_MACHINE, "HKLM"),
        ];
        let subpaths = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        ];
        for (hive, hname) in roots.iter() {
            for sub in subpaths.iter() {
                let mut hk: HKEY = std::ptr::null_mut();
                if RegOpenKeyExW(*hive, win::u16z(sub).as_ptr(), 0, KEY_READ, &mut hk) != 0 {
                    continue;
                }
                let mut idx: DWORD = 0;
                loop {
                    let mut name_buf = [0u16; 163];
                    let mut name_len: DWORD = name_buf.len() as DWORD;
                    let mut data_buf = [0u8; 1024];
                    let mut data_len: DWORD = data_buf.len() as DWORD;
                    let mut vtype: DWORD = 0;
                    let rc = RegEnumValueW(
                        hk,
                        idx,
                        name_buf.as_mut_ptr(),
                        &mut name_len,
                        std::ptr::null_mut(),
                        &mut vtype,
                        data_buf.as_mut_ptr(),
                        &mut data_len,
                    );
                    if rc == ERROR_NO_MORE_ITEMS as i32 {
                        break;
                    }
                    if rc != 0 {
                        break;
                    }
                    idx += 1;
                    if vtype != REG_SZ && vtype != REG_EXPAND_SZ {
                        continue;
                    }
                    let name = win::wide_buf_to_string(&name_buf[..name_len as usize]);
                    let cmd = wide_utf16_to_string(&data_buf[..data_len as usize]);
                    let (score, why) = suspect_score(&cmd);
                    out.push(dict_value(vec![
                        ("mechanism", Value::Str("run-key".into())),
                        ("name", Value::Str(format!("{hname}\\...\\{name}"))),
                        ("detail", Value::Str(cmd.chars().take(200).collect())),
                        ("score", Value::Int(score)),
                        ("why", Value::Str(why)),
                    ]));
                }
                RegCloseKey(hk);
            }
        }

        // auto-start services (Start <= 2)
        let mut hk: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            win::u16z(r"SYSTEM\CurrentControlSet\Services").as_ptr(),
            0,
            KEY_READ,
            &mut hk,
        ) == 0
        {
            let mut idx: DWORD = 0;
            loop {
                let mut name_buf = [0u16; 256];
                let mut name_len: DWORD = name_buf.len() as DWORD;
                let rc = RegEnumKeyExW(
                    hk,
                    idx,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                if rc == ERROR_NO_MORE_ITEMS as i32 || rc != 0 {
                    break;
                }
                idx += 1;
                let svc = win::wide_buf_to_string(&name_buf[..name_len as usize]);
                let mut sk: HKEY = std::ptr::null_mut();
                if RegOpenKeyExW(hk, win::u16z(&svc).as_ptr(), 0, KEY_READ, &mut sk) != 0 {
                    continue;
                }
                let qdword = |name: &str| -> Option<DWORD> {
                    let mut vtype: DWORD = 0;
                    let mut buf = [0u8; 8];
                    let mut blen: DWORD = buf.len() as DWORD;
                    let rc = RegQueryValueExW(
                        sk,
                        win::u16z(name).as_ptr(),
                        std::ptr::null_mut(),
                        &mut vtype,
                        buf.as_mut_ptr(),
                        &mut blen,
                    );
                    if rc != 0 {
                        None
                    } else if vtype == REG_DWORD && blen >= 4 {
                        Some(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
                    } else {
                        None
                    }
                };
                let start = qdword("Start");
                let img = winreg_read_string_h(sk, "ImagePath");
                RegCloseKey(sk);
                let start = match start {
                    Some(s) => s,
                    None => continue,
                };
                if start > 2 {
                    continue;
                }
                let img = img.unwrap_or_default();
                let (score, why) = suspect_score(&img);
                out.push(dict_value(vec![
                    ("mechanism", Value::Str("service".into())),
                    ("name", Value::Str(svc)),
                    ("detail", Value::Str(img.chars().take(200).collect())),
                    ("score", Value::Int(score)),
                    ("why", Value::Str(why)),
                ]));
            }
            RegCloseKey(hk);
        }
    }

    // startup folders
    let folders: Vec<(std::path::PathBuf, &str)> = vec![
        (
            std::env::var("APPDATA")
                .map(|p| std::path::PathBuf::from(p)
                    .join(r"Microsoft\Windows\Start Menu\Programs\Startup"))
                .unwrap_or_default(),
            "user",
        ),
        (
            std::env::var("ProgramData")
                .map(|p| std::path::PathBuf::from(p)
                    .join(r"Microsoft\Windows\Start Menu\Programs\Startup"))
                .unwrap_or_default(),
            "common",
        ),
    ];
    let exts = [".lnk", ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".js"];
    for (folder, _label) in folders {
        if let Ok(entries) = std::fs::read_dir(&folder) {
            for e in entries.filter_map(|e| e.ok()) {
                let name = e.file_name().to_string_lossy().into_owned();
                let lower = name.to_lowercase();
                if exts.iter().any(|x| lower.ends_with(x)) {
                    let full = folder.join(&name);
                    let cmd = full.to_string_lossy();
                    let (score, why) = suspect_score(&cmd);
                    out.push(dict_value(vec![
                        ("mechanism", Value::Str("startup-folder".into())),
                        ("name", Value::Str(name)),
                        ("detail", Value::Str(cmd.chars().take(200).collect())),
                        ("score", Value::Int(score)),
                        ("why", Value::Str(why)),
                    ]));
                }
            }
        }
    }
    Ok(out)
}

#[cfg(windows)]
fn winreg_read_string_h(hk: HKEY, value: &str) -> Option<String> {
    unsafe {
        let mut vtype: DWORD = 0;
        let mut buf = [0u8; 1024];
        let mut blen: DWORD = buf.len() as DWORD;
        let rc = RegQueryValueExW(
            hk,
            win::u16z(value).as_ptr(),
            std::ptr::null_mut(),
            &mut vtype,
            buf.as_mut_ptr(),
            &mut blen,
        );
        if rc != 0 || (vtype != REG_SZ && vtype != REG_EXPAND_SZ) {
            return None;
        }
        Some(wide_utf16_to_string(&buf[..blen as usize]))
    }
}

// ===========================================================================
// Linux implementations
// ===========================================================================

#[cfg(not(windows))]
fn procs_list() -> NatResult {
    let mut result = Vec::new();
    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e,
        Err(e) => return Err(e.to_string()),
    };
    for e in entries.filter_map(|e| e.ok()) {
        let fname = e.file_name().to_string_lossy().into_owned();
        if !fname.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid_dir = std::path::Path::new("/proc").join(&fname);
        let stat = match std::fs::read_to_string(pid_dir.join("stat")) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let end = match stat.rfind(')') {
            Some(e) => e,
            None => continue,
        };
        let head = &stat[..end];
        let tail: Vec<&str> = stat[end + 1..].split_whitespace().collect();
        let name = head
            .split_once('(')
            .map(|(_, n)| n.trim().to_string())
            .unwrap_or_default();
        let ppid: i64 = tail.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let cmdline = std::fs::read(pid_dir.join("cmdline"))
            .map(|b| {
                b.split(|c| *c == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let exe = std::fs::read_link(pid_dir.join("exe"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        result.push(dict_value(vec![
            ("pid", Value::Int(fname.parse().unwrap_or(0))),
            ("ppid", Value::Int(ppid)),
            ("name", Value::Str(name)),
            ("exe", Value::Str(exe)),
            ("cmdline", Value::Str(cmdline)),
        ]));
    }
    Ok(Value::List(result))
}

#[cfg(not(windows))]
fn proc_socket_inode_map() -> HashMap<String, i64> {
    let mut map = HashMap::new();
    if let Ok(pids) = std::fs::read_dir("/proc") {
        for e in pids.filter_map(|e| e.ok()) {
            let fname = e.file_name().to_string_lossy().into_owned();
            if !fname.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let pid: i64 = fname.parse().unwrap_or(0);
            let fd_dir = std::path::Path::new("/proc").join(&fname).join("fd");
            if let Ok(fds) = std::fs::read_dir(&fd_dir) {
                for fd in fds.filter_map(|f| f.ok()) {
                    if let Ok(link) = fd.path().read_link() {
                        let ls = link.to_string_lossy().into_owned();
                        if let Some(rest) = ls.strip_prefix("socket:[") {
                            if let Some(inode) = rest.strip_suffix(']') {
                                map.entry(inode.to_string()).or_insert(pid);
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

#[cfg(not(windows))]
fn hex_sockaddr(hexstr: &str) -> String {
    let (addr_hex, port_hex) = match hexstr.rsplit_once(':') {
        Some(p) => p,
        None => return hexstr.to_string(),
    };
    let port = u32::from_str_radix(port_hex, 16).unwrap_or(0);
    let raw = (0..addr_hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&addr_hex[i..i + 2], 16).ok())
        .collect::<Vec<u8>>();
    if raw.len() == 4 {
        format!("{}.{}.{}.{}:{port}", raw[3], raw[2], raw[1], raw[0])
    } else if raw.len() == 16 {
        let mut b = [0u8; 16];
        // /proc stores v6 addresses as four LE u32 groups
        for g in 0..4 {
            for i in 0..4 {
                b[g * 4 + i] = raw[g * 4 + (3 - i)];
            }
        }
        format!("[{}]:{port}", format_ipv6(&b))
    } else {
        format!("{addr_hex}:{port}")
    }
}

#[cfg(not(windows))]
fn tcp_state(n: usize) -> String {
    let states = [
        "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
        "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING",
    ];
    states
        .get(n.saturating_sub(1))
        .map(|s| s.to_string())
        .unwrap_or_else(|| n.to_string())
}

#[cfg(not(windows))]
fn netconns_list() -> NatResult {
    let inode_to_pid = proc_socket_inode_map();
    let mut result = Vec::new();
    for (fname, proto) in
        [("tcp", "TCP"), ("tcp6", "TCP6"), ("udp", "UDP"), ("udp6", "UDP6")]
    {
        let body = match std::fs::read_to_string(format!("/proc/net/{fname}")) {
            Ok(b) => b,
            Err(_) => continue,
        };
        for line in body.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let laddr = hex_sockaddr(parts[1]);
            let raddr = hex_sockaddr(parts[2]);
            let state = usize::from_str_radix(parts[3], 16).unwrap_or(0);
            let inode = parts.get(9).copied().unwrap_or("");
            let pid = inode_to_pid.get(inode).copied().unwrap_or(0);
            result.push(dict_value(vec![
                ("proto", Value::Str(proto.to_string())),
                ("local", Value::Str(laddr)),
                ("remote", Value::Str(raddr)),
                ("state", Value::Str(tcp_state(state))),
                ("pid", if pid == 0 {
                    Value::Str(String::new())
                } else {
                    Value::Int(pid)
                }),
            ]));
        }
    }
    Ok(Value::List(result))
}

#[cfg(not(windows))]
fn arp_linux() -> NatResult {
    let mut out = Vec::new();
    if let Ok(body) = std::fs::read_to_string("/proc/net/arp") {
        for line in body.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                out.push(dict_value(vec![
                    ("ip", Value::Str(parts[0].to_string())),
                    ("mac", Value::Str(parts[3].to_string())),
                    ("iface", Value::Str(parts[5].to_string())),
                    ("type", Value::Str(format!("0x{}", parts[2]))),
                ]));
            }
        }
    }
    Ok(Value::List(out))
}

#[cfg(not(windows))]
fn dnscache_linux() -> NatResult {
    let mut out = Vec::new();
    if let Ok(body) = std::fs::read_to_string("/etc/hosts") {
        for line in body.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                out.push(dict_value(vec![
                    ("name", Value::Str(parts[1].to_string())),
                    ("type", Value::Str(format!("hosts->{}", parts[0]))),
                ]));
            }
        }
    }
    Ok(Value::List(out))
}

#[cfg(not(windows))]
fn persistence_linux() -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    let mut candidates: Vec<String> = Vec::new();
    for dir in [
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.weekly", "/etc/cron.monthly",
        "/var/spool/cron/crontabs", "/var/spool/cron",
    ] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.filter_map(|e| e.ok()) {
                candidates.push(e.path().to_string_lossy().into_owned());
            }
        }
    }
    for f in ["/etc/crontab", "/etc/rc.local"] {
        if std::path::Path::new(f).is_file() {
            candidates.push(f.to_string());
        }
    }
    for path in candidates {
        if let Ok(body) = std::fs::read_to_string(&path) {
            let body = body.chars().take(4096).collect::<String>();
            let (score, why) = suspect_score(&body);
            out.push(dict_value(vec![
                ("mechanism", Value::Str("cron".into())),
                ("name", Value::Str(path)),
                ("detail", Value::Str(body.chars().take(200).collect())),
                ("score", Value::Int(score)),
                ("why", Value::Str(why)),
            ]));
        }
    }
    // systemd units
    let mut unit_paths = Vec::new();
    for dir in ["/etc/systemd/system"] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.filter_map(|e| e.ok()) {
                let p = e.path();
                let ext = p.extension().map(|x| x == "service").unwrap_or(false);
                if ext {
                    unit_paths.push(p.clone());
                }
                if let Ok(sub) = std::fs::read_dir(&p) {
                    // *.wants/*.service
                    if p.extension().map(|x| x == "wants").unwrap_or(false) {
                        for s in sub.filter_map(|s| s.ok()) {
                            if s.path().extension().map(|x| x == "service").unwrap_or(false) {
                                unit_paths.push(s.path());
                            }
                        }
                    }
                }
            }
        }
    }
    for path in unit_paths {
        if let Ok(body) = std::fs::read_to_string(&path) {
            let exec_line = body
                .lines()
                .map(|l| l.trim())
                .find(|l| l.starts_with("ExecStart="))
                .map(|l| l[10..].to_string())
                .unwrap_or_default();
            let (score, why) = suspect_score(if exec_line.is_empty() { &body } else { &exec_line });
            out.push(dict_value(vec![
                ("mechanism", Value::Str("systemd".into())),
                ("name", Value::Str(path.to_string_lossy().into_owned())),
                ("detail", Value::Str(if exec_line.is_empty() {
                    body.chars().take(200).collect()
                } else {
                    exec_line.chars().take(200).collect()
                })),
                ("score", Value::Int(score)),
                ("why", Value::Str(why)),
            ]));
        }
    }
    // XDG autostart
    let home = std::env::var("HOME").unwrap_or_default();
    for base in [format!("{home}/.config/autostart"), "/etc/xdg/autostart".to_string()] {
        if let Ok(rd) = std::fs::read_dir(&base) {
            for e in rd.filter_map(|e| e.ok()) {
                let p = e.path();
                if p.extension().map(|x| x == "desktop").unwrap_or(false) {
                    if let Ok(body) = std::fs::read_to_string(&p) {
                        let exec_line = body
                            .lines()
                            .map(|l| l.trim())
                            .find(|l| l.starts_with("Exec="))
                            .map(|l| l[5..].to_string())
                            .unwrap_or_default();
                        let (score, why) = suspect_score(&exec_line);
                        out.push(dict_value(vec![
                            ("mechanism", Value::Str("xdg-autostart".into())),
                            ("name", Value::Str(p.to_string_lossy().into_owned())),
                            ("detail", Value::Str(exec_line.chars().take(200).collect())),
                            ("score", Value::Int(score)),
                            ("why", Value::Str(why)),
                        ]));
                    }
                }
            }
        }
    }
    Ok(out)
}
