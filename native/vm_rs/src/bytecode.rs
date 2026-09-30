//! JY_IMG01 container decoder (Rust side of jocky/bytecode.py).
//!
//! Layout: MAGIC(8)=b"JY_IMG01" | u32 version | sections [tag:4B][size:u32][payload]
//!   OPTS  opcode permutation table (byte i = encoded id for base opcode i)
//!   CPOL  zlib+pickle const pool   -> Python-only; SKIPPED here
//!   CPOR  portable const pool      -> decoded here (see bytecode.py)
//!   CODE  instruction stream [u8 encoded_op][operand bytes]
//!   FUNC  u32 N; per entry: u8 name_id, u8 nparams, u8* param_ids, u32 addr
//!   ENTR  u32 entry function index
//!   HASH  sha256 of the canonical CODE stream

use crate::value::Value;

pub const MAGIC: &[u8; 8] = b"JY_IMG01";
pub const VERSION: u32 = 1;

pub const OP_NAMES: [&str; 30] = [
    "NOP", "PUSH", "LOAD", "STORE", "JMP", "JZ", "JNZ", "CALL", "NAT", "RET",
    "PUSHARG", "ITERMK", "ITERNX", "POP", "HALT",
    "ADD", "SUB", "MUL", "DIV", "MOD", "NEG",
    "EQ", "NE", "LT", "GT", "LE", "GE",
    "AND", "OR", "NOT",
];

pub const OP_WIDTHS: [usize; 30] = [
    1, 1, 1, 1, 4, 4, 4, 1, 1, 0,
    0, 1, 1, 0, 0,
    0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
    0, 0, 0,
];

#[derive(Debug, Clone)]
pub struct FuncEntry {
    pub name: String,
    pub nparams: usize,
    pub params: Vec<String>,
    pub addr: usize,
}

#[derive(Debug)]
pub struct Image {
    pub code: Vec<u8>,
    pub consts: Vec<Value>,
    pub funcs: Vec<FuncEntry>,
    pub entry: usize,
    /// inverse permutation: encoded opcode byte -> base opcode index
    pub inv: Vec<usize>,
    pub build_hash: Option<[u8; 32]>,
}

#[derive(Debug)]
pub enum ImageError {
    BadMagic,
    UnsupportedVersion(u32),
    Truncated(&'static str),
    MissingSection(&'static str),
    BadPerm(usize),
    BadCpor(String),
    BadFunc,
}

impl std::fmt::Display for ImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageError::BadMagic => write!(f, "bad magic: not a JOCKY image"),
            ImageError::UnsupportedVersion(v) => write!(f, "unsupported image version {v}"),
            ImageError::Truncated(w) => write!(f, "truncated section {w:?}"),
            ImageError::MissingSection(s) => write!(f, "missing section {s}"),
            ImageError::BadPerm(n) => {
                write!(f, "OPTS permutation table invalid (len {n})")
            }
            ImageError::BadCpor(m) => write!(f, "CPOR section: {m}"),
            ImageError::BadFunc => write!(f, "FUNC section malformed"),
        }
    }
}

fn u16_le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn i64_le(b: &[u8], off: usize) -> i64 {
    i64::from_le_bytes([
        b[off], b[off + 1], b[off + 2], b[off + 3],
        b[off + 4], b[off + 5], b[off + 6], b[off + 7],
    ])
}

fn f64_le(b: &[u8], off: usize) -> f64 {
    f64::from_le_bytes([
        b[off], b[off + 1], b[off + 2], b[off + 3],
        b[off + 4], b[off + 5], b[off + 6], b[off + 7],
    ])
}

/// Decode the CPOR portable constant pool (layout documented in
/// jocky/bytecode.py: u32 version | u32 count | per entry u8 type, u32 len, data).
fn parse_cpor(payload: &[u8]) -> Result<Vec<Value>, ImageError> {
    if payload.len() < 8 {
        return Err(ImageError::BadCpor("too short".into()));
    }
    let ver = u32_le(payload, 0);
    if ver != 1 {
        return Err(ImageError::BadCpor(format!("unsupported version {ver}")));
    }
    let count = u32_le(payload, 4) as usize;
    let mut pos = 8usize;
    let mut consts = Vec::with_capacity(count);
    for i in 0..count {
        if pos + 5 > payload.len() {
            return Err(ImageError::BadCpor(format!("entry {i} truncated")));
        }
        let ctype = payload[pos];
        let len = u32_le(payload, pos + 1) as usize;
        pos += 5;
        if pos + len > payload.len() {
            return Err(ImageError::BadCpor(format!("entry {i} data truncated")));
        }
        let data = &payload[pos..pos + len];
        pos += len;
        let value = match ctype {
            0 => Value::None,
            1 => Value::Bool(data.first().map(|b| *b != 0).unwrap_or(false)),
            2 => {
                if data.len() != 8 {
                    return Err(ImageError::BadCpor(format!("entry {i}: bad int")));
                }
                Value::Int(i64_le(data, 0))
            }
            3 => {
                if data.len() != 8 {
                    return Err(ImageError::BadCpor(format!("entry {i}: bad float")));
                }
                Value::Float(f64_le(data, 0))
            }
            4 => match std::str::from_utf8(data) {
                Ok(s) => Value::Str(s.to_string()),
                Err(_) => return Err(ImageError::BadCpor(format!("entry {i}: bad utf-8"))),
            },
            other => {
                return Err(ImageError::BadCpor(format!(
                    "entry {i}: unknown type {other}"
                )))
            }
        };
        consts.push(value);
    }
    Ok(consts)
}

impl Image {
    /// Parse a JY_IMG01 blob. The Python runtime ignores CPOR and the native
    /// VM ignores CPOL, so both run the same image unchanged.
    pub fn parse(blob: &[u8]) -> Result<Image, ImageError> {
        if blob.len() < 12 || &blob[..8] != MAGIC {
            return Err(ImageError::BadMagic);
        }
        let ver = u32_le(blob, 8);
        if ver != VERSION {
            return Err(ImageError::UnsupportedVersion(ver));
        }
        let mut pos = 12usize;
        let mut opt: Option<Vec<u8>> = None;
        let mut cpor: Option<Vec<u8>> = None;
        let mut code: Option<&[u8]> = None;
        let mut func: Option<&[u8]> = None;
        let mut entr: Option<u32> = None;
        let mut hash: Option<[u8; 32]> = None;
        while pos + 8 <= blob.len() {
            let tag = &blob[pos..pos + 4];
            let size = u32_le(blob, pos + 4) as usize;
            let start = pos + 8;
            if start + size > blob.len() {
                return Err(ImageError::Truncated("payload"));
            }
            let payload = &blob[start..start + size];
            match tag {
                b"OPTS" => opt = Some(payload.to_vec()),
                b"CPOR" => cpor = Some(payload.to_vec()),
                b"CODE" => code = Some(payload),
                b"FUNC" => func = Some(payload),
                b"ENTR" => entr = Some(u32_le(payload, 0)),
                b"HASH" => {
                    if payload.len() == 32 {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(payload);
                        hash = Some(h);
                    }
                }
                _ => {} // CPOL etc. -- native VM skips Python-only sections
            }
            pos = start + size;
        }

        let n_ops = OP_NAMES.len();
        let perm = opt.unwrap_or_else(|| (0..n_ops as u8).collect());
        if perm.len() != n_ops {
            return Err(ImageError::BadPerm(perm.len()));
        }
        let mut inv = vec![0usize; n_ops];
        for (base, enc) in perm.iter().enumerate() {
            if (*enc as usize) >= n_ops {
                return Err(ImageError::BadPerm(perm.len()));
            }
            inv[*enc as usize] = base;
        }

        let consts = parse_cpor(
            cpor.as_deref()
                .ok_or(ImageError::MissingSection("CPOR"))?,
        )?;
        let code = code.ok_or(ImageError::MissingSection("CODE"))?.to_vec();
        let fdata = func.ok_or(ImageError::MissingSection("FUNC"))?;
        let entry = entr.ok_or(ImageError::MissingSection("ENTR"))? as usize;

        if fdata.len() < 4 {
            return Err(ImageError::BadFunc);
        }
        let n_funcs = u32_le(fdata, 0) as usize;
        let mut off = 4usize;
        let mut funcs = Vec::with_capacity(n_funcs);
        for _ in 0..n_funcs {
            if off + 2 > fdata.len() {
                return Err(ImageError::BadFunc);
            }
            let name_id = fdata[off] as usize;
            let nparams = fdata[off + 1] as usize;
            off += 2;
            if off + nparams + 4 > fdata.len() {
                return Err(ImageError::BadFunc);
            }
            let mut params = Vec::with_capacity(nparams);
            for p in 0..nparams {
                let pid = fdata[off + p] as usize;
                let name = match consts.get(pid) {
                    Some(Value::Str(s)) => s.clone(),
                    _ => return Err(ImageError::BadFunc),
                };
                params.push(name);
            }
            off += nparams;
            let addr = u32_le(fdata, off) as usize;
            off += 4;
            let name = match consts.get(name_id) {
                Some(Value::Str(s)) => s.clone(),
                _ => return Err(ImageError::BadFunc),
            };
            funcs.push(FuncEntry { name, nparams, params, addr });
        }

        Ok(Image { code, consts, funcs, entry, inv, build_hash: hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpor_roundtrip_matches_python_layout() {
        // manually assembled CPOR: version 1, 3 entries: int 7, str "ab", none
        let mut p = Vec::new();
        p.extend_from_slice(&1u32.to_le_bytes());
        p.extend_from_slice(&3u32.to_le_bytes());
        p.push(2);
        p.extend_from_slice(&8u32.to_le_bytes());
        p.extend_from_slice(&7i64.to_le_bytes());
        p.push(4);
        p.extend_from_slice(&2u32.to_le_bytes());
        p.extend_from_slice(b"ab");
        p.push(0);
        p.extend_from_slice(&0u32.to_le_bytes());
        let vals = parse_cpor(&p).unwrap();
        assert_eq!(vals[0], Value::Int(7));
        assert_eq!(vals[1], Value::Str("ab".into()));
        assert_eq!(vals[2], Value::None);
    }
}
