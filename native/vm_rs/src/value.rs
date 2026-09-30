//! value.rs — JOCKY runtime values with Python-compatible display,
//! arithmetic, comparison and truthiness (mirrors jocky/vm.py + jocky/stdlib.py
//! semantics so the native VM produces byte-identical output).
//!
//! Dependency-free: std only, so `cargo build` works fully offline.

use std::cmp::Ordering;

/// JOCKY runtime value. `Mark` is the PUSHARG sentinel; it is never visible
/// to scripts and only ever appears on the stack while a call is assembled.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    /// Insertion-ordered mapping (Python dict parity).
    Dict(Vec<(Value, Value)>),
    Mark,
}

impl Value {
    /// Native type-name in the exact spelling the `type` native returns.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::None => "none",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "str",
            Value::List(_) => "list",
            Value::Dict(_) => "dict",
            Value::Mark => "argmark",
        }
    }

    pub fn is_num(&self) -> bool {
        matches!(self, Value::Bool(_) | Value::Int(_) | Value::Float(_))
    }

    /// Python `bool(value)`.
    pub fn truthy(&self) -> bool {
        match self {
            Value::None => false,
            Value::Mark => true,
            Value::Bool(b) => *b,
            Value::Int(i) => *i != 0,
            Value::Float(x) => *x != 0.0, // NaN is truthy in Python
            Value::Str(s) => !s.is_empty(),
            Value::List(items) => !items.is_empty(),
            Value::Dict(pairs) => !pairs.is_empty(),
        }
    }

    /// Numeric coercion used for promotion / `int()` casts.
    /// Bool participates as 0/1, like Python. Floats coerce only when they
    /// hold an exact integral value inside the i64 range.
    pub fn to_i64(&self) -> Option<i64> {
        match self {
            Value::Bool(b) => Some(if *b { 1 } else { 0 }),
            Value::Int(i) => Some(*i),
            Value::Float(x) => {
                if *x != *x || *x > 9_223_372_036_854_775_807.0 || *x < -9_223_372_036_854_775_808.0 {
                    return None;
                }
                let t = *x as i64;
                if (t as f64) == *x {
                    Some(t)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_f64(&self) -> Option<f64> {
        match self {
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Int(i) => Some(*i as f64),
            Value::Float(x) => Some(*x),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Python float repr — shortest round-trip digits with Python exponent rules:
//     repr(1.0)  == "1.0",    repr(0.5) == "0.5",    repr(1e15) == "1000000000000000.0"
//     repr(1e16) == "1e+16",  repr(1e-5) == "1e-05", repr(5e-324) == "5e-324"
//     repr(nan)  == "nan",    repr(inf)  == "inf",   repr(-0.0) == "-0.0"
// ---------------------------------------------------------------------------

/// Python `repr(float)`: shortest digit string that round-trips exactly.
/// Mirrors CPython's "shortest repr" rule (Ryu-equivalent result).
pub fn py_float_repr(x: f64) -> String {
    if x.is_nan() {
        return "nan".to_string();
    }
    if x.is_infinite() {
        return if x.is_sign_positive() { "inf".to_string() } else { "-inf".to_string() };
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0.0".to_string() } else { "0.0".to_string() };
    }
    let neg = x < 0.0;
    let ax = x.abs();

    // Rust's Display ({:e}) already produces the shortest round-trip digit
    // string — the same digits CPython's repr selects. (The previous
    // precision-search loop used {:.prec$e}, which this toolchain truncates
    // for denormals: 4.9406...e-324 came out "4.9e-324" instead of "5e-324".)
    let s = format!("{:e}", ax);
    let (mant_part, exp_part) = match s.split_once('e') {
        Some((m, e)) => (m, e),
        None => (s.as_str(), "0"), // defensive; Display always emits an exponent
    };
    let exp: i64 = exp_part.parse().unwrap_or(0);
    let digits: Vec<u8> = mant_part.bytes().filter(|b| b.is_ascii_digit()).collect();
    debug_assert!(!digits.is_empty(), "no digits in float display '{s}'");
    let nd = digits.len();
    let mant = &digits[..nd];

    if (-4..16).contains(&exp) {
        // Fixed-point notation, exactly like Python.
        let mut out = String::new();
        if neg {
            out.push('-');
        }
        if exp >= 0 {
            let e = exp as usize;
            if e + 1 >= nd {
                out.push_str(std::str::from_utf8(mant).unwrap());
                for _ in 0..(e + 1 - nd) {
                    out.push('0');
                }
                out.push_str(".0");
            } else {
                out.push_str(std::str::from_utf8(&mant[..e + 1]).unwrap());
                out.push('.');
                out.push_str(std::str::from_utf8(&mant[e + 1..]).unwrap());
            }
        } else {
            out.push_str("0.");
            for _ in 0..(-exp as usize - 1) {
                out.push('0');
            }
            out.push_str(std::str::from_utf8(mant).unwrap());
        }
        out
    } else {
        // Scientific notation with Python exponent formatting:
        // "1e+16", "1e-05", "1e+100" (sign + at least two digits).
        let mut out = String::new();
        if neg {
            out.push('-');
        }
        out.push(mant[0] as char);
        if nd > 1 {
            out.push('.');
            out.push_str(std::str::from_utf8(&mant[1..]).unwrap());
        }
        out.push('e');
        out.push(if exp < 0 { '-' } else { '+' });
        let ea = exp.unsigned_abs();
        if ea < 10 {
            out.push('0');
        }
        out.push_str(&ea.to_string());
        out
    }
}

// ---------------------------------------------------------------------------
// Python str() / repr()
// ---------------------------------------------------------------------------

/// Python `repr(str)` — quoted with single quotes (or double quotes when the
/// string contains a single quote but no double quote), escaping the usual
/// control characters. Used *inside* containers where Python uses repr().
pub fn py_repr_str(s: &str) -> String {
    let has_sq = s.contains('\'');
    let has_dq = s.contains('"');
    let q = if has_sq && !has_dq { '"' } else { '\'' };
    let mut out = String::new();
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => {
                if q == '\'' {
                    out.push_str("\\'");
                } else {
                    out.push(c);
                }
            }
            '"' => {
                if q == '"' {
                    out.push_str("\\\"");
                } else {
                    out.push(c);
                }
            }
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\u{0}'..='\u{1f}' => out.push_str(&format!("\\x{:02x}", c as u32)),
            '\u{7f}' => out.push_str("\\x7f"),
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

/// Python `str(value)` at the top level (used by `log`, `join`, `str` native).
/// Note: Python str() of a string is the bare string; str() of a container
/// formats its *elements* with repr(), so nested strings are quoted.
pub fn py_str(v: &Value) -> String {
    match v {
        Value::None => "None".to_string(),
        Value::Mark => "<argmark>".to_string(),
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Int(i) => i.to_string(),
        Value::Float(x) => py_float_repr(*x),
        Value::Str(s) => s.clone(),
        Value::List(items) => {
            let mut out = String::from("[");
            for (i, x) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&py_repr(x));
            }
            out.push(']');
            out
        }
        Value::Dict(pairs) => {
            let mut out = String::from("{");
            for (i, (k, v)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&py_repr(k));
                out.push_str(": ");
                out.push_str(&py_repr(v));
            }
            out.push('}');
            out
        }
    }
}

/// Python `repr(value)` — identical to str() except strings are quoted.
pub fn py_repr(v: &Value) -> String {
    match v {
        Value::Str(s) => py_repr_str(s),
        other => py_str(other),
    }
}

// ---------------------------------------------------------------------------
// Equality (Python ==)
// ---------------------------------------------------------------------------

/// dict.get(key): linear scan over the insertion-ordered pairs.
pub fn dict_find(d: &[(Value, Value)], key: &Value) -> Option<usize> {
    d.iter().position(|(k, _)| value_eq(k, key))
}

pub fn dict_has(d: &[(Value, Value)], key: &Value) -> bool {
    dict_find(d, key).is_some()
}

pub fn dict_find_val(d: &[(Value, Value)], key: &Value) -> Option<Value> {
    dict_find(d, key).map(|i| d[i].1.clone())
}

/// Python `a == b`: numeric promotion, order-insensitive dict equality.
pub fn value_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::None, Value::None) => true,
        (Value::Mark, Value::Mark) => true,
        (Value::None, _) | (_, Value::None) => false,
        (Value::Mark, _) | (_, Value::Mark) => false,
        (Value::Bool(_) | Value::Int(_) | Value::Float(_),
         Value::Bool(_) | Value::Int(_) | Value::Float(_)) => num_eq(a, b),
        (Value::Str(x), Value::Str(y)) => x == y,
        (Value::List(x), Value::List(y)) => {
            if x.len() != y.len() {
                return false;
            }
            x.iter().zip(y.iter()).all(|(p, q)| value_eq(p, q))
        }
        (Value::Dict(x), Value::Dict(y)) => {
            if x.len() != y.len() {
                return false;
            }
            x.iter().all(|(k, v)| dict_find_val(y, k).map_or(false, |w| value_eq(&w, v)))
        }
        _ => false,
    }
}

fn num_eq(a: &Value, b: &Value) -> bool {
    if let (Some(x), Some(y)) = (a.to_i64(), b.to_i64()) {
        return x == y;
    }
    match (a.to_f64(), b.to_f64()) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// Python list/dict membership (`x in seq`).
pub fn seq_contains(seq: &Value, needle: &Value) -> Result<bool, String> {
    match seq {
        Value::Str(hay) => match needle {
            Value::Str(n) => Ok(hay.contains(n)),
            _ => Err("'in <string>' requires string as left operand, not '"
                .to_string() + needle.type_name() + "'"),
        },
        Value::List(items) => Ok(items.iter().any(|x| value_eq(x, needle))),
        Value::Dict(pairs) => Ok(dict_has(pairs, needle)),
        other => Err("argument of type '".to_string() + other.type_name() + "' is not iterable"),
    }
}

// ---------------------------------------------------------------------------
// Ordering (Python < <= > >=) — Err for non-ordered operand pairs,
// None for unordered float comparisons (NaN), which are all False in Python.
// ---------------------------------------------------------------------------

pub fn value_cmp(a: &Value, b: &Value, op: &str) -> Result<Option<Ordering>, String> {
    if a.is_num() && b.is_num() {
        if let (Some(x), Some(y)) = (a.to_i64(), b.to_i64()) {
            return Ok(Some(x.cmp(&y)));
        }
        return Ok(a.to_f64().unwrap().partial_cmp(&b.to_f64().unwrap()));
    }
    match (a, b) {
        (Value::Str(x), Value::Str(y)) => Ok(Some(x.cmp(y))),
        (Value::List(x), Value::List(y)) => cmp_lists(x, y, op),
        _ => Err(format!(
            "'{}' not supported between instances of '{}' and '{}'",
            op,
            a.type_name(),
            b.type_name()
        )),
    }
}

fn cmp_lists(x: &[Value], y: &[Value], op: &str) -> Result<Option<Ordering>, String> {
    for (p, q) in x.iter().zip(y.iter()) {
        match value_cmp(p, q, op)? {
            Some(Ordering::Equal) => continue,
            other => return Ok(other),
        }
    }
    Ok(Some(x.len().cmp(&y.len())))
}

// ---------------------------------------------------------------------------
// Python int() / float() conversions for the `int` native and friends
// ---------------------------------------------------------------------------

/// Python `int(str)`: whitespace, optional sign, digit-only with optional
/// underscores (PEP 515), no base argument. Returns None on any parse error.
pub fn parse_py_int(s: &str) -> Option<i64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    let neg = t.starts_with('-');
    let pos = t.starts_with('+');
    let body = if neg || pos { &t[1..] } else { t };
    if body.is_empty() {
        return None;
    }
    let mut clean = String::new();
    for c in body.chars() {
        if c == '_' {
            continue;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        clean.push(c);
    }
    if clean.is_empty() {
        return None;
    }
    let n: u64 = clean.parse().ok()?;
    if neg {
        if n > (1u64 << 63) {
            return None;
        }
        if n == (1u64 << 63) {
            return Some(i64::MIN);
        }
        Some(-(n as i64))
    } else {
        if n > i64::MAX as u64 {
            return None;
        }
        Some(n as i64)
    }
}

/// The `int` native: Python `int(value)` with TypeError/ValueError mapped to 0
/// (exactly like jocky/stdlib.py where exceptions are swallowed).
pub fn int_native_value(v: &Value) -> i64 {
    match v {
        Value::Bool(b) => {
            if *b {
                1
            } else {
                0
            }
        }
        Value::Int(i) => *i,
        Value::Float(x) => {
            if *x != *x || *x > 9_223_372_036_854_775_807.0 || *x < -9_223_372_036_854_775_808.0 {
                return 0; // int(nan)/int(inf)/overflow -> 0
            }
            // truncation toward zero like Python int()
            *x as i64
        }
        Value::Str(s) => parse_py_int(s).unwrap_or(0),
        _ => 0,
    }
}

/// Strict float coercion for e.g. `sleep`: Python `float(x)` raises on bad
/// input (the caller wraps the failure like the natives in stdlib.py).
pub fn float_coerce(v: &Value) -> Result<f64, String> {
    match v {
        Value::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
        Value::Int(i) => Ok(*i as f64),
        Value::Float(x) => Ok(*x),
        Value::Str(s) => s.trim().parse::<f64>().map_err(|_| {
            format!("could not convert string to float: '{}'", s)
        }),
        other => Err("float() argument must be a string or a real number, not '"
            .to_string()
            + other.type_name()
            + "'"),
    }
}

// ---------------------------------------------------------------------------
// Python floor-modulo (the % operator) for i64 and f64
// ---------------------------------------------------------------------------

/// Python `a % b` for integers: result sign follows the divisor.
pub fn int_floor_mod(a: i64, b: i64) -> i64 {
    if b == 0 {
        return 0; // caller checks for zero; keep total here for safety
    }
    if b == -1 {
        return 0; // avoids a % -1 overflow at i64::MIN
    }
    let r = a % b;
    if r != 0 && (r < 0) != (b < 0) {
        r + b
    } else {
        r
    }
}

/// Python `a % b` for floats.
pub fn float_floor_mod(a: f64, b: f64) -> f64 {
    let r = a % b; // C-style remainder
    if r != 0.0 && (r < 0.0) != (b < 0.0) {
        r + b
    } else {
        r
    }
}

// ---------------------------------------------------------------------------
// Arithmetic (Python + - * / % and unary -) with VM-parity promotion rules:
//   int/bool op int/bool -> int (checked; overflow -> Err)
//   any float operand    -> float
//   ADD with a str operand -> py_str(a) + py_str(b)   (Python VM behaviour)
//   DIV is always float and any zero divisor -> Err("division by zero")
//   MOD is floor-mod (sign follows divisor); zero divisor -> Err
// ---------------------------------------------------------------------------

fn is_int_like(v: &Value) -> bool {
    matches!(v, Value::Int(_) | Value::Bool(_))
}

pub fn bin_arith(op: &str, a: &Value, b: &Value) -> Result<Value, String> {
    match op {
        "ADD" => {
            if matches!(a, Value::Str(_)) || matches!(b, Value::Str(_)) {
                return Ok(Value::Str(format!("{}{}", py_str(a), py_str(b))));
            }
            if is_int_like(a) && is_int_like(b) {
                let (x, y) = (a.to_i64().unwrap(), b.to_i64().unwrap());
                return x
                    .checked_add(y)
                    .map(Value::Int)
                    .ok_or_else(|| "integer addition overflow".to_string());
            }
            Ok(Value::Float(a.to_f64().unwrap_or(0.0) + b.to_f64().unwrap_or(0.0)))
        }
        "SUB" => {
            if is_int_like(a) && is_int_like(b) {
                let (x, y) = (a.to_i64().unwrap(), b.to_i64().unwrap());
                return x
                    .checked_sub(y)
                    .map(Value::Int)
                    .ok_or_else(|| "integer subtraction overflow".to_string());
            }
            Ok(Value::Float(a.to_f64().unwrap_or(0.0) - b.to_f64().unwrap_or(0.0)))
        }
        "MUL" => {
            if is_int_like(a) && is_int_like(b) {
                let (x, y) = (a.to_i64().unwrap(), b.to_i64().unwrap());
                return x
                    .checked_mul(y)
                    .map(Value::Int)
                    .ok_or_else(|| "integer multiplication overflow".to_string());
            }
            Ok(Value::Float(a.to_f64().unwrap_or(0.0) * b.to_f64().unwrap_or(0.0)))
        }
        "DIV" => {
            let bf = b.to_f64().unwrap_or(0.0);
            if bf == 0.0 {
                return Err("division by zero".to_string());
            }
            Ok(Value::Float(a.to_f64().unwrap_or(0.0) / bf))
        }
        "MOD" => {
            if is_int_like(a) && is_int_like(b) {
                let (x, y) = (a.to_i64().unwrap(), b.to_i64().unwrap());
                if y == 0 {
                    return Err("modulo by zero".to_string());
                }
                return Ok(Value::Int(int_floor_mod(x, y)));
            }
            let bf = b.to_f64().unwrap_or(0.0);
            if bf == 0.0 {
                return Err("modulo by zero".to_string());
            }
            Ok(Value::Float(float_floor_mod(
                a.to_f64().unwrap_or(0.0),
                bf,
            )))
        }
        other => Err(format!("unimplemented arithmetic op {other}")),
    }
}

/// Unary minus. Bool negates as its 0/1 integer value (Python parity).
pub fn neg(v: &Value) -> Value {
    match v {
        Value::Int(i) => Value::Int(i.wrapping_neg()),
        Value::Bool(b) => Value::Int(if *b { -1 } else { 0 }),
        Value::Float(x) => Value::Float(-*x),
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fr(x: f64) -> String {
        py_float_repr(x)
    }

    #[test]
    fn float_repr_common() {
        assert_eq!(fr(1.0), "1.0");
        assert_eq!(fr(0.5), "0.5");
        assert_eq!(fr(0.1), "0.1");
        assert_eq!(fr(3.14), "3.14");
        assert_eq!(fr(-2.5), "-2.5");
        assert_eq!(fr(123.456), "123.456");
        assert_eq!(fr(0.07), "0.07");
        assert_eq!(fr(2.675), "2.675");
        assert_eq!(fr(0.0), "0.0");
        assert_eq!(fr(-0.0), "-0.0");
        assert_eq!(fr(0.30000000000000004), "0.30000000000000004");
    }

    #[test]
    fn float_repr_ranges() {
        assert_eq!(fr(1e15), "1000000000000000.0");
        assert_eq!(fr(1e16), "1e+16");
        assert_eq!(fr(1e-4), "0.0001");
        assert_eq!(fr(1e-5), "1e-05");
        assert_eq!(fr(1e-7), "1e-07");
        assert_eq!(fr(1e100), "1e+100");
        assert_eq!(fr(1e308), "1e+308");
        assert_eq!(fr(1.7976931348623157e308), "1.7976931348623157e+308");
        assert_eq!(fr(5e-324), "5e-324");
        assert_eq!(fr(1.5e-300), "1.5e-300");
    }

    #[test]
    fn float_repr_specials() {
        assert_eq!(fr(f64::NAN), "nan");
        assert_eq!(fr(f64::INFINITY), "inf");
        assert_eq!(fr(f64::NEG_INFINITY), "-inf");
    }

    #[test]
    fn float_repr_roundtrip() {
        // every repr must parse back to the identical double
        for x in [0.1, 0.2, 1.0 / 3.0, 2.0_f64.powi(52), 42.0, 1e-17, 7.7] {
            let r = fr(x);
            let back: f64 = r.parse().unwrap();
            assert_eq!(back, x, "repr({x}) = {r} did not round-trip");
        }
    }

    #[test]
    fn equality_python() {
        assert!(value_eq(&Value::Int(1), &Value::Float(1.0)));
        assert!(value_eq(&Value::Bool(true), &Value::Int(1)));
        assert!(!value_eq(&Value::Int(1), &Value::Float(1.5)));
        assert!(!value_eq(&Value::Float(f64::NAN), &Value::Float(f64::NAN)));
        assert!(value_eq(
            &Value::List(vec![Value::Int(1), Value::Str("a".into())]),
            &Value::List(vec![Value::Int(1), Value::Str("a".into())])
        ));
        let d1 = Value::Dict(vec![(Value::Str("x".into()), Value::Int(1))]);
        let d2 = Value::Dict(vec![(Value::Str("x".into()), Value::Int(1))]);
        assert!(value_eq(&d1, &d2));
    }

    #[test]
    fn truthiness() {
        assert!(!Value::None.truthy());
        assert!(!Value::Int(0).truthy());
        assert!(!Value::Float(0.0).truthy());
        assert!(Value::Float(f64::NAN).truthy());
        assert!(!Value::Str("".into()).truthy());
        assert!(Value::Str("x".into()).truthy());
        assert!(Value::List(vec![]).truthy() == false);
        assert!(Value::List(vec![Value::None]).truthy());
    }

    #[test]
    fn floor_mod() {
        assert_eq!(int_floor_mod(-7, 3), 2); // Python: -7 % 3 == 2
        assert_eq!(int_floor_mod(7, -3), -2); // Python: 7 % -3 == -2
        assert_eq!(int_floor_mod(7, 3), 1);
        assert_eq!(int_floor_mod(-7, -3), -1);
        assert_eq!(float_floor_mod(-7.0, 3.0), 2.0);
        assert_eq!(float_floor_mod(7.0, -3.0), -2.0);
        assert_eq!(int_floor_mod(i64::MIN, -1), 0);
    }

    #[test]
    fn py_int_parse() {
        assert_eq!(parse_py_int("42"), Some(42));
        assert_eq!(parse_py_int("  -7  "), Some(-7));
        assert_eq!(parse_py_int("+5"), Some(5));
        assert_eq!(parse_py_int("1_000"), Some(1000));
        assert_eq!(parse_py_int(""), None);
        assert_eq!(parse_py_int("3.14"), None);
        assert_eq!(parse_py_int("abc"), None);
        assert_eq!(parse_py_int("-9223372036854775808"), Some(i64::MIN));
        assert_eq!(parse_py_int("9223372036854775808"), None);
    }

    #[test]
    fn int_native() {
        assert_eq!(int_native_value(&Value::Float(3.7)), 3);
        assert_eq!(int_native_value(&Value::Float(-3.7)), -3);
        assert_eq!(int_native_value(&Value::Str("42".into())), 42);
        assert_eq!(int_native_value(&Value::Str("abc".into())), 0);
        assert_eq!(int_native_value(&Value::None), 0);
        assert_eq!(int_native_value(&Value::Bool(true)), 1);
        assert_eq!(int_native_value(&Value::Float(f64::NAN)), 0);
    }

    #[test]
    fn repr_str_python() {
        assert_eq!(py_repr_str("a"), "'a'");
        assert_eq!(py_repr_str("it's"), "\"it's\"");
        assert_eq!(py_repr_str("a\nb"), "'a\\nb'");
        assert_eq!(py_repr_str("a\tb"), "'a\\tb'");
        assert_eq!(py_repr_str("x\\y"), "'x\\\\y'");
        assert_eq!(py_str(&Value::Str("a".into())), "a");
        assert_eq!(
            py_str(&Value::List(vec![Value::Str("a".into()), Value::Int(1)])),
            "['a', 1]"
        );
        assert_eq!(
            py_str(&Value::Dict(vec![(Value::Str("k".into()), Value::Str("v".into()))])),
            "{'k': 'v'}"
        );
        assert_eq!(py_str(&Value::Bool(true)), "True");
        assert_eq!(py_str(&Value::None), "None");
    }

    #[test]
    fn cmp_semantics() {
        use std::cmp::Ordering::*;
        assert_eq!(value_cmp(&Value::Int(1), &Value::Float(1.5), "<").unwrap(), Some(Less));
        assert_eq!(value_cmp(&Value::Str("a".into()), &Value::Str("b".into()), "<").unwrap(), Some(Less));
        assert_eq!(value_cmp(&Value::Str("ab".into()), &Value::Str("a".into()), ">").unwrap(), Some(Greater));
        assert!(value_cmp(&Value::Float(f64::NAN), &Value::Int(3), "<").unwrap().is_none());
        assert!(value_cmp(&Value::Str("a".into()), &Value::Int(1), "<").is_err());
        assert_eq!(
            value_cmp(
                &Value::List(vec![Value::Int(1), Value::Int(2)]),
                &Value::List(vec![Value::Int(1), Value::Int(3)]),
                "<"
            )
            .unwrap(),
            Some(Less)
        );
    }

    #[test]
    fn str_ordering_is_codepoint() {
        // "é" (U+00E9) sorts after "a"; Rust byte ordering of UTF-8 matches
        let a = Value::Str("a".into());
        let b = Value::Str("é".into());
        assert_eq!(value_cmp(&a, &b, "<").unwrap(), Some(Ordering::Less));
    }
}
#[cfg(test)]
mod dbg_probe {
    #[test]
    fn probe_denormal() {
        let x: f64 = 5e-324;
        println!("fmt .1e  = {}", format!("{:.1e}", x));
        println!("fmt e    = {}", format!("{:e}", x));
        println!("parse eq = {}", "5e-324".parse::<f64>() == Ok(x));
        println!("parse val= {:?}", "5e-324".parse::<f64>());
    }
}
