//! jocky-rs — native VM CLI.
//!
//!   jocky-rs <image.jcx>              run a JOCKY bytecode image in RAM
//!   jocky-rs <payload.jxp> -k <hex>   verify + decrypt, then run (in RAM)
//!   jocky-rs --embed                  run the payload embedded at build time
//!   jocky-rs --info <image.jcx>       print image internals
//!
//! Exit codes mirror the Python CLI: 0 on success, 1 with
//! "jocky: error: ..." on stderr on failure.

use jocky_rs::bytecode::Image;
use jocky_rs::crypto;
use jocky_rs::vm::Vm;
use jocky_rs::PAYLOAD;
use std::io::Read;
use std::process::ExitCode;

fn err(msg: &str) -> ! {
    eprintln!("jocky: error: {msg}");
    std::process::exit(1);
}

fn run_bytes(blob: Vec<u8>) -> Result<(), String> {
    let image = Image::parse(&blob).map_err(|e| e.to_string())?;
    let mut vm = Vm::new(image);
    vm.run().map(|_| ()).map_err(|e| format!("VM: {e}"))
}

fn run_file(path: &str, key_hex: Option<&str>) -> Result<(), String> {
    let mut blob = Vec::new();
    std::fs::File::open(path)
        .and_then(|mut f| f.read_to_end(&mut blob))
        .map_err(|e| e.to_string())?;
    if let Some(k) = key_hex {
        let key = decode_hex(k)?;
        let plain = crypto::decrypt(&blob, &key).map_err(|e| e.to_string())?;
        return run_bytes(plain);
    }
    if blob.len() >= 8 && &blob[..8] == b"JYCRYPT1" {
        return Err(
            "payload is JYCRYPT1-encrypted; supply the key with -k <hex>".to_string(),
        );
    }
    run_bytes(blob)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex key".to_string());
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| format!("non-hex character in key at offset {}", i * 2))
        })
        .collect()
}

fn info_file(path: &str) -> Result<(), String> {
    let mut blob = Vec::new();
    std::fs::File::open(path)
        .and_then(|mut f| f.read_to_end(&mut blob))
        .map_err(|e| e.to_string())?;
    let image = Image::parse(&blob).map_err(|e| e.to_string())?;
    println!("build_id : {}", image
        .build_hash
        .map(|h| h.iter().map(|b| format!("{b:02x}")).take(8).collect::<String>())
        .unwrap_or_else(|| "-".to_string()));
    println!("magic    : JY_IMG01 v1");
    println!("code     : {} bytes", image.code.len());
    println!("consts   : {} entries", image.consts.len());
    println!("entry    : #{} {}", image.entry,
        image.funcs.get(image.entry).map(|f| f.name.clone()).unwrap_or_default());
    println!("functions:");
    for (i, f) in image.funcs.iter().enumerate() {
        println!("  {i:2}  {}({}) @ {:#06x}", f.name, f.params.join(", "), f.addr);
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut path: Option<String> = None;
    let mut key: Option<String> = None;
    let mut embed = false;
    let mut info = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-k" | "--key" => {
                i += 1;
                key = args.get(i).cloned();
                if key.is_none() {
                    err("missing argument for -k/--key");
                }
            }
            "--embed" => embed = true,
            "--info" => info = true,
            "-h" | "--help" => {
                println!("jocky-rs {}: native JOCKY VM (SIH26148)", jocky_rs::VERSION);
                println!("usage: jocky-rs <image.jcx> [-k <hex-key>] | --embed | --info <image.jcx>");
                return ExitCode::SUCCESS;
            }
            other => path = Some(other.to_string()),
        }
        i += 1;
    }

    if embed || path.is_none() {
        if PAYLOAD.is_empty() {
            eprintln!("jocky: error: no payload embedded at build time and no image given");
            return ExitCode::FAILURE;
        }
        let blob = match key.as_deref() {
            Some(k) => match decode_hex(k)
                .and_then(|key| crypto::decrypt(PAYLOAD, &key).map_err(|e| e.to_string()))
            {
                Ok(p) => p,
                Err(e) => err(&e),
            },
            None => PAYLOAD.to_vec(),
        };
        return match run_bytes(blob) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                err(&e);
                #[allow(unreachable_code)]
                ExitCode::FAILURE
            }
        };
    }

    let path = path.unwrap();
    let result = if info { info_file(&path) } else { run_file(&path, key.as_deref()) };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            err(&e);
            #[allow(unreachable_code)]
            ExitCode::FAILURE
        }
    }
}
