extern crate cbindgen;
extern crate regex;
extern crate serde;
extern crate serde_json;

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Serialize;

#[derive(Serialize)]
struct Constant {
    name: String,
    value: usize,
}

#[derive(Serialize)]
struct Alias {
    name: String,
    typename: String,
}

#[derive(Serialize)]
struct Param {
    name: String,
    typename: String,
}

#[derive(Serialize)]
struct Function {
    name: String,
    return_param: String,
    input_params: Vec<Param>,
}

#[derive(Serialize)]
struct Data {
    constants: Vec<Constant>,
    aliases: Vec<Alias>,
    callbacks: Vec<Function>,
    functions: Vec<Function>,
}

fn parse_param(params_raw: &str) -> Vec<Param> {
    // function param
    let param_pattern = Regex::new(r"(?m)(?P<type>(\w+ \**)+)(?P<name>\w+)").unwrap();
    // pattern for our gosling structs
    let struct_gosling_pattern = Regex::new(r"(?m)struct (?P<name>gosling_[\w]+) ").unwrap();

    let mut params: Vec<Param> = Default::default();
    for param in param_pattern.captures_iter(params_raw) {
        let t = &param["type"];
        let t = match struct_gosling_pattern.captures(t) {
            Some(cap) => struct_gosling_pattern.replace(t, &cap["name"]).to_string(),
            None => t.to_string(),
        };
        let t = t.replace(" *", "*");
        let n = &param["name"];

        params.push(Param {
            name: n.to_string(),
            typename: t.trim().to_string(),
        });
    }
    params
}

fn parse_header(mut file: File, source: &str) {
    // hacky-preprocess to exclude relevant platform-specific declarations
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let platform_pattern =
        Regex::new(r"(?m)#if defined\(GOSLING_PLATFORM_WINDOWS\)([^#].*\n)+#endif").unwrap();
    #[cfg(target_os = "windows")]
    let platform_pattern = Regex::new(r"(?m)#if \(defined\(GOSLING_PLATFORM_LINUX\) \|\| defined\(GOSLING_PLATFORM_MACOS\)\)([^#].*\n)+#endif").unwrap();

    let source = platform_pattern.replace_all(source, "").to_string();
    let source = source.as_str();

    // enum pattern
    let enum_pattern = Regex::new(r"(?m)enum \{(?P<constants>[\w\n ,=]*)}").unwrap();
    // constant pattern
    let constant_pattern =
        Regex::new(r"(?m)(?P<name>gosling_\w*) = (?P<value>[1-9][0-9]+),").unwrap();
    // primitive types
    let typedef_pattern =
        Regex::new(r"(?m)typedef (?P<type>[\w \*]+) (?P<name>gosling_[\w]+);").unwrap();
    // callback types
    let callback_pattern = Regex::new(r"(?m)typedef (?P<return>[\w \*]+) \(\*(?P<name>gosling_[\w]+_t)\)\((?P<params>[\w ,\*]*)\);").unwrap();
    // function declaration
    let function_pattern = Regex::new(
        r"(?m)(?P<return>[\w \*]+( | \*))(?P<name>gosling_[\w]+)\((?P<params>[\w ,\*]*)\);",
    )
    .unwrap();

    let mut constants: Vec<Constant> = Default::default();
    let mut aliases: Vec<Alias> = Default::default();
    let mut callbacks: Vec<Function> = Default::default();
    let mut functions: Vec<Function> = Default::default();

    // parse constants
    match enum_pattern.captures(source) {
        Some(cap) => {
            let c = &cap["constants"];
            for constant in constant_pattern.captures_iter(c) {
                let n = &constant["name"];
                let v = constant["value"].parse::<usize>().unwrap();
                constants.push(Constant {
                    name: n.to_string(),
                    value: v,
                });
            }
        }
        None => panic!("missing constants enum"),
    }

    // parse aliases
    for alias in typedef_pattern.captures_iter(source) {
        let t = &alias["type"];
        let n = &alias["name"];

        if t == format!("struct {}", n) {
            aliases.push(Alias {
                name: n.to_string(),
                typename: "uintptr_t".to_string(),
            });
        } else {
            aliases.push(Alias {
                name: n.to_string(),
                typename: t.trim().to_string(),
            });
        }
    }

    // parse callback defenitions
    for callback in callback_pattern.captures_iter(source) {
        let r = &callback["return"];
        let n = &callback["name"];
        let p = &callback["params"];

        // move the pointer char next to the type
        let r = r.trim().replace(" *", "*");

        let params = parse_param(p);
        callbacks.push(Function {
            name: n.to_string(),
            return_param: r,
            input_params: params,
        });
    }

    // parse function declaration
    for function in function_pattern.captures_iter(source) {
        let r = &function["return"];
        let n = &function["name"];
        let p = &function["params"];

        // move the pointer char next to the type
        let r = r.trim().replace(" *", "*");

        let params = parse_param(p);
        functions.push(Function {
            name: n.to_string(),
            return_param: r,
            input_params: params,
        });
    }

    let data = Data {
        constants,
        aliases,
        callbacks,
        functions,
    };
    writeln!(file, "{}", serde_json::to_string_pretty(&data).unwrap()).unwrap();
}

fn main() {

    if cfg! (not(feature = "impl-lib")) {
        // set by cargo
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        // Set by the user or by cmake.
        let target_dir = match std::env::var("CARGO_TARGET_DIR") {
            Ok(target) => PathBuf::from(target),
            Err(_) => Path::new(&crate_dir).join("target"),
        };

        let header_file_path = target_dir.join("include").join("cgosling.h");
        println!("cargo:rerun-if-changed={}",header_file_path.display());

        // generate libgosling.h C header
        match cbindgen::generate(&crate_dir) {
            Ok(bindings) => bindings.write_to_file(header_file_path.clone().into_os_string()),
            Err(cbindgen::Error::ParseSyntaxError { .. }) => return, // ignore in favor of cargo's syntax check
            Err(err) => panic!("{:?}", err),
        };

        // convert generated header to json IDL
        let json_file_path = target_dir.join("cgosling.json");
        println!("cargo:rerun-if-changed={}",json_file_path.display());
        let json_file = match File::create(json_file_path) {
            Ok(file) => file,
            Err(err) => panic!("{:?}", err),
        };
        let source = std::fs::read_to_string(header_file_path).unwrap();

        parse_header(json_file, source.as_str());
    }
}
