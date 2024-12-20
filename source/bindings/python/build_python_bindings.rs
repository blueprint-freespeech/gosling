use handlebars::{handlebars_helper, Handlebars, ScopedJson};
use heck::*;
use regex::Regex;
use serde::{Deserialize};
use serde_json::Value;


#[derive(Deserialize)]
struct Constant {
    name: String,
    value: usize,
}

#[derive(Deserialize)]
struct Param {
    name: String,
    typename: String,
}

#[derive(Deserialize)]
struct Function {
    name: String,
    return_param: String,
    input_params: Vec<Param>,
}

handlebars_helper!(toUppercase: |string: String| {
    string.to_uppercase()
});

handlebars_helper!(snakeCaseToCamelCase: |snake_case: String| {
    snake_case.to_upper_camel_case()
});

handlebars_helper!(nativeTypeToPythonType: |native_type: String| {
    let mut pointer_count = 0;
    let native_type = if native_type.ends_with("**") {
        pointer_count = 2;
        native_type[..native_type.len() - 2].to_string()
    } else if native_type.ends_with("*") {
        pointer_count = 1;
        native_type[..native_type.len() - 1].to_string()
    } else if native_type.contains("*") {
        panic!("unhandled pointer type: '{}'", native_type);
    } else {
        native_type
    };

    // strip const
    let native_type = if native_type.starts_with("const ") {
        native_type[6..].to_string()
    } else {
        native_type.to_string()
    };

    let python_type = match native_type.as_str() {
        "void" => "None".to_string(),
        "bool" => "c_bool".to_string(),
        "char" => "c_char".to_string(),
        "int" => "c_int".to_string(),
        "SOCKET" => "c_size_t".to_string(),
        "size_t" => "c_size_t".to_string(),
        "uint8_t" => "c_uint8".to_string(),
        "uint16_t" => "c_uint16".to_string(),
        "uint32_t" => "c_uint32".to_string(),
        native_type => {
            if native_type.starts_with("gosling_") && native_type.ends_with("callback_t") {
                // a callback
                native_type[..native_type.len() - 2].to_upper_camel_case()
            } else if native_type.starts_with("gosling_") && native_type.ends_with("_t") {
                // a typedef
                native_type[..native_type.len() - 2].to_upper_camel_case()
            } else if native_type.starts_with("gosling_") {
                // a gosling struct
                native_type.to_upper_camel_case()
            } else {
                panic!("unhandled native type conversion: '{}'", native_type);
            }
        }
    };

    let python_type = match python_type.as_ref() {
        "c_char" => match pointer_count {
            0 => python_type,
            1 => {
                pointer_count = 0;
                "c_char_p".to_string()
            },
            count => panic!("unexpected char**"),
        },
        "None" => match pointer_count {
            0 => python_type,
            1 => {
                pointer_count = 0;
                "py_object".to_string()
            },
            count => panic!("unexpected void**"),
        },
        _ => python_type
    };

    match pointer_count {
        0 => python_type,
        1 => format!("POINTER({})", python_type),
        2 => format!("POINTER(POINTER({}))", python_type),
        count => panic!("impossible pointer count: {}", count),
    }
});

fn main() {

    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 4);

    let source = &args[1];
    let template = &args[2];
    let dest = &args[3];

    let source = std::fs::read_to_string(source).unwrap();
    let source: Value = serde_json::from_str(source.as_str()).unwrap();

    let mut handlebars = Handlebars::new();
    handlebars.register_helper("toUppercase", Box::new(toUppercase));
    handlebars.register_helper("snakeCaseToCamelCase", Box::new(snakeCaseToCamelCase));
    handlebars.register_helper("nativeTypeToPythonType", Box::new(nativeTypeToPythonType));

    handlebars.register_template_file("source", template).unwrap();
    handlebars.register_escape_fn(|val| val.to_string());

    let dest = std::fs::File::create(dest).unwrap();
    handlebars.render_to_write("source", &source, dest).unwrap();
}
