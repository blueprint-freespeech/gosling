extern crate handlebars;
extern crate serde;
extern crate serde_json;

use handlebars::{handlebars_helper, Handlebars};
use regex::Regex;
use serde::{Deserialize};
use serde_json::Value;

#[derive(Deserialize)]
struct Param {
    #[allow(dead_code)]
    name: String,
    typename: String,
}

#[derive(Deserialize)]
struct Function {
    name: String,
    return_param: String,
    input_params: Vec<Param>,
}

handlebars_helper!(functionIsToString: |function: Function| {
    let input_params = &function.input_params;
    let handle_pattern = Regex::new(r"^const gosling_\w+\*$").unwrap();

    if function.return_param != "void" {
        false
    } else if input_params.len() != 4 {
        false
    } else if !handle_pattern.is_match(&input_params[0].typename) {
        false
    } else if input_params[1].typename != "char*" {
        false
    } else if input_params[2].typename != "size_t" {
        false
    } else if input_params[3].typename != "gosling_error**" {
        false
    } else {
        true
    }
});
handlebars_helper!(functionIsFree: |function: Function| {
    if function.return_param != "void" {
        false
    } else {
        let free_pattern = Regex::new(r"^gosling_[\w]+_free$").unwrap();
        if !free_pattern.is_match(&function.name) {
            false
        } else {
            true
        }
    }
});
handlebars_helper!(functionToObjectParam: |function: Function| {
    let from_param = &function.input_params[0];
    format!("{} obj", from_param.typename)
});
handlebars_helper!(toStringFunctionToSizeConstant: |function: Function| {
    let name = &function.name;
    let fromto_pattern = Regex::new(r"^gosling_(?P<from>\w+)_to_(?P<to>\w+)$").unwrap();
    let caps = fromto_pattern.captures(&name).unwrap();
    let (from, to) = (caps.name("from").unwrap().as_str(), caps.name("to").unwrap().as_str());
    format!("{}_{}_SIZE", from.to_uppercase(), to.to_uppercase())
});
handlebars_helper!(freeFunctionToType: |function: Function| {
    let typename = function.input_params[0].typename.clone();
    typename[0..typename.len() - 1].to_string()
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
    handlebars.register_helper("functionIsToString", Box::new(functionIsToString));
    handlebars.register_helper("functionIsFree", Box::new(functionIsFree));
    handlebars.register_helper("functionToObjectParam", Box::new(functionToObjectParam));
    handlebars.register_helper("toStringFunctionToSizeConstant", Box::new(toStringFunctionToSizeConstant));
    handlebars.register_helper("freeFunctionToType", Box::new(freeFunctionToType));

    handlebars.register_template_file("header", template).unwrap();

    let dest = std::fs::File::create(dest).unwrap();
    handlebars.render_to_write("header", &source, dest).unwrap();
}
