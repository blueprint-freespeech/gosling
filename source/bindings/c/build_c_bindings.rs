use handlebars::{handlebars_helper, Handlebars};
use serde_json::Value;

handlebars_helper!(to_uppercase: |str: String| {
    str.to_uppercase()
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
    handlebars.register_helper("to_uppercase", Box::new(to_uppercase));

    handlebars.register_template_file("source", template).unwrap();
    handlebars.register_escape_fn(|val| val.to_string());

    let dest = std::fs::File::create(dest).unwrap();
    handlebars.render_to_write("source", &source, dest).unwrap();
}
