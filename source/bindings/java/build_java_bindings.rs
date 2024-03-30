use handlebars::{handlebars_helper, Handlebars};
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

handlebars_helper!(aliasToClassName: |name: String| {
    assert!(name.starts_with("gosling_"));
    let name = &name[8..];
    name.to_upper_camel_case()
});

handlebars_helper!(functionToNativeMethodName: |name: String| {
    assert!(name.starts_with("gosling_"));
    let name = &name[8..];
    name.to_lower_camel_case()
});

handlebars_helper!(aliasToNativeFreeMethodName: |name: String| {
    assert!(name.starts_with("gosling_"));
    let name = &name[8..];
    format!("{}Free", name.to_lower_camel_case())
});

handlebars_helper!(callbackToInterfaceName: |name: String| {
    assert!(name.starts_with("gosling_"));
    assert!(name.ends_with("callback_t"));
    let name = &name[8..name.len() - 10];
    format!("I{}Listener", name.to_upper_camel_case())
});

handlebars_helper!(callbackToInterfaceMethodName: |name: String| {
    assert!(name.starts_with("gosling_"));
    assert!(name.ends_with("callback_t"));
    let name = &name[8..name.len() - 10];
    format!("on{}Event", name.to_upper_camel_case())
});

handlebars_helper!(returnTypeToJavaType: |typename: String| {
    match typename.as_ref() {
        "void" => "void".to_string(),
        "bool" => "boolean".to_string(),
        "size_t" => "long".to_string(),
        "const char*" => "String".to_string(),
        "gosling_handshake_handle_t" => "long".to_string(),
        other => panic!("unhandled typename: {}", other),
    }
});

handlebars_helper!(inputParamsToJavaParams: |params: Vec<Param>| {
    let mut java_args: Vec<String> = Default::default();

    for param in params {
        let java_typename = match param.typename.as_ref() {
            "bool" => "boolean".to_string(),
            "uint8_t" => "byte".to_string(),
            "uint16_t" => "int".to_string(),
            "uint32_t" => "long".to_string(),
            "size_t" => {
                if param.name.ends_with("_size") ||
                   param.name.ends_with("_length") {
                    // we don't need size or length args because we'll use
                    // Strings or byte[]
                    continue;
                } else {
                    // othewise we assume it is likely being used as a handle
                    "long".to_string()
                }
            }
            "char*" => "Out<String>".to_string(),
            "const char*" => "String".to_string(),
            "const uint8_t*" => "byte[]".to_string(),
            "uint8_t*" => "byte[]".to_string(),
            "gosling_handshake_handle_t" => "long".to_string(),
            "gosling_tcp_socket_t" => "java.net.Socket".to_string(),
            other => {
                let other = if other.starts_with("const ") {
                    &other[6..]
                } else {
                    other
                };

                assert!(other.starts_with("gosling_"), "found {}", other);

                if other.ends_with("**") {
                    format!("Out<{}>", other[8..].to_upper_camel_case())
                } else if other.ends_with("*") {
                    other[8..other.len() - 1].to_upper_camel_case()
                } else if other.ends_with("_callback_t") {
                    format!("I{}Listener", other[8..other.len() - 10].to_upper_camel_case())
                } else {
                    panic!("unhandled typename: {}", other);
                }
            }
        };

        java_args.push(format!("{} {}", java_typename, param.name));
    }
    java_args.join(", ")
});

handlebars_helper!(returnTypeToJNIType: |typename: String| {
    match typename.as_ref() {
        "void" => "void".to_string(),
        "bool" => "jboolean".to_string(),
        "const char*" => "jstring".to_string(),
        "gosling_handshake_handle_t" => "jlong".to_string(),
        other => panic!("unhandled typename: {}", other),
    }
});

handlebars_helper!(inputParamsToJNIParams: |params: Vec<Param>| {
    let mut jni_args: Vec<String> = Default::default();
    // JNI functions always have these two params first
    jni_args.push("JNIEnv* env".to_string());
    jni_args.push("jclass".to_string());
    for param in params {
        let jni_typename = match param.typename.as_ref() {
            "uint16_t" => "jint".to_string(),
            "uint32_t" => "jlong".to_string(),
            "size_t" => {
                if param.name.ends_with("_size") ||
                   param.name.ends_with("_length") {
                    // we don't need size or length args because we'll use
                    // Strings or byte[]
                    continue;
                } else {
                    // othewise we assume it is likely being used as a handle
                    "jlong".to_string()
                }
            }
            "char*" => "jobject".to_string(),
            "const char*" => "jstring".to_string(),
            "gosling_handshake_handle_t" => "jlong".to_string(),
            other => {
                let other = if other.starts_with("const ") {
                    &other[6..]
                } else {
                    other
                };

                assert!(other.starts_with("gosling_"), "found '{}'", other);

                if other.ends_with("**") || other.ends_with("*") || other.ends_with("_callback_t") {
                    "jobject".to_string()
                } else {
                    panic!("unhandled typename: {}", other);
                }
            }
        };

        jni_args.push(format!("{} {}", jni_typename, param.name));
    }
    jni_args.join(", ")
});

handlebars_helper!(marshallJNIParams: |function_name: String, params: Vec<Param>| {
    let mut marshall_lines: Vec<String> = Default::default();
    macro_rules! cpp_src {
        ($($arg:tt)*) => {
            {
                let line = format!($($arg)*);
                let indented_line = format!("    {}", line);
                marshall_lines.push(indented_line);
            }
        };
    }

    for param in &params {
        let name: &str = param.name.as_ref();
        let typename: &str = param.typename.as_ref();

        match typename {
            "uint16_t" => cpp_src!("const uint16_t {name}_native = static_cast<uint16_t>({name});"),
            "const char*" => {
                cpp_src!("const char* {name}_native = ({name} ? env->GetStringUTFChars({name}, nullptr) : nullptr);");
            },
            "char*" => {
                // marshalled in as a jstring
                let fromto_pattern = Regex::new(r"^gosling_(?P<from>\w+)_to_(?P<to>\w+)$").unwrap();
                assert!(fromto_pattern.is_match(&function_name));
                let caps = fromto_pattern.captures(&function_name).unwrap();
                let (from, to) = (caps.name("from").unwrap().as_str(), caps.name("to").unwrap().as_str());
                let buffer_size = format!("{}_{}_SIZE", from.to_uppercase(), to.to_uppercase());
                cpp_src!("char {name}_native[{buffer_size}] = {{}};");
            },
            "size_t" => {
                if name.ends_with("_length") {
                    // handle length param for a const char* utf8 string
                    let jstring_name = &name[..name.len() - 7];
                    cpp_src!("const size_t {name}_native = ({jstring_name} ? static_cast<size_t>(env->GetStringUTFLength({jstring_name})) : 0);");
                } else if name.ends_with("_size") {
                    // handle size param for an out char* utf8 string
                    let fromto_pattern = Regex::new(r"^gosling_(?P<from>\w+)_to_(?P<to>\w+)$").unwrap();
                    assert!(fromto_pattern.is_match(&function_name));
                    let caps = fromto_pattern.captures(&function_name).unwrap();
                    let (from, to) = (caps.name("from").unwrap().as_str(), caps.name("to").unwrap().as_str());
                    let buffer_size = format!("{}_{}_SIZE", from.to_uppercase(), to.to_uppercase());
                    cpp_src!("constexpr size_t {name}_native = {buffer_size};");
                } else {
                    panic!("unhandled argument => {name}: {typename}");
                }
            },
            "gosling_handshake_handle_t" => cpp_src!("const gosling_handshake_handle_t {name}_native = static_cast<gosling_handshake_handle_t>({name});"),
            _ => {
                let const_gosling_pointer_pattern = Regex::new(r"^const gosling_\w+\*$").unwrap();
                let gosling_pointer_pattern = Regex::new(r"^gosling_\w+\*$").unwrap();
                let out_gosling_pointer_pattern = Regex::new(r"^gosling_\w+\*\*$").unwrap();
                let gosling_callback_pattern = Regex::new(r"^gosling_\w+_callback_t$").unwrap();

                if const_gosling_pointer_pattern.is_match(&typename) ||
                   gosling_pointer_pattern.is_match(&typename) {
                    cpp_src!("{typename} {name}_native = reinterpret_cast<{typename}>(g_jni_glue->jobject_handle_to_void_pointer(env, {name}));");
                    if name.starts_with("in_") {
                        cpp_src!("g_jni_glue->invalidate_jobject_handle(env, {name});");
                    }
                } else if out_gosling_pointer_pattern.is_match(&typename) {
                    cpp_src!("{typename} {name}_dest = nullptr;", typename=&typename[..typename.len()-1]);
                    cpp_src!("{typename} {name}_native = &{name}_dest;");
                } else if gosling_callback_pattern.is_match(&typename) {
                    let callback = &typename[8..typename.len() -2];
                              cpp_src!("if (std::lock_guard<std::mutex> lock(g_jni_glue->listener_map_mutex); true) {{");
                    cpp_src!("    auto it = g_jni_glue->listener_map.find(context_native);");
                    cpp_src!("    assert(it != g_jni_glue->listener_map.end());");
                    cpp_src!("    jobject& callback_jni = it->second.{callback};");
                    cpp_src!("    if (callback_jni != nullptr) env->DeleteGlobalRef(callback_jni);");
                    cpp_src!("    callback_jni = env->NewGlobalRef(callback);");
                    cpp_src!("}}");
                    cpp_src!("{typename} {name}_native = ({name} ? {callback}_impl : nullptr);");
                } else {
                    panic!("unhandled argument => {name}: {typename}");
                }
            }
        }
    }
    marshall_lines.join("\n")
});

handlebars_helper!(callNativeFunction: |func_name: String, return_type: String, params: Vec<Param>| {
    let mut marshall_lines: Vec<String> = Default::default();
    macro_rules! cpp_src {
        ($($arg:tt)*) => {
            {
                let line = format!($($arg)*);
                let indented_line = format!("    {}", line);
                marshall_lines.push(indented_line);
            }
        };
    }

    let mut args: Vec<String> = Default::default();

    for param in params {
        let name = &param.name;
        args.push(format!("{name}_native"));
    }

    if return_type == "void" {
        cpp_src!("::{func_name}({});", args.join(", "))
    } else {
        cpp_src!("{return_type} result_native = ::{func_name}({});", args.join(", "))
    }

    // custom logic for context to regsiter/unregister java callbacks
    match func_name.as_ref() {
        "gosling_context_init" => {
            cpp_src!("std::lock_guard<std::mutex> lock(g_jni_glue->listener_map_mutex);");
            cpp_src!("g_jni_glue->listener_map.insert({{out_context_dest, {{}}}});");
        },
        "gosling_context_free" => {
            cpp_src!("std::lock_guard<std::mutex> lock(g_jni_glue->listener_map_mutex);");
            cpp_src!("g_jni_glue->listener_map.erase(g_jni_glue->listener_map.find(in_context_native));");
        },
        _ => (),
    }
    marshall_lines.join("\n")
});

handlebars_helper!(marshallNativeResults: |return_type: String, params: Vec<Param>| {
    let mut marshall_lines: Vec<String> = Default::default();
    macro_rules! cpp_src {
        ($($arg:tt)*) => {
            {
                let line = format!($($arg)*);
                let indented_line = format!("    {}", line);
                marshall_lines.push(indented_line);
            }
        };
    }

    // marshall native results to jni types
    for param in &params {
        let name: &str = param.name.as_ref();
        let typename: &str = param.typename.as_ref();

        match typename {
            "uint16_t" | "size_t" | "gosling_handshake_handle_t" => (),
            "const char*" => {
                cpp_src!("env->ReleaseStringUTFChars({name}, {name}_native);");
            },
            "char*" => {
                cpp_src!("g_jni_glue->set_out_jstring(env, {name}, {name}_native);");
            }
            _ => {
                let const_gosling_pointer_pattern = Regex::new(r"^const gosling_\w+\*$").unwrap();
                let gosling_pointer_pattern = Regex::new(r"^gosling_\w+\*$").unwrap();
                let out_gosling_pointer_pattern = Regex::new(r"^gosling_(?P<java_typename>\w+)\*\*$").unwrap();
                let gosling_callback_pattern = Regex::new(r"^gosling_\w+_callback_t$").unwrap();

                if const_gosling_pointer_pattern.is_match(&typename) ||
                   gosling_pointer_pattern.is_match(&typename) {
                    // nothing to do here
                } else if out_gosling_pointer_pattern.is_match(&typename) {
                    let caps = out_gosling_pointer_pattern.captures(&typename).unwrap();
                    let java_typename = caps.name("java_typename").unwrap().as_str();
                    let java_typename = java_typename.to_upper_camel_case();

                    cpp_src!("g_jni_glue->set_out_jobject_handle(env, {name}, \"net/blueprintforfreespeech/gosling/Gosling${java_typename}\", {name}_dest);");
                } else if gosling_callback_pattern.is_match(&typename) {
                    // nothing to do here
                } else {
                    panic!("unhandled argument => {name}: {typename}");
                }
            }
        }
    }

    if return_type != "void" {
        marshall_lines.push("".to_string());
        match return_type.as_ref() {
            "bool" => cpp_src!("return result_native ? JNI_TRUE : JNI_FALSE;"),
            "gosling_handshake_handle_t" => cpp_src!("return static_cast<jlong>(result_native);"),
            "const char*" => cpp_src!("return env->NewStringUTF(result_native);"),
            _ => println!("unhandled return => {return_type}"),
        }
    }

    marshall_lines.join("\n")
});

handlebars_helper!(callbackNameToMapName: |callback: String| {
    assert!(callback.starts_with("gosling_"));
    assert!(callback.ends_with("_callback_t"));

    callback[8..callback.len() - 2].to_string()
});

handlebars_helper!(inputParamsToNativeParams: |input_params: Vec<Param>| {
    let mut args: Vec<String> = Default::default();

    for param in input_params {
        let name: &str = param.name.as_ref();
        let typename: &str = param.typename.as_ref();
        args.push(format!("{typename} {name}"));
    }
    args.join(", ")
});

handlebars_helper!(marshallNativeParams: |input_params: Vec<Param>| {
    let mut marshall_lines: Vec<String> = Default::default();
    macro_rules! cpp_src {
        ($($arg:tt)*) => {
            {
                let line = format!($($arg)*);
                let indented_line = format!("    {}", line);
                marshall_lines.push(indented_line);
            }
        };
    }

    for param in input_params {
        let name: &str = param.name.as_ref();
        let typename: &str = param.typename.as_ref();

        match typename {
            "bool" => cpp_src!("const jboolean {name}_jni = ({name} ? JNI_TRUE : JNI_FALSE);"),
            "uint32_t" => cpp_src!("const jlong {name}_jni = static_cast<jlong>({name});"),
            "const char*" => cpp_src!("jstring {name}_jni = env->NewStringUTF({name});"),
            "size_t" => {
                if name.ends_with("_size") || name.ends_with("_length") {
                    continue;
                } else {
                    panic!("unexpected param -> {name} : {typename}");
                }
            },
            "const uint8_t*" => {
                cpp_src!("jbyteArray {name}_jni = env->NewByteArray({name}_size);");
                cpp_src!("env->SetByteArrayRegion({name}_jni, 0, {name}_size, reinterpret_cast<const jbyte*>({name}));");
            },
            "uint8_t*" => {
                cpp_src!("jbyteArray {name}_jni = env->NewByteArray({name}_size);");
                cpp_src!("jbyte* {name}_jni_buffer = env->GetByteArrayElements({name}_jni, nullptr);");
                cpp_src!("std::fill({name}_jni_buffer, {name}_jni_buffer + {name}_size, jbyte(0));");
                cpp_src!("env->ReleaseByteArrayElements({name}_jni, {name}_jni_buffer, 0);");
            },
            "gosling_handshake_handle_t" => cpp_src!("const jlong {name}_jni = static_cast<jlong>({name});"),
            "gosling_tcp_socket_t" => {
                cpp_src!("jobject {name}_jni = g_jni_glue->tcp_stream_to_java_socket(env, {name});");
            },
            _ => {
                assert!(typename.starts_with("gosling_") || typename.starts_with("const gosling_"));
                assert!(!typename.ends_with("**"));
                assert!(typename.ends_with("*"));

                match typename {
                    "gosling_context*" => cpp_src!("jobject {name}_jni = g_jni_glue->void_pointer_to_jobject_handle(env, \"net/blueprintforfreespeech/gosling/Gosling$Context\", {name}, true);"),
                    _ => {
                        if typename.starts_with("const gosling_") {
                            let typename = &typename[6..];
                            cpp_src!("{typename} {name}_clone = nullptr;");
                            cpp_src!("gosling_error* {name}_clone_error = nullptr;");
                            let typename = &typename[..typename.len() - 1];
                            cpp_src!("::{typename}_clone(&{name}_clone, {name}, &{name}_clone_error);");
                            cpp_src!("assert({name}_clone_error == nullptr);");
                            let classname = typename[8..].to_upper_camel_case();
                            cpp_src!("jobject {name}_jni = g_jni_glue->void_pointer_to_jobject_handle(env, \"net/blueprintforfreespeech/gosling/Gosling${classname}\", {name}_clone, false);");
                        } else {
                            panic!("unhandled param -> {name}: {typename}");
                        }
                    },
                }
            }
        }
    }
    marshall_lines.join("\n")
});

handlebars_helper!(callJavaCallback: |name: String, return_type: String, input_params: Vec<Param>| {
    let mut marshall_lines: Vec<String> = Default::default();
    macro_rules! cpp_src {
        ($($arg:tt)*) => {
            {
                let line = format!($($arg)*);
                let indented_line = format!("    {}", line);
                marshall_lines.push(indented_line);
            }
        };
    }

    match return_type.as_ref() {
        "void" => (),
        "bool" => cpp_src!("jboolean result_jni = JNI_FALSE;"),
        "size_t" => cpp_src!("jlong result_jni = jlong(0);"),
        __ => panic!("unhandled return -> {return_type}"),
    };
    cpp_src!("if (std::lock_guard<std::mutex> lock(g_jni_glue->listener_map_mutex); true) {{");
    cpp_src!("    auto it = g_jni_glue->listener_map.find(context);");
    cpp_src!("    assert(it != g_jni_glue->listener_map.end());");
    let jni_callback_name = &name[8..name.len()-2];
    cpp_src!("    const jobject& callback_jni = it->second.{jni_callback_name};");
    cpp_src!("    assert(callback_jni != nullptr);");
    cpp_src!("    jclass jc = env->GetObjectClass(callback_jni);");
    cpp_src!("    assert(jc != nullptr);");
    let callback_name = jni_callback_name[..jni_callback_name.len() - 9].to_upper_camel_case();
    let method_name = format!("on{callback_name}Event");
    cpp_src!("    const auto method_name = \"{method_name}\";");

    let mut method_params_signature: Vec<String> = Default::default();
    for param in &input_params {
        let name: &str = param.name.as_ref();
        let typename: &str = param.typename.as_ref();
        let param_signature = match typename {
            "bool" => "Z".to_string(),
            "uint32_t" | "gosling_handshake_handle_t" => "J".to_string(),
            "const char*" => "Ljava/lang/String;".to_string(),
            "const uint8_t*" | "uint8_t*" => "[B".to_string(),
            "gosling_tcp_socket_t" => "Ljava/net/Socket;".to_string(),
            "size_t" => {
                if name.ends_with("_size") || name.ends_with("_length") {
                    continue;
                } else {
                    panic!("unhandled param -> {name}: {typename}");
                }
            }
            _ => {
                assert!(typename.starts_with("gosling_") || typename.starts_with("const gosling_"));
                assert!(!typename.ends_with("**"));
                assert!(typename.ends_with("*"));

                let typename = if typename.starts_with("const gosling_") {
                    &typename[14..typename.len()-1]
                } else {
                    &typename[8..typename.len()-1]
                };
                format!("Lnet/blueprintforfreespeech/gosling/Gosling${};", typename.to_upper_camel_case())
            },
        };
        method_params_signature.push(param_signature);
    }
    let method_params_signature = method_params_signature.join("");
    let method_return_signature = match return_type.as_ref() {
        "void" => "V",
        "bool" => "Z",
        "size_t" => "J",
        _ => panic!("unhandled return -> {return_type}"),
    };

    let method_signature = format!("({method_params_signature}){method_return_signature}");
    cpp_src!("    const auto method_signature = \"{method_signature}\";");
    cpp_src!("    jmethodID method_id = env->GetMethodID(jc, method_name, method_signature);");
    cpp_src!("    assert(method_id != nullptr);");

    let mut call_method_params: Vec<String> = Default::default();
    call_method_params.push("callback_jni".to_string());
    call_method_params.push("method_id".to_string());
    for param in &input_params {
        let typename: &str = param.typename.as_ref();
        let name: &str = param.name.as_ref();
        if typename == "size_t" {
            assert!(name.ends_with("_length") || name.ends_with("_size"));
            continue;
        } else {
            call_method_params.push(format!("{name}_jni"));
        }
    }
    let call_method_params = call_method_params.join(", ");

    match return_type.as_ref() {
        "void" => cpp_src!("    env->CallVoidMethod({call_method_params});"),
        "bool" => cpp_src!("    result_jni = env->CallBooleanMethod({call_method_params});"),
        "size_t" => cpp_src!("    result_jni = env->CallLongMethod({call_method_params});"),
        _ => panic!("unhandled return -> {return_type}"),
    };
    cpp_src!("}}");

    marshall_lines.join("\n")
});

handlebars_helper!(marshallJNIResults: |return_type: String, input_params: Vec<Param>| {
    let mut marshall_lines: Vec<String> = Default::default();
    macro_rules! cpp_src {
        ($($arg:tt)*) => {
            {
                let line = format!($($arg)*);
                let indented_line = format!("    {}", line);
                marshall_lines.push(indented_line);
            }
        };
    }

    for param in input_params {
        let name: &str = param.name.as_ref();
        let typename: &str = param.typename.as_ref();

        match typename {
            "bool" | "uint32_t" | "size_t" | "gosling_handshake_handle_t" => {},
            "const char*" |"const uint8_t*" => cpp_src!("env->DeleteLocalRef({name}_jni);"),
            "uint8_t*" => {
                cpp_src!("{name}_jni_buffer = env->GetByteArrayElements({name}_jni, nullptr);");
                cpp_src!("std::copy({name}_jni_buffer, {name}_jni_buffer + {name}_size, {name});");
                cpp_src!("env->ReleaseByteArrayElements({name}_jni, {name}_jni_buffer, JNI_ABORT);");
                cpp_src!("env->DeleteLocalRef({name}_jni);");
            }
            "gosling_tcp_socket_t" => cpp_src!("env->DeleteLocalRef({name}_jni);"),
            _ => {
                assert!(typename.starts_with("gosling_") || typename.starts_with("const gosling_"));
                assert!(!typename.ends_with("**"));
                assert!(typename.ends_with("*"));

                cpp_src!("env->DeleteLocalRef({name}_jni);");
            },
        }
    }

    if return_type != "void" {
        marshall_lines.push("".to_string());
        match return_type.as_ref() {
            "bool" => cpp_src!("return (result_jni == JNI_TRUE);"),
            "size_t" => cpp_src!("return static_cast<size_t>(result_jni);"),
            _ => panic!("unhandled return -> {return_type}"),
        }
    }
    marshall_lines.join("\n")
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

    // .java helpers
    handlebars.register_helper("aliasToClassName", Box::new(aliasToClassName));
    handlebars.register_helper("functionToNativeMethodName", Box::new(functionToNativeMethodName));
    handlebars.register_helper("aliasToNativeFreeMethodName", Box::new(aliasToNativeFreeMethodName));
    handlebars.register_helper("callbackToInterfaceName", Box::new(callbackToInterfaceName));
    handlebars.register_helper("callbackToInterfaceMethodName", Box::new(callbackToInterfaceMethodName));
    handlebars.register_helper("returnTypeToJavaType", Box::new(returnTypeToJavaType));
    handlebars.register_helper("inputParamsToJavaParams", Box::new(inputParamsToJavaParams));

    // .cpp helpers
    handlebars.register_helper("returnTypeToJNIType", Box::new(returnTypeToJNIType));
    handlebars.register_helper("inputParamsToJNIParams", Box::new(inputParamsToJNIParams));
    handlebars.register_helper("marshallJNIParams", Box::new(marshallJNIParams));
    handlebars.register_helper("callNativeFunction", Box::new(callNativeFunction));
    handlebars.register_helper("marshallNativeResults", Box::new(marshallNativeResults));
    handlebars.register_helper("callbackNameToMapName", Box::new(callbackNameToMapName));
    handlebars.register_helper("inputParamsToNativeParams", Box::new(inputParamsToNativeParams));
    handlebars.register_helper("marshallNativeParams", Box::new(marshallNativeParams));
    handlebars.register_helper("callJavaCallback", Box::new(callJavaCallback));
    handlebars.register_helper("marshallJNIResults", Box::new(marshallJNIResults));

    handlebars.register_template_file("source", template).unwrap();
    handlebars.register_escape_fn(|val| val.to_string());

    let dest = std::fs::File::create(dest).unwrap();
    handlebars.render_to_write("source", &source, dest).unwrap();
}
