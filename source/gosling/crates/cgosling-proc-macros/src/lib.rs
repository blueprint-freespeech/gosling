use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

// This macro renames a function call to a _impl variant.
//
// Why is this necessary? Basically, cargo  cannot currently be relied
// on to build cdylibs correctly due to various issues limited to but
// probably not including:
// - not setting soname for linux shared libraries
// - naming import libs incorrectly for mingw windows
// - not generating correct symlinks based on version and major version for linux and macos
//
// The recommended solution is to use the cdylib_link_lines crate to work around
// some of these problems, but I've run into other fun issues with that crate:
// - import libs output to wrong directory for mingw windows
// - import_name being set incorrectly for macos
// - hasn't been updated in some years and seems abandoned
//
// So now dear reader, we come to this monstrosity. This is just one part of
// the rest of the build system hack to solve all the above problems; namely
// we will only use rustc to generate a static library, and from there build
// a shared library using native C tools via CMake which handles all of the
// above problems.
//
// So we need to build our cgosling crate as a static lib twice: first with the
// ordinary functions names and second with the functions renamed in the form
// foo() to foo_impl(). The foo_impl() variant will then be linked into a shared
// library and called through exported functions of the foo() variety using
// the ordinary toolchain.
//
// The cgosling shared library target will call the underlying functions via simple
// passthrough with the final (logical) call chain being like a so:
// - shared_library::foo() -> static_library::foo_impl()
//
// Static library callers will have the following call chain:
// - static_library::foo()
//
// I'm sorry it had to be this way
#[proc_macro_attribute]
pub fn rename_impl(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // parse the input as a function
    let mut impl_fn: ItemFn = parse_macro_input!(item);

    // append "_impl" to the original function name for the _impl function
    impl_fn.sig.ident = syn::Ident::new(
        &format!("{}_impl", impl_fn.sig.ident),
        impl_fn.sig.ident.span(),
    );

    let expanded = quote! {
        #impl_fn
    };

    // Return the combined TokenStream
    TokenStream::from(expanded)
}
