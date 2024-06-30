
// implemeents per-type registry types
macro_rules! define_registry {
    ($type:ty) => {
        paste::paste! {
            // ensure tag fits in 4 bits
            static_assertions::const_assert!([<$type:snake:upper _TAG>] <= 0b1111);

            static [<$type:snake:upper _REGISTRY>]: std::sync::Mutex<crate::object_registry::ObjectRegistry<$type, { [<$type:snake:upper _TAG>] }, 4>> = std::sync::Mutex::new(crate::object_registry::ObjectRegistry::new());

            pub(crate) fn [<get_ $type:snake _registry>]<'a>() -> std::sync::MutexGuard<'a, crate::object_registry::ObjectRegistry<$type, { [<$type:snake:upper _TAG>] }, 4>> {
                match [<$type:snake:upper _REGISTRY>].lock() {
                    Ok(registry) => registry,
                    Err(_) => unreachable!("another thread panicked while holding this registry's mutex"),
                }
            }

            pub(crate) fn [<clear_ $type:snake _registry>]() {
                match [<$type:snake:upper _REGISTRY>].lock() {
                    Ok(mut registry) => *registry = crate::object_registry::ObjectRegistry::new(),
                    Err(_) => unreachable!("another thread panicked while holding this registry's mutex"),
                }
            }
        }
    }
}
pub(crate) use define_registry;

// macro for defining the implementation of freeing objects
// owned by an ObjectRegistry
macro_rules! impl_registry_free {
    ($obj:expr, $type:ty) => {
        if $obj.is_null() {
            return;
        }

        let key = $obj as usize;
        paste::paste! {
            [<get_ $type:snake _registry>]().remove(key);
        }
    };
}
pub(crate) use impl_registry_free;

//
// Argument validation macros
//

// ensure pointer is not null
macro_rules! ensure_not_null {
    ($ptr:ident) => {
        paste::paste! {
            if $ptr.is_null() {
                bail!(stringify!([<$ptr>] must not be null));
            }
        }
    }
}
pub(crate) use ensure_not_null;
