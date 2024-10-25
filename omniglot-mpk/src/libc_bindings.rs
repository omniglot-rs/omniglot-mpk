#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod dlfcn {
    include!(concat!(env!("OUT_DIR"), "/dlfcn_bindings.rs"));
}

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(improper_ctypes)] // TODO: fix this by blocklisting or wrapping functions with u128s
#[allow(clashing_extern_declarations)] // _dl_find_object also declared by dlfcn above
pub mod link {
    include!(concat!(env!("OUT_DIR"), "/link_bindings.rs"));
}

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod sys_mman {
    include!(concat!(env!("OUT_DIR"), "/sys_mman_bindings.rs"));
}
