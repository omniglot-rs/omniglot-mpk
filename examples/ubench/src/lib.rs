// Necessary evil:
use omniglot::id::OGID;
use omniglot::markers::{AccessScope, AllocScope};

// Auto-generated bindings, so doesn't follow Rust conventions at all:
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[allow(improper_ctypes)] // TODO: fix this by wrapping functions with u128s
pub mod libogdemo {
    include!(concat!(env!("OUT_DIR"), "/libogdemo_bindings.rs"));
}

// These are the Omniglot wrapper types / traits generated.
use libogdemo::LibOGDemoRt;

pub fn with_mockrt_lib<'a, ID: OGID + 'a, A: omniglot::rt::mock::MockRtAllocator, R>(
    brand: ID,
    allocator: A,
    f: impl FnOnce(
        LibOGDemoRt<ID, omniglot::rt::mock::MockRt<ID, A>, omniglot::rt::mock::MockRt<ID, A>>,
        AllocScope<
            <omniglot::rt::mock::MockRt<ID, A> as omniglot::rt::OGRuntime>::AllocTracker<'a>,
            ID,
        >,
        AccessScope<ID>,
    ) -> R,
) -> R {
    // This is unsafe, as it instantiates a runtime that can be used to run
    // foreign functions without memory protection:
    let (rt, alloc, access) =
        unsafe { omniglot::rt::mock::MockRt::new(false, false, allocator, brand) };

    // Create a "bound" runtime, which implements the LibOGDemo API:no
    let bound_rt = LibOGDemoRt::new(rt).unwrap();

    // Run the provided closure:
    f(bound_rt, alloc, access)
}

pub fn with_mpkrt_lib<ID: OGID, R>(
    brand: ID,
    f: impl for<'a> FnOnce(
        LibOGDemoRt<ID, omniglot_mpk::OGMPKRuntime<ID>, omniglot_mpk::OGMPKRuntime<ID>>,
        AllocScope<
            <omniglot_mpk::OGMPKRuntime<ID> as omniglot::rt::OGRuntime>::AllocTracker<'a>,
            ID,
        >,
        AccessScope<ID>,
    ) -> R,
) -> R {
    let library_path = std::ffi::CString::new(concat!(env!("OUT_DIR"), "/libogdemo.so")).unwrap();

    let (rt, alloc, access) = omniglot_mpk::OGMPKRuntime::new(
        [library_path].into_iter(),
        brand,
        //Some(GLOBAL_PKEY_ALLOC.get_pkey()),
        None,
        false,
    );

    // Create a "bound" runtime, which implements the LibOGDemo API:
    let bound_rt = LibOGDemoRt::new(rt).unwrap();

    // Run the provided closure:
    f(bound_rt, alloc, access)
}
