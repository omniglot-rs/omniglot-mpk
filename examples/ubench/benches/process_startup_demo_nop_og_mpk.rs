fn main() {
    // Used to measure startup time against
    // process_startup_demo_nop_unsafe.rs
    omniglot::id::lifetime::OGLifetimeBranding::new(|brand| {
        og_ubench::with_mpkrt_lib(brand, |lib, mut alloc, mut access| {
            use og_ubench::libogdemo::LibOGDemo;
            lib.demo_nop(&mut alloc, &mut access).unwrap();
        });
    });
}
