use omniglot::rt::OGRuntime;

use og_libsodium::libsodium_bindings::{self, LibSodium};
use og_libsodium::{libsodium_hash_og, libsodium_hash_unsafe, with_mpkrt_lib};

use rand::distributions::Uniform;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use sandcrust::*;

// Disable this when benchmarking. This ensures that we're properly initializing
// the library in Sandcrust, i.e., that the sodium_init call runs in the same
// sandbox as the hash function.
const SANDCRUST_ASSERT_LIBRARY_PREINITIALIZED: bool = false;

fn push_stack_bytes<R>(bytes: usize, f: impl FnOnce() -> R) -> R {
    use omniglot::rt::mock::MockRtAllocator;
    let stack_alloc = omniglot::rt::mock::stack_alloc::StackAllocator::<
        omniglot::rt::mock::stack_alloc::StackFrameAllocAMD64,
    >::new();
    unsafe {
        stack_alloc
            .with_alloc(
                core::alloc::Layout::from_size_align(bytes, 1).unwrap(),
                |_| f(),
            )
            .map_err(|_| ())
            .unwrap()
    }
}

sandbox! {
    fn sodium_init_sandcrust() {
        assert!(unsafe { libsodium_bindings::sodium_init() } >= 0);
    }
}

sandbox! {
    fn libsodium_hash_sandcrust(message: &Vec<u8>) -> [u8; 32] {
        if SANDCRUST_ASSERT_LIBRARY_PREINITIALIZED {
            assert!(unsafe { libsodium_bindings::sodium_init() } == 1);
        }

        libsodium_hash_unsafe(message.as_slice())
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    env_logger::init();

    const STACK_RANDOMIZE_ITERS: usize = 3;

    let mut prng = SmallRng::seed_from_u64(0xDEADBEEFCAFEBABE);

    // Make sure the library is initialized. The MockRt and MPKRt closures do
    // this internally:
    assert!(unsafe { og_libsodium::libsodium_bindings::sodium_init() } >= 0);
    sodium_init_sandcrust();

    omniglot::id::lifetime::OGLifetimeBranding::new(|brand| {
        with_mpkrt_lib(brand, |lib, mut alloc, mut access| {
            let mut group = c.benchmark_group("libsodium_hash");
            for size in (0..).map(|n| 8usize.pow(n)).skip(2).take(4) {
                // for size in [4096_usize] {
                let to_hash = (&mut prng)
                    .sample_iter(Uniform::new_inclusive(u8::MIN, u8::MAX))
                    .take(size)
                    .collect::<Vec<u8>>();

                // Verify that all the functions work:
                let res_unsafe = libsodium_hash_unsafe(&to_hash);
                let res_sandcrust = libsodium_hash_sandcrust(&to_hash);
                libsodium_hash_og(&lib, &mut alloc, &mut access, &to_hash, |res_og| {
                    println!("{:x?}", res_unsafe);
                    assert!(&res_unsafe == res_og);
                    assert!(res_unsafe == res_sandcrust);
                });

                group.throughput(Throughput::Bytes(size as u64));

                group.bench_with_input(BenchmarkId::new("unsafe", size), &size, |b, _| {
                    for _ in 0..STACK_RANDOMIZE_ITERS {
                        let stack_bytes: usize = (&mut prng)
                            .gen_range(std::ops::RangeInclusive::new(1_usize, 4095_usize));
                        push_stack_bytes(stack_bytes, || {
                            // println!("Pushed {} bytes onto the stack...", stack_bytes);
                            b.iter(|| libsodium_hash_unsafe(black_box(&to_hash)));
                        });
                    }
                });

                group.bench_with_input(BenchmarkId::new("og_mpk", size), &size, |b, _| {
                    for _ in 0..STACK_RANDOMIZE_ITERS {
                        let stack_bytes: usize = (&mut prng)
                            .gen_range(std::ops::RangeInclusive::new(1_usize, 4095_usize));
                        let foreign_stack_bytes: usize = (&mut prng)
                            .gen_range(std::ops::RangeInclusive::new(1_usize, 4095_usize));
                        push_stack_bytes(stack_bytes, || {
                            lib.rt()
                                .allocate_stacked_mut(
                                    std::alloc::Layout::from_size_align(foreign_stack_bytes, 1)
                                        .unwrap(),
                                    &mut alloc,
                                    |_, alloc| {
                                        // println!("Pushed {} bytes onto the stack...", stack_bytes);
                                        b.iter(|| {
                                            libsodium_hash_og(
                                                &lib,
                                                alloc,
                                                &mut access,
                                                black_box(&to_hash),
                                                |_| (),
                                            )
                                        });
                                    },
                                )
                                .unwrap();
                        });
                    }
                });

                group.bench_with_input(BenchmarkId::new("sandcrust", size), &size, |b, _| {
                    for _ in 0..STACK_RANDOMIZE_ITERS {
                        let stack_bytes: usize = (&mut prng)
                            .gen_range(std::ops::RangeInclusive::new(1_usize, 4095_usize));
                        push_stack_bytes(stack_bytes, || {
                            // println!("Pushed {} bytes onto the stack...", stack_bytes);
                            b.iter(|| libsodium_hash_sandcrust(black_box(&to_hash)));
                        });
                    }
                });
            }
            group.finish();
        });
    });

    println!("Finished benchmarks!");
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
