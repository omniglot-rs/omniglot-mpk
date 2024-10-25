use rand::distributions::{DistString, Standard, Uniform};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use omniglot::rt::OGRuntime;

use og_ubench::libogdemo::LibOGDemo;
use og_ubench::with_mpkrt_lib;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

const STACK_RANDOMIZE_ITERS: usize = 1;

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

pub fn criterion_benchmark(c: &mut Criterion) {
    env_logger::init();

    let mut prng = SmallRng::seed_from_u64(0xDEADBEEFCAFEBABE);

    omniglot::id::lifetime::OGLifetimeBranding::new(|brand| {
        with_mpkrt_lib(brand, |lib, mut alloc, mut access| {
            let mut group = c.benchmark_group("validation");
            //for size in (0..).map(|n| 8usize.pow(n)).take(10) {
            for size in [1, 8, 64, 1024, 8 * 1028, 1024 * 1024] {
                let to_validate_bytes = (&mut prng)
                    .sample_iter(Uniform::new_inclusive(u8::MIN, u8::MAX))
                    .take(size)
                    .collect::<Vec<u8>>();

                let to_validate_string = DistString::sample_string(&Standard, &mut prng, size);

                group.throughput(Throughput::Bytes(size as u64));

                group.bench_with_input(BenchmarkId::new("u8", size), &size, |b, _| {
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
                                        lib.rt()
                                            .allocate_stacked_slice_mut::<u8, _, _>(
                                                to_validate_bytes.len(),
                                                alloc,
                                                |slice_alloc, _alloc| {
                                                    slice_alloc.copy_from_slice(
                                                        &to_validate_bytes,
                                                        &mut access,
                                                    );

                                                    let slice_ref = &slice_alloc;
                                                    b.iter(|| {
                                                        black_box(
                                                            black_box(slice_ref)
                                                                .validate(&mut access)
                                                                .unwrap(),
                                                        );
                                                    })
                                                },
                                            )
                                            .unwrap();
                                    },
                                )
                                .unwrap();
                        });
                    }
                });

                group.bench_with_input(BenchmarkId::new("str", size), &size, |b, _| {
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
                                        lib.rt()
                                            .allocate_stacked_slice_mut::<u8, _, _>(
                                                to_validate_string.as_bytes().len(),
                                                alloc,
                                                |slice_alloc, _alloc| {
                                                    slice_alloc.copy_from_slice(
                                                        &to_validate_string.as_bytes(),
                                                        &mut access,
                                                    );

                                                    let slice_ref = &slice_alloc;
                                                    b.iter(|| {
                                                        black_box(
                                                            black_box(slice_ref)
                                                                .as_immut()
                                                                .validate_as_str(&mut access)
                                                                .unwrap(),
                                                        );
                                                    })
                                                },
                                            )
                                            .unwrap();
                                    },
                                )
                                .unwrap();
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
