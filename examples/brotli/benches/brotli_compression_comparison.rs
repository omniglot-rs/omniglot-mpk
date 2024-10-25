use omniglot::rt::OGRuntime;

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use og_brotli::brotli::Brotli;
use og_brotli::{test_brotli, test_brotli_unsafe, with_mpkrt_lib};

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

    const STACK_RANDOMIZE_ITERS: usize = 3;
    assert!(STACK_RANDOMIZE_ITERS > 0);

    let mut prng = SmallRng::seed_from_u64(0xDEADBEEFCAFEBABE);

    omniglot::id::lifetime::OGLifetimeBranding::new(|brand| {
        with_mpkrt_lib(brand, |lib, mut alloc, mut access| {
            let mut group = c.benchmark_group("brotli_compress_decompress");

            for size in [8, 64, 128, 256, 512, 1024] {
                let tput_bytes: u64 = size as u64;

                group.throughput(Throughput::Bytes(tput_bytes as u64));

                group.bench_with_input(
                    BenchmarkId::new("unsafe", tput_bytes),
                    &tput_bytes,
                    |b, _| {
                        for _ in 0..STACK_RANDOMIZE_ITERS {
                            let stack_bytes: usize = (&mut prng)
                                .gen_range(std::ops::RangeInclusive::new(1_usize, 4095_usize));
                            push_stack_bytes(stack_bytes, || {
                                // println!("Pushed {} bytes onto the stack...", stack_bytes);
                                b.iter(|| {
                                    black_box(unsafe { test_brotli_unsafe(black_box(size)) });
                                });
                            });
                        }
                    },
                );

                group.bench_with_input(
                    BenchmarkId::new("og_mpk", tput_bytes),
                    &tput_bytes,
                    |b, _| {
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
                                                black_box(test_brotli(
                                                    &lib,
                                                    alloc,
                                                    &mut access,
                                                    black_box(size),
                                                ))
                                            });
                                        },
                                    )
                                    .unwrap();
                            });
                        }
                    },
                );
            }
            group.finish();
        });
    });

    println!("Finished benchmarks!");
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
