use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use omniglot::foreign_memory::og_mut_ref::OGMutRef;
use omniglot::id::OGID;
use omniglot::markers::{AccessScope, AllocScope};
use omniglot::rt::OGRuntime;

use og_ubench::libogdemo::LibOGDemo;
use og_ubench::with_mpkrt_lib;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

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

fn with_alloc<R, ID: OGID, RT: OGRuntime<ID = ID>, L: LibOGDemo<ID, RT, RT = RT>>(
    lib: &L,
    alloc: &mut AllocScope<'_, RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
    alloc_size: usize,
    f: impl FnOnce(&L, &mut AllocScope<'_, RT::AllocTracker<'_>, RT::ID>, &mut AccessScope<RT::ID>) -> R,
) -> R {
    lib.rt()
        .allocate_stacked_slice_mut::<u8, _, _>(alloc_size, alloc, |_, alloc| f(lib, alloc, access))
        .unwrap()
}

fn bench_upgrade<ID: OGID, RT: OGRuntime<ID = ID>, L: LibOGDemo<ID, RT, RT = RT>>(
    lib: &L,
    alloc: &mut AllocScope<'_, RT::AllocTracker<'_>, RT::ID>,
    _access: &mut AccessScope<RT::ID>,
    base_allocation: *mut u8,
    allocations: usize,
    prng: &mut SmallRng,
    c: &mut Criterion,
    randomize_foreign_stack: bool,
) {
    c.bench_with_input(
        BenchmarkId::new("upgrade", allocations),
        &allocations,
        |b, _| {
            for _ in 0..STACK_RANDOMIZE_ITERS {
                let stack_bytes: usize =
                    prng.gen_range(std::ops::RangeInclusive::new(1_usize, 4095_usize));
                let foreign_stack_bytes: usize =
                    prng.gen_range(std::ops::RangeInclusive::new(1_usize, 4095_usize));
                push_stack_bytes(stack_bytes, || {
                    if randomize_foreign_stack {
                        lib.rt()
                            .allocate_stacked_mut(
                                std::alloc::Layout::from_size_align(foreign_stack_bytes, 1)
                                    .unwrap(),
                                alloc,
                                |_, alloc| {
                                    // println!("Pushed {} bytes onto the stack...", stack_bytes);
                                    b.iter(|| {
                                        black_box(
                                            OGMutRef::upgrade_from_ptr(
                                                black_box(base_allocation),
                                                alloc,
                                            )
                                            .unwrap(),
                                        );
                                    });
                                },
                            )
                            .unwrap();
                    } else {
                        b.iter(|| {
                            black_box(
                                OGMutRef::upgrade_from_ptr(black_box(base_allocation), alloc)
                                    .unwrap(),
                            );
                        });
                    }
                });
            }
        },
    );
}

#[rustfmt::skip]
pub fn criterion_benchmark(c: &mut Criterion) {
    env_logger::init();

    let mut prng = SmallRng::seed_from_u64(0xDEADBEEFCAFEBABE);

    omniglot::id::lifetime::OGLifetimeBranding::new(|brand| {
        with_mpkrt_lib(brand, |lib, mut alloc, mut access| {
            const ALLOC_SIZE: usize = 64;

            lib.rt().allocate_stacked_slice_mut::<u8, _, _>(ALLOC_SIZE, &mut alloc, |base_allocation, alloc| {
                // 1 allocation!
                bench_upgrade(&lib, alloc, &mut access, base_allocation.as_ptr(), 1, &mut prng, c, false);

            with_alloc(&lib, alloc, &mut access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
                // 7 allocations! (we'll add another one to randmomize the stack offset though)
                bench_upgrade(lib, alloc, access, base_allocation.as_ptr(), 8, &mut prng, c, true);

            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
            with_alloc(lib, alloc, access, ALLOC_SIZE, |lib, alloc, access| {
                // 63 allocations! (again, we add one more in the bench function)
                bench_upgrade(lib, alloc, access, base_allocation.as_ptr(), 64, &mut prng, c, true);
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })
            })

            })
            })
            })
            })
            })
            })
            })
            }).unwrap();
        });
    });

    println!("Finished benchmarks!");
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
