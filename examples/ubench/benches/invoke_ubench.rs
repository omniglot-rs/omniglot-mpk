use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use omniglot::id::OGID;
use omniglot::markers::{AccessScope, AllocScope};
use omniglot::rt::OGRuntime;

use og_ubench::libogdemo::LibOGDemo;
use og_ubench::with_mpkrt_lib;

use sandcrust::*;

const STACK_RANDOMIZE_ITERS: usize = 10;

sandbox! {
    fn demo_nop_sandcrust() {
        unsafe { og_ubench::libogdemo::demo_nop() }
    }
}

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

#[inline(always)]
fn bench_args_ef<
    const ARG_COUNT: usize,
    ID: OGID,
    RT: OGRuntime<ID = ID>,
    L: LibOGDemo<ID, RT, RT = RT>,
>(
    lib: &L,
    alloc: &mut AllocScope<'_, RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
) {
    match ARG_COUNT {
        0 => lib.demo_nop(alloc, access).unwrap(),
        _ => panic!("Unsupported arg count: {:?}", ARG_COUNT),
    };
}

#[inline(always)]
fn bench_args_unsafe<const ARG_COUNT: usize>() {
    match ARG_COUNT {
        0 => unsafe { og_ubench::libogdemo::demo_nop() },
        _ => panic!("Unsupported arg count: {:?}", ARG_COUNT),
    };
}

#[inline(always)]
fn bench_args_sandcrust<const ARG_COUNT: usize>() {
    match ARG_COUNT {
        0 => demo_nop_sandcrust(),
        _ => panic!("Unsupported arg count: {:?}", ARG_COUNT),
    };
}

fn bench_group_args<
    'a,
    const ARG_COUNT: usize,
    ID: OGID,
    RT: OGRuntime<ID = ID>,
    L: LibOGDemo<ID, RT, RT = RT>,
    M: criterion::measurement::Measurement,
>(
    lib: &L,
    alloc: &mut AllocScope<'_, RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
    group: &mut criterion::BenchmarkGroup<'a, M>,
    prng: &mut SmallRng,
) {
    group.throughput(Throughput::Elements(ARG_COUNT as u64));

    group.bench_with_input(BenchmarkId::new("unsafe", ARG_COUNT), &ARG_COUNT, |b, _| {
        for _ in 0..STACK_RANDOMIZE_ITERS {
            let stack_bytes: usize =
                prng.gen_range(std::ops::RangeInclusive::new(1_usize, 4095_usize));
            push_stack_bytes(stack_bytes, || {
                // println!("Pushed {} bytes onto the stack...", stack_bytes);
                b.iter(|| bench_args_unsafe::<ARG_COUNT>());
            });
        }
    });

    group.bench_with_input(BenchmarkId::new("ef_mpk", ARG_COUNT), &ARG_COUNT, |b, _| {
        for _ in 0..STACK_RANDOMIZE_ITERS {
            let stack_bytes: usize =
                prng.gen_range(std::ops::RangeInclusive::new(1_usize, 4095_usize));
            let foreign_stack_bytes: usize =
                prng.gen_range(std::ops::RangeInclusive::new(1_usize, 4095_usize));
            push_stack_bytes(stack_bytes, || {
                lib.rt()
                    .allocate_stacked_mut(
                        std::alloc::Layout::from_size_align(foreign_stack_bytes, 1).unwrap(),
                        alloc,
                        |_, alloc| {
                            // println!("Pushed {} bytes onto the stack...", stack_bytes);
                            b.iter(|| bench_args_ef::<ARG_COUNT, _, _, _>(lib, alloc, access));
                        },
                    )
                    .unwrap();
            });
        }
    });

    group.bench_with_input(
        BenchmarkId::new("sandcrust", ARG_COUNT),
        &ARG_COUNT,
        |b, _| {
            for _ in 0..STACK_RANDOMIZE_ITERS {
                let stack_bytes: usize =
                    prng.gen_range(std::ops::RangeInclusive::new(1_usize, 4095_usize));
                push_stack_bytes(stack_bytes, || {
                    // println!("Pushed {} bytes onto the stack...", stack_bytes);
                    b.iter(|| bench_args_sandcrust::<ARG_COUNT>());
                });
            }
        },
    );
}

pub fn criterion_benchmark(c: &mut Criterion) {
    env_logger::init();

    let mut prng = SmallRng::seed_from_u64(0xDEADBEEFCAFEBABE);

    omniglot::id::lifetime::OGLifetimeBranding::new(|brand| {
        with_mpkrt_lib(brand, |lib, mut alloc, mut access| {
            let mut group = c.benchmark_group("ubench_invoke");

            bench_group_args::<0, _, _, _, _>(&lib, &mut alloc, &mut access, &mut group, &mut prng);

            group.finish();
        });
    });

    println!("Finished benchmarks!");
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
