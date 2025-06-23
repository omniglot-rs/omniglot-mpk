// TODO:
#![allow(static_mut_refs)]

use omniglot::rt::OGRuntime;

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use og_libpng::libpng_bindings::LibPng;
use og_libpng::{og_mpk, unsafe_ffi};

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

use sandcrust::*;

static mut SANDCRUST_PREALLOCATED_DST_BUF: Option<Vec<usize>> = None;

sandbox! {
    fn sandcrust_prealloc(preallocate_bytes: usize) {
        unsafe {
            SANDCRUST_PREALLOCATED_DST_BUF = Some(vec![0; preallocate_bytes.div_ceil(std::mem::size_of::<usize>())])
        }
    }
}

sandbox! {
    fn sandcrust_png_init() {
        unsafe {
            unsafe_ffi::png_init().unwrap();
        }
    }
}

sandbox! {
    fn sandcrust_decode_png_preallocated(png_image: Vec<u8>) -> Vec<u8> {
        unsafe {
            let decoded_size = unsafe_ffi::decode_png_preallocated(&png_image, SANDCRUST_PREALLOCATED_DST_BUF.as_mut().unwrap());
            let prealloc_slice: &[usize] = SANDCRUST_PREALLOCATED_DST_BUF.as_ref().unwrap().as_slice();
            let decoded_slice: &[u8] = std::slice::from_raw_parts(prealloc_slice.as_ptr()  as *const u8, decoded_size);
            decoded_slice.into()
        }
    }
}

sandbox! {
    fn sandcrust_png_destroy() {
        unsafe {
            unsafe_ffi::png_destroy();
        }
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    env_logger::init();

    let mut test_images: Vec<(String, Vec<u8>, (usize, usize, usize))> =
        std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/test-images/"))
            .unwrap()
            .filter_map(|dir_entry_res| {
                let dir_entry = dir_entry_res.unwrap();
                if dir_entry.file_type().unwrap().is_file()
                    && dir_entry
                        .path()
                        .extension()
                        .is_some_and(|ext| ext.to_ascii_lowercase() == "png")
                {
                    Some((
                        dir_entry.file_name().into_string().unwrap(),
                        std::fs::read(dir_entry.path()).unwrap(),
                        (0, 0, 0),
                    ))
                } else {
                    None
                }
            })
            .collect();

    // Get the decompressed image size (rows, col_bytes, buffer_size):
    test_images.iter_mut().for_each(|(_, png_image, dims)| {
        // Intialize the unsafe PNG library to determine the output buffer size:
        unsafe { unsafe_ffi::png_init().unwrap() };

        // Get the image dimensions:
        let d = unsafe { unsafe_ffi::get_decompressed_image_buffer_size(png_image) };
        *dims = d;

        // Reset the library:
        unsafe { unsafe_ffi::png_destroy() };
    });

    test_images.sort_by_key(|(_, _, (_, _, buffer_size))| *buffer_size);

    println!("Loaded test image dataset:");
    for (label, bytes, (rows, cols, buffer_size)) in &test_images {
        println!(
            "- {}: {}x{}px, {}b compressed, {}b decoded",
            label,
            rows,
            cols,
            bytes.len(),
            buffer_size
        );
    }
    assert!(test_images.len() >= 1);

    // Avoid measuring large allocation overheads & heap fragmentation, compute
    // & allocate the largest target buffer once:
    let max_buffer_size: usize = test_images
        .iter()
        .map(|(_, _, (_, _, buffer_size))| *buffer_size)
        .max()
        .unwrap();

    const STACK_RANDOMIZE_ITERS: usize = 3;
    assert!(STACK_RANDOMIZE_ITERS > 0);

    let mut prng = SmallRng::seed_from_u64(0xDEADBEEFCAFEBABE);

    // // Make sure the library is initialized. The MockRt and MPKRt closures do
    // // this internally:
    // assert!(unsafe { ef_libsodium_lib::libsodium_bindings::sodium_init() } >= 0);
    // sodium_init_sandcrust();

    omniglot::id::lifetime::OGLifetimeBranding::new(|brand| {
        og_mpk::with_mpkrt_lib(brand, |lib, mut alloc, mut access| {
            let mut group = c.benchmark_group("libpng_decode");

            // Allocate a buffer in the EF MPK domain:
            let og_mpk_dst_buffer: *mut u8 = lib
                .malloc(max_buffer_size as u64, &mut alloc, &mut access)
                .unwrap()
                .validate()
                .unwrap() as *mut u8;
            assert!(og_mpk_dst_buffer as usize % std::mem::align_of::<*mut u8>() == 0);

            let mut unsafe_dst_buffer =
                vec![0; max_buffer_size.div_ceil(std::mem::size_of::<usize>())];

            sandcrust_prealloc(max_buffer_size);

            for (test_label, png_image, (_rows, _cols, buffer_size)) in &test_images {
                // // Verify that all the functions work:
                // let res_unsafe = libsodium_hash_unsafe(&to_hash);
                // let res_sandcrust = libsodium_hash_sandcrust(&to_hash);
                // libsodium_hash_ef(&lib, &mut alloc, &mut access, &to_hash, |res_ef| {
                //     println!("{:x?}", res_unsafe);
                //     assert!(&res_unsafe == res_ef);
                //     assert!(res_unsafe == res_sandcrust);
                // });

                // let tput_bytes: u64 = png_image.len() as u64;
                let tput_bytes: u64 = *buffer_size as u64;

                group.throughput(Throughput::Bytes(tput_bytes as u64));

                group.bench_with_input(
                    BenchmarkId::new("unsafe", test_label),
                    &tput_bytes,
                    |b, _| {
                        for _ in 0..STACK_RANDOMIZE_ITERS {
                            let stack_bytes: usize = (&mut prng)
                                .gen_range(std::ops::RangeInclusive::new(1_usize, 4095_usize));
                            push_stack_bytes(stack_bytes, || {
                                // println!("Pushed {} bytes onto the stack...", stack_bytes);
                                b.iter(|| {
                                    unsafe { unsafe_ffi::png_init().unwrap() };

                                    unsafe {
                                        unsafe_ffi::decode_png_preallocated(
                                            png_image,
                                            &mut unsafe_dst_buffer,
                                        )
                                    };

                                    unsafe { unsafe_ffi::png_destroy() };
                                });
                            });
                        }
                    },
                );

                group.bench_with_input(
                    BenchmarkId::new("og_mpk", test_label),
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
                                                let (png_ptr, info_ptr) =
                                                    og_mpk::libpng_init(&lib, alloc, &mut access);

                                                og_mpk::decode_png(
                                                    &lib,
                                                    alloc,
                                                    &mut access,
                                                    png_ptr,
                                                    info_ptr,
                                                    png_image,
                                                    Some((og_mpk_dst_buffer, max_buffer_size)),
                                                    |_, _, _, _, _| (),
                                                );

                                                og_mpk::libpng_destroy(
                                                    &lib,
                                                    alloc,
                                                    &mut access,
                                                    png_ptr,
                                                    info_ptr,
                                                );
                                            });
                                        },
                                    )
                                    .unwrap();
                            });
                        }
                    },
                );

                group.bench_with_input(
                    BenchmarkId::new("sandcrust", test_label),
                    &tput_bytes,
                    |b, _| {
                        for _ in 0..STACK_RANDOMIZE_ITERS {
                            let stack_bytes: usize = (&mut prng)
                                .gen_range(std::ops::RangeInclusive::new(1_usize, 4095_usize));
                            push_stack_bytes(stack_bytes, || {
                                // println!("Pushed {} bytes onto the stack...", stack_bytes);
                                b.iter(|| {
                                    sandcrust_png_init();
                                    black_box(sandcrust_decode_png_preallocated(png_image.clone()));
                                    sandcrust_png_destroy();
                                });
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
