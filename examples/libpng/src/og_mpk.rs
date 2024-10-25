use std::ffi::CString;
use std::ptr;

use omniglot::foreign_memory::og_mut_slice::OGMutSlice;
use omniglot::id::OGID;
use omniglot::markers::{AccessScope, AllocScope};
use omniglot::rt::{CallbackContext, OGRuntime};

use crate::unsafe_ffi::{align_ptr, read_file};

use crate::libpng_bindings::{png_info, png_struct, LibPng, LibPngRt};

pub fn with_mpkrt_lib<ID: OGID, R>(
    brand: ID,
    f: impl for<'a> FnOnce(
        LibPngRt<ID, omniglot_mpk::OGMPKRuntime<ID>, omniglot_mpk::OGMPKRuntime<ID>>,
        AllocScope<
            <omniglot_mpk::OGMPKRuntime<ID> as omniglot::rt::OGRuntime>::AllocTracker<'a>,
            ID,
        >,
        AccessScope<ID>,
    ) -> R,
) -> R {
    let (rt, alloc, access) = omniglot_mpk::OGMPKRuntime::new(
        [CString::new(concat!(env!("OUT_DIR"), "/libpng_nojmp.so")).unwrap()].into_iter(),
        brand,
        //Some(GLOBAL_PKEY_ALLOC.get_pkey()),
        None,
        false,
    );

    // Create a "bound" runtime, which implements the LibPng API:
    let bound_rt = LibPngRt::new(rt).unwrap();

    // Run the provided closure:
    f(bound_rt, alloc, access)
}

pub fn libpng_init<ID: OGID, RT: OGRuntime<ID = ID>, L: LibPng<ID, RT, RT = RT>>(
    lib: &L,
    alloc: &mut AllocScope<RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
) -> (*mut png_struct, *mut png_info) {
    let png_ptr = lib
        .rt()
        .write_stacked_slice(
            b"1.6.28",
            alloc,
            access,
            |libpng_version_slice, alloc, access| {
                lib.png_create_read_struct(
                    libpng_version_slice.as_ptr().cast::<i8>().into(),
                    ptr::null_mut(),
                    None,
                    None,
                    alloc,
                    access,
                )
                .unwrap()
                .validate()
                .unwrap()
            },
        )
        .unwrap();
    assert!(!png_ptr.is_null(), "Failed to create png_struct type");

    let info_ptr = lib
        .png_create_info_struct(png_ptr, alloc, access)
        .unwrap()
        .validate()
        .unwrap();
    assert!(!info_ptr.is_null(), "Failed to create png_info type");

    (png_ptr, info_ptr)
}

pub fn libpng_destroy<ID: OGID, RT: OGRuntime<ID = ID>, L: LibPng<ID, RT, RT = RT>>(
    lib: &L,
    alloc: &mut AllocScope<RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
    png_ptr: *mut png_struct,
    info_ptr: *mut png_info,
) {
    lib.rt()
        .write_stacked_t_mut::<*mut png_struct, _, _>(
            png_ptr,
            alloc,
            access,
            |png_ptrptr, alloc, access| {
                lib.rt()
                    .write_stacked_t_mut::<*mut png_info, _, _>(
                        info_ptr,
                        alloc,
                        access,
                        |info_ptrptr, alloc, access| {
                            lib.png_destroy_read_struct(
                                png_ptrptr.as_ptr().into(),
                                info_ptrptr.as_ptr().into(),
                                std::ptr::null_mut(),
                                alloc,
                                access,
                            )
                            .unwrap()
                        },
                    )
                    .unwrap()
            },
        )
        .unwrap();
}

pub fn is_png<ID: OGID, RT: OGRuntime<ID = ID>, L: LibPng<ID, RT, RT = RT>>(
    lib: &L,
    alloc: &mut AllocScope<RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
    buf: &[u8],
) -> bool {
    lib.rt()
        .write_stacked_slice(buf, alloc, access, |png_signature_ptr, alloc, access| {
            let png_sig_cmp_res = lib
                .png_sig_cmp(
                    png_signature_ptr.as_ptr().into(),
                    0,
                    buf.len(),
                    alloc,
                    access,
                )
                .unwrap()
                .validate()
                .unwrap();
            png_sig_cmp_res == 0
        })
        .unwrap()
}

pub fn decode_png<ID: OGID, RT: OGRuntime<ID = ID>, L: LibPng<ID, RT, RT = RT>, R>(
    lib: &L,
    alloc: &mut AllocScope<RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
    png_ptr: *mut png_struct,
    info_ptr: *mut png_info,
    png_image: &[u8],
    dst_buffer: Option<(*mut u8, usize)>,
    f: impl for<'a> FnOnce(
        OGMutSlice<'_, RT::ID, *mut u8>,
        usize,
        usize,
        &mut AllocScope<RT::AllocTracker<'_>, RT::ID>,
        &mut AccessScope<ID>,
    ) -> R,
) -> R {
    // First, setup callback to read the file:
    let mut png_image_offset: usize = 0;
    lib.rt()
        .setup_callback(
            &mut |ctx, _ret, alloc, access| {
                // File read callback. Arguments: (png_ptr: *mut png_struct, buf_ptr: *mut u8, count: png_size_t)
                let _png_ptr: *mut png_struct = ctx.get_argument_register(0).unwrap() as *mut _;
                let buf_ptr: *mut u8 = ctx.get_argument_register(1).unwrap() as *mut _;
                let count: usize = ctx.get_argument_register(2).unwrap();

                // Upgrade the supplied destination buffer into an EFSlice:
                let dst_slice = OGMutSlice::upgrade_from_ptr(buf_ptr, count, alloc).unwrap();

                // We retain a buffer to the source image externally, no need to call
                // `png_get_io_ptr`. Simply copy data and increment the offset:
                dst_slice.copy_from_slice(
                    &png_image[png_image_offset..(png_image_offset + count)],
                    access,
                );
                png_image_offset += count;
                // println!("Copied {} bytes!", count);
            },
            alloc,
            |callback_ptr, alloc| {
                // Callback is valid in this scope. Set it to be called whenever libpng
                // wants to read from the compressed image:
                lib.png_set_read_fn(
                    png_ptr,
                    ptr::null_mut(), /* no user IO ptr */
                    // TODO: provide nicer API for this -- this is a "safe transmute"
                    unsafe {
                        std::mem::transmute::<*const _, Option<unsafe extern "C" fn(_, _, _)>>(
                            callback_ptr,
                        )
                    },
                    alloc,
                    access,
                )
                .unwrap();

                // Read image dimensions:
                assert!(lib
                    .png_read_info_nojmp(png_ptr, info_ptr, alloc, access)
                    .unwrap()
                    .validate()
                    .unwrap());
                let row_count = lib
                    .png_get_image_height(png_ptr, info_ptr, alloc, access)
                    .unwrap()
                    .validate()
                    .unwrap() as usize;
                let col_bytes = lib
                    .png_get_rowbytes(png_ptr, info_ptr, alloc, access)
                    .unwrap()
                    .validate()
                    .unwrap() as usize;

                // Allocate a stacked buffer large enough to hold all columns of all
                // rows, plus a "row" of pointers to the other rows:
                let alloc_size =
                    row_count * col_bytes + row_count * std::mem::size_of::<*mut *mut u8>();

                let dst_buffer = if let Some((dst_buffer, dst_buffer_len)) = dst_buffer {
                    assert!(
                        dst_buffer_len >= alloc_size,
                        "Provided buffer is too small to decode image into!"
                    );
                    dst_buffer
                } else {
                    let dst_buffer: *mut u8 = lib
                        .malloc(alloc_size as u64, alloc, access)
                        .unwrap()
                        .validate()
                        .unwrap() as *mut u8;
                    assert!(
                        !dst_buffer.is_null(),
                        "Failed to alloc {} bytes for the decompressed image!",
                        alloc_size
                    );
                    dst_buffer
                };

                // At a pointer offset of `row_count * col_bytes`, prepare an array of
                // pointers pointing to `base_ptr + i * col_bytes`:
                let row_pointers_arr: *mut *mut u8 = align_ptr(unsafe {
                    dst_buffer.byte_offset((row_count * col_bytes).try_into().unwrap())
                } as *mut *mut u8);
                let row_pointers_slice =
                    OGMutSlice::upgrade_from_ptr(row_pointers_arr, row_count, alloc)
                        .unwrap_or_else(|| {
                            panic!(
                                "Failed to upgrade row_pointers_slice: {:p}, {}",
                                row_pointers_arr, row_count
                            )
                        });
                row_pointers_slice.write_from_iter(
                    (0..row_count).map(|row_idx| unsafe {
                        dst_buffer.byte_offset((row_idx * col_bytes).try_into().unwrap())
                    }),
                    access,
                );

                lib.png_read_image_nojmp(png_ptr, row_pointers_arr, alloc, access)
                    .unwrap();

                f(row_pointers_slice, row_count, col_bytes, alloc, access)
            },
        )
        .unwrap()
}

pub fn ef_mpk_main() {
    env_logger::init();

    let arg1 = std::env::args().nth(1).expect("usage: png <png file>");
    let file_buf = read_file(&arg1.as_str());

    omniglot::id::lifetime::OGLifetimeBranding::new(|brand| {
        with_mpkrt_lib(brand, |lib, mut alloc, mut access| {
            if !is_png(&lib, &mut alloc, &mut access, &file_buf[0..8]) {
                panic!("no PNG!");
            }

            let (png_ptr, info_ptr) = libpng_init(&lib, &mut alloc, &mut access);

            decode_png(
                &lib,
                &mut alloc,
                &mut access,
                png_ptr,
                info_ptr,
                &file_buf,
                None,
                |decoded_image, _row_count, col_bytes, alloc, access| {
                    let rows = decoded_image.validate(access).unwrap();
                    let col_bytes = OGMutSlice::upgrade_from_ptr(rows[0], col_bytes, alloc)
                        .unwrap()
                        .validate(access)
                        .unwrap();
                    println!("Col bytes: {:x?}", &*col_bytes);
                },
            );
        });
    });
}
