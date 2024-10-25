use std::ffi::c_void;
use std::fs::File;
use std::ptr;

use crate::libpng_bindings::{
    jmp_buf, longjmp, png_create_info_struct, png_create_read_struct, png_destroy_read_struct,
    png_get_image_height, png_get_image_width, png_get_io_ptr, png_get_rowbytes, png_info,
    png_read_image, png_read_info, png_set_longjmp_fn, png_set_read_fn, png_sig_cmp, png_size_t,
    png_struct, setjmp,
};

static mut PNG_PTR: *mut png_struct = 0 as *mut png_struct;
static mut INFO_PTR: *mut png_info = 0 as *mut png_info;

pub fn read_file(path: &str) -> Vec<u8> {
    use std::io::Read;

    let mut file = File::open(path).unwrap();
    let size = file.metadata().unwrap().len() as usize;
    let mut buf = vec![0u8; size];
    file.read_exact(&mut buf).unwrap();
    buf
}

extern "C" fn callback(callback_png_ptr: *mut png_struct, buf_ptr: *mut u8, count: png_size_t) {
    use std::io::Read;

    unsafe {
        let mut buf = std::slice::from_raw_parts_mut(buf_ptr, count as usize);
        let image_ptr = png_get_io_ptr(callback_png_ptr);
        let image: &mut &[u8] = ::std::mem::transmute(image_ptr);
        image.read_exact(&mut buf).unwrap();
    }
}

#[allow(unused)]
fn decode_png(png_image: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    unsafe {
        // this call mimics the define in png.h:
        // # define png_jmpbuf(png_ptr) \
        // (*png_set_longjmp_fn((png_ptr), longjmp, (sizeof (jmp_buf))))
        if 0 != setjmp(png_set_longjmp_fn(
            PNG_PTR,
            Some(std::mem::transmute::<
                unsafe extern "C" fn(_, _) -> !,
                unsafe extern "C" fn(_, _) -> (),
            >(longjmp)),
            std::mem::size_of::<jmp_buf>(),
        ) as *mut _)
        {
            return Err("read failed in libpng".to_owned());
        }

        let image_ptr: *mut c_void = &png_image as *const &[u8] as *const _ as *mut _;
        png_set_read_fn(PNG_PTR, image_ptr, Some(callback));

        png_read_info(PNG_PTR, INFO_PTR);
        let height = png_get_image_height(PNG_PTR, INFO_PTR) as usize;

        let mut result = Vec::with_capacity(height);
        let rowbytes = png_get_rowbytes(PNG_PTR, INFO_PTR) as usize;

        // internal array of row pointers to feed to libpng
        let mut rows = vec![ptr::null_mut() as *mut u8; height];

        for i in 0..height {
            let mut row = vec![0u8; rowbytes];
            rows[i] = row.as_mut_ptr();
            result.push(row);
        }
        png_read_image(PNG_PTR, rows.as_mut_ptr());
        Ok(result)
    }
}

#[allow(unused)]
pub unsafe fn decode_png_preallocated<'a>(
    png_image: &[u8],
    // We'll be storing pointers in this, so needs to be aligned to 8 bytes
    preallocated: &mut [usize],
) -> usize {
    // this call mimics the define in png.h:
    // # define png_jmpbuf(png_ptr) \
    // (*png_set_longjmp_fn((png_ptr), longjmp, (sizeof (jmp_buf))))
    if 0 != setjmp(png_set_longjmp_fn(
        PNG_PTR,
        Some(std::mem::transmute::<
            unsafe extern "C" fn(_, _) -> !,
            unsafe extern "C" fn(_, _) -> (),
        >(longjmp)),
        std::mem::size_of::<jmp_buf>(),
    ) as *mut _)
    {
        panic!("read failed in libpng");
    }

    let image_ptr: *mut c_void = &png_image as *const &[u8] as *const _ as *mut _;
    png_set_read_fn(PNG_PTR, image_ptr, Some(callback));

    png_read_info(PNG_PTR, INFO_PTR);
    let row_count = png_get_image_height(PNG_PTR, INFO_PTR) as usize;
    let col_bytes = png_get_rowbytes(PNG_PTR, INFO_PTR) as usize;

    // Allocate a stacked buffer large enough to hold all columns of all
    // rows, plus a "row" of pointers to the other rows:
    let alloc_size = row_count * col_bytes + row_count * std::mem::size_of::<*mut *mut u8>();

    assert!(
        (preallocated.len() * std::mem::size_of::<usize>()) >= alloc_size,
        "Provided buffer is too small to decode image into!"
    );

    // Use pointer arithmetic, for a fair comparison with the EF MPK benchmark:
    let dst_buffer: *mut u8 = preallocated.as_mut_ptr() as *mut u8;

    let row_pointers_arr: *mut *mut u8 = align_ptr(
        dst_buffer.byte_offset((row_count * col_bytes).try_into().unwrap()) as *mut *mut u8,
    );
    let row_pointers_slice: &mut [*mut u8] =
        std::slice::from_raw_parts_mut(row_pointers_arr, row_count);
    row_pointers_slice
        .iter_mut()
        .enumerate()
        .for_each(|(row_idx, ptr_ref)| {
            *ptr_ref = dst_buffer.byte_offset((row_idx * col_bytes).try_into().unwrap());
        });

    png_read_image(PNG_PTR, row_pointers_slice.as_mut_ptr());

    alloc_size
}

#[allow(unused)]
fn decode_png_c_wrapped(png_image: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut rows: u32 = 0;
    let mut cols: u32 = 0;

    // println!("Passing in image pointer {:p}", png_image.as_ptr());

    let res: *mut *mut u8 = unsafe {
        crate::libpng_bindings::decode_png(
            PNG_PTR,
            INFO_PTR,
            png_image.as_ptr(),
            &mut rows as *mut _,
            &mut cols as *mut _,
        )
    };

    println!("Rows: {:?}, Cols: {:?}", rows, cols);

    let mut result_vec = (0..rows)
        .map(|_| Vec::with_capacity(cols as usize))
        .collect::<Vec<Vec<u8>>>();

    let rows_slice = unsafe { std::slice::from_raw_parts(res, rows as usize) };
    rows_slice.iter().zip(result_vec.iter_mut()).for_each(
        |(src_row, dst_row): (&*mut u8, &mut Vec<u8>)| {
            let col_slice = unsafe { std::slice::from_raw_parts(*src_row, cols as usize) };
            dst_row.extend_from_slice(col_slice);
        },
    );

    Ok(result_vec)
}

pub unsafe fn png_init() -> Result<(), String> {
    // for now, duplication is necessary
    // https://stackoverflow.com/questions/21485655/how-do-i-use-c-preprocessor-macros-with-rusts-ffi
    let ver = std::ffi::CString::new("1.6.28").unwrap();
    let ver_ptr = ver.as_ptr();

    PNG_PTR = png_create_read_struct(ver_ptr, ptr::null_mut(), None, None);
    if PNG_PTR.is_null() {
        return Err("failed to create png_ptr".to_owned());
    }
    INFO_PTR = png_create_info_struct(PNG_PTR);
    if INFO_PTR.is_null() {
        png_destroy_read_struct(&raw mut PNG_PTR, ptr::null_mut(), ptr::null_mut());

        return Err("failed to create info_ptr".to_owned());
    }

    return Ok(());
}

pub unsafe fn png_destroy() {
    png_destroy_read_struct(&raw mut PNG_PTR, &raw mut INFO_PTR, std::ptr::null_mut());
}

fn is_png(buf: &[u8]) -> bool {
    let buf_ptr = buf.as_ptr();
    let size = buf.len() as usize;
    unsafe {
        if png_sig_cmp(buf_ptr, 0, size) != 0 {
            return false;
        }
    }
    return true;
}

pub unsafe fn unsafe_main() {
    if let Some(arg1) = std::env::args().nth(1) {
        let file_buf = read_file(&arg1.as_str());
        if !is_png(&file_buf[0..8]) {
            panic!("no PNG!");
        }
        png_init().unwrap();
        #[allow(unused_variables)]
        let vec = decode_png(&file_buf).unwrap();
        // let vec = decode_png_c_wrapped(&file_buf).unwrap();
        println!("vec len: {}, first row: {:x?}", vec.len(), &vec[..1]);
    } else {
        println!("usage: png <png file>");
    }
}

pub unsafe fn get_decompressed_image_buffer_size(png_image: &[u8]) -> (usize, usize, usize) {
    if !is_png(&png_image[0..8]) {
        panic!("Supplied image is not a valid PNG file!");
    }

    unsafe {
        // this call mimics the define in png.h:
        // # define png_jmpbuf(png_ptr) \
        // (*png_set_longjmp_fn((png_ptr), longjmp, (sizeof (jmp_buf))))
        if 0 != setjmp(png_set_longjmp_fn(
            PNG_PTR,
            Some(std::mem::transmute::<
                unsafe extern "C" fn(_, _) -> !,
                unsafe extern "C" fn(_, _) -> (),
            >(longjmp)),
            std::mem::size_of::<jmp_buf>(),
        ) as *mut _)
        {
            panic!("read failed in libpng");
        }

        let image_ptr: *mut c_void = &png_image as *const &[u8] as *const _ as *mut _;
        png_set_read_fn(PNG_PTR, image_ptr, Some(callback));

        png_read_info(PNG_PTR, INFO_PTR);
        let row_count = png_get_image_height(PNG_PTR, INFO_PTR) as usize;
        let col_count = png_get_image_width(PNG_PTR, INFO_PTR) as usize;
        let col_bytes = png_get_rowbytes(PNG_PTR, INFO_PTR) as usize;

        (
            row_count,
            col_count,
            // Base array:
            row_count * col_bytes
            // Row pointers:
            + row_count * std::mem::size_of::<*mut *mut u8>()
            // Potential alignment bytes:
            + std::mem::align_of::<*mut u8>(),
        )
    }
}

pub fn align_ptr<T>(ptr: *mut T) -> *mut T {
    let a: usize = std::mem::align_of::<T>();
    unsafe { ptr.byte_offset((a - (ptr as usize % a)).try_into().unwrap()) }
}
