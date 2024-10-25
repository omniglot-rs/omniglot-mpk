#include "libpng_nojmp.h"

bool png_read_info_nojmp(png_structrp png_ptr, png_inforp info_ptr) {
  if (0 != setjmp(png_jmpbuf(png_ptr))) {
    return false;
  }

  png_read_info(png_ptr, info_ptr);

  return true;
}

bool png_read_image_nojmp(png_structrp png_ptr, png_bytepp image) {
  if (0 != setjmp(png_jmpbuf(png_ptr))) {
    return false;
  }

  png_read_image(png_ptr, image);

  return true;
}

// -----------------------------------------------------------------------------

void decode_png_read_cb(png_structrp png_ptr, uint8_t *buf_ptr,
                        png_size_t count) {
  const uint8_t **image_ptr = png_get_io_ptr(png_ptr);
  /* printf("Reading from image ptr: %p, %d\n", *image_ptr, count); */
  memcpy(buf_ptr, *image_ptr, count);
  *image_ptr += count;
}

uint8_t **decode_png(png_structrp png_ptr, png_inforp info_ptr,
                     const uint8_t *png_image, png_uint_32 *rows,
                     png_uint_32 *cols) {
  if (0 != setjmp(png_jmpbuf(png_ptr))) {
    return false;
  }

  const uint8_t *image_ptr = png_image;

  png_set_read_fn(png_ptr, &image_ptr, decode_png_read_cb);

  png_read_info(png_ptr, info_ptr);

  *rows = png_get_image_height(png_ptr, info_ptr);
  *cols = png_get_rowbytes(png_ptr, info_ptr);

  uint8_t **row_ptrs = calloc(sizeof(void *), *rows);
  if (row_ptrs == NULL) {
    return false;
  }

  for (size_t i = 0; i < *rows; i++) {
    row_ptrs[i] = malloc(*cols);
    if (row_ptrs[i] == NULL) {
      return false;
    }
  }

  png_read_image(png_ptr, row_ptrs);

  return row_ptrs;
}
