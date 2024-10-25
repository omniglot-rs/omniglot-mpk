#define _GNU_SOURCE
#include <sys/mman.h>

// The #define is not otherwise accessible to Rust
#define MAP_FAILED_CONST MAP_FAILED
