#include "omniglot_mpk_rt.h"

#include <stdint.h>

// ---------- Required scaffolding. These symbols must not be exported --------

__attribute__((visibility("hidden"), weak)) void
memcpy(void *dst, const void *src, size_t n) {
  unsigned char *cdst = (unsigned char *)dst;
  unsigned char *csrc = (unsigned char *)src;

  for (size_t i = 0; i < n; i++) {
    cdst[i] = csrc[i];
  }
}

__attribute__((visibility("hidden"), weak)) void memset(void *dst, int v,
                                                        size_t n) {
  // This apparently needs to be in assembly, because the compiler might
  // otherwise call memset in our implementation of memset:
  register void *dstr __asm__("rdi") = dst;
  register int vr __asm__("rsi") = v;
  register size_t nr __asm__("rdx") = n;
  __asm__ volatile("100:                     \n"
                   "  test %%rdx, %%rdx      \n"
                   "  je 200f                \n"
                   "  movb %%sil, (%%rdi)    \n"
                   "  add $1, %%rdi          \n"
                   "  sub $1, %%rdx          \n"
                   "  jmp 100b               \n"
                   " 200:                    \n"
                   :
                   : "r"(dstr), "r"(vr), "r"(nr)
                   : "memory" // Other regs above don't need to be listed
  );
}

__attribute__((visibility("hidden"), weak)) int strcmp(const char *str1,
                                                       const char *str2) {
  for (;;) {
    if (*str1 != *str2) {
      return *str1 - *str2;
    } else if (*str1 == 0) {
      return *str2;
    } else {
      str1++;
      str2++;
    }
  }
}

__attribute__((visibility("hidden"), weak)) size_t strlen(const char *str) {
  size_t len = 0;

  while (1) {
    if (str[len] == 0) {
      break;
    } else {
      len += 1;
    }
  }

  return len;
}

// ---------- EF Callback Infrastructure, to be initialized first -------------

typedef size_t (*ef_callback_t)(size_t a0, size_t a1, size_t a2, size_t a3,
                                size_t a4, size_t a5);

static ef_callback_t EF_DEBUG_CALLBACK = 0;
static size_t EF_DEBUG_SUBSYS_ENABLE_MAP = 0;

size_t ef_debug_callback(ef_debug_subsys_t subsys, size_t a1, size_t a2,
                         size_t a3, size_t a4, size_t a5) {
  if (EF_DEBUG_CALLBACK && ef_debug_subsys_enabled(subsys)) {
    return EF_DEBUG_CALLBACK(subsys, a1, a2, a3, a4, a5);
  } else {
    return 0;
  }
}

int ef_debug_subsys_enabled(ef_debug_subsys_t subsys) {
  return (EF_DEBUG_SUBSYS_ENABLE_MAP & (1 << subsys)) != 0;
}

void ef_debug_subsys_enable(ef_debug_subsys_t subsys) {
  EF_DEBUG_SUBSYS_ENABLE_MAP |= (1 << subsys);
}

void ef_debug_subsys_disable(ef_debug_subsys_t subsys) {
  EF_DEBUG_SUBSYS_ENABLE_MAP &= ~(1 << subsys);
}

void ef_debug_callback_init(void *debug_callback_addr) {
  // Initialize callbacks:
  EF_DEBUG_CALLBACK = debug_callback_addr;
}

// ---------- POSIX function overrides ----------------------------------------

static char **ef_environ = 0;

char *getenv(const char *name) {
  for (size_t i = 0; ef_environ[i] != 0; i++) {
    char *cur = ef_environ[i];

    // We effectively do a strcmp until we hit an `=` character in
    // the ef_environ variable. If that succeeds and the name is
    // `\0` at that position, return the string pointer after the
    // equals sign:
    size_t pos;

    // Search for the first non-equal, NULL,or `=` character:
    for (pos = 0; name[pos] != 0 && name[pos] != '=' && cur[pos] == name[pos];
         pos++) {
    }

    // We have hit either a NULL character, `=` character, or a
    // character where the strings are not equal. The only case
    // we're interested in is where our search string is NULL and
    // our environment variable is `=`:
    if (name[pos] == 0 && cur[pos] == '=') {
      // We've found our target string! Return the value:
      return &cur[pos + 1];
    }

    // This variable was not the correct one. Skip to the next.
  }

  // Variable not found:
  return 0;
}

void ef_environ_init(const char **environ) {
  // Get the count of environment variables we have:
  size_t environ_len = 0;

  while (1) {
    if (environ[environ_len] == 0) {
      break;
    } else {
      environ_len += 1;
    }
  }

  // Now, environ_len contains the count of non-NULL entries in environ.
  // We need to allocate sufficient capacity to contain all these
  // variables, and the subsequent NULL entry.
  //
  // Hence, we allocate `(environ_len + 1) * sizeof(char *)`.
  // This already zeroes all entries:
  ef_environ = calloc(sizeof(char *), environ_len + 1);

  // Finally, we copy all variables over:
  for (size_t var_idx = 0; var_idx < environ_len; var_idx++) {
    size_t len = strlen(environ[var_idx]);
    char *mem = malloc(len + 1);
    memcpy(mem, environ[var_idx], len);
    mem[len] = 0;
    ef_environ[var_idx] = mem;
  }
}

// ---------- EF Heap Allocator Infrastructure (malloc) -----------------------

static void *alloc_top;
static void *alloc_bottom;
static void *alloc_break;

// Get a large block of memory to use for allocating
void ef_alloc_init(void *top, void *bottom) {
  alloc_top = top;
  alloc_bottom = bottom;
  alloc_break = alloc_top;
}

// X86_64 uses 16 byte alignment
static const intptr_t ALIGN = 16;
static int num_allocs = 0;

// Custom allocator:
void *ef_malloc(size_t size) {

  size_t sizeWithTrack = size + sizeof(size_t);

  void *oldBreak = alloc_break;

  void *newBreak = oldBreak - sizeWithTrack;
  newBreak = (void *)(((intptr_t)newBreak) & ~(ALIGN - 1));
  if (newBreak < alloc_bottom) {
    // We ran out of room
    ef_debug_callback(EF_DEBUG_SUBSYS_ALLOC, 1, size, 0, 0, 0);
    return NULL;
  }

  *((size_t *)newBreak) = size;

  alloc_break = newBreak;
  void *allocated = newBreak + sizeof(size_t);

  ef_debug_callback(EF_DEBUG_SUBSYS_ALLOC, 2, size, 0, (size_t)allocated, 0);
  num_allocs++;
  return allocated;
}

// Actually override malloc
void *malloc(size_t size) { return ef_malloc(size); }

// Overwrite Calloc
void *calloc(size_t nitems, size_t size) {
  size_t totalSize = nitems * size;
  void *retVal = malloc(totalSize);

  if (retVal == NULL) {
    return NULL;
  }

  uint8_t *endPtr = ((uint8_t *)retVal) + size;
  for (uint8_t *ptr = retVal; ptr < endPtr; ptr++) {
    *ptr = 0;
  }

  ef_debug_callback(EF_DEBUG_SUBSYS_ALLOC, 3, nitems, size, (size_t)retVal, 0);
  return retVal;
}

void *realloc(void *ptr, size_t newSize) {
  ef_debug_callback(EF_DEBUG_SUBSYS_ALLOC, 4, (size_t)ptr, newSize, 0, 0);

  // If called with a null-pointer, same as if calling malloc(newSize):
  if (ptr == NULL) {
    return malloc(newSize);
  }

  size_t oldSize = *(size_t *)(ptr - 8);
  if (newSize <= oldSize) {
    *(size_t *)(ptr - 8) = newSize;
    return ptr;
  }

  void *retVal = malloc(newSize);

  if (retVal == NULL) {
    return NULL;
  }

  uint8_t *srcPtr = ptr;
  uint8_t *endPtr = ((uint8_t *)ptr) + oldSize;
  uint8_t *destPtr = retVal;

  while (srcPtr < endPtr) {
    *destPtr = *srcPtr;

    srcPtr++;
    destPtr++;
  }

  free(ptr);
  return retVal;
}

void free(void *ptr) {
  // Doesn't need to do anything, but could set size to 0?
  ef_debug_callback(EF_DEBUG_SUBSYS_ALLOC, 5, (size_t)ptr, 0, 0, 0);

  num_allocs--;
  if (num_allocs <= 0) {
    num_allocs = 0;
    alloc_break = alloc_top;
  }
  return;
}

// ---------- Generic initialization routine ----------------------------------

void ef_runtime_init(void *debug_callback_addr, void *heap_top,
                     void *heap_bottom, const char **environ) {
  // Initialize the callback infrastructure:
  ef_debug_callback_init(debug_callback_addr);

  // Initialize the allocator:
  ef_alloc_init(heap_top, heap_bottom);

  // Initialize the ef_environ variable from the still accessible
  // environ. This uses malloc, so it needs to be done after the
  // allocator has been initialized.
  /* ef_environ_init(environ); */

  ef_debug_callback(EF_DEBUG_SUBSYS_INIT, 0, 0, 0, 0, 0);
}
