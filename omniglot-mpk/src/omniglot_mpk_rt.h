// We should be careful in what we include here, and avoid having it pollute
// the implicit global namespace:
#include <stddef.h>

typedef enum {
  EF_DEBUG_SUBSYS_INIT = 1,
  EF_DEBUG_SUBSYS_ALLOC = 2,
} ef_debug_subsys_t;

size_t ef_debug_callback(ef_debug_subsys_t subsys, size_t a1, size_t a2,
                         size_t a3, size_t a4, size_t a5);
int ef_debug_subsys_enabled(ef_debug_subsys_t subsys);
void ef_debug_subsys_enable(ef_debug_subsys_t subsys);
void ef_debug_subsys_disable(ef_debug_subsys_t subsys);

char *getenv(const char *name);
void *malloc(size_t size);
void *calloc(size_t nitems, size_t size);
void *realloc(void *ptr, size_t newSize);
void free(void *ptr);

// void* malloc(size_t size);
/* int test_add(int a, int b); */
// void puts(char* arg);
