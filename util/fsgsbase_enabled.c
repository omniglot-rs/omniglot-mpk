/* Utility to detect whether FSGSBASE instructions are enabled for
 * userspace. This is example is taken almost verbatim from the Linux kernel
 * documentation: https://docs.kernel.org/arch/x86/x86_64/fsgs.html
 *
 * This is interesting in the context of the Encapsulated Functions MPK runtime,
 * as we need to efficiently identify which thread we are executing in upon a
 * protection domain switch, to load trusted thread-local runtime data. This is
 * tricky, as we want to avoid making system calls (such as for gettid), etc.
 *
 * We could use thread-local storage, but on AMD64 platforms with FSGSBASE
 * instructions enabled, userspace applications have the ability to set these
 * segement registers through the WRFSBASE / WRGSBASE instructions.
 *
 * On platforms which have FSGSBASE instructions enabled for userspace, we thus
 * need to scan for these instructions as they could be potentially dangerous
 * for the Encapsulated Functions MPK runtime.
 */

#include <elf.h>
#include <stdio.h>
#include <sys/auxv.h>

/* Will be eventually in asm/hwcap.h */
#ifndef HWCAP2_FSGSBASE
#define HWCAP2_FSGSBASE (1 << 1)
#endif

int main(void) {
  unsigned val = getauxval(AT_HWCAP2);

  if (val & HWCAP2_FSGSBASE) {
    printf("FSGSBASE enabled\n");
  } else {
    printf("FSGSBASE not enabled\n");
  }
}
