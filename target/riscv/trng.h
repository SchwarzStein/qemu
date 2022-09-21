#ifndef _RISCV_TRNG_H
#define _RISCV_TRNG_H

#include <stdlib.h>
static inline uint64_t trng(void) {
  return random() & 0xFF;
}

#endif // _RISCV_TRNG_H

