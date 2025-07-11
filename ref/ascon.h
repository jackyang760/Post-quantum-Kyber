#ifndef ASCON_H_
#define ASCON_H_

#include <stdint.h>

// typedef struct {
//   uint64_t x[5];
// } ascon_state_t;

typedef struct {
  uint64_t x[5];    // Ascon的5个64位状态字
  size_t absorbed;  // 已吸收的字节数(用于跟踪部分块)
} ascon_state_t;

#endif /* ASCON_H_ */
