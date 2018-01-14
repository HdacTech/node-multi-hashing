#ifndef _AES_NI_H
#define _AES_NI_H

#if defined(__cplusplus)
extern "C"
{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <cpuid.h>
#include <wmmintrin.h>

#if !defined(ALIGN16)
#if defined(__GNUC__)
#define ALIGN16 __attribute__((aligned(16)))
#else
#define ALIGN16 __declspec(align(16))
#endif
#endif

typedef struct KEY_SCHEDULE
{
  ALIGN16 unsigned char KEY[16 * 15];
  unsigned int nr;
} AES_KEY;

#if defined(__cplusplus)
}
#endif

#endif /* aes_ni.h */