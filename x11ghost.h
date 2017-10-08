#ifndef X11GHOST_H
#define X11GHOST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void x11ghost_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
