#include "precomp.h"

// we have to define this function here rather than in
// gosling because Rust doesn't support C variadic functions
void
tor_assertion_failed_(const char *fname, unsigned int line,
                      const char *func, const char *expr,
                      const char *fmt, ...)
{

}
