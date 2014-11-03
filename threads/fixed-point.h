#ifndef FIXED_POINT_ARITHMETIC
#define FIXED_POINT_ARITHMETIC

/* .16 fixed-point arithmetic macros. */

#define FIXED_BASE 14
#define FIXED_F (1LL << FIXED_BASE)

#define to_int_strict(x) ((x) / FIXED_F)
#define to_int(x) (((x) >= 0 ? ((x) + (FIXED_F/2)) : ((x) - (FIXED_F/2))) / FIXED_F)
#define to_fixed(n) ((n) * FIXED_F)

#define add_fixed(x, y) ((x) + (y))

#define sub_fixed(x, y) ((x) - (y))

#define mul_fixed(x, y) ((((int64_t)(x)) * (y)) / FIXED_F)

#define div_fixed(x, y) ((((int64_t)(x)) * FIXED_F) / (y))

#endif
