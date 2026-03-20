#ifndef MATHGF256_H
#define MATHGF256_H

#include <cstdint>

// Multiplication par x dans GF(2^8)
uint8_t xtime(uint8_t x);

// Multiplication de deux polynômes dans GF(2^8)
uint8_t multiply(uint8_t x, uint8_t y);

#endif // MATHGF256_H