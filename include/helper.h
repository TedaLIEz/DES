//
// Created by aLIEzTed on 5/11/17.
//

#ifndef DES_HELPER_H
#define DES_HELPER_H
#include <iostream>
inline void printbinary(uint64_t n) {
  bitset<64> a(n);
  std::cout << a << std::endl;
}

inline void printbinary(uint32_t n) {
  bitset<32> a(n);
  std::cout << a << std::endl;
}

inline int getBit(uint64_t input, int index) {
  input = input >> (63 - index);
  return (int) (input & 1);
}

inline int getBit(uint32_t input, int index) {
  input = input >> (31 - index);
  return (int) (input & 1);
}

inline void setBit(uint64_t &input, int index, bool zero) {
  uint64_t mask = (uint64_t) (1) << (63 - index);
  if (!zero) {
    input = input | mask;
  } else {
    input = input & (~mask);
  }
}

inline void setBit(uint32_t &input, int index, bool zero) {
  uint32_t mask = (uint32_t) (1) << (31 - index);
  if (!zero) {
    input = input | mask;
  } else {
    input = input & (~mask);
  }
}



/**
 * Get the left part of 64 bits, from left to right
 * @param in the 64 bits input
 * @return the left part of 64 bits, from left to right
 */
inline uint32_t leftPart(uint64_t in) {
  uint32_t rst = (uint32_t) (in >> 32);
  return rst;
}

/**
 * Get the right part of 64 bits, from left to right
 * @param in the 64 bits input
 * @return the right part of 64 bits, from left to right
 */
inline uint32_t rightPart(uint64_t in) {
  uint32_t rst = (uint32_t) in;
  return rst;
}

template<size_t bits>
inline
std::bitset<bits> subbitset(std::bitset<bits> set, int min, int max) {
  const int ignore_hi = bits - max;
  std::bitset<bits> range = (~std::bitset<bits>() << ignore_hi) >> ignore_hi;
  set &= range;
  return set >> min;
}

#endif //DES_HELPER_H
