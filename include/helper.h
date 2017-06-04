//
// Created by aLIEzTed on 5/11/17.
//

#ifndef DES_HELPER_H
#define DES_HELPER_H
#include <sstream>
#include <iostream>
#include <iomanip>
#define FILE_NOT_FOUND 1
#define FILE_OPEN_ERROR 2
#define FILE_CREATE_ERROR 3
inline void printbinary(uint64_t n) {
  std::bitset<64> a(n);
  std::cout << a << std::endl;
}

inline void printbinary(uint32_t n) {
  std::bitset<32> a(n);
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

template<size_t bits>
inline std::string printHex(std::bitset<bits> bit) {
  std::stringstream res;
  res << std::hex << bit.to_ulong();
  return res.str();
}

inline std::string printHex(uint32_t i) {
  std::stringstream res;
  res << std::hex << i;
  return res.str();
}


inline std::string printHex(uint64_t i) {
  std::stringstream res;
  res << std::hex << i;
  return res.str();
}

inline void convert(int s[]) {
  std::bitset<6> mask(0b011110);
  for (uint64_t i = 0; i < 64; i++) {
    std::bitset<6> t(i);
    int a = (t[5] << 1) + t[0];
    int b = (int) ((t & mask) >> 1).to_ullong();
    std::cout << s[a * 16 + b] << ",";
  }
  std::cout << std::endl;
  std::cout << std::endl;
}

template<typename T>
void dump(const std::string tag, T t) {
  std::cout << tag << " in hex: "
            << std::hex
            << std::uppercase
            << std::noshowbase
            << std::setw(sizeof(T) * 2)
            << std::setfill('0')
            << unsigned(t) << std::endl << std::dec;
}


inline std::string convert_data(char *buffer, size_t size) {
  std::stringstream ss;
  for (int i = 0; i < size; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << unsigned((uint8_t) buffer[i]);
  }
  std::string mystr = ss.str();
  return mystr;
}


inline std::string timeStampToHReadble(const time_t rawtime)
{
  struct tm *tm = localtime(&rawtime);
  char date[30];
  strftime(date, sizeof(date),"%A %c", tm);

  return std::string(date);
}


#endif //DES_HELPER_H
