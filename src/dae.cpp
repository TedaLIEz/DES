//
// Created by aLIEzTed on 5/10/17.
//
#include "dae.h"

void DAE::setBit(uint64_t &input, int index, bool zero) {
  uint64_t mask = (uint64_t) (1) << 63 - (index);
  if (!zero) {
    input = input | mask;
  } else {
    input = input & (~mask);
  }
}

int DAE::getBit(uint64_t input, int index) {
  input = input >> 63 - (index);

  return (int) (input & 1);
}

int DAE::getBit(uint32_t input, int index) {
  input = input >> 31 - (index);
  return (int) (input & 1);
}
uint32_t DAE::leftPart(uint64_t in) {
  uint32_t rst = (uint32_t) (in >> 32);
  return rst;
}

uint32_t DAE::rightPart(uint64_t in) {
  uint32_t rst = (uint32_t) in;
  return rst;
}

uint64_t DAE::toIP(uint64_t in) {
  uint64_t rst = in;
  for (int i = 0; i < 64; ++i) {
    setBit(rst, i, getBit(in, imap[i] - 1) == 0);
  }
  return rst;
}


uint32_t DAE::f(uint32_t in) {
  return 0;
}


bitset<48> DAE::e(uint32_t in) {
  bitset<48> rst;
  for (int i = 0; i < 48; i++) {
    int bit = getBit(in, emap[i] - 1);
    rst.set((size_t) (48 - i - 1), bit);
  }
  return rst;
}

uint32_t DAE::s(bitset<48> in) {

}

DAE::DAE() {
  smap.insert({0, s1map});
  smap.insert({1, s2map});
  smap.insert({2, s3map});
  smap.insert({3, s4map});
  smap.insert({4, s5map});
  smap.insert({5, s6map});
  smap.insert({6, s7map});
  smap.insert({7, s8map});
}




