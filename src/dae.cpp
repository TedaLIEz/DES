//
// Created by aLIEzTed on 5/10/17.
//
#include "dae.h"
#include "helper.h"

Pi DAE::toIP(uint64_t in) {
  uint64_t t = in;
  for (int i = 0; i < 64; ++i) {
    setBit(t, i, getBit(in, imap[i] - 1) == 0);
  }
  Pi rst;
  rst.left = leftPart(t);
  rst.right = rightPart(t);
  return rst;
}

uint32_t DAE::f(uint32_t in, bitset<48> k) {
  return p(s(e(in) ^ k));
}

bitset<48> DAE::e(uint32_t in) {
  bitset<48> rst;
  for (int i = 0; i < 48; i++) {
    int bit = getBit(in, emap[i] - 1);
    rst.set((size_t) (48 - i - 1), bit);
  }
  return rst;
}

// Done!
uint32_t DAE::s(bitset<48> in) {
  uint32_t rst = 0;
  for (int i = 0; i < 8; i++) {
    int s = (int) subbitset(in, 48 - (i + 1) * 6, 48 - i * 6).to_ulong();
    int tmp = sbox(i, s);
    rst |= (tmp << (28 - (i) * 4));
  }
  return rst;
}

int DAE::sbox(int i, int s) {
  return smap[i][s];
}

uint32_t DAE::p(uint32_t in) {
  uint32_t rst = in;
  for (int i = 0; i < 32; ++i) {
    setBit(rst, i, getBit(in, pmap[i] - 1) == 0);
  }
  return rst;
}

Pi DAE::layer(Pi input, bitset<48> k) {
  Pi rst;
  rst.right = input.left;
  rst.left = input.left + f(input.right, k);
  return rst;
}

uint64_t DAE::reverseIP(Pi in) {
  uint64_t t = (((uint64_t) in.left) << 32) | in.right;
  auto tmp = t;
  std::cout << std::endl;
  for (int i = 0; i < 64; ++i) {
    setBit(t, i, getBit(tmp, reverseIPmap[i] - 1) == 0);
  }
  return t;
}

DAE::DAE(uint64_t key) {
  smap.insert({0, s1map});
  smap.insert({1, s2map});
  smap.insert({2, s3map});
  smap.insert({3, s4map});
  smap.insert({4, s5map});
  smap.insert({5, s6map});
  smap.insert({6, s7map});
  smap.insert({7, s8map});
}




