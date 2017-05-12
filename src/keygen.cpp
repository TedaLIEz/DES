//
// Created by aLIEzTed on 5/11/17.
//

#include "keygen.h"
#include "helper.h"

Key Keygen::pc1(uint64_t k) {
  Key key;
  for (int i = 0; i < 28; i++) {
    int bit = getBit(k, pc1map[i] - 1);
    key.c.set((size_t) (28 - i - 1), bit);
  }
  for (int i = 0; i < 28; i++) {
    int bit = getBit(k, pc1map[i + 28] - 1);
    key.d.set((size_t) (28 - i - 1), bit);
  }
  return key;
}

Key Keygen::leftShift(Key key, int index) {
  Key rst;
  rst.c = leftShift(key.c, index);
  rst.d = leftShift(key.d, index);
  return rst;
}

bitset<28> Keygen::leftShift(bitset<28> k, int index) {
  bitset<28> mask(~((uint64_t) ((1 << (28 - index)) - 1)));
  bitset<28> left = (k & mask) >> (28 - index);
  bitset<28> right = k << index;
  return left | right;
}

bitset<48> Keygen::pc2(Key key) {
  bitset<48> rst(0);
  bitset<56> k(key.c.to_ullong());
  k = k << 28;
  k |= bitset<56>(key.d.to_ulong());
  for (int i = 0; i < 48; i++) {
    int bit = k[56 - pc2map[i]];
    rst.set((size_t) (48 - i - 1), bit);
  }
  return rst;
}

vector<bitset<48>> Keygen::getK(uint64_t key) {
  Key k = pc1(key);
  vector<bitset<48>> rst;
  for (int i = 0; i < 16; i++) {
    Key ki = leftShift(k, shifts[i]);
    k = ki;
    auto tmp = pc2(ki);
    rst.push_back(pc2(ki));
  }
  return rst;
}

